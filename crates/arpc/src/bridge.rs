//! OpenClaw gateway bridge — injects inbound ARP messages into an agent session.
//!
//! Connects to the OpenClaw gateway via WebSocket protocol v3, performs a
//! handshake, then forwards each [`InboundMsg`] as a `chat.send` request.
//! One-way only: ARP → session. The agent uses `arpc send` for outbound.

use crate::backoff::ExponentialBackoff;
use crate::config::BridgeConfig;
use crate::contacts::ContactStore;
use crate::relay::InboundMsg;

use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const SEND_TIMEOUT: Duration = Duration::from_secs(15);

fn rand_id() -> String {
    let bytes: [u8; 16] = rand::thread_rng().gen();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn format_message(contacts: &ContactStore, msg: &InboundMsg) -> String {
    let from_b58 = arp_common::base58::encode(&msg.from);
    let display_name = contacts
        .lookup_by_pubkey(&from_b58)
        .map_or_else(|| from_b58.clone(), |c| c.name);
    let body = String::from_utf8_lossy(&msg.payload);
    format!("[ARP from {display_name}]: {body}")
}

fn handshake_frame(token: &str) -> Value {
    json!({
        "type": "req",
        "id": "connect-1",
        "method": "connect",
        "params": {
            "minProtocol": 3,
            "maxProtocol": 3,
            "client": {
                "id": "arp-bridge",
                "version": env!("CARGO_PKG_VERSION"),
                "platform": "rust",
                "mode": "operator"
            },
            "role": "operator",
            "scopes": ["operator.read", "operator.write"],
            "auth": {
                "token": token
            }
        }
    })
}

fn chat_send_frame(session_key: &str, message: &str) -> Value {
    json!({
        "type": "req",
        "id": rand_id(),
        "method": "chat.send",
        "params": {
            "sessionKey": session_key,
            "message": message,
            "idempotencyKey": rand_id()
        }
    })
}

/// Top-level bridge loop with automatic reconnection and backoff.
///
/// Subscribes to the daemon's `inbox_tx` broadcast channel and, for each
/// inbound message, sends `chat.send` to the OpenClaw gateway.
pub async fn run_bridge(
    config: BridgeConfig,
    mut inbox_rx: broadcast::Receiver<InboundMsg>,
    contacts: Arc<ContactStore>,
) {
    info!(
        gateway = %config.gateway_url,
        session_key = "<REDACTED>",
        "bridge starting"
    );

    let mut backoff =
        ExponentialBackoff::new(Duration::from_millis(500), Duration::from_secs(30), 2.0);

    loop {
        match bridge_session(&config, &mut inbox_rx, &contacts).await {
            Ok(()) => {
                info!("bridge session ended cleanly");
                break;
            }
            Err(BridgeError::Fatal(e)) => {
                error!(error = %e, "fatal bridge error, not retrying");
                break;
            }
            Err(BridgeError::Transient(e)) => {
                warn!(error = %e, "bridge connection lost");
            }
        }

        let delay = backoff.next_delay();
        info!(delay_ms = delay.as_millis() as u64, "bridge reconnecting");
        tokio::time::sleep(delay).await;
    }
}

#[derive(Debug)]
enum BridgeError {
    Fatal(anyhow::Error),
    Transient(anyhow::Error),
}

async fn bridge_session(
    config: &BridgeConfig,
    inbox_rx: &mut broadcast::Receiver<InboundMsg>,
    contacts: &ContactStore,
) -> Result<(), BridgeError> {
    // --- Connect ---
    let (ws, _) = tokio_tungstenite::connect_async(&config.gateway_url)
        .await
        .map_err(|e| BridgeError::Transient(e.into()))?;

    let (mut ws_tx, mut ws_rx) = ws.split();
    info!("bridge connected to gateway");

    // --- Handshake ---
    let hs = handshake_frame(&config.gateway_token);
    ws_tx
        .send(Message::Text(hs.to_string()))
        .await
        .map_err(|e| BridgeError::Transient(e.into()))?;

    let hs_resp = tokio::time::timeout(HANDSHAKE_TIMEOUT, ws_rx.next())
        .await
        .map_err(|_| BridgeError::Transient(anyhow::anyhow!("handshake timeout")))?
        .ok_or_else(|| {
            BridgeError::Transient(anyhow::anyhow!("connection closed during handshake"))
        })?
        .map_err(|e| BridgeError::Transient(e.into()))?;

    let hs_text = match hs_resp {
        Message::Text(t) => t,
        other => {
            return Err(BridgeError::Transient(anyhow::anyhow!(
                "expected text handshake response, got: {other:?}"
            )));
        }
    };

    let hs_json: Value = serde_json::from_str(&hs_text)
        .map_err(|e| BridgeError::Transient(anyhow::anyhow!("handshake JSON parse error: {e}")))?;

    if hs_json.get("type").and_then(|v| v.as_str()) != Some("res") {
        return Err(BridgeError::Transient(anyhow::anyhow!(
            "unexpected handshake frame type: {hs_json}"
        )));
    }
    if hs_json.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        let err_msg = hs_json
            .pointer("/error/message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        return Err(BridgeError::Fatal(anyhow::anyhow!(
            "handshake rejected: {err_msg}"
        )));
    }

    info!("bridge handshake succeeded");

    // --- Message forwarding loop ---
    loop {
        tokio::select! {
            msg = inbox_rx.recv() => {
                match msg {
                    Ok(inbound) => {
                        let text = format_message(contacts, &inbound);
                        let frame = chat_send_frame(&config.session_key, &text);

                        debug!(message = %text, "bridge injecting message");

                        ws_tx
                            .send(Message::Text(frame.to_string()))
                            .await
                            .map_err(|e| BridgeError::Transient(e.into()))?;

                        // Response may be interleaved with gateway events; non-blocking check
                        match tokio::time::timeout(SEND_TIMEOUT, ws_rx.next()).await {
                            Ok(Some(Ok(Message::Text(resp_text)))) => {
                                if let Ok(resp) = serde_json::from_str::<Value>(&resp_text) {
                                    if resp.get("ok").and_then(|v| v.as_bool()) == Some(true) {
                                        debug!("chat.send succeeded");
                                    } else {
                                        let err = resp
                                            .pointer("/error/message")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("unknown");
                                        warn!(error = %err, "chat.send failed");
                                    }
                                }
                            }
                            Ok(Some(Ok(Message::Close(_)))) => {
                                return Err(BridgeError::Transient(
                                    anyhow::anyhow!("gateway closed connection"),
                                ));
                            }
                            Ok(Some(Err(e))) => {
                                return Err(BridgeError::Transient(e.into()));
                            }
                            Ok(None) => {
                                return Err(BridgeError::Transient(
                                    anyhow::anyhow!("gateway connection closed"),
                                ));
                            }
                            Err(_) => {
                                warn!("chat.send response timeout (message may still have been delivered)");
                            }
                            _ => {}
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(skipped = n, "bridge lagged behind inbox, some messages dropped");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        info!("inbox channel closed, bridge shutting down");
                        return Ok(());
                    }
                }
            }

            ws_msg = ws_rx.next() => {
                match ws_msg {
                    Some(Ok(Message::Ping(data))) => {
                        ws_tx.send(Message::Pong(data)).await
                            .map_err(|e| BridgeError::Transient(e.into()))?;
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        return Err(BridgeError::Transient(
                            anyhow::anyhow!("gateway closed connection"),
                        ));
                    }
                    Some(Ok(Message::Text(text))) => {
                        debug!(frame = %text, "bridge ignoring gateway event");
                    }
                    Some(Err(e)) => {
                        return Err(BridgeError::Transient(e.into()));
                    }
                    _ => {}
                }
            }
        }
    }
}
