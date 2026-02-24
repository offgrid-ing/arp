use crate::backoff::ExponentialBackoff;
use crate::config::ClientConfig;
use crate::contacts::ContactStore;
use crate::webhook::WebhookClient;
use arp_common::crypto;
use arp_common::frame::Frame;
use arp_common::Pubkey;
use chrono::Utc;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, error, info, warn};

#[derive(Debug)]
enum RelayError {
    Fatal(anyhow::Error),
    Transient(anyhow::Error),
}

/// Connection status of the relay WebSocket link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnStatus {
    /// Not connected to the relay.
    Disconnected,
    /// TCP/TLS connection in progress or admission handshake pending.
    Connecting,
    /// Admitted and ready to route messages.
    Connected,
}

/// A message received from a remote peer via the relay.
#[derive(Debug, Clone)]
pub struct InboundMsg {
    /// Sender's Ed25519 public key.
    pub from: Pubkey,
    /// Decrypted (or plaintext) message payload.
    pub payload: Vec<u8>,
    /// Local timestamp when the message was received.
    pub received_at: chrono::DateTime<Utc>,
}

/// A message to send to a remote peer via the relay.
#[derive(Debug)]
pub struct OutboundMsg {
    /// Recipient's Ed25519 public key.
    pub dest: Pubkey,
    /// Raw payload bytes (will be encrypted if encryption is enabled).
    pub payload: Vec<u8>,
    /// Optional channel to receive the relay's status code for this send.
    pub ack_tx: Option<oneshot::Sender<u8>>,
}

fn deliver_inbound(
    inbox_tx: &broadcast::Sender<InboundMsg>,
    webhook: Option<&WebhookClient>,
    contacts: &ContactStore,
    from: Pubkey,
    payload: Vec<u8>,
) {
    if !contacts.should_deliver(&from) {
        return;
    }
    if let Some(wh) = webhook {
        wh.fire(&from, &payload);
    }
    if inbox_tx
        .send(InboundMsg {
            from,
            payload,
            received_at: Utc::now(),
        })
        .is_err()
    {
        debug!("inbound message dropped: no active subscribers");
    }
}

/// Top-level relay connection loop with automatic reconnection and backoff.
pub async fn relay_connection_manager(
    config: Arc<ClientConfig>,
    keypair: ed25519_dalek::SigningKey,
    mut outbox_rx: mpsc::Receiver<OutboundMsg>,
    inbox_tx: broadcast::Sender<InboundMsg>,
    status_tx: watch::Sender<ConnStatus>,
    contacts: Arc<ContactStore>,
) {
    let webhook = WebhookClient::new(&config.webhook);
    if webhook.is_some() {
        info!("webhook push enabled → {}", config.webhook.url);
    }

    let mut backoff = ExponentialBackoff::new(
        Duration::from_millis(config.reconnect.initial_delay_ms),
        Duration::from_millis(config.reconnect.max_delay_ms),
        config.reconnect.backoff_factor,
    );

    loop {
        status_tx.send_replace(ConnStatus::Connecting);

        match connect_and_run(
            &config,
            &keypair,
            &mut outbox_rx,
            &inbox_tx,
            &status_tx,
            webhook.as_ref(),
            &contacts,
        )
        .await
        {
            Ok(()) => {
                info!("relay connection closed cleanly");
                break;
            }
            Err(RelayError::Fatal(e)) => {
                error!(error = %e, "fatal relay error, not retrying");
                status_tx.send_replace(ConnStatus::Disconnected);
                break;
            }
            Err(RelayError::Transient(e)) => {
                let was_connected = *status_tx.borrow() == ConnStatus::Connected;
                warn!(error = %e, "relay connection lost");
                status_tx.send_replace(ConnStatus::Disconnected);
                if was_connected {
                    backoff.reset();
                }
            }
        }

        let delay = backoff.next_delay();
        info!(
            delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            "reconnecting"
        );
        tokio::time::sleep(delay).await;
    }
}

async fn perform_relay_handshake<S>(
    ws_tx: &mut SplitSink<WebSocketStream<S>, Message>,
    ws_rx: &mut SplitStream<WebSocketStream<S>>,
    keypair: &ed25519_dalek::SigningKey,
) -> Result<(), RelayError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let challenge_frame = ws_rx
        .next()
        .await
        .ok_or_else(|| RelayError::Transient(anyhow::anyhow!("connection closed before challenge")))
        .and_then(|r| r.map_err(|e| RelayError::Transient(e.into())))?;
    let Message::Binary(challenge_data) = challenge_frame else {
        return Err(RelayError::Transient(anyhow::anyhow!(
            "expected binary challenge frame"
        )));
    };

    let frame = Frame::parse(&challenge_data)
        .map_err(|e| RelayError::Transient(anyhow::anyhow!("challenge parse error: {e}")))?;
    let Frame::Challenge {
        challenge,
        difficulty,
        ..
    } = frame
    else {
        return Err(RelayError::Transient(anyhow::anyhow!(
            "expected challenge frame"
        )));
    };
    let timestamp = crypto::unix_now()
        .map_err(|e| RelayError::Fatal(anyhow::anyhow!("system clock error: {e}")))?;
    let signature = crypto::sign_admission(keypair, &challenge, timestamp);
    let pubkey: Pubkey = keypair.verifying_key().to_bytes();
    let response = if difficulty > 0 {
        tracing::debug!(difficulty, "solving proof-of-work");
        let nonce = crypto::pow_solve(&challenge, &pubkey, timestamp, difficulty)
            .map_err(|e| RelayError::Fatal(anyhow::anyhow!("PoW solver failed: {e}")))?;
        Frame::response_with_pow(&pubkey, timestamp, &signature, nonce)
    } else {
        Frame::response(&pubkey, timestamp, &signature)
    };
    ws_tx
        .send(Message::Binary(response.serialize()))
        .await
        .map_err(|e| RelayError::Transient(e.into()))?;

    let admit_frame = ws_rx
        .next()
        .await
        .ok_or_else(|| {
            RelayError::Transient(anyhow::anyhow!(
                "connection closed before admission response"
            ))
        })
        .and_then(|r| r.map_err(|e| RelayError::Transient(e.into())))?;
    let Message::Binary(admit_data) = admit_frame else {
        return Err(RelayError::Transient(anyhow::anyhow!(
            "expected binary admission frame"
        )));
    };

    let admit = Frame::parse(&admit_data)
        .map_err(|e| RelayError::Transient(anyhow::anyhow!("admission parse error: {e}")))?;
    match admit {
        Frame::Admitted => Ok(()),
        Frame::Rejected { reason } => {
            if reason == arp_common::types::rejection_reason::OUTDATED_CLIENT {
                error!("arpc is outdated and incompatible with the relay server");
                eprintln!();
                eprintln!("arpc is outdated. Run 'arpc update' to update.");
                eprintln!();
            }
            Err(RelayError::Fatal(anyhow::anyhow!(
                "admission rejected with reason: 0x{reason:02x}"
            )))
        }
        _ => Err(RelayError::Fatal(anyhow::anyhow!(
            "unexpected frame during admission"
        ))),
    }
}

async fn connect_and_run(
    config: &ClientConfig,
    keypair: &ed25519_dalek::SigningKey,
    outbox_rx: &mut mpsc::Receiver<OutboundMsg>,
    inbox_tx: &broadcast::Sender<InboundMsg>,
    status_tx: &watch::Sender<ConnStatus>,
    webhook: Option<&WebhookClient>,
    contacts: &ContactStore,
) -> Result<(), RelayError> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut req = config
        .relay
        .as_str()
        .into_client_request()
        .map_err(|e| RelayError::Transient(e.into()))?;
    req.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        arp_common::types::PROTOCOL_VERSION
            .parse()
            .expect("valid header value"),
    );
    let (ws, _) = tokio_tungstenite::connect_async(req)
        .await
        .map_err(|e| RelayError::Transient(e.into()))?;
    let (mut ws_tx, mut ws_rx) = ws.split();

    perform_relay_handshake(&mut ws_tx, &mut ws_rx, keypair).await?;

    status_tx.send_replace(ConnStatus::Connected);
    info!("admitted to relay");

    #[cfg(feature = "encryption")]
    let encryption_enabled = config.encryption.enabled;

    let mut pending_acks: HashMap<Pubkey, VecDeque<oneshot::Sender<u8>>> = HashMap::new();
    let mut ping_interval = tokio::time::interval(Duration::from_secs(config.keepalive.interval_s));

    loop {
        tokio::select! {
            msg = ws_rx.next() => {
                let msg = msg
                    .ok_or_else(|| RelayError::Transient(anyhow::anyhow!("connection closed")))
                    .and_then(|r| r.map_err(|e| RelayError::Transient(e.into())))?;
                match msg {
                    Message::Binary(data) => {
                        let frame = match Frame::parse(&data) {
                            Ok(f) => f,
                            Err(e) => {
                                debug!(error = %e, "ignoring unparseable frame");
                                continue;
                            }
                        };
                        match frame {
                            Frame::Deliver { src, payload } => {
                                #[cfg(feature = "encryption")]
                                if encryption_enabled {
                                    match crate::hpke_seal::open(keypair, &src, &payload) {
                                        Ok(decrypted) => {
                                            deliver_inbound(inbox_tx, webhook, contacts, src, decrypted);
                                        }
                                        Err(e) => {
                                            if payload.first() == Some(&crate::hpke_seal::prefix::PLAINTEXT) {
                                                deliver_inbound(inbox_tx, webhook, contacts, src, payload[1..].to_vec());
                                            } else {
                                                warn!(error = %e, from = %arp_common::base58::encode(&src), "hpke: dropping undecryptable message");
                                            }
                                        }
                                    }
                                    continue;
                                }
                                deliver_inbound(inbox_tx, webhook, contacts, src, payload);
                            }
                            Frame::Status { ref_pubkey, code } => {
                                debug!(
                                    pubkey = %arp_common::base58::encode(&ref_pubkey),
                                    code = code,
                                    "status frame received"
                                );
                                if let Some(queue) = pending_acks.get_mut(&ref_pubkey) {
                                    if let Some(ack_tx) = queue.pop_front() {
                                        let _ = ack_tx.send(code);
                                    }
                                    if queue.is_empty() {
                                        pending_acks.remove(&ref_pubkey);
                                    }
                                }
                            }
                            Frame::Pong { .. } => {
                                debug!("pong received");
                            }
                            _ => {
                                debug!(frame_type = frame.frame_type(), "unexpected frame type");
                            }
                        }
                    }
                    Message::Ping(data) => {
                        ws_tx.send(Message::Pong(data)).await
                            .map_err(|e| RelayError::Transient(e.into()))?;
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }

            outbound = outbox_rx.recv() => {
                let Some(mut msg) = outbound else { break };

                let dest = msg.dest;
                let ack_tx = msg.ack_tx.take();

                #[cfg(feature = "encryption")]
                let wire_payload = if encryption_enabled {
                    match crate::hpke_seal::seal(keypair, &msg.dest, &msg.payload) {
                        Ok(encrypted) => encrypted,
                        Err(e) => {
                            error!(error = %e, "hpke seal failed");
                            continue;
                        }
                    }
                } else {
                    msg.payload
                };
                #[cfg(not(feature = "encryption"))]
                let wire_payload = msg.payload;

                let route = Frame::route(&dest, &wire_payload);
                ws_tx.send(Message::Binary(route.serialize())).await
                    .map_err(|e| RelayError::Transient(e.into()))?;
                if let Some(ack_tx) = ack_tx {
                    let queue = pending_acks.entry(dest).or_default();
                    if queue.len() >= 16 {
                        // Evict oldest pending ack — send synthetic OFFLINE
                        // so caller gets a meaningful error, not a generic RecvError
                        if let Some(evicted) = queue.pop_front() {
                            let _ = evicted.send(arp_common::types::status_code::OFFLINE);
                        }
                    }
                    queue.push_back(ack_tx);
                    if pending_acks.len() > 256 {
                        pending_acks.retain(|_, q| !q.is_empty());
                    }
                }
            }
            _ = ping_interval.tick() => {
                ws_tx.send(Message::Ping(vec![])).await
                    .map_err(|e| RelayError::Transient(e.into()))?;
            }
        }
    }

    Ok(())
}
