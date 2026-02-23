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
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, error, info, warn};

#[cfg(feature = "noise")]
use crate::noise::{InboundResult, NoiseSessionManager};

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
    /// Raw payload bytes (will be encrypted if Noise is enabled).
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

#[cfg(feature = "noise")]
const MAX_PENDING_PER_PEER: usize = 8;
#[cfg(feature = "noise")]
const MAX_TOTAL_PENDING: usize = 1024;
#[cfg(feature = "noise")]
const PENDING_TTL_SECONDS: u64 = 60;

/// Each queued outbound entry: (payload, enqueue_time, optional ack sender).
/// The ack sender is moved to `pending_acks` only when the encrypted message
/// is actually sent over the wire — NOT when the handshake init is sent.
#[cfg(feature = "noise")]
type PendingEntry = (Vec<u8>, Instant, Option<oneshot::Sender<u8>>);

#[cfg(feature = "noise")]
fn remove_oldest_pending(pending: &mut HashMap<Pubkey, VecDeque<PendingEntry>>) {
    let mut oldest_key = None;
    let mut oldest_time = Instant::now();

    for (key, queue) in pending.iter() {
        if let Some((_, time, _)) = queue.front() {
            if *time < oldest_time {
                oldest_time = *time;
                oldest_key = Some(*key);
            }
        }
    }

    if let Some(key) = oldest_key {
        if let Some(queue) = pending.get_mut(&key) {
            queue.pop_front(); // ack_tx dropped → receiver gets RecvError
            if queue.is_empty() {
                pending.remove(&key);
            }
        }
        warn!("removed oldest pending message due to global limit");
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
    let timestamp = crypto::unix_now();
    let signature = crypto::sign_admission(keypair, &challenge, timestamp);
    let pubkey: Pubkey = keypair.verifying_key().to_bytes();
    let response = if difficulty > 0 {
        tracing::debug!(difficulty, "solving proof-of-work");
        let nonce = crypto::pow_solve(&challenge, &pubkey, timestamp, difficulty);
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

#[cfg(feature = "noise")]
#[allow(clippy::too_many_arguments)]
async fn handle_noise_deliver<S>(
    noise_mgr: &mut NoiseSessionManager,
    pending_outbound: &mut HashMap<Pubkey, VecDeque<PendingEntry>>,
    pending_acks: &mut HashMap<Pubkey, VecDeque<oneshot::Sender<u8>>>,
    ws_tx: &mut SplitSink<WebSocketStream<S>, Message>,
    inbox_tx: &broadcast::Sender<InboundMsg>,
    webhook: Option<&WebhookClient>,
    contacts: &ContactStore,
    src: Pubkey,
    payload: Vec<u8>,
) -> Result<(), RelayError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match noise_mgr.process_inbound(&src, &payload) {
        Ok(InboundResult::Payload(decrypted)) => {
            deliver_inbound(inbox_tx, webhook, contacts, src, decrypted);
        }
        Ok(InboundResult::HandshakeResponse {
            to,
            data: resp_data,
        }) => {
            let route = Frame::route(&to, &resp_data);
            ws_tx
                .send(Message::Binary(route.serialize()))
                .await
                .map_err(|e| RelayError::Transient(e.into()))?;
            // Responder's session is ready — flush any queued outbound messages
            flush_pending_outbound(noise_mgr, pending_outbound, pending_acks, ws_tx, &to).await?;
        }
        Ok(InboundResult::HandshakeComplete) => {
            // Initiator's session is ready — flush any queued outbound messages
            flush_pending_outbound(noise_mgr, pending_outbound, pending_acks, ws_tx, &src).await?;
        }
        Err(e) => {
            warn!(error = %e, from = %arp_common::base58::encode(&src), "noise: dropping undecryptable message");
            noise_mgr.remove_session(&src);
        }
    }
    Ok(())
}

#[cfg(feature = "noise")]
async fn flush_pending_outbound<S>(
    noise_mgr: &mut NoiseSessionManager,
    pending_outbound: &mut HashMap<Pubkey, VecDeque<PendingEntry>>,
    pending_acks: &mut HashMap<Pubkey, VecDeque<oneshot::Sender<u8>>>,
    ws_tx: &mut SplitSink<WebSocketStream<S>, Message>,
    peer: &Pubkey,
) -> Result<(), RelayError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if let Some(queued) = pending_outbound.remove(peer) {
        let now = Instant::now();
        let ttl = Duration::from_secs(PENDING_TTL_SECONDS);
        for (queued_payload, timestamp, ack_tx) in queued {
            if now.duration_since(timestamp) < ttl {
                match noise_mgr.encrypt(peer, &queued_payload) {
                    Ok(Some(encrypted)) => {
                        let route = Frame::route(peer, &encrypted);
                        ws_tx
                            .send(Message::Binary(route.serialize()))
                            .await
                            .map_err(|e| RelayError::Transient(e.into()))?;
                        // Message actually sent — now register ack
                        if let Some(tx) = ack_tx {
                            pending_acks.entry(*peer).or_default().push_back(tx);
                        }
                    }
                    Ok(None) => {
                        warn!("session lost during queue flush");
                        // ack_tx dropped → receiver gets RecvError
                    }
                    Err(e) => {
                        warn!(error = %e, "encrypt failed during queue flush");
                        // ack_tx dropped → receiver gets RecvError
                    }
                }
            } else {
                warn!("dropping expired pending message for peer");
                // ack_tx dropped → receiver gets RecvError
            }
        }
    }
    Ok(())
}

#[cfg(feature = "noise")]
#[allow(clippy::too_many_arguments)]
async fn handle_noise_outbound<S>(
    noise_mgr: &mut NoiseSessionManager,
    pending_outbound: &mut HashMap<Pubkey, VecDeque<PendingEntry>>,
    pending_acks: &mut HashMap<Pubkey, VecDeque<oneshot::Sender<u8>>>,
    ws_tx: &mut SplitSink<WebSocketStream<S>, Message>,
    msg: OutboundMsg,
    ack_tx: Option<oneshot::Sender<u8>>,
) -> Result<(), RelayError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let total_pending: usize = pending_outbound.values().map(|v| v.len()).sum();
    if total_pending >= MAX_TOTAL_PENDING {
        remove_oldest_pending(pending_outbound);
    }

    match noise_mgr.encrypt(&msg.dest, &msg.payload) {
        Ok(Some(encrypted)) => {
            let route = Frame::route(&msg.dest, &encrypted);
            ws_tx
                .send(Message::Binary(route.serialize()))
                .await
                .map_err(|e| RelayError::Transient(e.into()))?;
            // Register ack for the actual encrypted message Route
            if let Some(tx) = ack_tx {
                pending_acks.entry(msg.dest).or_default().push_back(tx);
            }
        }
        Ok(None) => {
            if !noise_mgr.has_pending_handshake(&msg.dest) {
                match noise_mgr.initiate_handshake(&msg.dest) {
                    Ok(hs_data) => {
                        let route = Frame::route(&msg.dest, &hs_data);
                        ws_tx
                            .send(Message::Binary(route.serialize()))
                            .await
                            .map_err(|e| RelayError::Transient(e.into()))?;
                        // Do NOT register ack here — Status for handshake init
                        // is not the same as Status for the actual message
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to initiate noise handshake");
                        // ack_tx dropped → receiver gets RecvError
                        return Ok(());
                    }
                }
            }
            let queue = pending_outbound.entry(msg.dest).or_default();
            if queue.len() < MAX_PENDING_PER_PEER {
                queue.push_back((msg.payload, Instant::now(), ack_tx));
            } else {
                warn!("dropping message: pending queue full for peer");
                // ack_tx dropped → receiver gets RecvError
            }
        }
        Err(e) => {
            // Fail closed: do not send plaintext when encryption is enabled but fails.
            // This prevents accidental disclosure of sensitive data.
            // ack_tx dropped → receiver gets RecvError
            return Err(RelayError::Fatal(anyhow::anyhow!(
                "noise encrypt failed for {}: {}",
                arp_common::base58::encode(&msg.dest),
                e
            )));
        }
    }
    Ok(())
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

    #[cfg(feature = "noise")]
    let noise_enabled = config.noise.enabled;
    #[cfg(feature = "noise")]
    let mut noise_mgr = NoiseSessionManager::new(keypair);
    #[cfg(feature = "noise")]
    let mut pending_outbound: HashMap<Pubkey, VecDeque<PendingEntry>> = HashMap::new();

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
                                #[cfg(feature = "noise")]
                                if noise_enabled {
                                    handle_noise_deliver(
                                        &mut noise_mgr,
                                        &mut pending_outbound,
                                        &mut pending_acks,
                                        &mut ws_tx,
                                        inbox_tx,
                                        webhook,
                                        contacts,
                                        src,
                                        payload,
                                    )
                                    .await?;
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
                #[cfg(feature = "noise")]
                if noise_enabled {
                    handle_noise_outbound(
                        &mut noise_mgr,
                        &mut pending_outbound,
                        &mut pending_acks,
                        &mut ws_tx,
                        msg,
                        ack_tx,
                    )
                    .await?;
                    continue;
                }
                let route = Frame::route(&msg.dest, &msg.payload);
                ws_tx.send(Message::Binary(route.serialize())).await
                    .map_err(|e| RelayError::Transient(e.into()))?;
                if let Some(ack_tx) = ack_tx {
                    pending_acks.entry(dest).or_default().push_back(ack_tx);
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
