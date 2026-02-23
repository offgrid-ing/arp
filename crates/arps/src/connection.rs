use crate::admission::admit;
use crate::error::ArpsError;
use crate::metrics::{counters, gauges, histograms};
use crate::ratelimit::RateLimiter;
use crate::router::ConnHandle;
use crate::server::ServerState;
use arp_common::frame::Frame;
use arp_common::Pubkey;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use rand::rngs::OsRng;
use rand::Rng;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{interval, timeout, Duration};
use tokio_tungstenite::tungstenite::http::Request;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

type WsSink = SplitSink<WebSocketStream<TcpStream>, Message>;
type WsRecv = SplitStream<WebSocketStream<TcpStream>>;

/// Cloudflare IP ranges (IPv4 and IPv6)
/// Source: https://www.cloudflare.com/ips/
const CLOUDFLARE_IP_RANGES: &[&str] = &[
    // IPv4 ranges
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    // IPv6 ranges
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

/// Check if an IP address is within a CIDR range
fn ip_in_range(ip: IpAddr, range: &str) -> bool {
    let parts: Vec<&str> = range.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    let range_ip: IpAddr = match parts[0].parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    let prefix: u8 = match parts[1].parse() {
        Ok(p) => p,
        Err(_) => return false,
    };

    match (ip, range_ip) {
        (IpAddr::V4(ip), IpAddr::V4(range_ip)) => {
            // Validate prefix for IPv4 (0-32)
            if prefix > 32 {
                return false;
            }
            let ip_bits = u32::from(ip);
            let range_bits = u32::from(range_ip);
            // Handle prefix == 0 specially to avoid shift overflow
            let mask = if prefix == 0 {
                0
            } else {
                !((1u32 << (32 - prefix)) - 1)
            };
            (ip_bits & mask) == (range_bits & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(range_ip)) => {
            // Validate prefix for IPv6 (0-128)
            if prefix > 128 {
                return false;
            }
            let ip_bits = u128::from(ip);
            let range_bits = u128::from(range_ip);
            // Handle prefix == 0 specially to avoid shift overflow
            let mask = if prefix == 0 {
                0
            } else {
                !((1u128 << (128 - prefix)) - 1)
            };
            (ip_bits & mask) == (range_bits & mask)
        }
        _ => false,
    }
}

/// Check if an IP address belongs to Cloudflare
fn is_cloudflare_ip(ip: IpAddr) -> bool {
    CLOUDFLARE_IP_RANGES
        .iter()
        .any(|range| ip_in_range(ip, range))
}

/// Extract client IP from request headers
/// Only trusts headers if the connection comes from Cloudflare
fn extract_client_ip(request: &Request<()>, peer_addr: &SocketAddr) -> IpAddr {
    // Only trust headers from Cloudflare IPs
    let is_cloudflare = is_cloudflare_ip(peer_addr.ip());

    if is_cloudflare {
        // Cloudflare headers (most reliable)
        if let Some(v) = request
            .headers()
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
        {
            if let Ok(ip) = v.parse::<IpAddr>() {
                return ip;
            }
        }
    }

    // For non-Cloudflare connections, only use X-Forwarded-For if we can validate it
    // In production with Cloudflare orange cloud, we should never hit this path
    // because all traffic comes through Cloudflare
    peer_addr.ip()
}

struct IpGuard {
    state: Arc<ServerState>,
    ip: IpAddr,
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        let mut remove = false;
        if let Some(mut entry) = self.state.ip_connections.get_mut(&self.ip) {
            *entry = entry.saturating_sub(1);
            if *entry == 0 {
                remove = true;
            }
        }
        if remove {
            self.state
                .ip_connections
                .remove_if(&self.ip, |_, v| *v == 0);
        }
    }
}

/// Send a challenge frame, wait for a valid admission response, and return
/// the authenticated client's public key.
async fn perform_admission(
    ws_tx: &mut WsSink,
    ws_rx: &mut WsRecv,
    state: &ServerState,
) -> Result<Pubkey, ArpsError> {
    let mut challenge = [0u8; 32];
    OsRng.fill(&mut challenge);

    let server_pubkey = state.server_keypair.verifying_key().to_bytes();

    let challenge_frame = Frame::challenge(&challenge, &server_pubkey, state.config.pow_difficulty);
    ws_tx
        .send(Message::Binary(challenge_frame.serialize()))
        .await
        .map_err(ArpsError::WebSocket)?;

    match timeout(
        Duration::from_secs(state.config.admit_timeout),
        admit(ws_rx, &challenge, state.config.pow_difficulty),
    )
    .await
    {
        Ok(Ok(pk)) => {
            counters::admissions_total("admitted");
            let admitted_frame = Frame::admitted();
            ws_tx
                .send(Message::Binary(admitted_frame.serialize()))
                .await
                .map_err(ArpsError::WebSocket)?;
            Ok(pk)
        }
        Ok(Err(e)) => {
            counters::admissions_total("rejected");
            let rejected_frame = Frame::rejected(0x01);
            let _ = ws_tx
                .send(Message::Binary(rejected_frame.serialize()))
                .await;
            tracing::debug!("sent rejection frame to client");
            Err(e)
        }
        Err(_) => {
            counters::admissions_total("timeout");
            let rejected_frame = Frame::rejected(0x02);
            let _ = ws_tx
                .send(Message::Binary(rejected_frame.serialize()))
                .await;
            tracing::debug!("sent timeout rejection to client");
            Err(ArpsError::InvalidAdmission)
        }
    }
}

/// Drive the main message-relay select loop for an admitted connection.
async fn run_message_loop(
    ws_tx: &mut WsSink,
    ws_rx: &mut WsRecv,
    deliver_rx: &mut mpsc::Receiver<Vec<u8>>,
    state: &ServerState,
    conn_handle: &ConnHandle,
) -> Result<(), ArpsError> {
    let mut rate_limiter = RateLimiter::new();
    let mut ping_interval = interval(Duration::from_secs(state.config.ping_interval));
    let idle_timeout = Duration::from_secs(state.config.idle_timeout);
    let mut last_activity = Instant::now();

    loop {
        tokio::select! {
            msg = ws_rx.next() => {
                last_activity = Instant::now();
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        let start = Instant::now();
                        match process_frame(
                            &data,
                            state,
                            ws_tx,
                            &mut rate_limiter,
                            conn_handle,
                        )
                        .await
                        {
                            Ok(()) => {
                                histograms::relay_latency_seconds(start.elapsed().as_secs_f64());
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        if let Err(e) = ws_tx.send(Message::Pong(data)).await {
                            tracing::debug!("failed to send pong: {}", e);
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => return Ok(()),
                    Some(Err(e)) => return Err(ArpsError::WebSocket(e)),
                    _ => {}
                }
            }
            Some(data) = deliver_rx.recv() => {
                last_activity = Instant::now();
                counters::payload_bytes_total("out", data.len() as u64);
                ws_tx.send(Message::Binary(data)).await.map_err(ArpsError::WebSocket)?;
            }
            _ = ping_interval.tick() => {
                if last_activity.elapsed() >= idle_timeout {
                    tracing::debug!("idle timeout reached, closing connection");
                    return Ok(());
                }
                if let Err(e) = ws_tx.send(Message::Ping(vec![])).await {
                    tracing::debug!("failed to send ping: {}", e);
                }
            }
        }
    }
}

pub async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    state: Arc<ServerState>,
) -> Result<(), ArpsError> {
    // Acquire pre-auth semaphore to limit unauthenticated connections
    // This prevents DoS by exhausting file descriptors before authentication
    let _permit = state.pre_auth_semaphore.acquire().await.map_err(|_| {
        tracing::debug!("pre-auth semaphore closed");
        ArpsError::ConnectionClosed
    })?;

    let ws_config = WebSocketConfig {
        max_message_size: Some(33 + 65535),
        max_frame_size: Some(33 + 65535),
        ..WebSocketConfig::default()
    };

    let client_ip = Arc::new(std::sync::OnceLock::new());
    let client_proto = Arc::new(std::sync::OnceLock::new());
    let ip_cell = client_ip.clone();
    let proto_cell = client_proto.clone();
    let ws_stream = tokio_tungstenite::accept_hdr_async_with_config(
        stream,
        move |req: &Request<()>, mut resp: tokio_tungstenite::tungstenite::http::Response<()>| {
            let ip = extract_client_ip(req, &peer_addr);
            let _ = ip_cell.set(ip);
            if let Some(protocols) = req.headers().get("sec-websocket-protocol") {
                if let Ok(proto_str) = protocols.to_str() {
                    for p in proto_str.split(',').map(str::trim) {
                        let _ = proto_cell.set(p.to_string());
                        if p == arp_common::types::PROTOCOL_VERSION {
                            resp.headers_mut().insert(
                                "sec-websocket-protocol",
                                tokio_tungstenite::tungstenite::http::HeaderValue::from_static(
                                    arp_common::types::PROTOCOL_VERSION,
                                ),
                            );
                            break;
                        }
                    }
                }
            }
            Ok(resp)
        },
        Some(ws_config),
    )
    .await
    .map_err(ArpsError::WebSocket)?;

    let client_ip = client_ip.get().copied().unwrap_or_else(|| peer_addr.ip());

    // Atomic check-and-increment for per-IP connection limiting
    // Uses DashMap entry API to prevent race conditions between check and increment
    let mut should_reject = false;

    // Use entry API to atomically check and update
    match state.ip_connections.entry(client_ip) {
        dashmap::mapref::entry::Entry::Occupied(mut entry) => {
            let count = *entry.get();
            if count >= state.config.max_conns_ip {
                should_reject = true;
            } else {
                *entry.get_mut() += 1;
            }
        }
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(1);
        }
    }

    if should_reject {
        tracing::debug!(ip = %client_ip, limit = state.config.max_conns_ip, "per-IP connection limit exceeded");
        return Err(ArpsError::ConnectionClosed);
    }

    let _ip_guard = IpGuard {
        state: state.clone(),
        ip: client_ip,
    };

    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    // Reject clients with outdated protocol version
    let required = arp_common::types::PROTOCOL_VERSION;
    let client_version = client_proto.get().map(String::as_str).unwrap_or("");
    if client_version != required {
        tracing::debug!(
            client_proto = client_version,
            required = required,
            "rejecting outdated client"
        );
        let rejected = Frame::rejected(arp_common::types::rejection_reason::OUTDATED_CLIENT);
        let _ = ws_tx.send(Message::Binary(rejected.serialize())).await;
        return Err(ArpsError::ConnectionClosed);
    }

    let pubkey = perform_admission(&mut ws_tx, &mut ws_rx, &state).await?;

    let (deliver_tx, mut deliver_rx) = mpsc::channel::<Vec<u8>>(256);

    let admitted_at = Instant::now();
    let conn_handle = ConnHandle {
        tx: deliver_tx,
        pubkey,
        admitted_at,
    };

    if let Some(old_handle) = state.router.insert(pubkey, conn_handle.clone()) {
        drop(old_handle);
    }

    gauges::inc_connections_active();

    let result = run_message_loop(
        &mut ws_tx,
        &mut ws_rx,
        &mut deliver_rx,
        &state,
        &conn_handle,
    )
    .await;

    state.router.remove_if(&pubkey, admitted_at);
    gauges::dec_connections_active();

    result
}

async fn process_frame<T>(
    data: &[u8],
    state: &ServerState,
    ws_tx: &mut T,
    rate_limiter: &mut RateLimiter,
    conn_handle: &ConnHandle,
) -> Result<(), ArpsError>
where
    T: futures_util::Sink<Message> + Unpin,
    T::Error: std::fmt::Debug,
{
    let frame = Frame::parse(data).map_err(ArpsError::Frame)?;

    match frame {
        Frame::Route { dest, payload } => {
            if payload.len() > state.config.max_payload {
                counters::messages_dropped_total("oversize");
                let status = Frame::status(&dest, 0x03);
                ws_tx
                    .send(Message::Binary(status.serialize()))
                    .await
                    .map_err(|_| ArpsError::ConnectionClosed)?;
                return Ok(());
            }

            if let Some(_reason) = rate_limiter.check_and_record(
                state.config.msg_rate,
                state.config.bw_rate,
                payload.len(),
            ) {
                counters::messages_dropped_total("rate_limit");
                let status = Frame::status(&dest, 0x02);
                ws_tx
                    .send(Message::Binary(status.serialize()))
                    .await
                    .map_err(|_| ArpsError::ConnectionClosed)?;
                return Ok(());
            }

            if let Some(dest_handle) = state.router.get(&dest) {
                let deliver_bytes = Frame::serialize_deliver(&conn_handle.pubkey, &payload);

                match dest_handle.tx.try_send(deliver_bytes) {
                    Ok(()) => {
                        counters::messages_relayed_total();
                        counters::payload_bytes_total("in", payload.len() as u64);
                        let status =
                            Frame::status(&dest, arp_common::types::status_code::DELIVERED);
                        ws_tx
                            .send(Message::Binary(status.serialize()))
                            .await
                            .map_err(|_| ArpsError::ConnectionClosed)?;
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        counters::messages_dropped_total("rate_limit");
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        counters::messages_dropped_total("offline");
                        let status = Frame::status(&dest, 0x01);
                        ws_tx
                            .send(Message::Binary(status.serialize()))
                            .await
                            .map_err(|_| ArpsError::ConnectionClosed)?;
                        state.router.remove_if(&dest, dest_handle.admitted_at);
                    }
                }
            } else {
                counters::messages_dropped_total("offline");
                let status = Frame::status(&dest, 0x01);
                ws_tx
                    .send(Message::Binary(status.serialize()))
                    .await
                    .map_err(|_| ArpsError::ConnectionClosed)?;
            }
        }
        Frame::Ping { payload } => {
            let pong_frame = Frame::pong(&payload);
            ws_tx
                .send(Message::Binary(pong_frame.serialize()))
                .await
                .map_err(|_| ArpsError::ConnectionClosed)?;
        }
        other => {
            tracing::debug!(
                frame_type = other.frame_type(),
                "ignoring unexpected frame type post-admission"
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio_tungstenite::tungstenite::http::Request;

    fn peer_addr() -> SocketAddr {
        // Use a Cloudflare IP so headers are trusted in tests
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(173, 245, 48, 1)), 12345)
    }

    #[test]
    fn extract_ip_cf_connecting_ip() {
        let req = Request::builder()
            .header("cf-connecting-ip", "203.0.113.50")
            .body(())
            .unwrap();
        assert_eq!(
            extract_client_ip(&req, &peer_addr()),
            "203.0.113.50".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn extract_ip_priority_cf_over_others() {
        let req = Request::builder()
            .header("cf-connecting-ip", "203.0.113.50")
            .header("x-forwarded-for", "198.51.100.10")
            .body(())
            .unwrap();
        assert_eq!(
            extract_client_ip(&req, &peer_addr()),
            "203.0.113.50".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn extract_ip_fallback_to_peer() {
        let req = Request::builder().body(()).unwrap();
        assert_eq!(extract_client_ip(&req, &peer_addr()), peer_addr().ip());
    }

    #[test]
    fn ip_guard_decrements_on_drop() {
        use crate::config::ServerConfig;
        use crate::router::Router;

        let config = ServerConfig {
            listen: "127.0.0.1:8080".parse().unwrap(),
            metrics_addr: "127.0.0.1:9090".parse().unwrap(),
            max_conns: 100,
            max_conns_ip: 10,
            msg_rate: 120,
            bw_rate: 1_048_576,
            max_payload: 65535,
            admit_timeout: 5,
            ping_interval: 30,
            idle_timeout: 120,
            pow_difficulty: 0,
        };
        let state = Arc::new(ServerState {
            config,
            router: Router::new(),
            server_keypair: ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]),
            ip_connections: dashmap::DashMap::new(),
            pre_auth_semaphore: tokio::sync::Semaphore::new(1000),
        });

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        state.ip_connections.insert(ip, 2);

        {
            let _guard = IpGuard {
                state: state.clone(),
                ip,
            };
        } // guard drops here

        assert_eq!(*state.ip_connections.get(&ip).unwrap(), 1);
    }

    #[test]
    fn ip_guard_removes_entry_at_zero() {
        use crate::config::ServerConfig;
        use crate::router::Router;

        let config = ServerConfig {
            listen: "127.0.0.1:8080".parse().unwrap(),
            metrics_addr: "127.0.0.1:9090".parse().unwrap(),
            max_conns: 100,
            max_conns_ip: 10,
            msg_rate: 120,
            bw_rate: 1_048_576,
            max_payload: 65535,
            admit_timeout: 5,
            ping_interval: 30,
            idle_timeout: 120,
            pow_difficulty: 0,
        };
        let state = Arc::new(ServerState {
            config,
            router: Router::new(),
            server_keypair: ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]),
            ip_connections: dashmap::DashMap::new(),
            pre_auth_semaphore: tokio::sync::Semaphore::new(1000),
        });

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        state.ip_connections.insert(ip, 1);

        {
            let _guard = IpGuard {
                state: state.clone(),
                ip,
            };
        }

        assert!(state.ip_connections.get(&ip).is_none());
    }
}
