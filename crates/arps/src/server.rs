use crate::config::ServerConfig;
use crate::connection::handle_connection;
use crate::error::ArpsError;
use crate::router::Router;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

/// Shared state for the relay server.
pub struct ServerState {
    /// Message router for dispatching frames between connected agents.
    pub router: Router,
    /// Ed25519 signing key used for server-side authentication.
    pub server_keypair: ed25519_dalek::SigningKey,
    /// Runtime server configuration.
    pub config: ServerConfig,
    /// Per-IP connection counter for enforcing connection limits.
    pub ip_connections: DashMap<IpAddr, usize>,
    /// Semaphore to limit unauthenticated (pre-admission) connections.
    pub pre_auth_semaphore: Semaphore,
}

/// # Errors
///
/// Returns an error if the accept loop encounters an I/O failure.
pub async fn run(listener: TcpListener, state: Arc<ServerState>) -> Result<(), ArpsError> {
    let local_addr = listener.local_addr().map_err(ArpsError::Io)?;
    info!("server listening on {}", local_addr);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                if state.router.len() >= state.config.max_conns {
                    warn!("max connections reached, rejecting {}", addr);
                    drop(stream);
                    continue;
                }

                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, addr, state).await {
                        tracing::debug!("connection from {} closed: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                error!("failed to accept connection: {}", e);
            }
        }
    }
}
