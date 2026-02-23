#![forbid(unsafe_code)]

use anyhow::Result;
use arp_common::base58;
use arps::config::{Args, ServerConfig};
use arps::metrics::{start_metrics_server, HealthState};
use arps::router::Router;
use arps::run;
use arps::server::ServerState;
use clap::Parser;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{info, warn};

/// Maximum number of unauthenticated (pre-admission) connections
/// This prevents DoS by exhausting file descriptors before authentication
const MAX_PRE_AUTH_CONNECTIONS: usize = 1000;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let config: ServerConfig = args.clone().into();

    // Validate configuration before starting
    if let Err(e) = config.validate() {
        anyhow::bail!("configuration error: {}", e);
    }

    let server_keypair = if let Some(ref path) = args.keypair {
        load_keypair(path)?
    } else {
        generate_keypair()
    };

    let pubkey = server_keypair.verifying_key().to_bytes();
    info!("server public key: {}", base58::encode(&pubkey));

    let router = Router::new();

    let state = Arc::new(ServerState {
        router,
        server_keypair,
        config: config.clone(),
        ip_connections: dashmap::DashMap::new(),
        pre_auth_semaphore: Semaphore::new(MAX_PRE_AUTH_CONNECTIONS),
    });

    let listener = TcpListener::bind(config.listen).await?;
    info!("bound to {}", config.listen);

    let health_state = HealthState::new();

    tokio::spawn({
        let health_state = health_state.clone();
        async move {
            if let Err(e) = start_metrics_server(config.metrics_addr, health_state).await {
                warn!("metrics server error: {}", e);
            }
        }
    });

    tokio::select! {
        result = run(listener, state) => {
            if let Err(e) = result {
                tracing::error!("server error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received shutdown signal");
        }
    }

    Ok(())
}

fn load_keypair(path: &Path) -> Result<SigningKey> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path)?;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "keypair file permissions too open: {:o}. Expected 0600",
                mode
            );
        }
    }

    let data = std::fs::read(path)?;
    if data.len() < 32 {
        anyhow::bail!("keypair file too short, expected at least 32 bytes");
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data[..32]);
    let signing_key = SigningKey::from_bytes(&seed);
    info!("loaded keypair from {}", path.display());
    Ok(signing_key)
}

fn generate_keypair() -> SigningKey {
    let signing_key = SigningKey::generate(&mut OsRng);
    warn!("using ephemeral keypair (not persisted)");
    signing_key
}
