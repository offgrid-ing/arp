#![forbid(unsafe_code)]

use arpc::config::{load_config, Cli, Commands, ContactAction};
use arpc::contacts::ContactStore;
use arpc::keypair;
use arpc::local_api;
use arpc::relay::{relay_connection_manager, ConnStatus, InboundMsg, OutboundMsg};

use arp_common::base58;
use base64::Engine;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, watch};
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

fn daemon_addr(listen: Option<&str>) -> &str {
    let listen = listen.unwrap_or("tcp://127.0.0.1:7700");
    listen.strip_prefix("tcp://").unwrap_or(listen)
}

fn init_tracing(cli: &Cli) -> anyhow::Result<()> {
    let filter = if std::env::var("RUST_LOG").is_ok() {
        EnvFilter::from_default_env()
    } else {
        let directive = match cli.verbose {
            0 => "info",
            1 => "debug",
            _ => "trace",
        };
        EnvFilter::new(directive)
    };

    if let Some(ref path) = cli.log_file {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| anyhow::anyhow!("failed to open log file {path:?}: {e}"))?;
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::sync::Mutex::new(file))
            .with_ansi(false)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }

    Ok(())
}

async fn run_daemon(cli: &Cli) -> anyhow::Result<()> {
    let mut config = load_config(cli.config.as_deref())?;

    if let Some(ref relay) = cli.relay {
        config.relay = relay.clone();
    }
    if let Some(ref listen) = cli.listen {
        config.listen = listen.clone();
    }

    config
        .validate()
        .map_err(|e| anyhow::anyhow!("Invalid configuration: {e}"))?;

    let key_path = dirs::config_dir()
        .map_or_else(|| PathBuf::from("arpc.key"), |d| d.join("arpc").join("key"));

    let keypair = keypair::load_or_generate_keypair(&key_path)?;
    let pubkey: arp_common::Pubkey = keypair.verifying_key().to_bytes();

    let contacts_path = dirs::config_dir().map_or_else(
        || PathBuf::from("contacts.toml"),
        |d| d.join("arpc").join("contacts.toml"),
    );
    let contacts = Arc::new(ContactStore::load(contacts_path)?);

    info!(
        "Starting arpc daemon with identity {}",
        base58::encode(&pubkey)
    );

    // Non-blocking background version check
    tokio::spawn(async {
        match arpc::update::check_for_update_quiet().await {
            Ok(Some(latest)) => {
                warn!(
                    "arpc update available: {} (current: v{})",
                    latest,
                    env!("CARGO_PKG_VERSION")
                );
            }
            Ok(None) => {}
            Err(e) => {
                debug!("background version check failed: {e}");
            }
        }
    });

    let config = Arc::new(config);

    let (outbox_tx, outbox_rx) = mpsc::channel::<OutboundMsg>(256);
    let (inbox_tx, _inbox_rx) = broadcast::channel::<InboundMsg>(1024);
    let (status_tx, status_rx) = watch::channel(ConnStatus::Disconnected);

    let relay_handle = tokio::spawn({
        let config = config.clone();
        let inbox_tx = inbox_tx.clone();
        let status_tx = status_tx.clone();
        let contacts = contacts.clone();
        async move {
            relay_connection_manager(config, keypair, outbox_rx, inbox_tx, status_tx, contacts)
                .await;
        }
    });

    let api_handle = tokio::spawn({
        let listen = config.listen.clone();
        let outbox_tx = outbox_tx.clone();
        let inbox_tx = inbox_tx.clone();
        let status_rx = status_rx.clone();
        let contacts = contacts.clone();
        async move {
            if let Err(e) = local_api::start_local_api(
                &listen, outbox_tx, inbox_tx, status_rx, pubkey, contacts,
            )
            .await
            {
                error!("Local API error: {}", e);
            }
        }
    });

    let bridge_handle = if config.bridge.enabled {
        let bridge_config = config.bridge.clone();
        let inbox_rx = inbox_tx.subscribe();
        let contacts = contacts.clone();
        Some(tokio::spawn(async move {
            arpc::bridge::run_bridge(bridge_config, inbox_rx, contacts).await;
        }))
    } else {
        None
    };
    tokio::select! {
        _ = relay_handle => {
            info!("Relay connection manager exited");
        }
        _ = api_handle => {
            info!("Local API server exited");
        }
        _ = async { if let Some(h) = bridge_handle { h.await.ok(); } else { std::future::pending::<()>().await; } } => {
            info!("Bridge exited");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received shutdown signal");
        }
    }

    Ok(())
}

async fn send_daemon_cmd(listen: &str, cmd: &str) -> anyhow::Result<()> {
    match TcpStream::connect(listen).await {
        Ok(stream) => {
            let (reader, mut writer) = stream.into_split();
            let mut reader = tokio::io::BufReader::new(reader);

            writer.write_all(cmd.as_bytes()).await?;
            writer.write_all(b"\n").await?;

            let mut line = String::new();
            reader.read_line(&mut line).await?;

            print!("{line}");
            Ok(())
        }
        Err(e) => {
            eprintln!("Failed to connect to daemon: {e}");
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        eprintln!("Failed to install rustls crypto provider - may already be installed or unsupported platform");
    }

    let cli = Cli::parse();

    init_tracing(&cli)?;

    match &cli.command {
        Commands::Start => run_daemon(&cli).await?,
        Commands::Identity => {
            let key_path = dirs::config_dir()
                .map_or_else(|| PathBuf::from("arpc.key"), |d| d.join("arpc").join("key"));
            let keypair = keypair::load_or_generate_keypair(&key_path)?;
            let pubkey: arp_common::Pubkey = keypair.verifying_key().to_bytes();
            println!("{}", base58::encode(&pubkey));
        }
        Commands::Keygen => {
            let keypair = keypair::generate_keypair();
            let pubkey: arp_common::Pubkey = keypair.verifying_key().to_bytes();
            println!("{}", base58::encode(&pubkey));
        }
        Commands::Status => {
            let addr = daemon_addr(cli.listen.as_deref());
            send_daemon_cmd(addr, r#"{"cmd": "status"}"#).await?;
        }
        Commands::Send { pubkey, message } => {
            let addr = daemon_addr(cli.listen.as_deref());
            let payload = base64::engine::general_purpose::STANDARD.encode(message.as_bytes());
            let cmd = serde_json::json!({
                "cmd": "send",
                "to": pubkey,
                "payload": payload
            });
            send_daemon_cmd(addr, &serde_json::to_string(&cmd)?).await?;
        }
        Commands::Contact { action } => {
            let addr = daemon_addr(cli.listen.as_deref());
            let cmd = match action {
                ContactAction::Add {
                    name,
                    pubkey,
                    notes,
                } => serde_json::json!({
                    "cmd": "contact_add",
                    "name": name,
                    "pubkey": pubkey,
                    "notes": notes,
                }),
                ContactAction::Remove { name_or_pubkey } => {
                    // Try decoding as pubkey; if it's valid base58 pubkey, send as pubkey
                    if base58::decode_pubkey(name_or_pubkey).is_ok() {
                        serde_json::json!({
                            "cmd": "contact_remove",
                            "pubkey": name_or_pubkey,
                        })
                    } else {
                        serde_json::json!({
                            "cmd": "contact_remove",
                            "name": name_or_pubkey,
                        })
                    }
                }
                ContactAction::List => serde_json::json!({
                    "cmd": "contact_list",
                }),
            };
            send_daemon_cmd(addr, &serde_json::to_string(&cmd)?).await?;
        }
        Commands::Update { check } => {
            if *check {
                arpc::update::check_for_update().await?;
            } else {
                arpc::update::perform_update().await?;
            }
        }
    }
    Ok(())
}
