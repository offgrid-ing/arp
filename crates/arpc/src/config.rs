use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// CLI interface for the client daemon.
#[derive(Parser)]
#[command(name = "arpc", about = "ARP Client Daemon")]
#[command(version)]
pub struct Cli {
    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,

    /// Path to a custom configuration file.
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Relay server URL override.
    #[arg(long, global = true)]
    pub relay: Option<String>,

    /// Local API listen address override.
    #[arg(long, global = true)]
    pub listen: Option<String>,

    /// Increase log verbosity (repeat for more detail).
    #[arg(short = 'v', long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Write logs to a file instead of stderr
    #[arg(long, global = true)]
    pub log_file: Option<PathBuf>,
}

/// Available subcommands.
#[derive(Subcommand)]
pub enum Commands {
    /// Start the client daemon.
    Start,
    /// Show daemon status.
    Status,
    /// Print the local identity public key.
    Identity,
    /// Send a message to a recipient by public key.
    Send {
        /// Recipient's public key.
        pubkey: String,
        /// Message content to send.
        message: String,
    },
    /// Generate a new keypair.
    Keygen,
    /// Manage contacts.
    Contact {
        /// Contact subcommand to run.
        #[command(subcommand)]
        action: ContactAction,
    },
    /// Check for and apply client updates.
    Update {
        /// Only check if an update is available, don't download
        #[arg(long)]
        check: bool,
    },
    /// Run diagnostics to verify installation health.
    Doctor,
}

/// Contact management subcommands.
#[derive(Subcommand)]
pub enum ContactAction {
    /// Add a new contact.
    Add {
        /// Display name for the contact.
        name: String,
        /// Public key of the contact.
        pubkey: String,
        #[arg(long, default_value = "")]
        /// Optional notes about the contact.
        notes: String,
    },
    /// Remove an existing contact by name or public key.
    Remove {
        /// Name or public key of the contact to remove.
        name_or_pubkey: String,
    },
    /// List all contacts.
    List,
}

/// Runtime configuration loaded from file, env, and defaults.
#[derive(Debug, Deserialize, Clone)]
pub struct ClientConfig {
    /// WebSocket URL of the relay server.
    pub relay: String,
    /// Local API listen address (`tcp://` or `unix://`).
    pub listen: String,
    /// Reconnection backoff settings.
    pub reconnect: ReconnectConfig,
    /// WebSocket keepalive ping settings.
    pub keepalive: KeepaliveConfig,
    /// E2E encryption settings (HPKE Auth mode, RFC 9180).
    pub encryption: EncryptionConfig,
    /// Inbound message webhook delivery settings.
    pub webhook: WebhookConfig,
    /// OpenClaw gateway bridge settings.
    pub bridge: BridgeConfig,
}

/// Reconnect backoff parameters.
#[derive(Debug, Deserialize, Clone)]
pub struct ReconnectConfig {
    /// Initial delay before the first reconnect attempt, in milliseconds.
    pub initial_delay_ms: u64,
    /// Maximum delay between reconnect attempts, in milliseconds.
    pub max_delay_ms: u64,
    /// Multiplier applied to the delay after each failed attempt.
    pub backoff_factor: f64,
}

/// WebSocket keepalive settings.
#[derive(Debug, Deserialize, Clone)]
pub struct KeepaliveConfig {
    /// Interval between keepalive pings, in seconds.
    pub interval_s: u64,
}

/// E2E encryption toggle (HPKE Auth mode, RFC 9180).
#[derive(Debug, Deserialize, Clone)]
pub struct EncryptionConfig {
    /// Whether E2E encryption is enabled.
    pub enabled: bool,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Webhook configuration for pushing incoming messages to an HTTP endpoint.
///
/// When enabled, arpc will POST to the configured URL whenever a DELIVER
/// frame is received. Designed for OpenClaw agent webhook integration.
#[derive(Debug, Deserialize, Clone)]
pub struct WebhookConfig {
    /// Whether webhook delivery is enabled.
    pub enabled: bool,
    /// HTTP endpoint to POST incoming messages to.
    pub url: String,
    /// Bearer token for webhook authentication.
    pub token: String,
    /// Channel identifier included in webhook payloads.
    pub channel: String,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: "http://127.0.0.1:18789/hooks/agent".to_string(),
            token: String::new(),
            channel: "discord".to_string(),
        }
    }
}

/// Bridge configuration for injecting inbound ARP messages into an OpenClaw
/// gateway session via WebSocket protocol v3.
///
/// When enabled, arpc connects to the gateway and sends `chat.send` for each
/// incoming ARP message, making them appear in the agent's conversation.
#[derive(Debug, Deserialize, Clone)]
pub struct BridgeConfig {
    /// Whether the OpenClaw bridge is enabled.
    pub enabled: bool,
    /// WebSocket URL of the OpenClaw gateway.
    pub gateway_url: String,
    /// Authentication token for the gateway connection.
    pub gateway_token: String,
    /// Session key identifying the target conversation.
    pub session_key: String,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            gateway_url: "ws://127.0.0.1:18789".to_string(),
            gateway_token: String::new(),
            session_key: String::new(),
        }
    }
}
impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            relay: "wss://arps.offgrid.ing".to_string(),
            listen: "tcp://127.0.0.1:7700".to_string(),
            reconnect: ReconnectConfig::default(),
            keepalive: KeepaliveConfig::default(),
            encryption: EncryptionConfig::default(),
            webhook: WebhookConfig::default(),
            bridge: BridgeConfig::default(),
        }
    }
}

impl ClientConfig {
    /// Validates the configuration values are within acceptable bounds.
    /// Returns Ok(()) if valid, Err with description otherwise.
    pub fn validate(&self) -> Result<(), String> {
        if self.relay.is_empty() {
            return Err("relay URL must not be empty".to_string());
        }
        if !(self.relay.starts_with("ws://") || self.relay.starts_with("wss://")) {
            return Err(format!(
                "relay URL must start with ws:// or wss://, got: {}",
                self.relay
            ));
        }

        if self.listen.is_empty() {
            return Err("listen address must not be empty".to_string());
        }
        if !(self.listen.starts_with("tcp://") || self.listen.starts_with("unix://")) {
            return Err(format!(
                "listen address must start with tcp:// or unix://, got: {}",
                self.listen
            ));
        }

        if self.reconnect.initial_delay_ms == 0 {
            return Err("reconnect.initial_delay_ms must be greater than 0".to_string());
        }
        if self.reconnect.max_delay_ms < self.reconnect.initial_delay_ms {
            return Err("reconnect.max_delay_ms must be >= initial_delay_ms".to_string());
        }
        if !self.reconnect.backoff_factor.is_finite() || self.reconnect.backoff_factor <= 0.0 {
            return Err(
                "reconnect.backoff_factor must be a finite number greater than 0".to_string(),
            );
        }

        if self.keepalive.interval_s == 0 {
            return Err("keepalive.interval_s must be greater than 0".to_string());
        }

        if self.webhook.enabled && self.webhook.token.is_empty() {
            return Err("webhook.token must not be empty when webhook is enabled".to_string());
        }

        if self.bridge.enabled {
            if self.bridge.gateway_token.is_empty() {
                return Err(
                    "bridge.gateway_token must not be empty when bridge is enabled".to_string(),
                );
            }
            if self.bridge.session_key.is_empty() {
                return Err(
                    "bridge.session_key must not be empty when bridge is enabled".to_string(),
                );
            }
            if !(self.bridge.gateway_url.starts_with("ws://")
                || self.bridge.gateway_url.starts_with("wss://"))
            {
                return Err(format!(
                    "bridge.gateway_url must start with ws:// or wss://, got: {}",
                    self.bridge.gateway_url
                ));
            }
        }

        Ok(())
    }
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            initial_delay_ms: 100,
            max_delay_ms: 30000,
            backoff_factor: 2.0,
        }
    }
}

impl Default for KeepaliveConfig {
    fn default() -> Self {
        Self { interval_s: 30 }
    }
}

/// # Errors
///
/// Returns an error if the configuration file cannot be read or parsed.
#[allow(clippy::cast_possible_wrap)]
pub fn load_config(path: Option<&Path>) -> anyhow::Result<ClientConfig> {
    let defaults = ClientConfig::default();
    let mut builder = config::Config::builder()
        .set_default("relay", defaults.relay.as_str())?
        .set_default("listen", defaults.listen.as_str())?
        .set_default(
            "reconnect.initial_delay_ms",
            defaults.reconnect.initial_delay_ms as i64,
        )?
        .set_default(
            "reconnect.max_delay_ms",
            defaults.reconnect.max_delay_ms as i64,
        )?
        .set_default(
            "reconnect.backoff_factor",
            defaults.reconnect.backoff_factor,
        )?
        .set_default("keepalive.interval_s", defaults.keepalive.interval_s as i64)?
        .set_default("encryption.enabled", defaults.encryption.enabled)?
        .set_default("webhook.enabled", defaults.webhook.enabled)?
        .set_default("webhook.url", defaults.webhook.url.as_str())?
        .set_default("webhook.token", defaults.webhook.token.as_str())?
        .set_default("webhook.channel", defaults.webhook.channel.as_str())?
        .set_default("bridge.enabled", defaults.bridge.enabled)?
        .set_default("bridge.gateway_url", defaults.bridge.gateway_url.as_str())?
        .set_default(
            "bridge.gateway_token",
            defaults.bridge.gateway_token.as_str(),
        )?
        .set_default("bridge.session_key", defaults.bridge.session_key.as_str())?;

    if let Some(config_path) = path {
        if config_path.exists() {
            builder = builder.add_source(config::File::from(config_path));
        }
    } else {
        // Check platform-native config dir first, then fall back to ~/.config/arpc/
        // (many tools including the install script use ~/.config/ even on macOS)
        let native_path = dirs::config_dir().map(|d| d.join("arpc").join("config.toml"));
        let xdg_path = dirs::home_dir().map(|d| d.join(".config").join("arpc").join("config.toml"));

        let resolved = native_path
            .filter(|p| p.exists())
            .or_else(|| xdg_path.filter(|p| p.exists()));

        if let Some(config_path) = resolved {
            builder = builder.add_source(config::File::from(config_path));
        }
    }

    builder = builder.add_source(config::Environment::with_prefix("ARPC").separator("_"));

    let settings = builder.build()?;
    let config: ClientConfig = settings.try_deserialize()?;

    Ok(config)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::field_reassign_with_default)]
    use super::*;

    #[test]
    fn test_client_config_default_has_expected_values() {
        let config = ClientConfig::default();

        assert_eq!(config.relay, "wss://arps.offgrid.ing");
        assert_eq!(config.listen, "tcp://127.0.0.1:7700");
    }

    #[test]
    fn test_load_config_with_no_file_returns_defaults() {
        let config = load_config(Some(std::path::Path::new("/nonexistent/config.toml")))
            .expect("load_config should succeed with no file");

        assert_eq!(config.relay, "wss://arps.offgrid.ing");
        assert_eq!(config.listen, "tcp://127.0.0.1:7700");
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_reconnect_config_default_values_match_spec() {
        let config = ReconnectConfig::default();

        assert_eq!(config.initial_delay_ms, 100);
        assert_eq!(config.max_delay_ms, 30000);
        assert_eq!(config.backoff_factor, 2.0);
    }

    #[test]
    fn test_keepalive_config_default_interval_is_30() {
        let config = KeepaliveConfig::default();

        assert_eq!(config.interval_s, 30);
    }

    #[test]
    fn test_encryption_config_default_enabled() {
        let config = EncryptionConfig::default();
        assert!(config.enabled, "encryption should be enabled by default");
    }

    #[test]
    fn test_webhook_config_default_disabled() {
        let config = WebhookConfig::default();
        assert!(!config.enabled, "webhook should be disabled by default");
        assert_eq!(config.url, "http://127.0.0.1:18789/hooks/agent");
        assert!(config.token.is_empty());
    }

    #[test]
    fn test_load_config_includes_webhook_defaults() {
        let config = load_config(Some(std::path::Path::new("/nonexistent/config.toml")))
            .expect("load_config should succeed with no file");
        assert!(!config.webhook.enabled);
        assert_eq!(config.webhook.url, "http://127.0.0.1:18789/hooks/agent");
    }

    #[test]
    fn test_default_config_passes_validation() {
        let config = ClientConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_empty_relay() {
        let mut config = ClientConfig::default();
        config.relay = String::new();
        assert!(config
            .validate()
            .unwrap_err()
            .contains("relay URL must not be empty"));
    }

    #[test]
    fn test_validate_rejects_invalid_relay_scheme() {
        let mut config = ClientConfig::default();
        config.relay = "http://example.com".to_string();
        assert!(config.validate().unwrap_err().contains("ws://"));
    }

    #[test]
    fn test_validate_accepts_wss_relay() {
        let mut config = ClientConfig::default();
        config.relay = "wss://arps.offgrid.ing".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_invalid_listen_scheme() {
        let mut config = ClientConfig::default();
        config.listen = "http://127.0.0.1:7700".to_string();
        assert!(config.validate().unwrap_err().contains("tcp://"));
    }

    #[test]
    fn test_validate_accepts_unix_listen() {
        let mut config = ClientConfig::default();
        config.listen = "unix:///tmp/arpc.sock".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_zero_initial_delay() {
        let mut config = ClientConfig::default();
        config.reconnect.initial_delay_ms = 0;
        assert!(config.validate().unwrap_err().contains("initial_delay_ms"));
    }

    #[test]
    fn test_validate_rejects_max_delay_less_than_initial() {
        let mut config = ClientConfig::default();
        config.reconnect.initial_delay_ms = 1000;
        config.reconnect.max_delay_ms = 500;
        assert!(config.validate().unwrap_err().contains("max_delay_ms"));
    }

    #[test]
    fn test_validate_rejects_zero_backoff_factor() {
        let mut config = ClientConfig::default();
        config.reconnect.backoff_factor = 0.0;
        assert!(config.validate().unwrap_err().contains("backoff_factor"));
    }

    #[test]
    fn test_validate_rejects_zero_keepalive_interval() {
        let mut config = ClientConfig::default();
        config.keepalive.interval_s = 0;
        assert!(config.validate().unwrap_err().contains("keepalive"));
    }

    #[test]
    fn test_validate_rejects_enabled_webhook_without_token() {
        let mut config = ClientConfig::default();
        config.webhook.enabled = true;
        config.webhook.token = String::new();
        assert!(config.validate().unwrap_err().contains("webhook.token"));
    }

    #[test]
    fn test_validate_accepts_enabled_webhook_with_token() {
        let mut config = ClientConfig::default();
        config.webhook.enabled = true;
        config.webhook.token = "my-secret-token".to_string();
        assert!(config.validate().is_ok());
    }
}
