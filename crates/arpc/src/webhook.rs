use crate::config::WebhookConfig;
use arp_common::Pubkey;
use reqwest::Client;
use serde::Serialize;
use std::sync::Arc;
use tracing::{debug, warn};

const MAX_CONCURRENT_WEBHOOKS: usize = 100;

#[derive(Serialize)]
struct WebhookPayload {
    message: String,
    name: String,
    #[serde(rename = "sessionKey")]
    session_key: String,
    deliver: bool,
    channel: String,
}

/// Validates that the webhook URL has a valid scheme and host.
///
/// Only allows `http` and `https` schemes and requires a host component.
/// No SSRF restrictions are applied because arpc is a local daemon whose
/// config is fully user-controlled — the webhook URL does not originate
/// from untrusted input.
fn validate_webhook_url(url: &str) -> anyhow::Result<()> {
    let parsed = url.parse::<reqwest::Url>()?;

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        anyhow::bail!("webhook URL scheme must be http or https, got: {}", scheme);
    }

    if parsed.host_str().is_none() {
        anyhow::bail!("webhook URL must have a host");
    }

    Ok(())
}

/// HTTP client for delivering inbound ARP messages to the OpenClaw webhook.
#[derive(Clone)]
pub struct WebhookClient {
    http: Client,
    url: String,
    token: String,
    channel: String,
    semaphore: Arc<tokio::sync::Semaphore>,
}

impl WebhookClient {
    /// Creates a new webhook client from the given config, or `None` if webhooks are disabled.
    pub fn new(config: &WebhookConfig) -> Option<Self> {
        if !config.enabled || config.token.is_empty() {
            return None;
        }

        if let Err(e) = validate_webhook_url(&config.url) {
            warn!("Invalid webhook URL: {}, disabling webhook", e);
            return None;
        }

        Some(Self {
            http: Client::builder()
                .redirect(reqwest::redirect::Policy::limited(5))
                .build()
                .expect("failed to build HTTP client"),
            url: config.url.clone(),
            token: config.token.clone(),
            channel: config.channel.clone(),
            semaphore: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_WEBHOOKS)),
        })
    }

    /// Fires a webhook notification for an inbound message (fire-and-forget).
    pub fn fire(&self, from: &Pubkey, payload: &[u8]) {
        let from_b58 = arp_common::base58::encode(from);
        let body_text = String::from_utf8_lossy(payload);

        let webhook_body = WebhookPayload {
            message: format!("ARP message from {from_b58}:\n\n{body_text}"),
            name: "ARP".to_string(),
            session_key: format!("hook:arp:{from_b58}"),
            deliver: true,
            channel: self.channel.clone(),
        };

        // Try to acquire semaphore permit without blocking
        let permit = match self.semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                warn!("webhook concurrency limit reached, dropping message");
                return;
            }
        };

        let http = self.http.clone();
        let url = self.url.clone();
        let token = self.token.clone();

        tokio::spawn(async move {
            let _permit = permit; // Hold permit until async block completes
            let result = http
                .post(&url)
                .bearer_auth(&token)
                .json(&webhook_body)
                .send()
                .await;
            match result {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() || status.as_u16() == 202 {
                        debug!(status = %status, "webhook delivered");
                    } else {
                        warn!(status = %status, "webhook POST returned non-success");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "webhook POST failed");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WebhookConfig;

    #[test]
    fn new_returns_none_when_disabled() {
        let config = WebhookConfig {
            enabled: false,
            url: "http://localhost:9999/hooks/agent".to_string(),
            token: "secret".to_string(),
            channel: "discord".to_string(),
        };
        assert!(WebhookClient::new(&config).is_none());
    }

    #[test]
    fn new_returns_none_when_token_empty() {
        let config = WebhookConfig {
            enabled: true,
            url: "http://localhost:9999/hooks/agent".to_string(),
            token: String::new(),
            channel: "discord".to_string(),
        };
        assert!(WebhookClient::new(&config).is_none());
    }

    #[test]
    fn new_returns_some_when_enabled_with_token() {
        let config = WebhookConfig {
            enabled: true,
            url: "http://example.com/hooks/agent".to_string(),
            token: "secret".to_string(),
            channel: "discord".to_string(),
        };
        assert!(WebhookClient::new(&config).is_some());
    }

    #[test]
    fn new_accepts_localhost_url() {
        let config = WebhookConfig {
            enabled: true,
            url: "http://localhost:9999/hooks/agent".to_string(),
            token: "secret".to_string(),
            channel: "discord".to_string(),
        };
        // arpc is a local daemon — localhost is the primary use case
        assert!(WebhookClient::new(&config).is_some());
    }

    #[test]
    fn new_accepts_loopback_ip() {
        let config = WebhookConfig {
            enabled: true,
            url: "http://127.0.0.1:18789/hooks/agent".to_string(),
            token: "secret".to_string(),
            channel: "discord".to_string(),
        };
        // Default config targets 127.0.0.1 — must work
        assert!(WebhookClient::new(&config).is_some());
    }

    #[test]
    fn new_accepts_private_ip() {
        let config = WebhookConfig {
            enabled: true,
            url: "http://192.168.1.1/hooks/agent".to_string(),
            token: "secret".to_string(),
            channel: "discord".to_string(),
        };
        // User controls config; private IPs are valid targets
        assert!(WebhookClient::new(&config).is_some());
    }

    #[test]
    fn new_rejects_invalid_scheme() {
        let config = WebhookConfig {
            enabled: true,
            url: "ftp://example.com/hooks/agent".to_string(),
            token: "secret".to_string(),
            channel: "discord".to_string(),
        };
        assert!(WebhookClient::new(&config).is_none());
    }

    #[test]
    fn new_rejects_invalid_url() {
        let config = WebhookConfig {
            enabled: true,
            url: "not a url".to_string(),
            token: "secret".to_string(),
            channel: "discord".to_string(),
        };
        assert!(WebhookClient::new(&config).is_none());
    }
}
