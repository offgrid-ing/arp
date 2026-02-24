//! ARP client daemon — persistent relay connection with local JSON API.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Exponential backoff with jitter for reconnection.
pub mod backoff;
/// OpenClaw gateway bridge for injecting inbound ARP messages into agent sessions.
pub mod bridge;
/// CLI parsing and TOML configuration.
pub mod config;
/// Contact management and inbound message filtering.
pub mod contacts;
/// HPKE Auth mode end-to-end encryption (RFC 9180).
#[cfg(feature = "encryption")]
pub mod hpke_seal;
/// Ed25519 keypair generation and loading.
pub mod keypair;
/// Line-delimited JSON API over TCP/Unix sockets.
pub mod local_api;
/// WebSocket relay connection manager.
pub mod relay;
/// Webhook push for incoming messages.
pub mod webhook;
