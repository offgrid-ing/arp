//! Common types and utilities shared across the ARP protocol stack.
//!
//! This crate provides:
//! - Binary frame serialization and parsing ([`frame`])
//! - Ed25519 cryptographic helpers ([`crypto`])
//! - Base58 encoding/decoding ([`base58`])
//! - Protocol type definitions and constants ([`types`])

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod base58;
pub mod crypto;
pub mod frame;
pub mod types;
/// Self-update from GitHub Releases (feature-gated).
#[cfg(feature = "update")]
pub mod update;

pub use crypto::{ClockError, PowError};
pub use types::Pubkey;
