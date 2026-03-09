//! Core type definitions and protocol constants for ARP.

/// A 32-byte Ed25519 public key used as an agent identity.
pub type Pubkey = [u8; 32];

/// Current WebSocket subprotocol identifier.
/// Bump this on breaking wire-format changes.
pub const PROTOCOL_VERSION: &str = "arp.v2";
/// Status codes sent in STATUS frames from relay to client.
pub mod status_code {
    /// Message was delivered to the destination's channel.
    pub const DELIVERED: u8 = 0x00;
    /// Destination agent is not connected to the relay.
    pub const OFFLINE: u8 = 0x01;
    /// Sender has exceeded their rate limit.
    pub const RATE_LIMITED: u8 = 0x02;
    /// Payload exceeds the maximum allowed size.
    pub const OVERSIZE: u8 = 0x03;
    /// Destination explicitly rejected the message.
    pub const REJECTED_BY_DEST: u8 = 0x04;
}

/// Reason codes sent in REJECTED frames during admission.
pub mod rejection_reason {
    /// Ed25519 signature verification failed.
    pub const BAD_SIG: u8 = 0x01;
    /// Admission timestamp is outside the ±30s tolerance window.
    pub const TIMESTAMP_EXPIRED: u8 = 0x02;
    /// Admission rate limit exceeded.
    pub const RATE_LIMITED: u8 = 0x03;
    /// Client protocol version is too old; update required.
    pub const OUTDATED_CLIENT: u8 = 0x10;
    /// Proof-of-work nonce failed verification.
    pub const INVALID_POW: u8 = 0x04;
}

/// Reserved frame type range for future relay federation.
///
/// These frame types are NOT implemented in ARP v2.
/// They are reserved to prevent future wire protocol conflicts.
/// Do not use values 0x10-0x1F for other purposes.
pub mod reserved_federation {
    /// Relay-to-relay message forwarding (future).
    pub const FEDERATED_ROUTE: u8 = 0x10;
    /// Relay-to-relay status response (future).
    pub const FEDERATED_STATUS: u8 = 0x11;
    /// Pubkey presence announcement between relays (future).
    pub const PRESENCE_ANNOUNCE: u8 = 0x12;
    /// Pubkey presence withdrawal between relays (future).
    pub const PRESENCE_WITHDRAW: u8 = 0x13;
    // 0x14-0x1F: reserved for additional federation frames
}
