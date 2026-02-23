use thiserror::Error;

/// Errors that can occur during relay server operation.
#[derive(Error, Debug)]
pub enum ArpsError {
    /// The admission handshake response was malformed or invalid.
    #[error("invalid admission response")]
    InvalidAdmission,
    /// The client-provided timestamp is outside the acceptable window.
    #[error("timestamp expired")]
    TimestampExpired,
    /// Ed25519 signature verification failed.
    #[error("signature verification failed: {0}")]
    SignatureError(#[from] ed25519_dalek::SignatureError),
    /// WebSocket transport error.
    #[error("websocket error: {0}")]
    WebSocket(#[from] tungstenite::Error),
    /// Underlying I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Proof-of-work challenge solution was invalid.
    #[error("invalid proof-of-work")]
    InvalidPoW,
    /// The connection was closed by the remote peer.
    #[error("connection closed")]
    ConnectionClosed,
    /// Binary frame encoding or decoding error.
    #[error("frame error: {0}")]
    Frame(#[from] arp_common::frame::FrameError),
}
