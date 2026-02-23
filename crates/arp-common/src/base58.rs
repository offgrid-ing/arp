//! Base58 encoding and decoding utilities for ARP public keys.
//!
//! Wraps the `bs58` crate with convenience functions for encoding
//! and decoding Ed25519 public keys used as agent identities.

use thiserror::Error;

pub use bs58::decode::Error as DecodeError;

/// Errors that can occur when decoding a Base58-encoded public key.
///
/// # Examples
///
/// ```
/// use arp_common::base58;
/// // Wrong length returns WrongLength error
/// let short = base58::encode(&[1u8; 16]);
/// assert!(base58::decode_pubkey(&short).is_err());
/// ```
#[derive(Debug, Error)]
pub enum PubkeyDecodeError {
    /// The input is not valid Base58.
    #[error("invalid base58: {0}")]
    Base58(#[from] DecodeError),
    /// The decoded bytes are not exactly 32 bytes.
    #[error("pubkey must be exactly 32 bytes, got {0}")]
    WrongLength(usize),
}

/// Encodes raw bytes to a Base58 string.
///
/// # Examples
///
/// ```
/// let encoded = arp_common::base58::encode(&[1, 2, 3]);
/// assert!(!encoded.is_empty());
/// ```
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    bs58::encode(bytes).into_string()
}

/// Decodes a Base58 string to raw bytes.
///
/// # Errors
///
/// Returns `DecodeError` if the input is not valid Base58.
///
/// # Examples
///
/// ```
/// let encoded = arp_common::base58::encode(&[1, 2, 3]);
/// let decoded = arp_common::base58::decode(&encoded).unwrap();
/// assert_eq!(decoded, vec![1, 2, 3]);
/// ```
pub fn decode(s: &str) -> Result<Vec<u8>, DecodeError> {
    bs58::decode(s).into_vec()
}

/// Decodes a Base58 string to a 32-byte public key array.
///
/// # Errors
///
/// Returns [`PubkeyDecodeError`] if the input is not valid Base58
/// or does not decode to exactly 32 bytes.
///
/// # Examples
///
/// ```
/// let pubkey = [0x42u8; 32];
/// let encoded = arp_common::base58::encode(&pubkey);
/// let decoded = arp_common::base58::decode_pubkey(&encoded).unwrap();
/// assert_eq!(decoded, pubkey);
/// ```
pub fn decode_pubkey(s: &str) -> Result<[u8; 32], PubkeyDecodeError> {
    let bytes = decode(s)?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_: Vec<u8>| PubkeyDecodeError::WrongLength(len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trip() {
        let data = [0xABu8; 32];
        let encoded = encode(&data);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn decode_pubkey_round_trip() {
        let pubkey = [0x42u8; 32];
        let encoded = encode(&pubkey);
        let decoded = decode_pubkey(&encoded).unwrap();
        assert_eq!(decoded, pubkey);
    }

    #[test]
    fn decode_pubkey_wrong_length() {
        let short = encode(&[1u8; 16]);
        let err = decode_pubkey(&short).unwrap_err();
        assert!(matches!(err, PubkeyDecodeError::WrongLength(16)));
    }

    #[test]
    fn decode_pubkey_empty_string() {
        let err = decode_pubkey("").unwrap_err();
        assert!(matches!(err, PubkeyDecodeError::WrongLength(0)));
    }
}
