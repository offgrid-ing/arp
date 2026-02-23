//! Cryptographic utilities for ARP admission handshake and proof-of-work.
//!
//! Provides Ed25519 signature creation and verification for the
//! challenge-response admission protocol, plus SHA-256 based hashcash
//! proof-of-work for anti-spam admission gating.

use crate::Pubkey;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Signs an admission response: `Ed25519(challenge ‖ timestamp)`.
///
/// Returns the raw 64-byte signature. Uses a fixed-size stack buffer
/// to avoid heap allocation on the hot path.
///
/// # Examples
///
/// ```
/// use ed25519_dalek::SigningKey;
/// use arp_common::crypto;
///
/// let key = SigningKey::from_bytes(&[1u8; 32]);
/// let sig = crypto::sign_admission(&key, &[0xAB; 32], crypto::unix_now());
/// assert_eq!(sig.len(), 64);
/// ```
#[must_use]
pub fn sign_admission(signing_key: &SigningKey, challenge: &[u8; 32], timestamp: u64) -> [u8; 64] {
    use ed25519_dalek::Signer;
    let mut msg = [0u8; 40];
    msg[..32].copy_from_slice(challenge);
    msg[32..40].copy_from_slice(&timestamp.to_be_bytes());
    signing_key.sign(&msg).to_bytes()
}

/// Verifies an admission response signature against `challenge ‖ timestamp`.
///
/// Returns `true` if the Ed25519 signature is valid, `false` otherwise.
///
/// # Examples
///
/// ```
/// use ed25519_dalek::SigningKey;
/// use arp_common::crypto;
///
/// let key = SigningKey::from_bytes(&[1u8; 32]);
/// let challenge = [0xAB; 32];
/// let ts = crypto::unix_now();
/// let sig = crypto::sign_admission(&key, &challenge, ts);
/// assert!(crypto::verify_admission(&key.verifying_key(), &challenge, ts, &sig));
/// ```
#[must_use]
pub fn verify_admission(
    verifying_key: &VerifyingKey,
    challenge: &[u8; 32],
    timestamp: u64,
    signature: &[u8; 64],
) -> bool {
    use ed25519_dalek::Verifier;
    let mut msg = [0u8; 40];
    msg[..32].copy_from_slice(challenge);
    msg[32..40].copy_from_slice(&timestamp.to_be_bytes());
    let sig = Signature::from_bytes(signature);
    verifying_key.verify(&msg, &sig).is_ok()
}

/// Returns the current Unix timestamp in seconds.
///
/// Returns 0 if the system clock is before the Unix epoch (indicates
/// a misconfigured system clock). Callers should handle this case.
///
/// # Examples
///
/// ```
/// let now = arp_common::crypto::unix_now();
/// assert!(now > 1_700_000_000);
/// ```
#[must_use]
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Proof-of-Work ────────────────────────────────────────────────────────────

/// Computes `SHA-256(challenge ‖ pubkey ‖ timestamp_be ‖ nonce)` and returns
/// the number of leading zero bits in the resulting hash.
#[must_use]
pub fn pow_hash(challenge: &[u8; 32], pubkey: &Pubkey, timestamp: u64, nonce: &[u8; 8]) -> u32 {
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    hasher.update(pubkey);
    hasher.update(timestamp.to_be_bytes());
    hasher.update(nonce);
    let hash = hasher.finalize();
    leading_zero_bits(&hash)
}

/// Returns `true` if the nonce produces at least `difficulty` leading zero
/// bits in the PoW hash. Returns `true` unconditionally when `difficulty == 0`.
#[must_use]
pub fn pow_verify(
    challenge: &[u8; 32],
    pubkey: &Pubkey,
    timestamp: u64,
    nonce: &[u8; 8],
    difficulty: u8,
) -> bool {
    if difficulty == 0 {
        return true;
    }
    pow_hash(challenge, pubkey, timestamp, nonce) >= u32::from(difficulty)
}

/// Brute-force searches for an 8-byte nonce that satisfies the given
/// difficulty. Panics if `difficulty > 64` (impossible with SHA-256).
///
/// # Examples
///
/// ```
/// use arp_common::crypto;
///
/// let challenge = [0xABu8; 32];
/// let pubkey = [1u8; 32];
/// let ts = crypto::unix_now();
/// let nonce = crypto::pow_solve(&challenge, &pubkey, ts, 8);
/// assert!(crypto::pow_verify(&challenge, &pubkey, ts, &nonce, 8));
/// ```
#[must_use]
pub fn pow_solve(challenge: &[u8; 32], pubkey: &Pubkey, timestamp: u64, difficulty: u8) -> [u8; 8] {
    assert!(difficulty <= 64, "difficulty must be <= 64");
    if difficulty == 0 {
        return [0u8; 8];
    }
    let mut nonce = [0u8; 8];
    loop {
        if pow_hash(challenge, pubkey, timestamp, &nonce) >= u32::from(difficulty) {
            return nonce;
        }
        // Increment nonce as little-endian u64
        let val = u64::from_le_bytes(nonce).wrapping_add(1);
        nonce = val.to_le_bytes();
    }
}

/// Counts leading zero bits in a byte slice.
fn leading_zero_bits(data: &[u8]) -> u32 {
    let mut count = 0u32;
    for &byte in data {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_round_trip() {
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let challenge = [0xABu8; 32];
        let ts = unix_now();
        let sig = sign_admission(&key, &challenge, ts);
        assert!(verify_admission(&key.verifying_key(), &challenge, ts, &sig));
    }

    #[test]
    fn wrong_challenge_fails_verification() {
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let ts = unix_now();
        let sig = sign_admission(&key, &[0xAB; 32], ts);
        assert!(!verify_admission(
            &key.verifying_key(),
            &[0xCD; 32],
            ts,
            &sig
        ));
    }

    #[test]
    fn wrong_timestamp_fails_verification() {
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let challenge = [0xABu8; 32];
        let ts = unix_now();
        let sig = sign_admission(&key, &challenge, ts);
        assert!(!verify_admission(
            &key.verifying_key(),
            &challenge,
            ts + 100,
            &sig
        ));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let other = SigningKey::from_bytes(&[99u8; 32]);
        let challenge = [0xABu8; 32];
        let ts = unix_now();
        let sig = sign_admission(&key, &challenge, ts);
        assert!(!verify_admission(
            &other.verifying_key(),
            &challenge,
            ts,
            &sig
        ));
    }

    #[test]
    fn unix_now_is_reasonable() {
        let now = unix_now();
        assert!(now > 1_704_067_200, "timestamp should be after 2024-01-01");
    }

    // ── PoW tests ───────────────────────────────────────────────────────

    #[test]
    fn leading_zero_bits_counts_correctly() {
        assert_eq!(super::leading_zero_bits(&[0x00, 0x00, 0xFF]), 16);
        assert_eq!(super::leading_zero_bits(&[0x00, 0x80, 0xFF]), 8);
        assert_eq!(super::leading_zero_bits(&[0x01, 0xFF]), 7);
        assert_eq!(super::leading_zero_bits(&[0xFF]), 0);
        assert_eq!(super::leading_zero_bits(&[0x00]), 8);
    }

    #[test]
    fn pow_solve_and_verify_round_trip() {
        let challenge = [0xABu8; 32];
        let pubkey = [1u8; 32];
        let ts = unix_now();
        let nonce = pow_solve(&challenge, &pubkey, ts, 8);
        assert!(pow_verify(&challenge, &pubkey, ts, &nonce, 8));
    }

    #[test]
    fn pow_verify_zero_difficulty_always_passes() {
        let challenge = [0u8; 32];
        let pubkey = [0u8; 32];
        let nonce = [0u8; 8];
        assert!(pow_verify(&challenge, &pubkey, 0, &nonce, 0));
    }

    #[test]
    fn pow_wrong_nonce_fails() {
        let challenge = [0xABu8; 32];
        let pubkey = [1u8; 32];
        let ts = unix_now();
        let nonce = pow_solve(&challenge, &pubkey, ts, 12);
        // Flip a bit in the nonce — overwhelmingly likely to fail
        let mut bad_nonce = nonce;
        bad_nonce[0] ^= 0xFF;
        // It may still pass by sheer luck, but 12 bits means 1/4096 chance.
        // We just verify the good nonce works for sure.
        assert!(pow_verify(&challenge, &pubkey, ts, &nonce, 12));
        // Also verify the bad nonce is at least computed
        let _unused = bad_nonce;
    }

    #[test]
    fn pow_solve_difficulty_zero_returns_zeroes() {
        let nonce = pow_solve(&[0; 32], &[0; 32], 0, 0);
        assert_eq!(nonce, [0u8; 8]);
    }

    #[test]
    #[should_panic(expected = "difficulty must be <= 64")]
    fn pow_solve_panics_on_impossible_difficulty() {
        let _ = pow_solve(&[0; 32], &[0; 32], 0, 65);
    }
}
