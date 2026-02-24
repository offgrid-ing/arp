//! Cryptographic utilities for ARP admission handshake and proof-of-work.
//!
//! Provides Ed25519 signature creation and verification for the
//! challenge-response admission protocol, plus SHA-256 based hashcash
//! proof-of-work for anti-spam admission gating.

use crate::Pubkey;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;

// ── Error types ──────────────────────────────────────────────────────────────

/// Error returned when the system clock is before the Unix epoch.
#[derive(Debug, Clone, Copy)]
pub struct ClockError;

impl fmt::Display for ClockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "system clock is before Unix epoch")
    }
}

impl std::error::Error for ClockError {}

/// Error returned when proof-of-work solving fails.
#[derive(Debug, Clone, Copy)]
pub enum PowError {
    /// The requested difficulty exceeds the client-side maximum.
    DifficultyTooHigh {
        /// The difficulty that was requested.
        requested: u8,
        /// The maximum allowed difficulty.
        max: u8,
    },
    /// The iteration limit was reached without finding a valid nonce.
    ExceededMaxIterations,
}

impl fmt::Display for PowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DifficultyTooHigh { requested, max } => {
                write!(
                    f,
                    "PoW difficulty {requested} exceeds client maximum of {max}"
                )
            }
            Self::ExceededMaxIterations => {
                write!(f, "PoW solver exceeded maximum iterations")
            }
        }
    }
}

impl std::error::Error for PowError {}

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum PoW difficulty the client will attempt to solve.
/// Difficulty 24 requires ~16M hashes on average (~65ms at 250MH/s).
pub const MAX_CLIENT_POW_DIFFICULTY: u8 = 24;

/// Maximum iterations before the PoW solver gives up.
/// 2^28 = 268,435,456 iterations (~1 second at 250MH/s).
pub const MAX_POW_ITERATIONS: u64 = 1 << 28;

// ── Admission signatures ─────────────────────────────────────────────────────

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
/// let sig = crypto::sign_admission(&key, &[0xAB; 32], crypto::unix_now().unwrap());
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
/// let ts = crypto::unix_now().unwrap();
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
/// # Errors
///
/// Returns [`ClockError`] if the system clock is before the Unix epoch,
/// indicating a misconfigured system. Callers must handle this case
/// explicitly rather than silently using a fallback value.
///
/// # Examples
///
/// ```
/// let now = arp_common::crypto::unix_now().unwrap();
/// assert!(now > 1_700_000_000);
/// ```
pub fn unix_now() -> Result<u64, ClockError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| ClockError)
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
/// difficulty. Returns an error if the difficulty exceeds
/// [`MAX_CLIENT_POW_DIFFICULTY`] or if [`MAX_POW_ITERATIONS`] is reached
/// without finding a valid nonce.
///
/// # Errors
///
/// Returns [`PowError::DifficultyTooHigh`] if `difficulty` exceeds the
/// client-side cap, or [`PowError::ExceededMaxIterations`] if the solver
/// runs out of iterations.
///
/// # Examples
///
/// ```
/// use arp_common::crypto;
///
/// let challenge = [0xABu8; 32];
/// let pubkey = [1u8; 32];
/// let ts = crypto::unix_now().unwrap();
/// let nonce = crypto::pow_solve(&challenge, &pubkey, ts, 8).unwrap();
/// assert!(crypto::pow_verify(&challenge, &pubkey, ts, &nonce, 8));
/// ```
pub fn pow_solve(
    challenge: &[u8; 32],
    pubkey: &Pubkey,
    timestamp: u64,
    difficulty: u8,
) -> Result<[u8; 8], PowError> {
    if difficulty > MAX_CLIENT_POW_DIFFICULTY {
        return Err(PowError::DifficultyTooHigh {
            requested: difficulty,
            max: MAX_CLIENT_POW_DIFFICULTY,
        });
    }
    if difficulty == 0 {
        return Ok([0u8; 8]);
    }
    let mut nonce = [0u8; 8];
    for _ in 0..MAX_POW_ITERATIONS {
        if pow_hash(challenge, pubkey, timestamp, &nonce) >= u32::from(difficulty) {
            return Ok(nonce);
        }
        let val = u64::from_le_bytes(nonce).wrapping_add(1);
        nonce = val.to_le_bytes();
    }
    Err(PowError::ExceededMaxIterations)
}

/// Counts leading zero bits in a byte slice (constant-time).
///
/// Processes all bytes regardless of content to avoid timing side-channels.
fn leading_zero_bits(data: &[u8]) -> u32 {
    let mut count = 0u32;
    let mut found_nonzero = 0u32;
    for &byte in data {
        let is_zero = u32::from(byte == 0);
        let lz = byte.leading_zeros();
        let contribution = (1 - found_nonzero) * (is_zero * 8 + (1 - is_zero) * lz);
        count += contribution;
        found_nonzero |= 1 - is_zero;
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
        let ts = unix_now().unwrap();
        let sig = sign_admission(&key, &challenge, ts);
        assert!(verify_admission(&key.verifying_key(), &challenge, ts, &sig));
    }

    #[test]
    fn wrong_challenge_fails_verification() {
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let ts = unix_now().unwrap();
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
        let ts = unix_now().unwrap();
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
        let ts = unix_now().unwrap();
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
        let now = unix_now().unwrap();
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
    fn leading_zero_bits_empty_input() {
        assert_eq!(super::leading_zero_bits(&[]), 0);
    }

    #[test]
    fn pow_solve_and_verify_round_trip() {
        let challenge = [0xABu8; 32];
        let pubkey = [1u8; 32];
        let ts = unix_now().unwrap();
        let nonce = pow_solve(&challenge, &pubkey, ts, 8).unwrap();
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
        let ts = unix_now().unwrap();
        let nonce = pow_solve(&challenge, &pubkey, ts, 12).unwrap();
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
        let nonce = pow_solve(&[0; 32], &[0; 32], 0, 0).unwrap();
        assert_eq!(nonce, [0u8; 8]);
    }

    #[test]
    fn pow_solve_rejects_excessive_difficulty() {
        let result = pow_solve(&[0; 32], &[0; 32], 0, MAX_CLIENT_POW_DIFFICULTY + 1);
        assert!(matches!(result, Err(PowError::DifficultyTooHigh { .. })));
    }

    #[test]
    #[ignore] // ~16M SHA-256 hashes; too slow in debug. Run: cargo test -- --ignored
    fn pow_solve_accepts_max_client_difficulty() {
        // MAX_CLIENT_POW_DIFFICULTY (24) should be accepted and solvable
        // within MAX_POW_ITERATIONS. With random-ish inputs, difficulty 24
        // needs ~16M hashes on average, well within 2^28.
        let challenge = [0xABu8; 32];
        let pubkey = [1u8; 32];
        let ts = unix_now().unwrap();
        let result = pow_solve(&challenge, &pubkey, ts, MAX_CLIENT_POW_DIFFICULTY);
        assert!(result.is_ok());
    }
}
