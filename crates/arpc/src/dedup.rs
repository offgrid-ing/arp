//! Message deduplication for multi-relay inbound delivery.
//!
//! When connected to multiple relays, the same DELIVER frame may arrive
//! from more than one relay. This module provides a bounded, time-expiring
//! set that tracks recently-seen messages by their SHA-256 hash.
//!
//! **Security invariant:** Only insert into the seen set AFTER successful
//! HPKE decryption. Checking before decryption is safe (fast-path skip for
//! known duplicates), but inserting before decryption allows cache poisoning:
//! an attacker could send garbage with the same `src || payload` prefix,
//! causing the real message from another relay to be dropped.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Deduplication state for inbound messages.
///
/// Tracks SHA-256 hashes of `src_pubkey || wire_payload` (pre-decryption bytes).
/// Bounded by both capacity and TTL to prevent unbounded memory growth.
pub struct Deduplicator {
    seen: HashMap<[u8; 32], Instant>,
    capacity: usize,
    ttl: Duration,
}

impl Deduplicator {
    /// Create a new deduplicator.
    ///
    /// - `capacity`: Maximum number of entries before eviction (default: 4096)
    /// - `ttl`: Time-to-live for each entry (default: 60s)
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            seen: HashMap::with_capacity(capacity.min(1024)),
            capacity,
            ttl,
        }
    }

    /// Compute the dedup key from wire-level bytes (pre-decryption).
    ///
    /// The key is SHA-256(src_pubkey || payload). Since all relays deliver
    /// identical ciphertext (sealed once by sender), this hash is identical
    /// across relays for the same message.
    pub fn key(src: &[u8; 32], payload: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(src);
        hasher.update(payload);
        hasher.finalize().into()
    }

    /// Check if this message has already been seen.
    ///
    /// Returns `true` if the key is in the set and not expired.
    /// Does NOT insert — call `mark_seen()` after successful decryption.
    pub fn is_duplicate(&self, key: &[u8; 32]) -> bool {
        self.seen
            .get(key)
            .map(|t| t.elapsed() < self.ttl)
            .unwrap_or(false)
    }

    /// Mark a message as seen. Call ONLY after successful HPKE decryption.
    ///
    /// This prevents cache poisoning: if we inserted before decrypt,
    /// an attacker could send garbage with matching `src || payload`
    /// to suppress the real message arriving from another relay.
    pub fn mark_seen(&mut self, key: [u8; 32]) {
        if self.seen.len() >= self.capacity {
            self.evict_expired();
            if self.seen.len() >= self.capacity {
                self.evict_oldest();
            }
        }
        self.seen.insert(key, Instant::now());
    }

    /// Remove all expired entries.
    fn evict_expired(&mut self) {
        let ttl = self.ttl;
        self.seen.retain(|_, t| t.elapsed() < ttl);
    }

    /// Remove the oldest entry to make room.
    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self.seen.iter().min_by_key(|(_, t)| *t).map(|(k, _)| *k) {
            self.seen.remove(&oldest_key);
        }
    }
}

impl Default for Deduplicator {
    fn default() -> Self {
        Self::new(4096, Duration::from_secs(60))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_deduplicator_is_empty() {
        let d = Deduplicator::default();
        let key = Deduplicator::key(&[0u8; 32], b"hello");
        assert!(!d.is_duplicate(&key));
    }

    #[test]
    fn test_mark_seen_then_is_duplicate() {
        let mut d = Deduplicator::default();
        let key = Deduplicator::key(&[1u8; 32], b"payload");
        assert!(!d.is_duplicate(&key));
        d.mark_seen(key);
        assert!(d.is_duplicate(&key));
    }

    #[test]
    fn test_different_payloads_different_keys() {
        let mut d = Deduplicator::default();
        let src = [2u8; 32];
        let key1 = Deduplicator::key(&src, b"message A");
        let key2 = Deduplicator::key(&src, b"message B");
        d.mark_seen(key1);
        assert!(d.is_duplicate(&key1));
        assert!(!d.is_duplicate(&key2));
    }

    #[test]
    fn test_different_sources_different_keys() {
        let mut d = Deduplicator::default();
        let key1 = Deduplicator::key(&[3u8; 32], b"same payload");
        let key2 = Deduplicator::key(&[4u8; 32], b"same payload");
        d.mark_seen(key1);
        assert!(d.is_duplicate(&key1));
        assert!(!d.is_duplicate(&key2));
    }

    #[test]
    fn test_expired_entry_not_duplicate() {
        let mut d = Deduplicator::new(4096, Duration::from_millis(1));
        let key = Deduplicator::key(&[5u8; 32], b"ephemeral");
        d.mark_seen(key);
        std::thread::sleep(Duration::from_millis(5));
        assert!(!d.is_duplicate(&key));
    }

    #[test]
    fn test_capacity_eviction() {
        let mut d = Deduplicator::new(2, Duration::from_secs(60));
        let key1 = Deduplicator::key(&[1u8; 32], b"first");
        let key2 = Deduplicator::key(&[2u8; 32], b"second");
        let key3 = Deduplicator::key(&[3u8; 32], b"third");

        d.mark_seen(key1);
        d.mark_seen(key2);
        // At capacity — inserting key3 should evict oldest (key1)
        d.mark_seen(key3);

        assert!(!d.is_duplicate(&key1)); // evicted
        assert!(d.is_duplicate(&key2));
        assert!(d.is_duplicate(&key3));
    }
}
