use std::collections::VecDeque;
use std::time::{Duration, Instant};

const WINDOW_SECS: u64 = 60;
const MAX_BUCKET_ENTRIES: usize = 1000; // Prevent unbounded growth

/// A single entry in the rate limiter's sliding window.
#[derive(Debug, Clone)]
struct BucketEntry {
    timestamp: Instant,
    bytes: u64,
}

/// Sliding window rate limiter for messages and bandwidth.
///
/// Unlike a fixed window that resets at fixed intervals, this tracks
/// individual message timestamps and only counts messages within the
/// sliding window. This prevents "clock edge" attacks where an attacker
/// sends max messages just before and after a window boundary.
#[derive(Debug)]
pub struct RateLimiter {
    /// Ring buffer of message entries (timestamp + byte count)
    window: VecDeque<BucketEntry>,
    /// Current byte count within the window (cached for efficiency)
    current_bytes: u64,
}

impl RateLimiter {
    /// Creates a new sliding window rate limiter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            window: VecDeque::with_capacity(64),
            current_bytes: 0,
        }
    }

    /// Remove entries older than the window duration.
    fn expire_old_entries(&mut self, now: Instant) {
        let window = Duration::from_secs(WINDOW_SECS);
        while let Some(entry) = self.window.front() {
            if now.duration_since(entry.timestamp) >= window {
                self.current_bytes = self.current_bytes.saturating_sub(entry.bytes);
                self.window.pop_front();
            } else {
                break;
            }
        }
    }

    /// Returns the number of messages in the current window.
    fn msg_count(&self) -> u32 {
        // VecDeque::len() returns usize, but we know our limits are small
        self.window.len().try_into().unwrap_or(u32::MAX)
    }

    /// Returns the total bytes in the current window.
    #[allow(dead_code)]
    fn byte_count(&self) -> u64 {
        self.current_bytes
    }

    /// Check rate limits and record message in a single pass.
    /// Returns `Some(reason)` if rate-limited, `None` if allowed.
    pub fn check_and_record(
        &mut self,
        msg_rate: u32,
        bw_rate: u64,
        bytes: usize,
    ) -> Option<&'static str> {
        let now = Instant::now();
        self.expire_old_entries(now);

        // Check limits before recording
        if self.msg_count() >= msg_rate {
            return Some("msg_rate");
        }
        if self.current_bytes.saturating_add(bytes as u64) > bw_rate {
            return Some("bw_rate");
        }

        // Record the message
        self.window.push_back(BucketEntry {
            timestamp: now,
            bytes: bytes as u64,
        });
        self.current_bytes = self.current_bytes.saturating_add(bytes as u64);

        // Prevent unbounded growth (defense in depth)
        if self.window.len() > MAX_BUCKET_ENTRIES {
            // Remove oldest entry if we've exceeded max capacity
            if let Some(entry) = self.window.pop_front() {
                self.current_bytes = self.current_bytes.saturating_sub(entry.bytes);
            }
        }

        None
    }

    /// Returns statistics about the current window state.
    #[must_use]
    #[allow(dead_code)]
    pub fn stats(&self) -> RateLimiterStats {
        RateLimiterStats {
            message_count: self.msg_count(),
            byte_count: self.byte_count(),
            window_duration_secs: WINDOW_SECS,
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the current rate limiter state.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct RateLimiterStats {
    /// Number of messages in the current window.
    pub message_count: u32,
    /// Total bytes in the current window.
    pub byte_count: u64,
    /// Window duration in seconds.
    pub window_duration_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_and_record_returns_none_when_within_limits() {
        let mut limiter = RateLimiter::new();
        assert!(limiter.check_and_record(10, 1000, 100).is_none());
        assert_eq!(limiter.msg_count(), 1);
        assert_eq!(limiter.byte_count(), 100);
    }

    #[test]
    fn check_and_record_increments_counters_cumulatively() {
        let mut limiter = RateLimiter::new();
        assert!(limiter.check_and_record(10, 1000, 100).is_none());
        assert!(limiter.check_and_record(10, 1000, 50).is_none());
        assert_eq!(limiter.msg_count(), 2);
        assert_eq!(limiter.byte_count(), 150);
    }

    #[test]
    fn check_and_record_returns_msg_rate_when_exceeded() {
        let mut limiter = RateLimiter::new();
        // Pre-fill to limit
        for _ in 0..10 {
            limiter.window.push_back(BucketEntry {
                timestamp: Instant::now(),
                bytes: 1,
            });
        }
        limiter.current_bytes = 10;

        assert_eq!(limiter.check_and_record(10, 1000, 100), Some("msg_rate"));
        // Counters should not be incremented when rate-limited
        assert_eq!(limiter.msg_count(), 10);
    }

    #[test]
    fn check_and_record_returns_bw_rate_when_exceeded() {
        let mut limiter = RateLimiter::new();
        limiter.current_bytes = 950;
        limiter.window.push_back(BucketEntry {
            timestamp: Instant::now(),
            bytes: 950,
        });

        assert_eq!(limiter.check_and_record(10, 1000, 100), Some("bw_rate"));
        // Counters should not be incremented when rate-limited
        assert_eq!(limiter.byte_count(), 950);
    }

    #[test]
    fn old_entries_expire_after_window() {
        let mut limiter = RateLimiter::new();
        let old_time = Instant::now() - Duration::from_secs(61);

        // Add old entry
        limiter.window.push_back(BucketEntry {
            timestamp: old_time,
            bytes: 100,
        });
        limiter.current_bytes = 100;

        // Add recent entry
        limiter.window.push_back(BucketEntry {
            timestamp: Instant::now(),
            bytes: 50,
        });
        limiter.current_bytes = 150;

        // Trigger expiration check
        limiter.check_and_record(100, 10000, 1);

        // Old entry should be expired
        assert_eq!(limiter.msg_count(), 2); // Recent + new
        assert_eq!(limiter.byte_count(), 51); // Recent (50) + new (1)
    }

    #[test]
    fn sliding_window_prevents_clock_edge_attack() {
        let mut limiter = RateLimiter::new();
        let now = Instant::now();

        // Simulate messages at the end of a fixed window (t=59s)
        for i in 0..60 {
            limiter.window.push_back(BucketEntry {
                timestamp: now - Duration::from_secs(59) + Duration::from_millis(i * 10),
                bytes: 1,
            });
        }
        limiter.current_bytes = 60;

        // With sliding window, new messages should be rate-limited
        // because we still have 60 messages within the last 60 seconds
        assert_eq!(limiter.check_and_record(60, 10000, 1), Some("msg_rate"));
    }

    #[test]
    fn byte_count_saturates_instead_of_overflow() {
        let mut limiter = RateLimiter::new();
        limiter.current_bytes = u64::MAX - 10;
        limiter.window.push_back(BucketEntry {
            timestamp: Instant::now(),
            bytes: u64::MAX - 10,
        });

        // This should saturate, not panic
        assert!(limiter.check_and_record(u32::MAX, u64::MAX, 100).is_none());
        assert_eq!(limiter.byte_count(), u64::MAX);
    }

    #[test]
    fn stats_returns_current_state() {
        let mut limiter = RateLimiter::new();
        assert!(limiter.check_and_record(100, 10000, 50).is_none());
        assert!(limiter.check_and_record(100, 10000, 30).is_none());

        let stats = limiter.stats();
        assert_eq!(stats.message_count, 2);
        assert_eq!(stats.byte_count, 80);
        assert_eq!(stats.window_duration_secs, 60);
    }

    #[test]
    fn max_entries_prevents_unbounded_growth() {
        let mut limiter = RateLimiter::new();

        // Fill beyond max
        for _ in 0..MAX_BUCKET_ENTRIES + 100 {
            limiter.check_and_record(u32::MAX, u64::MAX, 1);
        }

        // Should be capped at max entries
        assert!(limiter.window.len() <= MAX_BUCKET_ENTRIES);
    }
}
