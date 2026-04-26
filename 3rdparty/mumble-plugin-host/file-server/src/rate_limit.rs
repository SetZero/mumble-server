//! Per-peer sliding-window failure counter used to throttle credential
//! checks (H-4).
//!
//! The store is intentionally minimal: it tracks failure timestamps per
//! peer key (the peer IP, optionally combined with a file id), trims old
//! entries when consulted, and exposes a single `check_and_record_failure`
//! API that the caller invokes only on credential-check failure.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// In-memory per-peer failure counter.
#[derive(Debug, Default)]
pub struct RateLimiter {
    inner: Mutex<HashMap<String, Vec<Instant>>>,
}

/// Outcome of a [`RateLimiter::check`] call.
#[derive(Debug, PartialEq, Eq)]
pub enum LimitDecision {
    /// Caller may proceed.
    Allow,
    /// Caller must be rejected with `429 Too Many Requests`.
    Block,
}

impl RateLimiter {
    /// Construct an empty limiter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decide whether `peer` may attempt another check right now.
    /// Trims entries older than `window`.
    pub fn check(&self, peer: &str, window: Duration, max_failures: u32) -> LimitDecision {
        let Ok(mut map) = self.inner.lock() else {
            return LimitDecision::Allow;
        };
        let now = Instant::now();
        if let Some(entries) = map.get_mut(peer) {
            entries.retain(|t| now.duration_since(*t) < window);
            if entries.len() as u32 >= max_failures {
                return LimitDecision::Block;
            }
        }
        LimitDecision::Allow
    }

    /// Record a single failure for `peer`. Old entries are pruned.
    pub fn record_failure(&self, peer: &str, window: Duration) {
        let Ok(mut map) = self.inner.lock() else { return };
        let now = Instant::now();
        let entries = map.entry(peer.to_owned()).or_default();
        entries.retain(|t| now.duration_since(*t) < window);
        entries.push(now);
    }

    /// Clear failures for `peer` after a successful credential check.
    /// Prevents legitimate users from being locked out by a few typos.
    pub fn clear(&self, peer: &str) {
        let Ok(mut map) = self.inner.lock() else { return };
        let _ = map.remove(peer);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, reason = "tests panic on failure")]
    use super::*;

    const W: Duration = Duration::from_secs(60);

    #[test]
    fn allows_below_threshold_blocks_at_threshold() {
        let r = RateLimiter::new();
        for _ in 0..4 {
            assert_eq!(r.check("1.2.3.4", W, 5), LimitDecision::Allow);
            r.record_failure("1.2.3.4", W);
        }
        // 5th attempt: 4 failures recorded, still under the cap of 5
        assert_eq!(r.check("1.2.3.4", W, 5), LimitDecision::Allow);
        r.record_failure("1.2.3.4", W);
        // 6th attempt: 5 failures => blocked
        assert_eq!(r.check("1.2.3.4", W, 5), LimitDecision::Block);
    }

    #[test]
    fn clear_resets_failures() {
        let r = RateLimiter::new();
        for _ in 0..6 {
            r.record_failure("1.2.3.4", W);
        }
        assert_eq!(r.check("1.2.3.4", W, 5), LimitDecision::Block);
        r.clear("1.2.3.4");
        assert_eq!(r.check("1.2.3.4", W, 5), LimitDecision::Allow);
    }

    #[test]
    fn other_peers_are_independent() {
        let r = RateLimiter::new();
        for _ in 0..6 {
            r.record_failure("1.2.3.4", W);
        }
        assert_eq!(r.check("5.6.7.8", W, 5), LimitDecision::Allow);
    }

    #[test]
    fn old_failures_are_pruned() {
        let r = RateLimiter::new();
        for _ in 0..6 {
            r.record_failure("1.2.3.4", Duration::from_millis(1));
        }
        std::thread::sleep(Duration::from_millis(10));
        // Entries older than the window are pruned on next consultation.
        assert_eq!(
            r.check("1.2.3.4", Duration::from_millis(1), 5),
            LimitDecision::Allow
        );
    }
}
