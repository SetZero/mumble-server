//! Single-use, short-lived download tickets.
//!
//! After verifying credentials at `POST /files/{id}/auth`, the server
//! issues a random opaque token that the client appends to its `GET`
//! request as `?ticket=`. Tickets:
//!
//! * are 32 random bytes (hex-encoded, 64 chars) - opaque, no credential
//!   data
//! * are valid for 30 seconds by default
//! * are removed from the in-memory map on first use (single-use)
//!
//! Because tickets are not embedded in the shareable message URL and
//! expire quickly, leaking one through logs is harmless.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::RngCore;

/// Default ticket lifetime.
pub const DEFAULT_TICKET_TTL: Duration = Duration::from_secs(30);

/// Ticket length in bytes (hex-encoded length is 2x).
pub const TICKET_BYTES: usize = 32;

/// In-memory map of issued tickets. Keyed by the opaque token string.
#[derive(Debug, Default)]
pub struct TicketStore {
    inner: Mutex<HashMap<String, TicketEntry>>,
}

#[derive(Debug, Clone)]
struct TicketEntry {
    file_id: String,
    expires_at: Instant,
    /// Cert hash of the user that authenticated. Useful for invalidating
    /// all tickets for a user on disconnect.
    cert_hash: Option<String>,
}

/// Outcome of [`TicketStore::consume`].
#[derive(Debug, PartialEq, Eq)]
pub enum ConsumeResult {
    /// Ticket existed, matched the requested file, and had not expired.
    Ok,
    /// No such ticket (already consumed, never issued, or expired).
    NotFound,
    /// Ticket exists but was issued for a different file.
    WrongFile,
}

impl TicketStore {
    /// Construct a fresh empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a new ticket for the given file. Returns the opaque token
    /// that should be returned to the client.
    pub fn issue(&self, file_id: &str, ttl: Duration, cert_hash: Option<String>) -> String {
        let mut bytes = [0u8; TICKET_BYTES];
        rand::thread_rng().fill_bytes(&mut bytes);
        let token = hex::encode(bytes);
        let entry = TicketEntry {
            file_id: file_id.to_owned(),
            expires_at: Instant::now() + ttl,
            cert_hash,
        };
        if let Ok(mut map) = self.inner.lock() {
            self.cull_locked(&mut map);
            let _ = map.insert(token.clone(), entry);
        }
        token
    }

    /// Validate a ticket and consume it (single-use). Returns whether
    /// the ticket was valid for the given file.
    pub fn consume(&self, token: &str, file_id: &str) -> ConsumeResult {
        let Ok(mut map) = self.inner.lock() else {
            return ConsumeResult::NotFound;
        };
        let Some(entry) = map.remove(token) else {
            return ConsumeResult::NotFound;
        };
        if entry.expires_at < Instant::now() {
            return ConsumeResult::NotFound;
        }
        if entry.file_id != file_id {
            // Wrong file: re-insert? No - drop it; tickets are single-use
            // anyway and a mismatch is a sign of misuse.
            return ConsumeResult::WrongFile;
        }
        ConsumeResult::Ok
    }

    /// Remove all tickets issued to the given cert hash. Called when a
    /// user disconnects so leaked tickets cannot outlive the session.
    pub fn invalidate_for(&self, cert_hash: &str) {
        if let Ok(mut map) = self.inner.lock() {
            map.retain(|_, entry| entry.cert_hash.as_deref() != Some(cert_hash));
        }
    }

    fn cull_locked(&self, map: &mut HashMap<String, TicketEntry>) {
        let now = Instant::now();
        map.retain(|_, entry| entry.expires_at > now);
    }

    /// Number of currently live tickets. Test-only helper.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// Whether there are no live tickets. Test-only helper.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, reason = "tests panic on failure")]
    use super::*;

    #[test]
    fn issue_and_consume_once() {
        let store = TicketStore::new();
        let t = store.issue("file-a", DEFAULT_TICKET_TTL, None);
        assert_eq!(store.consume(&t, "file-a"), ConsumeResult::Ok);
        assert_eq!(store.consume(&t, "file-a"), ConsumeResult::NotFound);
    }

    #[test]
    fn ticket_for_wrong_file_rejected_and_consumed() {
        let store = TicketStore::new();
        let t = store.issue("file-a", DEFAULT_TICKET_TTL, None);
        assert_eq!(store.consume(&t, "file-b"), ConsumeResult::WrongFile);
        assert_eq!(store.consume(&t, "file-a"), ConsumeResult::NotFound);
    }

    #[test]
    fn expired_ticket_rejected() {
        let store = TicketStore::new();
        let t = store.issue("file-a", Duration::from_millis(1), None);
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(store.consume(&t, "file-a"), ConsumeResult::NotFound);
    }

    #[test]
    fn invalidate_for_removes_user_tickets() {
        let store = TicketStore::new();
        let t1 = store.issue("file-a", DEFAULT_TICKET_TTL, Some("alice".into()));
        let t2 = store.issue("file-b", DEFAULT_TICKET_TTL, Some("bob".into()));
        store.invalidate_for("alice");
        assert_eq!(store.consume(&t1, "file-a"), ConsumeResult::NotFound);
        assert_eq!(store.consume(&t2, "file-b"), ConsumeResult::Ok);
    }

    #[test]
    fn issue_returns_unique_tokens() {
        let store = TicketStore::new();
        let mut tokens = std::collections::HashSet::new();
        for _ in 0..50 {
            assert!(tokens.insert(store.issue("f", DEFAULT_TICKET_TTL, None)));
        }
    }

    #[test]
    fn token_is_hex_encoded_correct_length() {
        let store = TicketStore::new();
        let t = store.issue("f", DEFAULT_TICKET_TTL, None);
        assert_eq!(t.len(), TICKET_BYTES * 2);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
