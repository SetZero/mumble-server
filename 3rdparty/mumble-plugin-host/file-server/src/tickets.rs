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
//! expire quickly, leaking the *token* through logs is harmless.  For
//! encrypted (password-protected) files a ticket additionally carries the
//! ephemeral file-decryption key derived at auth time; that key lives only in
//! this in-memory map, is single-use, expires in 30s, is zeroized on drop, and
//! is redacted from `Debug` / never logged.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::RngCore;
use zeroize::Zeroizing;

/// Default ticket lifetime.
pub const DEFAULT_TICKET_TTL: Duration = Duration::from_secs(30);

/// Ticket length in bytes (hex-encoded length is 2x).
pub const TICKET_BYTES: usize = 32;

/// In-memory map of issued tickets. Keyed by the opaque token string.
#[derive(Debug, Default)]
pub struct TicketStore {
    inner: Mutex<HashMap<String, TicketEntry>>,
}

struct TicketEntry {
    file_id: String,
    expires_at: Instant,
    /// Cert hash of the user that authenticated. Useful for invalidating
    /// all tickets for a user on disconnect.
    cert_hash: Option<String>,
    /// Ephemeral file-decryption key for password-protected (encrypted) files,
    /// derived from the password at auth time.  `None` for plaintext blobs.
    /// Zeroized on drop; redacted from `Debug` so it never reaches logs.
    enc_key: Option<Zeroizing<[u8; 32]>>,
}

// Manual `Debug` that never prints key material (the struct must be `Debug` so
// the enclosing `TicketStore` can derive it).
impl std::fmt::Debug for TicketEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TicketEntry")
            .field("file_id", &self.file_id)
            .field("expires_at", &self.expires_at)
            .field("cert_hash", &self.cert_hash)
            .field("enc_key", &self.enc_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
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
    /// that should be returned to the client.  `enc_key` is the ephemeral
    /// file-decryption key for encrypted files (or `None`).
    pub fn issue(
        &self,
        file_id: &str,
        ttl: Duration,
        cert_hash: Option<String>,
        enc_key: Option<Zeroizing<[u8; 32]>>,
    ) -> String {
        let mut bytes = [0u8; TICKET_BYTES];
        rand::thread_rng().fill_bytes(&mut bytes);
        let token = hex::encode(bytes);
        let entry = TicketEntry {
            file_id: file_id.to_owned(),
            expires_at: Instant::now() + ttl,
            cert_hash,
            enc_key,
        };
        if let Ok(mut map) = self.inner.lock() {
            self.cull_locked(&mut map);
            let _ = map.insert(token.clone(), entry);
        }
        token
    }

    /// Validate a ticket and consume it (single-use).  Returns whether the
    /// ticket was valid for the given file, and - on success - the ephemeral
    /// decryption key it carried (`Some` only for encrypted files).
    pub fn consume(
        &self,
        token: &str,
        file_id: &str,
    ) -> (ConsumeResult, Option<Zeroizing<[u8; 32]>>) {
        let Ok(mut map) = self.inner.lock() else {
            return (ConsumeResult::NotFound, None);
        };
        let Some(entry) = map.remove(token) else {
            return (ConsumeResult::NotFound, None);
        };
        if entry.expires_at < Instant::now() {
            return (ConsumeResult::NotFound, None);
        }
        if entry.file_id != file_id {
            // Wrong file: drop it (single-use); a mismatch is a sign of misuse.
            return (ConsumeResult::WrongFile, None);
        }
        (ConsumeResult::Ok, entry.enc_key)
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
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        reason = "tests panic on failure"
    )]
    use super::*;

    #[test]
    fn issue_and_consume_once() {
        let store = TicketStore::new();
        let t = store.issue("file-a", DEFAULT_TICKET_TTL, None, None);
        assert_eq!(store.consume(&t, "file-a").0, ConsumeResult::Ok);
        assert_eq!(store.consume(&t, "file-a").0, ConsumeResult::NotFound);
    }

    #[test]
    fn ticket_for_wrong_file_rejected_and_consumed() {
        let store = TicketStore::new();
        let t = store.issue("file-a", DEFAULT_TICKET_TTL, None, None);
        assert_eq!(store.consume(&t, "file-b").0, ConsumeResult::WrongFile);
        assert_eq!(store.consume(&t, "file-a").0, ConsumeResult::NotFound);
    }

    #[test]
    fn expired_ticket_rejected() {
        let store = TicketStore::new();
        let t = store.issue("file-a", Duration::from_millis(1), None, None);
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(store.consume(&t, "file-a").0, ConsumeResult::NotFound);
    }

    #[test]
    fn invalidate_for_removes_user_tickets() {
        let store = TicketStore::new();
        let t1 = store.issue("file-a", DEFAULT_TICKET_TTL, Some("alice".into()), None);
        let t2 = store.issue("file-b", DEFAULT_TICKET_TTL, Some("bob".into()), None);
        store.invalidate_for("alice");
        assert_eq!(store.consume(&t1, "file-a").0, ConsumeResult::NotFound);
        assert_eq!(store.consume(&t2, "file-b").0, ConsumeResult::Ok);
    }

    #[test]
    fn issue_returns_unique_tokens() {
        let store = TicketStore::new();
        let mut tokens = std::collections::HashSet::new();
        for _ in 0..50 {
            assert!(tokens.insert(store.issue("f", DEFAULT_TICKET_TTL, None, None)));
        }
    }

    #[test]
    fn token_is_hex_encoded_correct_length() {
        let store = TicketStore::new();
        let t = store.issue("f", DEFAULT_TICKET_TTL, None, None);
        assert_eq!(t.len(), TICKET_BYTES * 2);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn ticket_carries_enc_key_once() {
        let store = TicketStore::new();
        let key = Zeroizing::new([42u8; 32]);
        let t = store.issue("file-a", DEFAULT_TICKET_TTL, None, Some(key));
        let (result, returned) = store.consume(&t, "file-a");
        assert_eq!(result, ConsumeResult::Ok);
        assert_eq!(returned.map(|k| *k), Some([42u8; 32]));
        // Single-use: the key is gone after the first consume.
        let (result2, returned2) = store.consume(&t, "file-a");
        assert_eq!(result2, ConsumeResult::NotFound);
        assert!(returned2.is_none());
    }
}
