//! In-memory tracking of currently connected client sessions.
//!
//! For each active session the plugin records:
//!
//! * `upload_token` - opaque random token clients send with each upload
//!   request (in the form body, never the URL).
//! * `session_jwt`  - HS256 JWT clients use to authenticate downloads of
//!   `mode=session` files.
//! * `cert_hash`    - stable cross-session identifier from TLS cert.

use std::collections::HashMap;
use std::sync::RwLock;

/// Per-session info used to validate uploads and downloads.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Stable hex-encoded SHA-1 of the client's TLS cert.
    pub cert_hash: String,
    /// Opaque random token authorizing uploads from this session.
    pub upload_token: String,
    /// Display name of the connected user (captured at connect time so an
    /// uploaded file's owner can be shown in the admin dashboard).
    pub username: String,
}

/// Thread-safe map of session id -> info.
#[derive(Debug, Default)]
pub struct SessionMap {
    inner: RwLock<HashMap<u32, SessionInfo>>,
}

impl SessionMap {
    /// Construct an empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or replace) session info for the given session.
    pub fn insert(&self, session_id: u32, info: SessionInfo) {
        if let Ok(mut g) = self.inner.write() {
            let _ = g.insert(session_id, info);
        }
    }

    /// Look up session info, cloning the small struct out under the lock.
    pub fn get(&self, session_id: u32) -> Option<SessionInfo> {
        self.inner
            .read()
            .ok()
            .and_then(|g| g.get(&session_id).cloned())
    }

    /// Remove and return session info on disconnect.
    pub fn remove(&self, session_id: u32) -> Option<SessionInfo> {
        self.inner
            .write()
            .ok()
            .and_then(|mut g| g.remove(&session_id))
    }

    /// Return a snapshot of every active session id. Used to broadcast
    /// the custom emote list to all connected users after a mutation.
    pub fn all_session_ids(&self) -> Vec<u32> {
        self.inner
            .read()
            .map(|g| g.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Returns `true` if the upload token matches what was issued for
    /// this session. Constant-time comparison avoids timing attacks.
    pub fn validate_upload_token(&self, session_id: u32, candidate: &str) -> bool {
        use subtle::ConstantTimeEq;
        let Some(info) = self.get(session_id) else {
            return false;
        };
        info.upload_token
            .as_bytes()
            .ct_eq(candidate.as_bytes())
            .unwrap_u8()
            == 1
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

    fn info(token: &str) -> SessionInfo {
        SessionInfo {
            cert_hash: "hash".into(),
            upload_token: token.into(),
            username: "tester".into(),
        }
    }

    #[test]
    fn insert_get_remove() {
        let map = SessionMap::new();
        map.insert(1, info("token-1"));
        assert_eq!(map.get(1).expect("present").upload_token, "token-1");
        let removed = map.remove(1).expect("present");
        assert_eq!(removed.upload_token, "token-1");
        assert!(map.get(1).is_none());
    }

    #[test]
    fn validate_upload_token_matches() {
        let map = SessionMap::new();
        map.insert(1, info("good-token"));
        assert!(map.validate_upload_token(1, "good-token"));
        assert!(!map.validate_upload_token(1, "bad-token"));
        assert!(!map.validate_upload_token(2, "good-token"));
    }

    #[test]
    fn validate_returns_false_for_missing_session() {
        let map = SessionMap::new();
        assert!(!map.validate_upload_token(99, "anything"));
    }
}
