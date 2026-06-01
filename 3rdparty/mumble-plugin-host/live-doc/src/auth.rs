//! JWT minting / verification for the WS handshake.
//!
//! A token binds (`server_id`, `session_id`, `doc_slug`) so a client
//! cannot reuse a JWT for a different doc or impersonate another session.
//! The document is server-scoped (channel-independent); the actual
//! access decision (owner / shared-with) is re-checked live at WS
//! connect time so a revoked grant cannot ride an unexpired token.
//! Tokens are short-lived ([`crate::HANDSHAKE_JWT_TTL_SECS`]) and signed
//! with HMAC-SHA256.

use jsonwebtoken::{
    decode, encode, errors::Error as JwtError, Algorithm, DecodingKey, EncodingKey, Header,
    Validation,
};
use mumble_plugin_api::{ServerId, SessionId};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Claims embedded in a handshake JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeClaims {
    /// Virtual server id the session belongs to.
    pub server_id: ServerId,
    /// Mumble session id this token authenticates.
    pub session_id: SessionId,
    /// Server-scoped document slug.
    pub doc_slug: String,
    /// Unix-seconds expiry.
    pub exp: u64,
    /// Unix-seconds issued-at.
    pub iat: u64,
}

/// Mint a handshake token for the given session.
pub fn issue_handshake_jwt(
    secret: &[u8],
    server_id: ServerId,
    session_id: SessionId,
    doc_slug: &str,
    ttl_secs: u64,
) -> Result<String, JwtError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let claims = HandshakeClaims {
        server_id,
        session_id,
        doc_slug: doc_slug.to_string(),
        exp: now + ttl_secs,
        iat: now,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
}

/// Verify a handshake token and return its claims.
///
/// `Validation::default()` currently pins to HS256, but we set it
/// explicitly so a future change to the upstream default cannot
/// silently widen the accepted algorithm set (e.g. let `alg: none`
/// tokens through).
pub fn verify_handshake_jwt(secret: &[u8], token: &str) -> Result<HandshakeClaims, JwtError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 5;
    decode::<HandshakeClaims>(token, &DecodingKey::from_secret(secret), &validation)
        .map(|d| d.claims)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test assertions")]
    use super::*;

    #[test]
    fn jwt_round_trip() {
        let secret = b"deadbeefdeadbeefdeadbeefdeadbeef";
        let tok = issue_handshake_jwt(secret, 1, 42, "design-notes", 60).unwrap();
        let claims = verify_handshake_jwt(secret, &tok).unwrap();
        assert_eq!(claims.session_id, 42);
        assert_eq!(claims.doc_slug, "design-notes");
    }

    #[test]
    fn jwt_rejects_other_secret() {
        let tok = issue_handshake_jwt(b"aaaaaaaaaaaaaaaa", 1, 42, "design-notes", 60).unwrap();
        assert!(verify_handshake_jwt(b"bbbbbbbbbbbbbbbb", &tok).is_err());
    }

    #[test]
    fn jwt_rejects_wrong_algorithm() {
        use jsonwebtoken::Header;
        let secret = b"deadbeefdeadbeefdeadbeefdeadbeef";
        let claims = HandshakeClaims {
            server_id: 1,
            session_id: 42,
            doc_slug: "x".into(),
            exp: u64::MAX / 2,
            iat: 0,
        };
        // Sign with HS384 - our verifier only accepts HS256.
        let tok = encode(
            &Header::new(Algorithm::HS384),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();
        assert!(verify_handshake_jwt(secret, &tok).is_err());
    }
}
