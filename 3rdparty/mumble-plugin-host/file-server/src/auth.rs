//! Credential verification for `password` and `session` access modes.
//!
//! Both flows happen at `POST /files/{id}/auth`. Credentials arrive in
//! the `Authorization: Bearer <value>` header so they never appear in
//! GET parameters, URL history, or access logs.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, PasswordHash,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

/// JWT payload issued by the file server to clients on connect. Allows
/// the file server to identify the requesting session statelessy without
/// a round-trip to the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionClaims {
    /// Subject - the client's stable cert hash.
    pub sub: String,
    /// Mumble session id at JWT issue time.
    pub sid: u32,
    /// Mumble virtual server id.
    pub srv: u32,
    /// Per-user private-storage scope: a durable `"<server_id>:<user_id>"`
    /// key for registered users (empty for guests).  Unlike `sub` (the cert
    /// hash) it survives certificate regeneration across reconnects.
    /// `#[serde(default)]` keeps older tokens (without the claim) decodable.
    #[serde(default)]
    pub scope: String,
    /// Registered Mumble user id, or `-1` for an unregistered guest.
    #[serde(default = "default_uid")]
    pub uid: i64,
    /// Whether the subject is a registered (non-guest) Mumble user.
    /// Gates access to per-user private storage.
    #[serde(default)]
    pub reg: bool,
    /// Issued-at (unix seconds).
    pub iat: u64,
    /// Expiry (unix seconds).
    pub exp: u64,
}

/// `serde` default for [`SessionClaims::uid`] on tokens minted before the
/// field existed: treat them as unregistered guests.
fn default_uid() -> i64 {
    -1
}

/// Reasons a credential check might fail.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Argon2 hashing failed (programmer error or corrupted DB hash).
    #[error("password hashing failed")]
    Hashing,
    /// Provided password did not match the stored hash.
    #[error("invalid password")]
    InvalidPassword,
    /// JWT signature, expiry, or claims were invalid.
    #[error("invalid session token: {0}")]
    InvalidJwt(String),
}

/// Hash a password using Argon2id with a random salt.
pub fn hash_password(plaintext: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(plaintext.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| AuthError::Hashing)
}

/// Verify a plaintext password against a stored Argon2 hash. Constant-
/// time-comparison is performed by the underlying crate.
pub fn verify_password(plaintext: &str, stored_hash: &str) -> Result<(), AuthError> {
    let parsed = PasswordHash::new(stored_hash).map_err(|_| AuthError::Hashing)?;
    Argon2::default()
        .verify_password(plaintext.as_bytes(), &parsed)
        .map_err(|_| AuthError::InvalidPassword)
}

/// Verify and decode a session JWT signed with HS256 against the
/// server's signing secret. The `exp` claim is validated automatically.
pub fn verify_session_jwt(secret: &[u8], token: &str) -> Result<SessionClaims, AuthError> {
    let key = DecodingKey::from_secret(secret);
    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.leeway = 0;
    validation.set_required_spec_claims(&["exp", "sub", "iat"]);
    decode::<SessionClaims>(token, &key, &validation)
        .map(|data| data.claims)
        .map_err(|e| AuthError::InvalidJwt(e.to_string()))
}

/// Issue a new session JWT for the given session.
///
/// `ttl_seconds` is added to the current Unix timestamp to compute `exp`.
pub fn issue_session_jwt(
    secret: &[u8],
    cert_hash: &str,
    scope: &str,
    session_id: u32,
    server_id: u32,
    user_id: i64,
    ttl_seconds: u64,
) -> Result<String, AuthError> {
    use jsonwebtoken::{encode, EncodingKey, Header};
    let now = crate::signing::now_unix_seconds();
    let claims = SessionClaims {
        sub: cert_hash.to_owned(),
        sid: session_id,
        srv: server_id,
        scope: scope.to_owned(),
        uid: user_id,
        reg: user_id >= 0,
        iat: now,
        exp: now.saturating_add(ttl_seconds),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .map_err(|e| AuthError::InvalidJwt(e.to_string()))
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
    fn password_hash_roundtrip() {
        let hash = hash_password("hunter2").expect("hashes");
        verify_password("hunter2", &hash).expect("verifies");
    }

    #[test]
    fn wrong_password_rejected() {
        let hash = hash_password("hunter2").expect("hashes");
        let err = verify_password("hunter3", &hash).unwrap_err();
        assert!(matches!(err, AuthError::InvalidPassword));
    }

    #[test]
    fn corrupted_hash_rejected() {
        let err = verify_password("x", "not-a-valid-argon2-hash").unwrap_err();
        assert!(matches!(err, AuthError::Hashing));
    }

    #[test]
    fn jwt_roundtrip() {
        let secret = b"super-secret-key-32-bytes-x-x-x";
        let token = issue_session_jwt(secret, "cert-hash-abc", "cert-hash-abc", 42, 1, 5, 3600)
            .expect("issues");
        let claims = verify_session_jwt(secret, &token).expect("verifies");
        assert_eq!(claims.sub, "cert-hash-abc");
        assert_eq!(claims.scope, "cert-hash-abc");
        assert_eq!(claims.sid, 42);
        assert_eq!(claims.srv, 1);
        assert_eq!(claims.uid, 5);
        assert!(claims.reg, "user_id >= 0 must be registered");
    }

    #[test]
    fn jwt_scope_falls_back_to_username() {
        let secret = b"k";
        // Cert-less client: sub is empty but scope carries a stable identity.
        let token = issue_session_jwt(secret, "", "SuperUser", 1, 0, 0, 3600).expect("issues");
        let claims = verify_session_jwt(secret, &token).expect("verifies");
        assert_eq!(claims.sub, "");
        assert_eq!(claims.scope, "SuperUser");
        assert_eq!(claims.uid, 0);
        assert!(claims.reg, "user_id >= 0 must be registered");
    }

    #[test]
    fn jwt_guest_is_not_registered() {
        let secret = b"super-secret-key-32-bytes-x-x-x";
        let token = issue_session_jwt(secret, "guest", "", 1, 1, -1, 3600).expect("issues");
        let claims = verify_session_jwt(secret, &token).expect("verifies");
        assert_eq!(claims.uid, -1);
        assert!(!claims.reg, "guest must not be registered");
    }

    #[test]
    fn jwt_signed_with_other_secret_rejected() {
        let token = issue_session_jwt(b"secret-a", "x", "x", 1, 1, -1, 3600).expect("issues");
        let err = verify_session_jwt(b"secret-b", &token).unwrap_err();
        assert!(matches!(err, AuthError::InvalidJwt(_)));
    }

    #[test]
    fn expired_jwt_rejected() {
        let secret = b"secret";
        // ttl 0 -> exp == iat == now, validation rejects it as expired
        // (jsonwebtoken default leeway is 0)
        let token = issue_session_jwt(secret, "x", "x", 1, 1, -1, 0).expect("issues");
        std::thread::sleep(std::time::Duration::from_secs(1));
        let err = verify_session_jwt(secret, &token).unwrap_err();
        assert!(matches!(err, AuthError::InvalidJwt(_)));
    }
}
