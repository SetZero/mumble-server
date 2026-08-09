//! Discord-style stateless signed download URLs.
//!
//! Every download URL embeds three query parameters that are validated
//! against a server-held HMAC key before any database lookup:
//!
//! ```text
//! /files/{id}?ex={hex_unix_seconds}&is={hex_nonce}&hm={hex_hmac32}
//! ```
//!
//! `hm` is the first 32 hex characters of `HMAC-SHA256(secret,
//! "{id}:{ex}:{is}")`. Verification is constant-time against
//! recomputation, so tampered or expired URLs are rejected without
//! touching the database.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// `ex` value used when TTL is disabled (max u64 in hex).
pub const NO_EXPIRY: u64 = u64::MAX;

/// Length of the HMAC prefix embedded in URLs (hex chars).
pub const HMAC_HEX_LEN: usize = 32;

/// Length of the URL nonce in bytes (so 16 hex chars).
pub const NONCE_BYTES: usize = 8;

/// Errors raised when verifying a signed URL.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SignatureError {
    /// One of the required parameters was missing or malformed.
    #[error("malformed signature parameters")]
    Malformed,
    /// The HMAC did not match the expected value.
    #[error("hmac mismatch")]
    BadSignature,
    /// The expiry timestamp is in the past.
    #[error("link expired")]
    Expired,
}

/// Output of [`sign`]: the three values embedded into the download URL.
#[derive(Debug, Clone)]
pub struct SignedParams {
    /// `ex` query parameter (hex-encoded unix seconds, or `NO_EXPIRY`).
    pub ex: String,
    /// `is` query parameter (hex-encoded random nonce).
    pub is: String,
    /// `hm` query parameter (truncated hex HMAC).
    pub hm: String,
}

/// Compute the signed URL parameters for `file_id` with the given expiry.
///
/// Pass `NO_EXPIRY` for `expiry_unix_seconds` to disable TTL.
pub fn sign(
    secret: &[u8],
    file_id: &str,
    expiry_unix_seconds: u64,
    nonce: [u8; NONCE_BYTES],
) -> SignedParams {
    let ex = format!("{expiry_unix_seconds:x}");
    let is = hex::encode(nonce);
    let hm = compute_hmac(secret, file_id, &ex, &is);
    SignedParams { ex, is, hm }
}

/// Verify the signature and expiry of a signed URL request.
///
/// Returns the decoded nonce on success so the caller can do its own
/// database lookup against `url_nonce`.
pub fn verify(
    secret: &[u8],
    file_id: &str,
    ex: &str,
    is: &str,
    hm: &str,
    now_unix_seconds: u64,
) -> Result<[u8; NONCE_BYTES], SignatureError> {
    if hm.len() != HMAC_HEX_LEN {
        return Err(SignatureError::Malformed);
    }
    let expected = compute_hmac(secret, file_id, ex, is);
    if expected.as_bytes().ct_eq(hm.as_bytes()).unwrap_u8() != 1 {
        return Err(SignatureError::BadSignature);
    }
    let expiry = u64::from_str_radix(ex, 16).map_err(|_| SignatureError::Malformed)?;
    if expiry != NO_EXPIRY && expiry < now_unix_seconds {
        return Err(SignatureError::Expired);
    }
    let nonce_bytes = hex::decode(is).map_err(|_| SignatureError::Malformed)?;
    nonce_bytes
        .try_into()
        .map_err(|_| SignatureError::Malformed)
}

/// Current Unix timestamp in seconds. Returns 0 if the clock is before
/// the epoch (essentially impossible).
pub fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn compute_hmac(secret: &[u8], file_id: &str, ex: &str, is: &str) -> String {
    // `Hmac<Sha256>` accepts keys of any length so the only Err variant is
    // structurally unreachable; we use `unreachable!` rather than
    // `expect`/`unwrap` so any future refactor that breaks the invariant
    // is caught at the panic site instead of silently returning an empty
    // signature.
    let Ok(mut mac) = <HmacSha256 as KeyInit>::new_from_slice(secret) else {
        unreachable!("Hmac<Sha256> accepts keys of any length");
    };
    mac.update(file_id.as_bytes());
    mac.update(b":");
    mac.update(ex.as_bytes());
    mac.update(b":");
    mac.update(is.as_bytes());
    let bytes = mac.finalize().into_bytes();
    let mut hex_full = hex::encode(bytes);
    hex_full.truncate(HMAC_HEX_LEN);
    hex_full
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        reason = "tests panic on failure"
    )]
    use super::*;

    const SECRET: &[u8] = b"test-secret-32-bytes-for-hmac--";

    #[test]
    fn sign_then_verify_roundtrip() {
        let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let params = sign(SECRET, "abc123", 9_999_999_999, nonce);
        let recovered =
            verify(SECRET, "abc123", &params.ex, &params.is, &params.hm, 0).expect("verifies");
        assert_eq!(recovered, nonce);
    }

    #[test]
    fn rejects_tampered_id() {
        let nonce = [0u8; 8];
        let params = sign(SECRET, "abc", 9_999_999_999, nonce);
        let err = verify(SECRET, "xyz", &params.ex, &params.is, &params.hm, 0).unwrap_err();
        assert_eq!(err, SignatureError::BadSignature);
    }

    #[test]
    fn rejects_tampered_expiry() {
        let nonce = [0u8; 8];
        let params = sign(SECRET, "abc", 1_000, nonce);
        let err = verify(SECRET, "abc", "ffffffff", &params.is, &params.hm, 0).unwrap_err();
        assert_eq!(err, SignatureError::BadSignature);
    }

    #[test]
    fn rejects_expired_link() {
        let nonce = [0u8; 8];
        let params = sign(SECRET, "abc", 1_000, nonce);
        let err = verify(SECRET, "abc", &params.ex, &params.is, &params.hm, 9_999_999).unwrap_err();
        assert_eq!(err, SignatureError::Expired);
    }

    #[test]
    fn no_expiry_never_expires() {
        let nonce = [0u8; 8];
        let params = sign(SECRET, "abc", NO_EXPIRY, nonce);
        let _ = verify(
            SECRET,
            "abc",
            &params.ex,
            &params.is,
            &params.hm,
            u64::MAX - 1,
        )
        .expect("never expires");
    }

    #[test]
    fn malformed_hmac_length_rejected() {
        assert_eq!(
            verify(SECRET, "abc", "0", "00", "short", 0),
            Err(SignatureError::Malformed)
        );
    }

    #[test]
    fn different_secret_rejected() {
        let nonce = [0u8; 8];
        let params = sign(SECRET, "abc", 9_999_999_999, nonce);
        let err = verify(b"different", "abc", &params.ex, &params.is, &params.hm, 0).unwrap_err();
        assert_eq!(err, SignatureError::BadSignature);
    }
}
