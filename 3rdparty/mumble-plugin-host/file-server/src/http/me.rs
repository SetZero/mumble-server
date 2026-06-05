//! `GET|PUT /me/storage/{key}` - per-user opaque key/value storage.
//!
//! Authenticated by the caller's session JWT; the value is scoped to the JWT
//! `scope` claim (the registered account, `"<server_id>:<user_id>"`).  An
//! unregistered guest has no scope and is rejected, so only registered
//! accounts get storage.
//!
//! The live-doc plugin uses this to persist each user's sidebar/document
//! index under a fixed key, but the endpoint is plugin-agnostic.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::routing::get;
use axum::Router;

use crate::auth::verify_session_jwt;
use crate::http::common::{parse_bearer, ApiError};
use crate::state::AppState;

/// Maximum size of a single stored value.  The sidebar index is small; this
/// is a generous bound to stop a client filling the DB.
const MAX_VALUE_BYTES: usize = 1024 * 1024;

/// Build the `/me/*` sub-router.  Always mounted; each route authenticates
/// per-request via the session JWT.
pub fn router() -> Router<AppState> {
    Router::new().route("/me/storage/{key}", get(get_value).put(put_value))
}

/// Verify the session JWT and return the caller's per-user storage scope
/// (cert hash, or username for cert-less registered users).  Rejects callers
/// without a stable identity.
fn caller_scope(state: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("missing Authorization header"))?;
    let token = parse_bearer(auth)
        .ok_or_else(|| ApiError::unauthorized("Authorization must use Bearer scheme"))?;
    let claims = verify_session_jwt(state.signing_secret.as_ref(), token)
        .map_err(|e| ApiError::unauthorized(format!("invalid session token: {e}")))?;
    if claims.scope.is_empty() {
        return Err(ApiError::forbidden(
            "private storage requires a stable identity",
        ));
    }
    Ok(claims.scope)
}

/// Validate a storage key: a short, filesystem-safe identifier.
fn validate_key(key: &str) -> Result<(), ApiError> {
    let ok = !key.is_empty()
        && key.len() <= 128
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if ok {
        Ok(())
    } else {
        Err(ApiError::bad_request("invalid storage key"))
    }
}

async fn get_value(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<(StatusCode, String), ApiError> {
    let scope = caller_scope(&state, &headers)?;
    validate_key(&key)?;
    match state
        .private
        .get(&scope, &key)
        .map_err(|e| ApiError::internal(format!("private storage: {e}")))?
    {
        Some(value) => Ok((StatusCode::OK, value)),
        None => Err(ApiError::not_found("no value stored for key")),
    }
}

async fn put_value(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(key): Path<String>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let scope = caller_scope(&state, &headers)?;
    validate_key(&key)?;
    if body.len() > MAX_VALUE_BYTES {
        return Err(ApiError::too_large("value too large"));
    }
    let value = String::from_utf8(body.to_vec())
        .map_err(|_| ApiError::bad_request("value must be UTF-8"))?;
    state
        .private
        .put(&scope, &key, &value)
        .map_err(|e| ApiError::internal(format!("private storage: {e}")))?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests panic on failure")]
mod tests {
    use super::*;

    #[test]
    fn validate_key_accepts_safe_and_rejects_unsafe() {
        assert!(validate_key("livedoc-sidebar").is_ok());
        assert!(validate_key("a.b_c-1").is_ok());
        assert!(validate_key("").is_err());
        assert!(validate_key("with/slash").is_err());
        assert!(validate_key("with space").is_err());
        assert!(validate_key(&"x".repeat(129)).is_err());
    }
}
