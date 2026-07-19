//! Per-user private storage endpoints (`/me/storage/...`).
//!
//! Generic key/value storage scoped to the authenticated user's stable
//! cert hash.  **Registered users only**: the session JWT must carry
//! `reg == true`.  The file-server attaches no meaning to keys or values;
//! callers (e.g. the client's live-doc sidebar) treat it as transparent
//! backing storage.
//!
//! Endpoints (all authenticated by the session JWT in
//! `Authorization: Bearer <jwt>`):
//!
//! * `GET    /me/storage`          - list the caller's keys
//! * `GET    /me/storage/{key}`    - fetch one blob
//! * `PUT    /me/storage/{key}`    - store one blob
//! * `DELETE /me/storage/{key}`    - delete one blob

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::auth::{verify_session_jwt, SessionClaims};
use crate::http::common::{parse_bearer, ApiError};
use crate::state::AppState;

/// Maximum size of a single private blob (1 MiB).
const MAX_PRIVATE_BYTES: usize = 1024 * 1024;

/// Build the `/me/storage` sub-router.
pub fn router() -> Router<AppState> {
    Router::new().route("/me/storage", get(list_keys)).route(
        "/me/storage/{key}",
        get(get_value).put(put_value).delete(delete_value),
    )
}

#[derive(Debug, Serialize)]
struct KeysResponse {
    keys: Vec<String>,
}

/// Authenticate the request and require a registered user.  Returns the
/// caller's durable storage namespace (the JWT `scope` claim,
/// `"<server_id>:<user_id>"`), which survives certificate regeneration
/// across reconnects - unlike the cert-hash `sub`.
fn authenticate_registered(state: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    let claims = verify_claims(state, headers)?;
    if !claims.reg || claims.scope.is_empty() {
        return Err(ApiError::forbidden(
            "private storage is available to registered users only",
        ));
    }
    Ok(claims.scope)
}

fn verify_claims(state: &AppState, headers: &HeaderMap) -> Result<SessionClaims, ApiError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_bearer)
        .ok_or_else(|| ApiError::unauthorized("missing Authorization header"))?;
    verify_session_jwt(state.signing_secret.as_ref(), token)
        .map_err(|e| ApiError::forbidden(format!("invalid session token: {e}")))
}

async fn list_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<KeysResponse>, ApiError> {
    let cert_hash = authenticate_registered(&state, &headers)?;
    let keys = state
        .private_store
        .list_keys(&cert_hash)
        .map_err(|e| ApiError::internal(format!("private store: {e}")))?;
    Ok(Json(KeysResponse { keys }))
}

async fn get_value(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let cert_hash = authenticate_registered(&state, &headers)?;
    let key = validate_key(&key)?;
    match state.private_store.get(&cert_hash, &key) {
        Ok(Some(blob)) => Ok((
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            blob,
        )
            .into_response()),
        Ok(None) => Err(ApiError::not_found("no value for key")),
        Err(e) => Err(ApiError::internal(format!("private store: {e}"))),
    }
}

async fn put_value(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(key): Path<String>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let cert_hash = authenticate_registered(&state, &headers)?;
    let key = validate_key(&key)?;
    if body.len() > MAX_PRIVATE_BYTES {
        return Err(ApiError::too_large("value exceeds private storage limit"));
    }
    state
        .private_store
        .put(&cert_hash, &key, &body)
        .map_err(|e| ApiError::internal(format!("private store: {e}")))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_value(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<StatusCode, ApiError> {
    let cert_hash = authenticate_registered(&state, &headers)?;
    let key = validate_key(&key)?;
    match state.private_store.delete(&cert_hash, &key) {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(ApiError::not_found("no value for key")),
        Err(e) => Err(ApiError::internal(format!("private store: {e}"))),
    }
}

/// Validate a storage key: ASCII alphanumeric plus `-_.`, length 1..=128,
/// no path separators or traversal.  Keys are opaque but must be safe.
fn validate_key(raw: &str) -> Result<String, ApiError> {
    if raw.is_empty() || raw.len() > 128 {
        return Err(ApiError::bad_request("invalid storage key length"));
    }
    if !raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(ApiError::bad_request("invalid storage key characters"));
    }
    if raw.contains("..") {
        return Err(ApiError::bad_request("invalid storage key"));
    }
    Ok(raw.to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test code - panics are acceptable")]
mod tests {
    use super::*;

    #[test]
    fn validate_key_accepts_safe() {
        assert_eq!(validate_key("livedoc-sidebar").unwrap(), "livedoc-sidebar");
        assert_eq!(validate_key("a.b_c-1").unwrap(), "a.b_c-1");
    }

    #[test]
    fn validate_key_rejects_unsafe() {
        assert!(validate_key("").is_err());
        assert!(validate_key("with/slash").is_err());
        assert!(validate_key("..").is_err());
        assert!(validate_key("a b").is_err());
    }
}
