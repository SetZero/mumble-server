//! Admin endpoints for plugin-to-plugin document persistence.
//!
//! Used by `mumble-live-doc` (and any future sibling plugin) to put
//! revisioned blobs under stable names.  Authenticated by a static
//! bearer token configured under `[plugin.file-server].admin_token`.
//!
//! Endpoints:
//!
//! * `GET  /admin/documents/{name}`                 - latest revision body
//! * `PUT  /admin/documents/{name}`                 - append new revision
//! * `GET  /admin/documents/{name}/revisions`       - list revisions (newest first)
//! * `GET  /admin/documents/{name}/revisions/{rev}` - specific revision body
//!
//! The `{name}` segment is URL-percent-decoded and validated against
//! a strict alphabet (ASCII alphanumeric + `-_./`) so directory
//! traversal and shell escapes are impossible.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Json;
use axum::Router;
use serde::Serialize;
use subtle::ConstantTimeEq;

use crate::documents::RevisionMeta;
use crate::state::AppState;

/// Maximum bytes accepted by `PUT /admin/documents/{name}`.
const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;

/// Build the admin sub-router.  Returns an empty router when no
/// `admin_token` is configured (the endpoints are disabled).
pub fn router(state: &AppState) -> Router<AppState> {
    if state.config.admin_token.is_none() {
        return Router::new();
    }
    Router::new()
        .route(
            "/admin/documents/{name}",
            get(get_latest).put(put_revision),
        )
        .route("/admin/documents/{name}/revisions", get(list_revisions))
        .route(
            "/admin/documents/{name}/revisions/{rev}",
            get(get_revision),
        )
}

#[derive(Debug, Serialize)]
struct RevisionsResponse {
    name: String,
    revisions: Vec<RevisionMeta>,
}

#[derive(Debug, Serialize)]
struct PutAccepted {
    rev_seq: u32,
}

async fn get_latest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    authenticate(&state, &headers)?;
    let validated = validate_name(&name)?;
    match state.documents.get_latest(&validated) {
        Ok(Some(body)) => Ok((StatusCode::OK, [("content-type", "text/markdown")], body).into_response()),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(err) => {
            tracing::warn!(?err, "admin get_latest failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn get_revision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((name, rev)): Path<(String, u32)>,
) -> Result<impl IntoResponse, StatusCode> {
    authenticate(&state, &headers)?;
    let validated = validate_name(&name)?;
    match state.documents.get_revision(&validated, rev) {
        Ok(Some(body)) => Ok((StatusCode::OK, [("content-type", "text/markdown")], body).into_response()),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(err) => {
            tracing::warn!(?err, "admin get_revision failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn list_revisions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<Json<RevisionsResponse>, StatusCode> {
    authenticate(&state, &headers)?;
    let validated = validate_name(&name)?;
    match state.documents.list_revisions(&validated) {
        Ok(revisions) => Ok(Json(RevisionsResponse {
            name: validated,
            revisions,
        })),
        Err(err) => {
            tracing::warn!(?err, "admin list_revisions failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn put_revision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    body: Bytes,
) -> Result<Json<PutAccepted>, StatusCode> {
    authenticate(&state, &headers)?;
    let validated = validate_name(&name)?;
    if body.len() > MAX_DOCUMENT_BYTES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    if body.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    match state.documents.put(&validated, &body) {
        Ok(rev_seq) => Ok(Json(PutAccepted { rev_seq })),
        Err(err) => {
            tracing::warn!(?err, "admin put_revision failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Constant-time comparison of the supplied bearer token against the
/// configured admin token.
fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let expected = state
        .config
        .admin_token
        .as_deref()
        .ok_or(StatusCode::NOT_FOUND)?;
    let header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let supplied = header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if supplied.as_bytes().ct_eq(expected.as_bytes()).into() {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

fn validate_name(raw: &str) -> Result<String, StatusCode> {
    let decoded = urlencoding_decode(raw).map_err(|_| StatusCode::BAD_REQUEST)?;
    if decoded.is_empty() || decoded.len() > 200 {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !decoded.chars().all(is_name_char) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if decoded.contains("..") || decoded.starts_with('/') || decoded.ends_with('/') {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(decoded)
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/')
}

/// Minimal percent-decode (RFC 3986 reserved + unreserved).  Avoids
/// pulling in another crate for a 20-line helper.
fn urlencoding_decode(input: &str) -> Result<String, ()> {
    let mut out = String::with_capacity(input.len());
    let mut bytes = input.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hi = bytes.next().ok_or(())?;
            let lo = bytes.next().ok_or(())?;
            let v = (hex_digit(hi)? << 4) | hex_digit(lo)?;
            out.push(v as char);
        } else if b == b'+' {
            out.push(' ');
        } else {
            out.push(b as char);
        }
    }
    Ok(out)
}

fn hex_digit(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test code - panics are acceptable")]
mod tests {
    use super::*;

    #[test]
    fn validate_name_accepts_safe_input() {
        assert_eq!(validate_name("live-doc-1-7-design.md").unwrap(), "live-doc-1-7-design.md");
        assert_eq!(validate_name("notes/plan.md").unwrap(), "notes/plan.md");
    }

    #[test]
    fn validate_name_rejects_traversal() {
        assert!(validate_name("../etc/passwd").is_err());
        assert!(validate_name("/abs").is_err());
        assert!(validate_name("trailing/").is_err());
        assert!(validate_name("with space").is_err());
        assert!(validate_name("").is_err());
    }
}
