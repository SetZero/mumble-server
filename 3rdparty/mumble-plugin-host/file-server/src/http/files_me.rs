//! Per-user "my shared files" endpoints.
//!
//! Mirrors [`super::files_admin`] but scoped to the **caller's own** uploads:
//! every route resolves the requester's certificate hash from their session
//! JWT (`sub`) and only ever touches files whose `uploader_cert_hash` matches
//! it.  A user can therefore never list, preview, or delete another user's
//! files - that stays admin-only via `/admin/files`.  Callers without a
//! certificate identity (an empty `sub`, e.g. a password-only login) are
//! rejected, since their uploads cannot be securely attributed.
//!
//! Routes:
//!
//! * `GET    /me/files`            - list the caller's own files
//! * `GET    /me/files/{id}/raw`   - stream one of the caller's files (preview)
//! * `DELETE /me/files/{id}`       - delete one of the caller's files

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::auth::verify_session_jwt;
use crate::http::common::{parse_bearer, ApiError};
use crate::http::files_admin::{record_to_dto, stream_blob_preview, AdminFileDto};
use crate::http::upload::build_download_url;
use crate::signing;
use crate::state::AppState;
use crate::storage::{AccessMode, FileRecord};

/// `GET /me/files` response body.  Uses the same per-file DTO as the admin
/// dashboard so the client can reuse the exact rendering.
#[derive(Debug, Serialize)]
pub struct MyFilesResponse {
    /// The caller's own uploaded files (newest first).
    pub files: Vec<AdminFileDto>,
}

/// `GET /me/files/{id}/link` response body.
#[derive(Debug, Serialize)]
pub struct FileLinkResponse {
    /// Public signed download URL the user can share / open in a browser.
    pub url: String,
}

/// Build the `/me/files` sub-router.  Always mounted; every route authenticates
/// per-request via the session JWT.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/me/files", get(list))
        .route("/me/files/{id}/raw", get(raw))
        .route("/me/files/{id}/link", get(link))
        .route("/me/files/{id}", axum::routing::delete(delete_one))
}

/// Verify the session JWT and return the caller's ownership identity: the
/// current certificate hash plus the stable registered user id (`Some` only
/// for registered users).  Rejects callers without a certificate identity.
fn caller_identity(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(String, Option<i64>), ApiError> {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("missing Authorization header"))?;
    let token = parse_bearer(auth)
        .ok_or_else(|| ApiError::unauthorized("Authorization must use Bearer scheme"))?;
    let claims = verify_session_jwt(state.signing_secret.as_ref(), token)
        .map_err(|e| ApiError::unauthorized(format!("invalid session token: {e}")))?;
    if claims.sub.is_empty() {
        return Err(ApiError::forbidden(
            "viewing your shared files requires a certificate identity",
        ));
    }
    let uid = (claims.uid >= 0).then(|| i64::from(claims.uid));
    Ok((claims.sub, uid))
}

/// Resolve a file the caller owns.  Matches on the stable user id when the
/// caller has one (so files survive certificate regeneration) and otherwise on
/// the current cert hash.  Returns 404 both when the file is missing *and* when
/// it belongs to someone else, so a user cannot probe for another user's files.
fn owned_file(
    state: &AppState,
    cert_hash: &str,
    uid: Option<i64>,
    file_id: &str,
) -> Result<FileRecord, ApiError> {
    state
        .storage
        .get(file_id)
        .map_err(|e| ApiError::internal(format!("storage: {e}")))?
        .filter(|r| {
            mumble_plugin_api::identity_owns(
                uid.unwrap_or(-1),
                cert_hash,
                r.uploader_user_id,
                r.uploader_cert_hash.as_deref().unwrap_or(""),
            )
        })
        .ok_or_else(|| ApiError::not_found("file not found"))
}

/// `GET /me/files` - list the caller's own uploaded files.
async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<MyFilesResponse>, ApiError> {
    let (cert_hash, uid) = caller_identity(&state, &headers)?;
    let records = state
        .storage
        .list_for_uploader(uid, &cert_hash)
        .map_err(|e| ApiError::internal(format!("storage: {e}")))?;
    let files = records.into_iter().map(record_to_dto).collect();
    Ok(Json(MyFilesResponse { files }))
}

/// `GET /me/files/{id}/raw` - stream one of the caller's own files for preview.
async fn raw(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> Result<Response<Body>, ApiError> {
    let (cert_hash, uid) = caller_identity(&state, &headers)?;
    let record = owned_file(&state, &cert_hash, uid, &file_id)?;
    stream_blob_preview(&state, &record).await
}

/// `DELETE /me/files/{id}` - delete one of the caller's own files.
async fn delete_one(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (cert_hash, uid) = caller_identity(&state, &headers)?;
    let record = owned_file(&state, &cert_hash, uid, &file_id)?;
    state
        .storage
        .delete(&record.id)
        .map_err(|e| ApiError::internal(format!("delete failed: {e}")))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// `GET /me/files/{id}/link` - the public, browser-openable signed download URL
/// for one of the caller's own files.
///
/// Only `public` files get a link: `password`/`session` files require an
/// in-app single-use ticket that a plain browser can't obtain, so a raw link
/// would not work for them.  The URL is reconstructed from the stored nonce +
/// expiry, so it is byte-for-byte the link issued at upload time.
async fn link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> Result<Json<FileLinkResponse>, ApiError> {
    let (cert_hash, uid) = caller_identity(&state, &headers)?;
    let record = owned_file(&state, &cert_hash, uid, &file_id)?;
    if record.access_mode != AccessMode::Public {
        return Err(ApiError::bad_request(
            "only public files have a shareable browser link",
        ));
    }
    let nonce = decode_nonce(&record.url_nonce)?;
    let signed = signing::sign(
        state.signing_secret.as_ref(),
        &record.id,
        record.url_expiry,
        nonce,
    );
    let url = build_download_url(&state.config.base_url, &record.id, &signed);
    Ok(Json(FileLinkResponse { url }))
}

/// Decode the stored hex `url_nonce` back into the raw nonce bytes.
fn decode_nonce(hex_nonce: &str) -> Result<[u8; signing::NONCE_BYTES], ApiError> {
    hex::decode(hex_nonce)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| ApiError::internal("corrupt url nonce"))
}
