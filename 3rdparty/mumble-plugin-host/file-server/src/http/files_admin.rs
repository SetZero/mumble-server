//! Admin dashboard endpoints for managing *all* stored files.
//!
//! These power the Fancy Mumble client's "File server" admin tab: an admin
//! can list every file the server is storing, see the total/remaining storage,
//! preview common file types, and delete files.
//!
//! Auth model (distinct from the plugin-token `/admin/documents` routes in
//! [`super::admin`]): every request must carry a valid
//! `Authorization: Bearer <session-jwt>` whose subject currently holds
//! `Write` on the root channel - the canonical Mumble "is server admin" ACL
//! check (the same gate the client uses for its other admin tabs).
//!
//! Routes:
//!
//! * `GET    /admin/files`              - list all files + storage stats
//! * `DELETE /admin/files/{id}`         - delete one file (blob + metadata)
//! * `GET    /admin/files/{id}/raw`     - stream raw bytes (admin preview)

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Response, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use mumble_plugin_api::Permissions;
use serde::{Deserialize, Serialize};
use tokio_util::io::ReaderStream;

use crate::auth::verify_session_jwt;
use crate::documents::DocumentSummary;
use crate::http::common::{parse_bearer, ApiError};
use crate::state::AppState;
use crate::storage::{AccessMode, FileRecord};

/// One file as exposed to the admin dashboard.  Deliberately omits the
/// signing/secret columns (`url_nonce`, `password_hash`) - the dashboard only
/// needs descriptive metadata.
#[derive(Debug, Serialize)]
pub struct AdminFileDto {
    /// Opaque file id (also the blob filename).
    pub id: String,
    /// Original upload file name.
    pub filename: String,
    /// MIME type as provided by the uploader.
    pub mime_type: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// `public` | `password` | `session`.
    pub access_mode: AccessMode,
    /// Channel the file was shared in.
    pub channel_id: u32,
    /// Mumble virtual server id.
    pub server_id: u32,
    /// Unix-millis upload time.
    pub uploaded_at: i64,
    /// Unix-millis last download, or `null`.
    pub downloaded_at: Option<i64>,
    /// Unix-seconds TTL expiry, or `null` when no TTL applies.
    pub expires_at: Option<u64>,
    /// Display name of the uploader captured at upload time (survives the
    /// uploader disconnecting).  `null` for files uploaded before this was
    /// recorded.
    pub uploader_name: Option<String>,
    /// Stable cert hash of the uploader, so the client can match the file to a
    /// currently-connected user and show their live profile card.
    pub uploader_cert_hash: Option<String>,
    /// Stable registered user id of the uploader (`>= 0`), or `null`.  Preferred
    /// over the cert hash for matching a connected user, since it survives
    /// certificate regeneration across sessions.
    pub uploader_user_id: Option<i64>,
    /// Whether the uploader's session is still connected (its id is cleared on
    /// disconnect), so the dashboard can show "owner online".
    pub uploader_online: bool,
}

/// Aggregate storage statistics for the dashboard header + charts.
#[derive(Debug, Serialize)]
pub struct StorageStats {
    /// Sum of every file's `size_bytes`.
    pub total_bytes_used: u64,
    /// Configured total-storage cap.
    pub max_total_storage_bytes: u64,
    /// Configured single-file upload cap.
    pub max_file_size_bytes: u64,
    /// Number of files stored.
    pub file_count: u64,
}

/// `GET /admin/files` response body.
#[derive(Debug, Serialize)]
pub struct AdminFilesResponse {
    /// Every stored file (newest upload first).
    pub files: Vec<AdminFileDto>,
    /// Aggregate storage usage.
    pub stats: StorageStats,
}

/// `GET /admin/documents` response body.
#[derive(Debug, Serialize)]
pub struct AdminDocumentsResponse {
    /// Every persisted live-doc document (most recently updated first).
    pub documents: Vec<DocumentSummary>,
}

/// Map a stored [`FileRecord`] to the descriptive DTO.  Shared with the
/// per-user `/me/files` listing so both surfaces present files identically.
pub(crate) fn record_to_dto(r: FileRecord) -> AdminFileDto {
    AdminFileDto {
        id: r.id,
        filename: r.filename,
        mime_type: r.mime_type,
        size_bytes: r.size_bytes,
        access_mode: r.access_mode,
        channel_id: r.channel_id,
        server_id: r.server_id,
        uploaded_at: r.uploaded_at,
        downloaded_at: r.downloaded_at,
        expires_at: r.expires_at,
        uploader_name: r.uploader_name,
        uploader_cert_hash: r.uploader_cert_hash,
        uploader_user_id: r.uploader_user_id,
        uploader_online: r.session_id.is_some(),
    }
}

/// Maximum bytes streamed by the admin raw-preview route.  Previews are for
/// small/common types (images), so a generous-but-bounded cap keeps a huge
/// blob from being pulled inline.
const MAX_PREVIEW_BYTES: u64 = 32 * 1024 * 1024;

/// Build the admin sub-router.  Always mounted; every route authenticates
/// per-request via [`require_admin`].
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/files", get(list))
        .route("/admin/files/{id}", axum::routing::delete(delete_one))
        .route("/admin/files/{id}/raw", get(raw))
        .route("/admin/documents", get(list_documents))
        .route(
            "/admin/documents/{name}",
            axum::routing::delete(delete_document),
        )
        .route("/admin/private-storage", get(list_private))
}

/// Verify the request comes from a server admin (Write on the root channel).
fn require_admin(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("missing Authorization header"))?;
    let token = parse_bearer(auth)
        .ok_or_else(|| ApiError::unauthorized("Authorization must use Bearer scheme"))?;
    let claims = verify_session_jwt(state.signing_secret.as_ref(), token)
        .map_err(|e| ApiError::unauthorized(format!("invalid session token: {e}")))?;
    let is_admin = state
        .plugin_ctx
        .has_permission(claims.srv, claims.sid, 0, Permissions::WRITE);
    if !is_admin {
        return Err(ApiError::forbidden("server admin privileges required"));
    }
    Ok(())
}

/// `GET /admin/files` - list every stored file plus storage stats.
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AdminFilesResponse>, ApiError> {
    require_admin(&state, &headers)?;

    let records = state
        .storage
        .list_all()
        .map_err(|e| ApiError::internal(format!("storage: {e}")))?;
    let total_bytes_used = state
        .storage
        .total_bytes_used()
        .map_err(|e| ApiError::internal(format!("storage: {e}")))?;
    let file_count = records.len() as u64;
    let files = records.into_iter().map(record_to_dto).collect();

    Ok(Json(AdminFilesResponse {
        files,
        stats: StorageStats {
            total_bytes_used,
            max_total_storage_bytes: state.config.max_total_storage_bytes,
            max_file_size_bytes: state.config.max_file_size_bytes,
            file_count,
        },
    }))
}

/// `GET /admin/documents` - list every persisted live-doc document.
///
/// Distinct from the sibling-plugin `/admin/documents/{name}` CRUD routes
/// (which authenticate with the shared `admin_token`): this dashboard listing
/// is gated by the admin session JWT, like the other `/admin/files` routes, so
/// the Fancy Mumble client can show `LiveDocs` without holding the server secret.
pub async fn list_documents(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AdminDocumentsResponse>, ApiError> {
    require_admin(&state, &headers)?;
    let documents = state
        .documents
        .list_documents()
        .map_err(|e| ApiError::internal(format!("documents: {e}")))?;
    Ok(Json(AdminDocumentsResponse { documents }))
}

/// Query for `GET /admin/private-storage` (optional key-prefix filter).
#[derive(Debug, Deserialize)]
pub struct PrivateQuery {
    /// Only return entries whose key starts with this prefix (e.g. `calendar`).
    pub prefix: Option<String>,
}

/// One per-user private-storage blob, surfaced to the admin dashboard.
#[derive(Debug, Serialize)]
pub struct PrivateUsageEntry {
    /// Durable `"<server_id>:<user_id>"` namespace the blob belongs to.
    pub scope: String,
    /// Storage key (e.g. `calendar`).
    pub key: String,
    /// Blob size in bytes.
    pub size_bytes: i64,
    /// Last-updated time (unix millis).
    pub updated_at: i64,
}

/// Response for `GET /admin/private-storage`.
#[derive(Debug, Serialize)]
pub struct PrivateUsageResponse {
    /// One entry per stored private blob.
    pub entries: Vec<PrivateUsageEntry>,
}

/// `GET /admin/private-storage[?prefix=calendar]` - per-user private-store usage
/// (e.g. each user's calendar blob and its size) for the admin dashboard.
pub async fn list_private(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PrivateQuery>,
) -> Result<Json<PrivateUsageResponse>, ApiError> {
    require_admin(&state, &headers)?;
    let rows = state
        .private_store
        .list_usage(q.prefix.as_deref())
        .map_err(|e| ApiError::internal(format!("private-store: {e}")))?;
    let entries = rows
        .into_iter()
        .map(|(scope, key, size_bytes, updated_at)| PrivateUsageEntry {
            scope,
            key,
            size_bytes,
            updated_at,
        })
        .collect();
    Ok(Json(PrivateUsageResponse { entries }))
}

/// `DELETE /admin/documents/{name}` - delete a persisted live-doc document and
/// all its revisions (blobs + metadata rows).  Admin-session-JWT gated, like
/// the file routes; distinct from the sibling-plugin `admin_token` GET/PUT on
/// the same path (axum merges the disjoint methods).
pub async fn delete_document(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&state, &headers)?;
    let existed = state
        .documents
        .delete(&name)
        .map_err(|e| ApiError::internal(format!("documents: {e}")))?;
    if !existed {
        return Err(ApiError::not_found("document not found"));
    }
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// `DELETE /admin/files/{id}` - remove a file's blob + metadata.
pub async fn delete_one(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&state, &headers)?;
    // 404 rather than silently succeeding on an unknown id, so the dashboard
    // can surface a stale-list error instead of a misleading success.
    let exists = state
        .storage
        .get(&file_id)
        .map_err(|e| ApiError::internal(format!("storage: {e}")))?
        .is_some();
    if !exists {
        return Err(ApiError::not_found("file not found"));
    }
    state
        .storage
        .delete(&file_id)
        .map_err(|e| ApiError::internal(format!("delete failed: {e}")))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// `GET /admin/files/{id}/raw` - stream the blob bytes for an admin preview.
///
/// Unlike the signed `GET /files/{id}` download this needs no ticket; it is
/// gated purely by the admin session JWT.  `Content-Disposition: inline` is
/// never sent - the bytes are consumed by the Tauri backend, not a browser -
/// and the same hardening headers as the public download are applied.
pub async fn raw(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> Result<Response<Body>, ApiError> {
    require_admin(&state, &headers)?;

    let record = state
        .storage
        .get(&file_id)
        .map_err(|e| ApiError::internal(format!("storage: {e}")))?
        .ok_or_else(|| ApiError::not_found("file not found"))?;

    stream_blob_preview(&state, &record).await
}

/// Stream a file's blob bytes as a hardened inline preview response.  Shared by
/// the admin `/admin/files/{id}/raw` route and the per-user
/// `/me/files/{id}/raw` route; the *caller* is responsible for authorising
/// access to `record` before invoking this.
pub(crate) async fn stream_blob_preview(
    state: &AppState,
    record: &FileRecord,
) -> Result<Response<Body>, ApiError> {
    // Encrypted-at-rest (password) files cannot be decrypted without the
    // password, so neither admins nor owners can preview them.  This is the
    // whole point of zero-knowledge encryption - refuse rather than serve
    // ciphertext.
    if record.enc_salt.is_some() {
        return Err(ApiError::forbidden(
            "encrypted password-protected files cannot be previewed without the password",
        ));
    }
    if record.size_bytes > MAX_PREVIEW_BYTES {
        return Err(ApiError::too_large("file too large to preview"));
    }

    let blob_path = state.storage.blob_path(&record.id);
    let file = tokio::fs::File::open(&blob_path)
        .await
        .map_err(|_| ApiError::not_found("file blob missing"))?;
    let body = Body::from_stream(ReaderStream::new(file));

    let mime = HeaderValue::from_str(&record.mime_type)
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CONTENT_LENGTH, record.size_bytes)
        .header(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))
        .header(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        )
        .header(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static(
                "default-src 'none'; img-src 'self'; media-src 'self'; \
                 object-src 'none'; script-src 'none'; style-src 'none'; \
                 base-uri 'none'; frame-ancestors 'none'; sandbox;",
            ),
        )
        .body(body)
        .map_err(|e| ApiError::internal(format!("response build: {e}")))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "tests panic on failure"
)]
mod tests {
    use super::*;

    fn sample(id: &str, size: u64, online: bool) -> FileRecord {
        FileRecord {
            id: id.to_owned(),
            session_id: if online { Some(1) } else { None },
            channel_id: 3,
            server_id: 1,
            filename: "photo.png".into(),
            mime_type: "image/png".into(),
            size_bytes: size,
            url_nonce: "0011223344556677".into(),
            url_expiry: 9_999_999_999,
            access_mode: AccessMode::Session,
            password_hash: None,
            uploaded_at: 42,
            expires_at: Some(123),
            downloaded_at: None,
            uploader_cert_hash: Some("ab12".into()),
            uploader_name: Some("alice".into()),
            enc_salt: None,
            enc_nonce: None,
            uploader_user_id: None,
        }
    }

    #[test]
    fn record_to_dto_maps_fields_and_online_flag() {
        let dto = record_to_dto(sample("abc", 1024, true));
        assert_eq!(dto.id, "abc");
        assert_eq!(dto.size_bytes, 1024);
        assert_eq!(dto.access_mode, AccessMode::Session);
        assert_eq!(dto.channel_id, 3);
        assert_eq!(dto.expires_at, Some(123));
        assert_eq!(dto.uploader_name.as_deref(), Some("alice"));
        assert_eq!(dto.uploader_cert_hash.as_deref(), Some("ab12"));
        assert!(dto.uploader_online);

        let offline = record_to_dto(sample("def", 1, false));
        assert!(!offline.uploader_online);
    }

    #[test]
    fn dto_serializes_access_mode_lowercase() {
        let dto = record_to_dto(sample("abc", 1, true));
        let json = serde_json::to_value(&dto).expect("serialize");
        assert_eq!(json["access_mode"], "session");
        assert_eq!(json["uploader_online"], true);
    }
}
