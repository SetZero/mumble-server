//! `POST /files` - multipart upload handler.

use std::path::PathBuf;

use axum::extract::{Multipart, Query, State};
use axum::Json;
use mumble_plugin_api::Permissions;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

use crate::auth::hash_password;
use crate::host_facade::HostFacade;
use crate::http::common::ApiError;
use crate::signing::{self, NONCE_BYTES, NO_EXPIRY};
use crate::state::AppState;
use crate::storage::{AccessMode, FileRecord};

/// Determine the MIME type of a file from its magic bytes, falling back to
/// extension-based guessing, and finally `application/octet-stream`.
///
/// Using magic bytes means the server never trusts the MIME type the client
/// claims to be uploading, closing a class of content-type confusion attacks.
fn sniff_mime(magic: &[u8], filename: &str) -> String {
    if let Some(kind) = infer::get(magic) {
        return kind.mime_type().to_owned();
    }
    // Fall back to extension for types infer doesn't cover (e.g. plain text).
    let ext = filename
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "txt" => "text/plain".to_owned(),
        "md" => "text/markdown".to_owned(),
        "csv" => "text/csv".to_owned(),
        "json" => "application/json".to_owned(),
        "pdf" => "application/pdf".to_owned(),
        _ => "application/octet-stream".to_owned(),
    }
}

/// Query string for `POST /files` - identifies the uploading session.
#[derive(Debug, Deserialize)]
pub struct UploadQuery {
    /// Session id of the uploader (assigned by Mumble at connect).
    pub session: u32,
    /// Upload token previously delivered to this session via plugin data.
    pub token: String,
}

/// JSON response body returned to the client after a successful upload.
#[derive(Debug, Serialize)]
pub struct UploadResponse {
    /// Random file id (also embedded in the URL).
    pub file_id: String,
    /// Full shareable download URL with `?ex=&is=&hm=` parameters.
    pub download_url: String,
    /// Access mode for this file.
    pub access_mode: AccessMode,
    /// Unix-seconds expiry, or `None` if TTL disabled.
    pub expires_at: Option<u64>,
    /// File size in bytes.
    pub size_bytes: u64,
}

/// Handler for `POST /files`.
pub async fn upload(
    State(state): State<AppState>,
    Query(q): Query<UploadQuery>,
    multipart: Multipart,
) -> Result<Json<UploadResponse>, ApiError> {
    tracing::info!(session = q.session, "upload: handler entered");
    if !state.plugin_ctx.is_session_active(0, q.session) {
        tracing::warn!(session = q.session, "upload: session not active");
        return Err(ApiError::unauthorized("session not active"));
    }
    if !state.sessions.validate_upload_token(q.session, &q.token) {
        tracing::warn!(session = q.session, "upload: invalid token");
        return Err(ApiError::unauthorized("invalid upload token"));
    }
    let session_info = state.sessions.get(q.session);
    let cert_hash = session_info.as_ref().map(|s| s.cert_hash.clone());
    let uploader_name = session_info.as_ref().map(|s| s.username.clone());
    tracing::info!(session = q.session, "upload: auth ok, parsing multipart");

    let parsed = parse_multipart(&state, multipart, state.config.max_file_size_bytes).await?;
    enforce_share_permissions(
        state.plugin_ctx.as_ref(),
        q.session,
        parsed.channel_id,
        parsed.mode,
    )?;
    tracing::info!(
        session = q.session,
        bytes = parsed.size_bytes,
        filename = %parsed.filename,
        "upload: multipart parsed, inserting record"
    );
    let result = insert_record(&state, q.session, cert_hash, uploader_name, parsed).await;
    tracing::info!(session = q.session, ok = result.is_ok(), "upload: complete");
    result
}

/// Verify the uploading session is allowed to share files in the
/// requested channel using the requested access mode.
///
/// Two ACL flags gate file uploads:
///
/// * [`Permissions::SHARE_FILES`] - master switch.  Required for any
///   upload regardless of access mode.  When denied, the user cannot
///   upload files at all.
/// * [`Permissions::SHARE_FILES_PUBLIC`] - additionally required for
///   `public` and `password` modes ("link-shareable").  When denied,
///   the user can still upload `session`-scoped files (downloadable
///   only by currently-connected users) but cannot create links that
///   work outside the server.
///
/// Permissions are checked against the upload's target channel so an
/// admin can disable file sharing in specific channels without
/// affecting the rest of the server.
fn enforce_share_permissions(
    plugin_ctx: &dyn HostFacade,
    session_id: u32,
    channel_id: u32,
    mode: AccessMode,
) -> Result<(), ApiError> {
    // Defence-in-depth: the channel id is a client-supplied value in the
    // upload form, so verify that the session is actually in the channel
    // they claim before consulting per-channel ACLs.  Without this a user
    // could pick a channel they had `SHARE_FILES` in, then attach the
    // resulting URL to a chat in a different channel they did not have
    // sharing rights in (M-1).
    match plugin_ctx.current_channel(0, session_id) {
        Some(actual) if actual != channel_id => {
            tracing::warn!(
                session = session_id,
                claimed_channel = channel_id,
                actual_channel = actual,
                "upload: rejected channel-id mismatch"
            );
            return Err(ApiError::forbidden(
                "channel mismatch: you can only upload from the channel you are in",
            ));
        }
        // `None` means the host doesn't expose `current_channel` (older
        // build) - fall through and rely on per-channel ACLs alone.
        _ => {}
    }
    if !plugin_ctx.has_permission(0, session_id, channel_id, Permissions::SHARE_FILES) {
        tracing::warn!(
            session = session_id,
            channel = channel_id,
            "upload: denied (missing ShareFiles permission)"
        );
        return Err(ApiError::forbidden(
            "you do not have permission to share files in this channel",
        ));
    }
    if matches!(mode, AccessMode::Public | AccessMode::Password)
        && !plugin_ctx.has_permission(0, session_id, channel_id, Permissions::SHARE_FILES_PUBLIC)
    {
        tracing::warn!(
            session = session_id,
            channel = channel_id,
            mode = ?mode,
            "upload: denied (missing ShareFilesPublic permission)"
        );
        return Err(ApiError::forbidden(
            "you do not have permission to share files via public or password-protected links; use session-scoped sharing instead",
        ));
    }
    Ok(())
}

struct ParsedUpload {
    /// File id assigned at parse time so we can stream straight to disk.
    file_id: String,
    /// On-disk path the bytes were streamed into.
    blob_path: PathBuf,
    /// Bytes written to `blob_path`.
    size_bytes: u64,
    filename: String,
    mime_type: String,
    channel_id: u32,
    mode: AccessMode,
    password: Option<String>,
}

/// RAII guard that removes a partially-written blob file if the upload
/// path errors out before it gets a chance to commit.
struct BlobGuard {
    path: Option<PathBuf>,
}

impl BlobGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }
    /// Detach the guard so the file is NOT removed on drop.
    fn commit(mut self) {
        let _ = self.path.take();
    }
}

impl Drop for BlobGuard {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

async fn parse_multipart(
    state: &AppState,
    mut multipart: Multipart,
    max_size: u64,
) -> Result<ParsedUpload, ApiError> {
    let mut file_meta: Option<(String, PathBuf, u64, String, String, BlobGuard)> = None;
    let mut channel_id: u32 = 0;
    let mut mode = AccessMode::Public;
    let mut password: Option<String> = None;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::bad_request(format!("multipart error: {e}")))?
    {
        let name = field.name().unwrap_or("").to_owned();
        tracing::debug!(field = %name, "upload: parsing field");
        match name.as_str() {
            "file" => {
                if file_meta.is_some() {
                    return Err(ApiError::bad_request("multiple `file` fields not allowed"));
                }
                let filename = field
                    .file_name()
                    .map(str::to_owned)
                    .unwrap_or_else(|| "upload.bin".to_owned());
                // Discard the client-supplied Content-Type entirely; we will
                // sniff the real MIME from the file's magic bytes after the
                // bytes are on disk.

                let file_id = generate_file_id();
                let blob_path = state.storage.blob_path(&file_id);
                let guard = BlobGuard::new(blob_path.clone());

                let mut written: u64 = 0;
                // Keep the first 16 bytes so we can identify the file type
                // from its magic bytes without an extra seek.
                let mut magic_buf: Vec<u8> = Vec::with_capacity(16);
                let mut sink = tokio::fs::File::create(&blob_path)
                    .await
                    .map_err(|e| ApiError::internal(format!("create blob: {e}")))?;
                while let Some(chunk) = field.chunk().await.map_err(|e| {
                    tracing::error!(error = %e, "upload: chunk error");
                    ApiError::bad_request(format!("failed to read file bytes: {e}"))
                })? {
                    written = written.saturating_add(chunk.len() as u64);
                    if written > max_size {
                        tracing::warn!(size = written, max = max_size, "upload: file too large");
                        return Err(ApiError::too_large(format!(
                            "file exceeds max_file_size_bytes ({max_size})"
                        )));
                    }
                    if magic_buf.len() < 16 {
                        let needed = 16 - magic_buf.len();
                        magic_buf.extend_from_slice(&chunk[..needed.min(chunk.len())]);
                    }
                    sink.write_all(&chunk)
                        .await
                        .map_err(|e| ApiError::internal(format!("write blob: {e}")))?;
                }
                sink.flush()
                    .await
                    .map_err(|e| ApiError::internal(format!("flush blob: {e}")))?;
                drop(sink);
                let mime_type = sniff_mime(&magic_buf, &filename);
                file_meta = Some((file_id, blob_path, written, filename, mime_type, guard));
            }
            "channel_id" => {
                let s = field.text().await.unwrap_or_default();
                channel_id = s.parse().unwrap_or(0);
            }
            "mode" => {
                let s = field.text().await.unwrap_or_default();
                mode = AccessMode::parse(&s)
                    .ok_or_else(|| ApiError::bad_request(format!("unknown mode: {s}")))?;
            }
            "password" => {
                let s = field.text().await.unwrap_or_default();
                if !s.is_empty() {
                    password = Some(s);
                }
            }
            _ => {}
        }
    }

    let (file_id, blob_path, size_bytes, filename, mime_type, guard) =
        file_meta.ok_or_else(|| ApiError::bad_request("missing file part"))?;
    if mode == AccessMode::Password && password.is_none() {
        return Err(ApiError::bad_request(
            "mode=password requires `password` field",
        ));
    }
    // Hand the guard back to the caller via the parsed struct so the
    // file is removed if `insert_record` fails.
    guard.commit();
    Ok(ParsedUpload {
        file_id,
        blob_path,
        size_bytes,
        filename,
        mime_type,
        channel_id,
        mode,
        password,
    })
}

async fn insert_record(
    state: &AppState,
    session_id: u32,
    cert_hash: Option<String>,
    uploader_name: Option<String>,
    parsed: ParsedUpload,
) -> Result<Json<UploadResponse>, ApiError> {
    let file_id = parsed.file_id;
    let mut nonce = [0u8; NONCE_BYTES];
    rand::thread_rng().fill_bytes(&mut nonce);
    let now_s = signing::now_unix_seconds();
    let expiry_s = if state.config.delete_on_ttl {
        now_s.saturating_add(state.config.ttl.as_secs())
    } else {
        NO_EXPIRY
    };
    let signed = signing::sign(state.signing_secret.as_ref(), &file_id, expiry_s, nonce);

    let password_hash = match (parsed.mode, parsed.password.as_deref()) {
        (AccessMode::Password, Some(pw)) => {
            Some(hash_password(pw).map_err(|_| ApiError::internal("failed to hash password"))?)
        }
        _ => None,
    };

    let record = FileRecord {
        id: file_id.clone(),
        session_id: Some(session_id),
        channel_id: parsed.channel_id,
        server_id: 0,
        filename: parsed.filename,
        mime_type: parsed.mime_type,
        size_bytes: parsed.size_bytes,
        url_nonce: signed.is.clone(),
        url_expiry: expiry_s,
        access_mode: parsed.mode,
        password_hash,
        uploaded_at: now_unix_ms(),
        expires_at: if expiry_s == NO_EXPIRY {
            None
        } else {
            Some(expiry_s)
        },
        downloaded_at: None,
        uploader_cert_hash: cert_hash,
        uploader_name,
    };

    if let Err(e) = state.storage.insert(&record) {
        let _ = tokio::fs::remove_file(&parsed.blob_path).await;
        return Err(map_storage_error(e));
    }

    Ok(Json(UploadResponse {
        download_url: build_download_url(&state.config.base_url, &file_id, &signed),
        file_id,
        access_mode: record.access_mode,
        expires_at: record.expires_at,
        size_bytes: record.size_bytes,
    }))
}

fn map_storage_error(e: crate::storage::StorageError) -> ApiError {
    use crate::storage::StorageError;
    match e {
        StorageError::CapExceeded { total_after, limit } => {
            ApiError::too_large(format!("storage cap exceeded ({total_after} > {limit})"))
        }
        other => ApiError::internal(format!("storage: {other}")),
    }
}

fn generate_file_id() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bs58::encode(bytes).into_string()
}

fn now_unix_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn build_download_url(base: &str, file_id: &str, p: &signing::SignedParams) -> String {
    format!(
        "{}/files/{}?ex={}&is={}&hm={}",
        base, file_id, p.ex, p.is, p.hm
    )
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        reason = "tests panic on failure"
    )]
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex;

    /// Test plugin context that returns true only when every flag in
    /// the requested mask is in `granted` for the requested channel.
    #[derive(Debug, Default)]
    struct PermCtx {
        granted: Mutex<HashSet<(u32, Permissions)>>,
        current_channel: Mutex<Option<u32>>,
    }

    impl PermCtx {
        fn grant(&self, channel: u32, perm: Permissions) {
            let _ = self.granted.lock().unwrap().insert((channel, perm));
        }
        fn set_current_channel(&self, c: Option<u32>) {
            *self.current_channel.lock().unwrap() = c;
        }
    }

    impl HostFacade for PermCtx {
        fn send_plugin_data(
            &self,
            _: u32,
            _: u32,
            _: &str,
            _: &[u8],
        ) -> crate::host_facade::FacadeResult<()> {
            Ok(())
        }
        fn is_session_active(&self, _: u32, _: u32) -> bool {
            true
        }
        fn user_has_channel_access(&self, _: u32, _: u32, _: u32) -> bool {
            true
        }
        fn has_permission(
            &self,
            _server: u32,
            _session: u32,
            channel: u32,
            perm: Permissions,
        ) -> bool {
            let granted = self.granted.lock().unwrap();
            perm.iter().all(|flag| granted.contains(&(channel, flag)))
        }
        fn current_channel(&self, _server: u32, _session: u32) -> Option<u32> {
            *self.current_channel.lock().unwrap()
        }
        fn get_config(&self, _: &str) -> Option<String> {
            None
        }
    }

    fn assert_forbidden(result: Result<(), ApiError>, expected_substr: &str) {
        let err = result.expect_err("expected forbidden error");
        let msg = format!("{err:?}");
        assert!(
            msg.contains(expected_substr),
            "error message {msg:?} did not contain {expected_substr:?}"
        );
    }

    #[test]
    fn share_files_denied_blocks_all_modes() {
        let ctx = PermCtx::default();
        for mode in [
            AccessMode::Session,
            AccessMode::Public,
            AccessMode::Password,
        ] {
            assert_forbidden(enforce_share_permissions(&ctx, 1, 0, mode), "share files");
        }
    }

    #[test]
    fn session_mode_only_requires_share_files() {
        let ctx = PermCtx::default();
        ctx.grant(0, Permissions::SHARE_FILES);
        // ShareFilesPublic is intentionally NOT granted.
        enforce_share_permissions(&ctx, 1, 0, AccessMode::Session)
            .expect("session-mode upload should be permitted with ShareFiles only");
    }

    #[test]
    fn public_mode_requires_both_permissions() {
        let ctx = PermCtx::default();
        ctx.grant(0, Permissions::SHARE_FILES);
        // Missing SHARE_FILES_PUBLIC -> public denied.
        assert_forbidden(
            enforce_share_permissions(&ctx, 1, 0, AccessMode::Public),
            "public",
        );
        ctx.grant(0, Permissions::SHARE_FILES_PUBLIC);
        enforce_share_permissions(&ctx, 1, 0, AccessMode::Public)
            .expect("public upload should be permitted once both flags are granted");
    }

    #[test]
    fn password_mode_requires_share_files_public() {
        let ctx = PermCtx::default();
        ctx.grant(0, Permissions::SHARE_FILES);
        assert_forbidden(
            enforce_share_permissions(&ctx, 1, 0, AccessMode::Password),
            "public",
        );
        ctx.grant(0, Permissions::SHARE_FILES_PUBLIC);
        enforce_share_permissions(&ctx, 1, 0, AccessMode::Password)
            .expect("password upload should be permitted once both flags are granted");
    }

    #[test]
    fn permissions_are_per_channel() {
        let ctx = PermCtx::default();
        // Granted only on channel 5.
        ctx.grant(5, Permissions::SHARE_FILES);
        ctx.grant(5, Permissions::SHARE_FILES_PUBLIC);
        enforce_share_permissions(&ctx, 1, 5, AccessMode::Public)
            .expect("upload to channel 5 should succeed");
        assert_forbidden(
            enforce_share_permissions(&ctx, 1, 7, AccessMode::Session),
            "share files",
        );
    }

    #[test]
    fn channel_id_mismatch_is_rejected() {
        let ctx = PermCtx::default();
        ctx.grant(5, Permissions::SHARE_FILES);
        ctx.grant(5, Permissions::SHARE_FILES_PUBLIC);
        // Session is actually in channel 7 but is claiming channel 5.
        ctx.set_current_channel(Some(7));
        assert_forbidden(
            enforce_share_permissions(&ctx, 1, 5, AccessMode::Public),
            "channel mismatch",
        );
    }

    #[test]
    fn channel_id_match_is_allowed() {
        let ctx = PermCtx::default();
        ctx.grant(5, Permissions::SHARE_FILES);
        ctx.grant(5, Permissions::SHARE_FILES_PUBLIC);
        ctx.set_current_channel(Some(5));
        enforce_share_permissions(&ctx, 1, 5, AccessMode::Public)
            .expect("matching channel should be allowed");
    }
}
