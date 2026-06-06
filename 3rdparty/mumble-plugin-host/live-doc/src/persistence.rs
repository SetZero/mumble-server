//! File-server-backed persistence for live documents.
//!
//! Each document is stored as a single markdown file on the
//! `file-server` plugin, keyed by [`crate::doc::DocKey::as_filename`].
//! The file embeds two base64 HTML-comment markers so it stays valid
//! markdown while remaining losslessly rehydratable by the plugin:
//!
//! * `<!--YJS-STATE:...-->`   - the binary Yjs CRDT update blob.
//! * `<!--LIVEDOC-META:...-->`- JSON document metadata (owner, title,
//!   channel binding, visibility).
//!
//! The set of users a document has been shared with lives in the
//! file-server's generic per-document ACL (`/admin/documents/{name}/shared-with`),
//! which is opaque to the file-server.

use std::collections::HashSet;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::config::LiveDocConfig;
use crate::doc::{DocMeta, DocRoom};

/// One member a document is shared with, as surfaced to clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedMember {
    /// Recipient's stable cert hash.
    pub cert_hash: String,
    /// Registered Mumble user id, or `-1` for a guest.
    pub user_id: i64,
    /// Display name captured when the grant was recorded.
    pub display_name: String,
}

/// Marker that wraps the binary CRDT state inside a markdown file.
const YJS_MARKER_PREFIX: &str = "<!--YJS-STATE:";
const YJS_MARKER_SUFFIX: &str = "-->";
/// Marker that wraps the base64 JSON document metadata.
const META_MARKER_PREFIX: &str = "<!--LIVEDOC-META:";
const META_MARKER_SUFFIX: &str = "-->";

#[derive(Debug, Deserialize)]
struct SharedWithResponse {
    #[serde(default)]
    shared_with: Vec<SharedMember>,
}

/// Try to seed a freshly-created room from the file-server: hydrate the
/// CRDT state, the metadata marker, and the shared-with set.  Every
/// failure is logged and ignored - a missing snapshot is the normal
/// "first open" condition, and an unreachable file-server must not block
/// editing.
pub async fn try_seed_room(cfg: &LiveDocConfig, client: &reqwest::Client, room: &DocRoom) {
    let filename = room.key().as_filename();
    let Some(url) = cfg.file_server_url.as_deref() else {
        tracing::warn!(
            ?filename,
            "live-doc seed skipped: plugin.fancy-live-doc.file_server_url is not set - \
             live documents are NOT persisted and will be lost on teardown"
        );
        return;
    };
    if cfg.file_server_admin_token.is_none() {
        tracing::warn!(
            ?filename,
            %url,
            "live-doc seed skipped: plugin.fancy-live-doc.file_server_admin_token is not set - \
             cannot read or write the file-server, documents will be lost"
        );
        return;
    }
    match fetch_file(client, url, cfg.file_server_admin_token.as_deref(), &filename).await {
        Ok(Some(contents)) => {
            let mut consistent = true;
            if let Some(snapshot) = extract_snapshot(&contents) {
                if let Err(err) = room.seed_from_snapshot(&snapshot).await {
                    tracing::warn!(?err, ?filename, "live-doc seed failed");
                    consistent = false;
                } else {
                    tracing::trace!(
                        ?filename,
                        snapshot_len = snapshot.len(),
                        "live-doc seeded existing document from storage"
                    );
                }
            } else {
                // The stored file exists but carries no recognisable CRDT
                // snapshot.  Persisting our empty state would destroy it,
                // so the room stays "unsafe" until it can be loaded.
                tracing::warn!(
                    ?filename,
                    "live-doc seed: stored file has no CRDT snapshot marker - \
                     refusing to overwrite it"
                );
                consistent = false;
            }
            if let Some(meta) = extract_meta(&contents) {
                room.set_meta(meta).await;
            }
            if consistent {
                room.mark_persist_safe().await;
            }
        }
        Ok(None) => {
            // No stored document yet: this is a brand-new doc, so a flush
            // creates it rather than overwriting anything.
            tracing::trace!(?filename, "live-doc seed: no stored document yet (new)");
            room.mark_persist_safe().await;
        }
        Err(err) => {
            tracing::warn!(?err, ?filename, "live-doc seed fetch failed");
        }
    }

    if let Some(members) = fetch_shared_with(cfg, client, &filename).await {
        let certs: HashSet<String> = members.into_iter().map(|m| m.cert_hash).collect();
        room.set_shared_with(certs).await;
    }
}

/// Fetch the full shared-with member list (with display names) for a
/// document, for surfacing to clients.  Empty when the file-server is
/// unavailable or has no record.
pub async fn fetch_shared_with_members(
    cfg: &LiveDocConfig,
    client: &reqwest::Client,
    room: &DocRoom,
) -> Vec<SharedMember> {
    let filename = room.key().as_filename();
    fetch_shared_with(cfg, client, &filename)
        .await
        .unwrap_or_default()
}

/// Persist the current state of a room to the file-server: the CRDT blob
/// plus the metadata marker.  Best-effort - returns silently on failure
/// so it never blocks teardown or the autosave loop.
pub async fn persist_room(cfg: &LiveDocConfig, client: &reqwest::Client, room: &DocRoom) {
    let filename = room.key().as_filename();
    let Some(url) = cfg.file_server_url.as_deref() else {
        tracing::warn!(
            ?filename,
            "live-doc persist skipped: plugin.fancy-live-doc.file_server_url is not set - \
             this document is being discarded, not saved"
        );
        return;
    };
    if cfg.file_server_admin_token.is_none() {
        tracing::warn!(
            ?filename,
            %url,
            "live-doc persist skipped: plugin.fancy-live-doc.file_server_admin_token is not set - \
             cannot authenticate to the file-server, this document is being discarded"
        );
        return;
    }
    if !room.is_persist_safe().await {
        // The room never confirmed its state against storage (the
        // file-server was unreachable at open, or the stored file could
        // not be parsed).  Flushing now could overwrite a saved document
        // with the room's empty/partial state, so skip the write.  The
        // document is left intact and will be loaded on the next open.
        tracing::warn!(
            ?filename,
            "live-doc skipping persist: room state not confirmed against storage"
        );
        return;
    }
    let snapshot = room.encode_snapshot().await;
    let meta = room.meta().await;
    tracing::trace!(
        ?filename,
        snapshot_len = snapshot.len(),
        owner = %meta.owner_cert_hash,
        title = %meta.title,
        "live-doc persisting room to file-server"
    );
    if snapshot.is_empty() && meta.owner_cert_hash.is_empty() {
        tracing::trace!(?filename, "live-doc persist skipped: empty snapshot, no owner");
        return;
    }

    let body = render_document(&snapshot, &meta);
    let body_len = body.len();
    match put_file(
        client,
        url,
        cfg.file_server_admin_token.as_deref(),
        &filename,
        body,
    )
    .await
    {
        Ok(()) => {
            tracing::trace!(?filename, bytes = body_len, "live-doc persisted to file-server");
            room.mark_saved().await;
        }
        Err(err) => tracing::warn!(?err, ?filename, "live-doc persist failed"),
    }
}

/// Record a share recipient in the file-server's per-document ACL.
/// Best-effort; also updates the room's in-memory set so access works
/// this session even if the file-server is unreachable.
pub async fn record_shared_with(
    cfg: &LiveDocConfig,
    client: &reqwest::Client,
    room: &DocRoom,
    cert_hash: &str,
    user_id: i64,
    display_name: &str,
) {
    room.add_member(cert_hash.to_owned()).await;
    let (Some(url), Some(token)) = (
        cfg.file_server_url.as_deref(),
        cfg.file_server_admin_token.as_deref(),
    ) else {
        return;
    };
    let filename = room.key().as_filename();
    let endpoint = format!(
        "{}/admin/documents/{}/shared-with",
        url.trim_end_matches('/'),
        filename
    );
    let payload = json!({
        "cert_hash": cert_hash,
        "user_id": user_id,
        "display_name": display_name,
    });
    if let Err(err) = client
        .put(&endpoint)
        .bearer_auth(token)
        .json(&payload)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
    {
        tracing::warn!(?err, ?filename, "live-doc record shared-with failed");
    }
}

/// Render the persisted markdown body from a snapshot + metadata.
fn render_document(snapshot: &[u8], meta: &DocMeta) -> String {
    let meta_json = serde_json::to_vec(meta).unwrap_or_default();
    format!(
        "{YJS_MARKER_PREFIX}{}{YJS_MARKER_SUFFIX}\n{META_MARKER_PREFIX}{}{META_MARKER_SUFFIX}\n",
        B64.encode(snapshot),
        B64.encode(meta_json),
    )
}

/// Extract a Yjs update blob from a markdown file body.
fn extract_snapshot(body: &str) -> Option<Vec<u8>> {
    extract_marker(body, YJS_MARKER_PREFIX, YJS_MARKER_SUFFIX).and_then(|b64| B64.decode(b64).ok())
}

/// Extract document metadata from a markdown file body.
fn extract_meta(body: &str) -> Option<DocMeta> {
    let b64 = extract_marker(body, META_MARKER_PREFIX, META_MARKER_SUFFIX)?;
    let json = B64.decode(b64).ok()?;
    serde_json::from_slice(&json).ok()
}

fn extract_marker<'a>(body: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
    let start = body.find(prefix)? + prefix.len();
    let rest = &body[start..];
    let end = rest.find(suffix)?;
    Some(rest[..end].trim())
}

async fn fetch_shared_with(
    cfg: &LiveDocConfig,
    client: &reqwest::Client,
    filename: &str,
) -> Option<Vec<SharedMember>> {
    let url = cfg.file_server_url.as_deref()?;
    let token = cfg.file_server_admin_token.as_deref()?;
    let endpoint = format!(
        "{}/admin/documents/{}/shared-with",
        url.trim_end_matches('/'),
        filename
    );
    let resp = client.get(&endpoint).bearer_auth(token).send().await.ok()?;
    let parsed: SharedWithResponse = resp.error_for_status().ok()?.json().await.ok()?;
    Some(parsed.shared_with)
}

async fn fetch_file(
    client: &reqwest::Client,
    base_url: &str,
    admin_token: Option<&str>,
    filename: &str,
) -> Result<Option<String>, reqwest::Error> {
    let Some(token) = admin_token else {
        return Ok(None);
    };
    let url = format!(
        "{}/admin/documents/{}",
        base_url.trim_end_matches('/'),
        filename
    );
    let resp = client.get(&url).bearer_auth(token).send().await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let body = resp.error_for_status()?.text().await?;
    Ok(Some(body))
}

async fn put_file(
    client: &reqwest::Client,
    base_url: &str,
    admin_token: Option<&str>,
    filename: &str,
    body: String,
) -> Result<(), reqwest::Error> {
    let Some(token) = admin_token else {
        return Ok(());
    };
    let url = format!(
        "{}/admin/documents/{}",
        base_url.trim_end_matches('/'),
        filename
    );
    let _response = client
        .put(&url)
        .bearer_auth(token)
        .header("content-type", "text/markdown")
        .body(body)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test assertions")]
    use super::*;
    use crate::doc::Visibility;

    #[test]
    fn extract_snapshot_finds_marker() {
        let body = "<!--YJS-STATE:SGVsbG8=-->\n";
        let bytes = extract_snapshot(body).unwrap();
        assert_eq!(&bytes, b"Hello");
    }

    #[test]
    fn extract_snapshot_returns_none_without_marker() {
        assert!(extract_snapshot("plain markdown body").is_none());
    }

    #[test]
    fn meta_round_trip_through_document() {
        let meta = DocMeta {
            owner_cert_hash: "abc123".into(),
            title: "Design --> Notes".into(),
            bound_channel: Some(7),
            visibility: Visibility::Published,
        };
        let body = render_document(b"snapshot-bytes", &meta);
        let extracted = extract_meta(&body).unwrap();
        assert_eq!(extracted.owner_cert_hash, "abc123");
        assert_eq!(extracted.title, "Design --> Notes");
        assert_eq!(extracted.bound_channel, Some(7));
        assert_eq!(extracted.visibility, Visibility::Published);
        // Snapshot survives alongside the metadata marker.
        assert_eq!(extract_snapshot(&body).unwrap(), b"snapshot-bytes");
    }

    // ---- persist-safety regression tests -------------------------------
    //
    // These guard the data-loss fix: a room must never flush its empty /
    // partial state over a saved document it could not load.  They spin a
    // tiny mock of the file-server admin API and assert whether a PUT
    // (overwrite) is issued.

    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};

    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use axum::routing::get;
    use axum::Router;
    use tokio::net::TcpListener;

    use crate::doc::DocKey;

    /// How the mock answers a GET for a stored document.
    #[derive(Clone)]
    enum GetMode {
        /// No such document yet (a brand-new doc).
        NotFound,
        /// The file-server is reachable but failing (transient outage).
        ServerError,
        /// An existing, parseable stored document body.
        Body(String),
    }

    struct Mock {
        get_mode: GetMode,
        put_count: AtomicUsize,
        last_put_body: StdMutex<Option<String>>,
    }

    async fn mock_get(State(m): State<Arc<Mock>>, Path(_n): Path<String>) -> Response {
        match &m.get_mode {
            GetMode::NotFound => StatusCode::NOT_FOUND.into_response(),
            GetMode::ServerError => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            GetMode::Body(b) => (StatusCode::OK, b.clone()).into_response(),
        }
    }

    async fn mock_put(State(m): State<Arc<Mock>>, Path(_n): Path<String>, body: String) -> StatusCode {
        let _ = m.put_count.fetch_add(1, Ordering::SeqCst);
        *m.last_put_body.lock().unwrap() = Some(body);
        StatusCode::OK
    }

    async fn mock_shared() -> Response {
        (StatusCode::OK, axum::Json(json!({ "shared_with": [] }))).into_response()
    }

    /// Start a mock file-server and return its base URL plus the shared
    /// mock handle for assertions.
    async fn start_mock(get_mode: GetMode) -> (String, Arc<Mock>) {
        let mock = Arc::new(Mock {
            get_mode,
            put_count: AtomicUsize::new(0),
            last_put_body: StdMutex::new(None),
        });
        let router = Router::new()
            .route("/admin/documents/{name}", get(mock_get).put(mock_put))
            .route(
                "/admin/documents/{name}/shared-with",
                get(mock_shared).put(mock_shared),
            )
            .with_state(mock.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Detach the server task; dropping the handle keeps it running.
        drop(tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        }));
        (format!("http://{addr}"), mock)
    }

    fn cfg_for(base_url: String) -> LiveDocConfig {
        LiveDocConfig {
            bind: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            public_url: None,
            jwt_secret: Some("test-secret".to_owned()),
            state_path: std::env::temp_dir(),
            max_update_bytes: 4 * 1024 * 1024,
            snapshot_idle_secs: 60,
            teardown_grace_secs: 30,
            file_server_url: Some(base_url),
            file_server_admin_token: Some("token".to_owned()),
            port: 0,
        }
    }

    fn test_room(slug: &str) -> DocRoom {
        DocRoom::new(DocKey {
            server_id: 1,
            slug: slug.to_owned(),
        })
    }

    #[tokio::test]
    async fn fresh_room_is_not_persist_safe_by_default() {
        let room = test_room("never-seeded");
        assert!(!room.is_persist_safe().await);
        room.mark_persist_safe().await;
        assert!(room.is_persist_safe().await);
    }

    #[tokio::test]
    async fn new_document_seeds_safe_and_persists() {
        let (base, mock) = start_mock(GetMode::NotFound).await;
        let cfg = cfg_for(base);
        let client = reqwest::Client::new();
        let room = test_room("brand-new");

        try_seed_room(&cfg, &client, &room).await;
        assert!(
            room.is_persist_safe().await,
            "a 404 (new doc) must mark the room safe to persist"
        );

        persist_room(&cfg, &client, &room).await;
        assert_eq!(
            mock.put_count.load(Ordering::SeqCst),
            1,
            "a new document must be written to storage"
        );
    }

    #[tokio::test]
    async fn unreachable_storage_does_not_clobber_saved_document() {
        // The reported bug: an existing doc whose content could not be
        // loaded (file-server hiccup) must NOT be overwritten with the
        // room's empty state when the connection closes.
        let (base, mock) = start_mock(GetMode::ServerError).await;
        let cfg = cfg_for(base);
        let client = reqwest::Client::new();
        let room = test_room("existing-doc");

        try_seed_room(&cfg, &client, &room).await;
        assert!(
            !room.is_persist_safe().await,
            "a failed seed must leave the room unsafe to persist"
        );

        persist_room(&cfg, &client, &room).await;
        assert_eq!(
            mock.put_count.load(Ordering::SeqCst),
            0,
            "an unseeded room must never overwrite the stored document"
        );
    }

    #[tokio::test]
    async fn existing_document_seeds_safe_and_persists_content() {
        let meta = DocMeta {
            owner_cert_hash: "owner-cert".into(),
            title: "Saved".into(),
            bound_channel: None,
            visibility: Visibility::Private,
        };
        let snapshot = test_room("seed-src").encode_snapshot().await;
        let stored = render_document(&snapshot, &meta);

        let (base, mock) = start_mock(GetMode::Body(stored)).await;
        let cfg = cfg_for(base);
        let client = reqwest::Client::new();
        let room = test_room("loaded-doc");

        try_seed_room(&cfg, &client, &room).await;
        assert!(room.is_persist_safe().await);
        assert_eq!(room.meta().await.owner_cert_hash, "owner-cert");

        persist_room(&cfg, &client, &room).await;
        assert_eq!(mock.put_count.load(Ordering::SeqCst), 1);
        let written = mock.last_put_body.lock().unwrap().clone().unwrap();
        assert!(
            written.contains(YJS_MARKER_PREFIX),
            "the flushed body must carry the CRDT snapshot marker"
        );
    }
}