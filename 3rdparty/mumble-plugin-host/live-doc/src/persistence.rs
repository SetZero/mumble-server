//! File-server-backed persistence for live documents.
//!
//! Each document is stored as a single markdown file on the
//! `file-server` plugin, keyed by [`crate::doc::DocKey::as_filename`].
//! The canonical state is the Yjs CRDT update blob - it is appended
//! to the markdown as a base64-encoded HTML comment
//! (`<!--YJS-STATE:...-->`) so a human opening the file still sees
//! the rendered markdown, but the room can be rehydrated losslessly
//! on next open.
//!
//! TODO(revisions): when the file-server gains a revision endpoint,
//! switch [`persist_room`] from PUT-overwrite to "append revision".

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use crate::config::LiveDocConfig;
use crate::doc::DocRoom;

/// Marker that wraps the binary CRDT state inside a markdown file
/// so the file remains valid markdown but is also losslessly
/// rehydratable by the plugin.
const YJS_MARKER_PREFIX: &str = "<!--YJS-STATE:";
const YJS_MARKER_SUFFIX: &str = "-->";

/// Returns `Some((url, token))` only when persistence is **fully**
/// configured.  A half-configured setup (URL without token, or vice
/// versa) is a misconfiguration the operator almost certainly didn't
/// intend, so it is reported loudly rather than silently skipped.
fn persistence_target(cfg: &LiveDocConfig) -> Option<(&str, &str)> {
    match (
        cfg.file_server_url.as_deref(),
        cfg.file_server_admin_token.as_deref(),
    ) {
        (Some(url), Some(token)) => Some((url, token)),
        (Some(_), None) => {
            tracing::error!(
                "live-doc persistence is HALF-configured: \
                 plugin.fancy-live-doc.file_server_url is set but \
                 plugin.fancy-live-doc.file_server_admin_token is missing - documents will \
                 NOT be saved. Set the token to match the file server's admin_token."
            );
            None
        }
        (None, Some(_)) => {
            tracing::error!(
                "live-doc persistence is HALF-configured: \
                 plugin.fancy-live-doc.file_server_admin_token is set but \
                 plugin.fancy-live-doc.file_server_url is missing - documents will NOT be saved."
            );
            None
        }
        // Fully unconfigured: persistence is intentionally disabled. The
        // operator is warned once at startup (see `warn_if_persistence_disabled`),
        // so per-room paths stay quiet to avoid log spam.
        (None, None) => None,
    }
}

/// Log a single, prominent warning at plugin start-up when document
/// persistence is not configured, so a "my doc vanished" surprise is
/// never a silent surprise.
pub fn warn_if_persistence_disabled(cfg: &LiveDocConfig) {
    if cfg.file_server_url.is_none() && cfg.file_server_admin_token.is_none() {
        tracing::warn!(
            "live-doc persistence is DISABLED: neither \
             plugin.fancy-live-doc.file_server_url nor \
             plugin.fancy-live-doc.file_server_admin_token is set. Documents will live only in \
             memory and are LOST when the room is torn down. Set both keys (the token must match \
             plugin.fancy-file-server.admin_token) to persist documents to the file server."
        );
    }
}

/// Try to seed a freshly-created room from the file-server, if a
/// previous snapshot exists.  A missing snapshot is a normal "first
/// open" condition; a *fetch failure* on a configured store is loud
/// because it means a saved document silently opened blank.
pub async fn try_seed_room(cfg: &LiveDocConfig, client: &reqwest::Client, room: &DocRoom) {
    let Some((url, token)) = persistence_target(cfg) else {
        return;
    };
    let filename = room.key().as_filename();
    match fetch_file(client, url, token, &filename).await {
        Ok(Some(contents)) => {
            if let Some(snapshot) = extract_snapshot(&contents) {
                if let Err(err) = room.seed_from_snapshot(&snapshot).await {
                    tracing::error!(
                        ?err,
                        %filename,
                        "live-doc seed FAILED - room opened EMPTY despite a saved revision"
                    );
                }
            }
        }
        Ok(None) => {}
        Err(err) => {
            tracing::error!(
                ?err,
                %filename,
                "live-doc seed fetch FAILED - room opened EMPTY; previously saved content not loaded"
            );
        }
    }
}

/// Persist the current state of a room to the file-server.
///
/// Persistence is best-effort and must not block teardown, but a
/// failure is **always** surfaced at `error` level so a lost save is
/// never silent.
/// `owner` is `(display_name, cert_hash)` of the document's creator, recorded
/// by the file server only on the first revision.
pub async fn persist_room(
    cfg: &LiveDocConfig,
    client: &reqwest::Client,
    room: &DocRoom,
    owner: Option<(&str, &str)>,
) {
    let Some((url, token)) = persistence_target(cfg) else {
        return;
    };
    let filename = room.key().as_filename();
    let snapshot = room.encode_snapshot().await;
    if snapshot.is_empty() {
        return;
    }

    // For the first cut we only persist the Yjs blob.  When the
    // markdown export is wired through the client, the body will be
    // included alongside the marker so the file is human-readable.
    let body = format!(
        "{YJS_MARKER_PREFIX}{}{YJS_MARKER_SUFFIX}\n",
        B64.encode(&snapshot),
    );

    match put_file(client, url, token, &filename, body, owner).await {
        Ok(()) => tracing::debug!(%filename, "live-doc document persisted"),
        Err(err) => tracing::error!(
            ?err,
            %filename,
            "live-doc persist FAILED - document changes were NOT saved to the file server"
        ),
    }
}

/// Extract a Yjs update blob from a markdown file body, if the file
/// contains the `<!--YJS-STATE:...-->` marker.
fn extract_snapshot(body: &str) -> Option<Vec<u8>> {
    let start = body.find(YJS_MARKER_PREFIX)? + YJS_MARKER_PREFIX.len();
    let rest = &body[start..];
    let end = rest.find(YJS_MARKER_SUFFIX)?;
    let b64 = rest[..end].trim();
    B64.decode(b64).ok()
}

async fn fetch_file(
    client: &reqwest::Client,
    base_url: &str,
    token: &str,
    filename: &str,
) -> Result<Option<String>, reqwest::Error> {
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
    token: &str,
    filename: &str,
    body: String,
    owner: Option<(&str, &str)>,
) -> Result<(), reqwest::Error> {
    let url = format!(
        "{}/admin/documents/{}",
        base_url.trim_end_matches('/'),
        filename
    );
    let mut req = client
        .put(&url)
        .bearer_auth(token)
        .header("content-type", "text/markdown");
    if let Some((name, cert)) = owner {
        // The display name may contain non-ASCII bytes, which are not valid in
        // an HTTP header value; base64 it so the header is always well-formed.
        req = req
            .header("x-doc-owner-name", B64.encode(name))
            .header("x-doc-owner-cert", cert);
    }
    let _response = req.body(body).send().await?.error_for_status()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test assertions")]
    use super::*;

    #[test]
    fn extract_snapshot_finds_marker() {
        let body = "# title\n\n<!--YJS-STATE:SGVsbG8=-->\n";
        let bytes = extract_snapshot(body).unwrap();
        assert_eq!(&bytes, b"Hello");
    }

    #[test]
    fn extract_snapshot_returns_none_without_marker() {
        assert!(extract_snapshot("plain markdown body").is_none());
    }
}
