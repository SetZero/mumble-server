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

/// Try to seed a freshly-created room from the file-server, if a
/// previous snapshot exists.  Failure is logged and ignored - a
/// missing snapshot is a normal "first open" condition.
pub async fn try_seed_room(cfg: &LiveDocConfig, client: &reqwest::Client, room: &DocRoom) {
    let Some(url) = cfg.file_server_url.as_deref() else {
        return;
    };
    let filename = room.key().as_filename();
    match fetch_file(
        client,
        url,
        cfg.file_server_admin_token.as_deref(),
        &filename,
    )
    .await
    {
        Ok(Some(contents)) => {
            if let Some(snapshot) = extract_snapshot(&contents) {
                if let Err(err) = room.seed_from_snapshot(&snapshot).await {
                    tracing::warn!(?err, ?filename, "live-doc seed failed");
                }
            }
        }
        Ok(None) => {}
        Err(err) => {
            tracing::warn!(?err, ?filename, "live-doc seed fetch failed");
        }
    }
}

/// Persist the current state of a room to the file-server.
///
/// Returns silently on any failure - persistence is best-effort and
/// must not block teardown.
pub async fn persist_room(cfg: &LiveDocConfig, client: &reqwest::Client, room: &DocRoom) {
    let Some(url) = cfg.file_server_url.as_deref() else {
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

    if let Err(err) = put_file(
        client,
        url,
        cfg.file_server_admin_token.as_deref(),
        &filename,
        body,
    )
    .await
    {
        tracing::warn!(?err, ?filename, "live-doc persist failed");
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
