//! `GET /files/{id}` - signed-URL download handler.
//!
//! For `mode=public`, the signed URL alone is enough.
//! For `mode=password` and `mode=session`, the client must additionally
//! present a single-use ticket obtained from `POST /files/{id}/auth`.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderName, HeaderValue, Response, StatusCode};
use futures_core::Stream;
use serde::Deserialize;
use tokio_util::io::ReaderStream;

use crate::http::common::ApiError;
use crate::signing;
use crate::state::AppState;
use crate::storage::{AccessMode, Storage};
use crate::tickets::ConsumeResult;

/// MIME types whose content browsers are safe to render inline.  This is
/// an explicit allow-list - in particular `image/svg+xml` is **not**
/// included because SVG can carry script, and `text/plain` is excluded
/// because of historical sniffing behaviour.
const INLINE_MIME_ALLOWLIST: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/avif",
    "audio/mpeg",
    "audio/ogg",
    "audio/wav",
    "audio/webm",
    "video/mp4",
    "video/webm",
    "video/ogg",
    "application/pdf",
];

/// Signed-URL parameters + optional ticket.
#[derive(Debug, Deserialize)]
pub struct DownloadQuery {
    /// Hex-encoded unix-seconds expiry.
    pub ex: String,
    /// Hex-encoded URL nonce.
    pub is: String,
    /// Hex-encoded HMAC prefix.
    pub hm: String,
    /// Single-use download ticket (required for non-public files).
    #[serde(default)]
    pub ticket: Option<String>,
}

/// Handler for `GET /files/{id}`.
pub async fn download(
    State(state): State<AppState>,
    Path(file_id): Path<String>,
    Query(q): Query<DownloadQuery>,
) -> Result<Response<Body>, ApiError> {
    let now = signing::now_unix_seconds();
    let _nonce = signing::verify(
        state.signing_secret.as_ref(),
        &file_id,
        &q.ex,
        &q.is,
        &q.hm,
        now,
    )
    .map_err(|e| match e {
        signing::SignatureError::Expired => ApiError::not_found("link expired"),
        _ => ApiError::forbidden("invalid signature"),
    })?;

    let record = state
        .storage
        .get(&file_id)
        .map_err(|e| ApiError::internal(format!("storage: {e}")))?
        .ok_or_else(|| ApiError::not_found("file not found"))?;

    if record.url_nonce != q.is {
        return Err(ApiError::forbidden("invalid signature"));
    }

    if record.access_mode != AccessMode::Public {
        let ticket = q.ticket.as_deref().ok_or_else(|| {
            ApiError::unauthorized("missing ticket; call POST /files/{id}/auth first")
        })?;
        match state.tickets.consume(ticket, &file_id) {
            ConsumeResult::Ok => {}
            ConsumeResult::WrongFile | ConsumeResult::NotFound => {
                return Err(ApiError::forbidden("invalid or expired ticket"));
            }
        }
    }

    stream_blob(state, record).await
}

async fn stream_blob(
    state: AppState,
    record: crate::storage::FileRecord,
) -> Result<Response<Body>, ApiError> {
    let blob_path = state.storage.blob_path(&record.id);
    let file = tokio::fs::File::open(&blob_path)
        .await
        .map_err(|_| ApiError::not_found("file blob missing"))?;

    if let Err(e) = state.storage.mark_downloaded(&record.id, now_unix_ms()) {
        tracing::warn!(error = %e, "failed to mark file as downloaded");
    }

    let delete_guard = state
        .config
        .delete_on_download
        .then(|| DeleteOnDrop::new(state.storage.clone(), record.id.clone()));

    let stream = ReaderStream::new(file);
    let body = Body::from_stream(GuardedStream::new(stream, delete_guard));

    let disposition = build_content_disposition(&record.filename, &record.mime_type);
    let mime = HeaderValue::from_str(&record.mime_type)
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));

    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CONTENT_LENGTH, record.size_bytes)
        .header(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))
        // Defense-in-depth headers (C-2): refuse MIME sniffing, deny
        // framing, and a strict CSP that forbids any active content from
        // running inside the file-server origin.  These apply equally to
        // attachment and inline downloads.
        .header(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        )
        .header(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        )
        .header(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static(
                "default-src 'none'; img-src 'self'; media-src 'self'; \
                 object-src 'none'; script-src 'none'; style-src 'none'; \
                 base-uri 'none'; frame-ancestors 'none'; sandbox;",
            ),
        )
        .header(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        )
        .header(
            HeaderName::from_static("cross-origin-resource-policy"),
            HeaderValue::from_static("same-site"),
        );
    if let Ok(disp) = HeaderValue::from_str(&disposition) {
        resp = resp.header(header::CONTENT_DISPOSITION, disp);
    }
    resp.body(body)
        .map_err(|e| ApiError::internal(format!("response build: {e}")))
}

/// Pick the disposition mode for the response.
///
/// Browser-renderable types (raster images, audio, video, PDF) are sent
/// as `inline` so that opening the link in a browser displays the file
/// instead of forcing a download.  Everything else (including SVG, HTML,
/// XML, archives) stays `attachment`.
fn is_inline_mime(mime: &str) -> bool {
    let lower = mime.to_ascii_lowercase();
    let primary = lower.split(';').next().unwrap_or("").trim();
    INLINE_MIME_ALLOWLIST.contains(&primary)
}

fn sanitize_filename(filename: &str) -> String {
    // Strip C0/C1 control bytes, the bidi-override range (which can
    // visually disguise a `.exe` as `.png`), DEL, and the few characters
    // that have special meaning in `Content-Disposition` parameter
    // values.  Anything not in this set passes through to the
    // RFC 5987 percent-encoded `filename*` form below, so legitimate
    // unicode filenames still arrive intact at the client.
    let stripped: String = filename
        .chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(c, '"' | '\\' | ';' | '/' | '\u{007F}')
                && !('\u{202A}'..='\u{202E}').contains(c)
                && !('\u{2066}'..='\u{2069}').contains(c)
        })
        .collect();
    if stripped.is_empty() {
        "file".to_owned()
    } else {
        stripped
    }
}

fn ascii_fallback(filename: &str) -> String {
    let mut out: String = filename
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() && !matches!(c, '"' | '\\' | ';') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() {
        out.push_str("file");
    }
    out
}

fn build_content_disposition(filename: &str, mime_type: &str) -> String {
    let safe = sanitize_filename(filename);
    let ascii = ascii_fallback(&safe);
    let mode = if is_inline_mime(mime_type) {
        "inline"
    } else {
        "attachment"
    };
    let encoded = percent_encode(&safe);
    format!("{mode}; filename=\"{ascii}\"; filename*=UTF-8''{encoded}")
}

/// Minimal RFC 5987 percent-encoder for `filename*=UTF-8''<value>`.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        let unreserved = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~');
        if unreserved {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Stream wrapper that owns an optional [`DeleteOnDrop`] guard.  When
/// the body is dropped (whether the client received every byte or
/// disconnected early) the guard's `Drop` impl fires the delete.  This
/// avoids the H-6 race where the blob was being unlinked while the
/// stream was still being read on Windows.
struct GuardedStream<S> {
    inner: S,
    _guard: Option<DeleteOnDrop>,
}

impl<S> GuardedStream<S> {
    fn new(inner: S, guard: Option<DeleteOnDrop>) -> Self {
        Self {
            inner,
            _guard: guard,
        }
    }
}

impl<S: Stream + Unpin> Stream for GuardedStream<S> {
    type Item = S::Item;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

struct DeleteOnDrop {
    storage: Arc<Storage>,
    file_id: String,
}

impl DeleteOnDrop {
    fn new(storage: Arc<Storage>, file_id: String) -> Self {
        Self { storage, file_id }
    }
}

impl Drop for DeleteOnDrop {
    fn drop(&mut self) {
        let storage = self.storage.clone();
        let id = std::mem::take(&mut self.file_id);
        let handle = tokio::runtime::Handle::try_current();
        match handle {
            Ok(rt) => {
                drop(rt.spawn_blocking(move || {
                    if let Err(e) = storage.delete(&id) {
                        tracing::warn!(error = %e, "delete-on-download cleanup failed");
                    }
                }));
            }
            Err(_) => {
                if let Err(e) = storage.delete(&id) {
                    tracing::warn!(error = %e, "delete-on-download cleanup failed");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        reason = "tests panic on failure"
    )]
    use super::*;

    #[test]
    fn content_disposition_strips_quotes() {
        let d = build_content_disposition(r#"foo"bar.txt"#, "application/octet-stream");
        assert!(d.starts_with("attachment; filename=\"foobar.txt\""));
        assert!(d.contains("filename*=UTF-8''foobar.txt"));
    }

    #[test]
    fn content_disposition_strips_newlines_and_controls() {
        let d = build_content_disposition("a\nb\rc\0d.bin", "application/octet-stream");
        assert!(d.contains("filename=\"abcd.bin\""));
    }

    #[test]
    fn content_disposition_strips_bidi_override() {
        // U+202E RIGHT-TO-LEFT OVERRIDE is a classic spoofing trick
        // (e.g. "exe.png" rendered as "png.exe"). Must be removed.
        let evil = "photo\u{202E}gnp.exe";
        let d = build_content_disposition(evil, "application/octet-stream");
        assert!(!d.contains('\u{202E}'));
    }

    #[test]
    fn content_disposition_uses_inline_for_raster_images() {
        let d = build_content_disposition("photo.png", "image/png");
        assert!(d.starts_with("inline;"));
    }

    #[test]
    fn content_disposition_does_not_inline_svg() {
        // SVG can carry script - must stay attachment to avoid stored XSS.
        let d = build_content_disposition("evil.svg", "image/svg+xml");
        assert!(d.starts_with("attachment;"));
    }

    #[test]
    fn content_disposition_does_not_inline_text_plain() {
        // text/plain is excluded because of MIME sniffing concerns.
        let d = build_content_disposition("a.txt", "text/plain; charset=utf-8");
        assert!(d.starts_with("attachment;"));
    }

    #[test]
    fn content_disposition_uses_inline_for_video_audio_pdf() {
        assert!(build_content_disposition("a.mp4", "video/mp4").starts_with("inline;"));
        assert!(build_content_disposition("a.mp3", "audio/mpeg").starts_with("inline;"));
        assert!(build_content_disposition("a.pdf", "application/pdf").starts_with("inline;"));
    }

    #[test]
    fn content_disposition_keeps_attachment_for_archives_and_html() {
        assert!(build_content_disposition("data.zip", "application/zip").starts_with("attachment;"));
        assert!(build_content_disposition("page.html", "text/html").starts_with("attachment;"));
        assert!(build_content_disposition("page.xml", "application/xml").starts_with("attachment;"));
    }

    #[test]
    fn percent_encode_escapes_non_unreserved() {
        assert_eq!(percent_encode("foo bar"), "foo%20bar");
        assert_eq!(percent_encode("a/b"), "a%2Fb");
        assert_eq!(percent_encode("hi.txt"), "hi.txt");
    }

    #[test]
    fn empty_filename_falls_back_to_file() {
        assert_eq!(sanitize_filename(""), "file");
        assert_eq!(ascii_fallback(""), "file");
    }
}
