//! Shared, size-capped HTTP GET used by every provider and the media
//! downscaler. Re-checks [`ssrf::is_safe_url`] before issuing the request,
//! honours a declared `Content-Length` cap, and aborts mid-stream if the body
//! overruns `max_bytes` (mirrors the C++ streaming size guards).

use futures_util::StreamExt as _;
use url::Url;

use crate::ssrf;

/// Why a capped fetch failed. All variants degrade gracefully to "no preview".
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// URL rejected by the SSRF pre-filter (scheme/host).
    #[error("unsafe url")]
    Unsafe,
    /// Non-2xx HTTP status.
    #[error("http status {0}")]
    Status(u16),
    /// Body exceeded the configured cap (declared or streamed).
    #[error("body exceeds {0} bytes")]
    TooLarge(usize),
    /// Transport/DNS/SSRF-resolver error.
    #[error("request failed: {0}")]
    Request(String),
}

/// A successfully fetched, size-bounded body.
#[derive(Debug)]
pub struct FetchedBody {
    /// Raw response bytes (<= the cap).
    pub bytes: Vec<u8>,
    /// Lower-cased-trimmed MIME (no parameters), if the server sent one.
    pub content_type: Option<String>,
}

/// GET `url` with `Accept: accept`, returning at most `max_bytes` of body.
pub async fn fetch_capped(
    client: &reqwest::Client,
    url: &Url,
    accept: &str,
    max_bytes: usize,
) -> Result<FetchedBody, FetchError> {
    if !ssrf::is_safe_url(url) {
        return Err(FetchError::Unsafe);
    }

    let resp = client
        .get(url.clone())
        .header(reqwest::header::ACCEPT, accept)
        .send()
        .await
        .map_err(|e| FetchError::Request(e.to_string()))?;

    let status = resp.status();
    if !status.is_success() {
        return Err(FetchError::Status(status.as_u16()));
    }

    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(';').next().unwrap_or("").trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());

    if let Some(len) = resp.content_length() {
        if len as usize > max_bytes {
            return Err(FetchError::TooLarge(max_bytes));
        }
    }

    let mut bytes: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| FetchError::Request(e.to_string()))?;
        if bytes.len() + chunk.len() > max_bytes {
            return Err(FetchError::TooLarge(max_bytes));
        }
        bytes.extend_from_slice(&chunk);
    }

    Ok(FetchedBody {
        bytes,
        content_type,
    })
}

/// Convenience: fetch a capped body and decode it as UTF-8 (lossy), for HTML /
/// JSON providers.
pub async fn fetch_text_capped(
    client: &reqwest::Client,
    url: &Url,
    accept: &str,
    max_bytes: usize,
) -> Result<String, FetchError> {
    let body = fetch_capped(client, url, accept, max_bytes).await?;
    Ok(String::from_utf8_lossy(&body.bytes).into_owned())
}
