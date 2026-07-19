//! Orchestration: validate + rate-limit a request, run each URL through the
//! provider chain (direct-media -> oEmbed -> `OpenGraph`), enrich with an
//! `OpenGraph` description fallback and server-side downscaled media previews,
//! cache raw provider results, and assemble the response. Port of
//! `LinkPreviewManager.cpp`.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine as _;
use url::Url;

use crate::embed::{Embed, Media, PreviewResponse};
use crate::media_preview::{fetch_and_downscale, DEFAULT_MAX_DIM, FAVICON_MAX_DIM, JPEG_QUALITY};
use crate::providers::{direct_media, oembed, opengraph};
use crate::ssrf::{build_http_client, is_safe_url};

const MAX_URLS_PER_REQUEST: usize = 5;
const MAX_CONCURRENT_FETCHES: usize = 20;
const CACHE_TTL: Duration = Duration::from_secs(3600);
const MAX_CACHE_ENTRIES: usize = 2000;
const MAX_REQUESTS_PER_MIN: usize = 10;
const RATE_WINDOW: Duration = Duration::from_secs(60);
const FETCH_TIMEOUT: Duration = Duration::from_secs(20);

struct CacheEntry {
    embed: Embed,
    fetched_at: Instant,
}

/// Owns the HTTP client, cache, rate-limiter and concurrency limiter. Shared
/// (behind `Arc`) across the plugin's async tasks.
#[derive(Debug)]
pub struct Manager {
    client: reqwest::Client,
    sem: tokio::sync::Semaphore,
    cache: Mutex<HashMap<String, CacheEntry>>,
    rate: Mutex<HashMap<u32, Vec<Instant>>>,
}

impl std::fmt::Debug for CacheEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheEntry").finish_non_exhaustive()
    }
}

impl Default for Manager {
    fn default() -> Self {
        Self::new()
    }
}

impl Manager {
    /// Build a manager with the SSRF-gated client and default limits.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: build_http_client(FETCH_TIMEOUT),
            sem: tokio::sync::Semaphore::new(MAX_CONCURRENT_FETCHES),
            cache: Mutex::new(HashMap::new()),
            rate: Mutex::new(HashMap::new()),
        }
    }

    /// Handle one client request: returns the resolved embeds (empty when
    /// rate-limited or no URL was usable, mirroring the C++ empty response).
    pub async fn handle_request(&self, session: u32, urls: &[String]) -> PreviewResponse {
        if self.is_rate_limited(session) {
            tracing::warn!(session, "link-preview: rate limited");
            return PreviewResponse::default();
        }
        let valid = validate_urls(urls);
        if valid.is_empty() {
            return PreviewResponse::default();
        }
        let results =
            futures_util::future::join_all(valid.iter().map(|u| self.resolve_url(u))).await;
        PreviewResponse {
            embeds: results.into_iter().flatten().collect(),
        }
    }

    /// Resolve a single URL: cache or provider chain, then enrich. A global
    /// permit caps total in-flight resolutions.
    async fn resolve_url(&self, url: &Url) -> Option<Embed> {
        let _permit = self.sem.acquire().await.ok()?;

        let mut embed = match self.cache_get(url) {
            Some(e) => e,
            None => {
                let fetched = fetch_via_chain(&self.client, url).await?;
                self.cache_put(url, fetched.clone());
                fetched
            }
        };

        // Secondary OpenGraph fetch when the provider produced no description
        // (the OG URL may be rewritten, e.g. Reddit www -> old).
        if embed.needs_og_enrichment() && is_safe_url(url) {
            let og_url = oembed::transform_for_og(url);
            if let Some(og) = opengraph::fetch_preview(&self.client, &og_url).await {
                merge_og(&mut embed, og);
            }
        }

        self.enrich_media(&mut embed.image, DEFAULT_MAX_DIM).await;
        self.enrich_media(&mut embed.thumbnail, DEFAULT_MAX_DIM)
            .await;
        self.enrich_media(&mut embed.favicon, FAVICON_MAX_DIM).await;
        Some(embed)
    }

    /// Download + inline a downscaled preview for one media slot, in place, when
    /// it has a safe URL and no preview yet (mirrors `enrichEmbedWithPreviews`).
    async fn enrich_media(&self, media: &mut Option<Media>, max_dim: u32) {
        let Some(m) = media.as_mut() else {
            return;
        };
        if m.has_preview() {
            return;
        }
        let Some(url) = m.url.as_deref().and_then(|u| Url::parse(u).ok()) else {
            return;
        };
        if !is_safe_url(&url) {
            return;
        }
        if let Some(res) = fetch_and_downscale(&self.client, &url, max_dim, JPEG_QUALITY).await {
            m.preview_data_b64 = Some(base64::engine::general_purpose::STANDARD.encode(&res.jpeg));
            m.preview_mime = Some(res.mime);
            m.preview_width = Some(res.preview_width);
            m.preview_height = Some(res.preview_height);
            m.original_size = Some(res.original_size);
            if m.width.is_none() && res.original_width > 0 {
                m.width = Some(res.original_width);
            }
            if m.height.is_none() && res.original_height > 0 {
                m.height = Some(res.original_height);
            }
        }
    }

    fn is_rate_limited(&self, session: u32) -> bool {
        let now = Instant::now();
        let mut map = lock(&self.rate);
        let ts = map.entry(session).or_default();
        ts.retain(|t| now.duration_since(*t) <= RATE_WINDOW);
        if ts.len() >= MAX_REQUESTS_PER_MIN {
            return true;
        }
        ts.push(now);
        false
    }

    fn cache_get(&self, url: &Url) -> Option<Embed> {
        let mut map = lock(&self.cache);
        let key = url.as_str();
        if let Some(e) = map.get(key) {
            if e.fetched_at.elapsed() < CACHE_TTL {
                return Some(e.embed.clone());
            }
            let _ = map.remove(key);
        }
        None
    }

    fn cache_put(&self, url: &Url, embed: Embed) {
        let mut map = lock(&self.cache);
        if map.len() >= MAX_CACHE_ENTRIES {
            if let Some(oldest) = map
                .iter()
                .min_by_key(|(_, e)| e.fetched_at)
                .map(|(k, _)| k.clone())
            {
                let _ = map.remove(&oldest);
            }
        }
        let _ = map.insert(
            url.as_str().to_owned(),
            CacheEntry {
                embed,
                fetched_at: Instant::now(),
            },
        );
    }
}

/// Provider chain in priority order: direct-media (5) -> oEmbed (10) ->
/// `OpenGraph` (1000). First success wins.
async fn fetch_via_chain(client: &reqwest::Client, url: &Url) -> Option<Embed> {
    if direct_media::can_handle(url) {
        if let Some(e) = direct_media::fetch_preview(client, url).await {
            return Some(e);
        }
    }
    if let Some(provider) = oembed::match_provider(url) {
        if let Some(e) = oembed::fetch_preview(client, provider, url).await {
            return Some(e);
        }
    }
    opengraph::fetch_preview(client, url).await
}

/// Fill empty fields of `target` from an `OpenGraph` `og` embed (mirrors
/// `LinkPreviewManager::mergeOgIntoTarget`).
fn merge_og(target: &mut Embed, og: Embed) {
    fn fill(t: &mut Option<String>, s: Option<String>) {
        if t.as_deref().unwrap_or("").is_empty() {
            if let Some(v) = s.filter(|v| !v.is_empty()) {
                *t = Some(v);
            }
        }
    }
    fill(&mut target.description, og.description);
    fill(&mut target.summary, og.summary);
    fill(&mut target.site_name, og.site_name);
    fill(&mut target.canonical_url, og.canonical_url);
    fill(&mut target.lang, og.lang);
    fill(&mut target.published_time, og.published_time);
    fill(&mut target.modified_time, og.modified_time);
    fill(&mut target.reading_time, og.reading_time);
    fill(&mut target.content_type, og.content_type);
    if target.image.is_none() {
        target.image = og.image;
    }
    if target.thumbnail.is_none() {
        target.thumbnail = og.thumbnail;
    }
    if target.author.is_none() {
        target.author = og.author;
    }
    if target.favicon.is_none() {
        target.favicon = og.favicon;
    }
    if target.keywords.is_empty() {
        target.keywords = og.keywords;
    }
}

fn validate_urls(urls: &[String]) -> Vec<Url> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for raw in urls.iter().take(MAX_URLS_PER_REQUEST) {
        let Ok(url) = Url::parse(raw) else { continue };
        if url.host_str().unwrap_or("").is_empty() || !is_safe_url(&url) {
            continue;
        }
        let mut canonical = url.clone();
        canonical.set_fragment(None);
        if seen.insert(canonical.to_string()) {
            out.push(url);
        }
    }
    out
}

/// Lock a mutex, recovering the guard on poison (a panicked preview task must
/// not wedge the whole plugin).
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_filters_unsafe_and_dedups() {
        let urls = vec![
            "https://example.com/a#frag".to_owned(),
            "https://example.com/a".to_owned(), // dup of above (fragment-insensitive)
            "http://127.0.0.1/x".to_owned(),    // unsafe
            "not a url".to_owned(),             // invalid
            "https://example.org/b".to_owned(),
        ];
        let valid = validate_urls(&urls);
        let strs: Vec<_> = valid.iter().map(Url::as_str).collect();
        assert_eq!(
            strs,
            vec!["https://example.com/a#frag", "https://example.org/b"]
        );
    }

    #[test]
    fn validate_caps_at_five() {
        let urls: Vec<String> = (0..10)
            .map(|i| format!("https://example.com/{i}"))
            .collect();
        assert_eq!(validate_urls(&urls).len(), 5);
    }

    #[test]
    fn rate_limiter_trips_after_threshold() {
        let m = Manager::new();
        for _ in 0..MAX_REQUESTS_PER_MIN {
            assert!(!m.is_rate_limited(1));
        }
        assert!(m.is_rate_limited(1));
        // A different session is unaffected.
        assert!(!m.is_rate_limited(2));
    }

    #[test]
    fn merge_og_fills_only_empty() {
        let mut target = Embed {
            title: Some("keep".to_owned()),
            ..Embed::default()
        };
        let og = Embed {
            title: Some("ignored".to_owned()),
            description: Some("from og".to_owned()),
            keywords: vec!["k".to_owned()],
            ..Embed::default()
        };
        merge_og(&mut target, og);
        assert_eq!(target.title.as_deref(), Some("keep"));
        assert_eq!(target.description.as_deref(), Some("from og"));
        assert_eq!(target.keywords, vec!["k"]);
    }
}
