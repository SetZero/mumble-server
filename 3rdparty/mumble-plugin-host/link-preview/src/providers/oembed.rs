//! oEmbed provider (priority between direct-media and `OpenGraph`). A static table
//! of known providers maps a URL regex to an oEmbed endpoint; the JSON response
//! is normalised to the embed contract. Port of `OEmbedPlugin.cpp` +
//! `LinkPreviewManager::initDefaultPlugins`.

use std::sync::LazyLock;

use regex::Regex;
use url::Url;

use crate::embed::{Embed, Media, NamedLink};
use crate::fetch::fetch_text_capped;
use crate::providers::opengraph::MAX_RESPONSE_BYTES;
use crate::ssrf::{decode_html_entities, is_safe_url};

/// A known oEmbed provider.
pub struct Provider {
    /// Human-readable provider name (for logs).
    pub name: &'static str,
    pattern: Regex,
    endpoint: &'static str,
    /// Optional URL rewrite for the `OpenGraph` enrichment fallback (e.g. Reddit
    /// www -> old, which serves SSR HTML with og: tags).
    og_url_transform: Option<fn(&Url) -> Url>,
}

impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Provider").field("name", &self.name).finish_non_exhaustive()
    }
}

impl Provider {
    #[allow(
        clippy::expect_used,
        reason = "only called with hardcoded regex literals in the static PROVIDERS table below"
    )]
    fn new(name: &'static str, pattern: &str, endpoint: &'static str) -> Self {
        Self {
            name,
            pattern: Regex::new(pattern).expect("static provider regex compiles"),
            endpoint,
            og_url_transform: None,
        }
    }
    fn with_transform(mut self, t: fn(&Url) -> Url) -> Self {
        self.og_url_transform = Some(t);
        self
    }
}

fn reddit_to_old(url: &Url) -> Url {
    let mut u = url.clone();
    let _ = u.set_host(Some("old.reddit.com"));
    u
}

/// The provider table (order/patterns mirror `initDefaultPlugins`).
static PROVIDERS: LazyLock<Vec<Provider>> = LazyLock::new(|| {
    vec![
        Provider::new("YouTube", r"(?i)https?://(?:www\.)?youtube\.com/(?:watch|shorts/)", "https://www.youtube.com/oembed"),
        Provider::new("YouTube Short", r"(?i)https?://youtu\.be/", "https://www.youtube.com/oembed"),
        Provider::new("Vimeo", r"(?i)https?://(?:www\.)?vimeo\.com/\d+", "https://vimeo.com/api/oembed.json"),
        Provider::new("Twitter/X", r"(?i)https?://(?:www\.)?(twitter|x)\.com/.+/status/", "https://publish.twitter.com/oembed"),
        Provider::new("Spotify", r"(?i)https?://open\.spotify\.com/", "https://open.spotify.com/oembed"),
        Provider::new("SoundCloud", r"(?i)https?://soundcloud\.com/", "https://soundcloud.com/oembed"),
        Provider::new("Twitch", r"(?i)https?://(?:www|clips)\.twitch\.tv/", "https://api.twitch.tv/v5/oembed"),
        Provider::new("TikTok", r"(?i)https?://(?:www\.)?tiktok\.com/", "https://www.tiktok.com/oembed"),
        Provider::new("Reddit", r"(?i)https?://(?:www\.)?reddit\.com/r/", "https://www.reddit.com/oembed")
            .with_transform(reddit_to_old),
        Provider::new("Dailymotion", r"(?i)https?://(?:www\.)?dailymotion\.com/video/", "https://www.dailymotion.com/services/oembed"),
        Provider::new("Dailymotion Short", r"(?i)https?://dai\.ly/", "https://www.dailymotion.com/services/oembed"),
    ]
});

/// First provider whose pattern matches `url`, if any.
#[must_use]
pub fn match_provider(url: &Url) -> Option<&'static Provider> {
    let s = url.as_str();
    PROVIDERS.iter().find(|p| p.pattern.is_match(s))
}

/// Apply the matching provider's OG-fallback URL rewrite (identity if none).
#[must_use]
pub fn transform_for_og(url: &Url) -> Url {
    match match_provider(url).and_then(|p| p.og_url_transform) {
        Some(t) => t(url),
        None => url.clone(),
    }
}

/// Fetch and normalise the oEmbed metadata for `url` via `provider`.
pub async fn fetch_preview(client: &reqwest::Client, provider: &Provider, url: &Url) -> Option<Embed> {
    let mut endpoint = Url::parse(provider.endpoint).ok()?;
    let _ = endpoint
        .query_pairs_mut()
        .append_pair("url", url.as_str())
        .append_pair("format", "json")
        .append_pair("maxwidth", "512")
        .append_pair("maxheight", "512");

    let text = match fetch_text_capped(client, &endpoint, "application/json", MAX_RESPONSE_BYTES).await {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!(provider = provider.name, error = %e, "oembed fetch failed");
            return None;
        }
    };
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;
    oembed_to_embed(json.as_object()?, url)
}

fn oembed_to_embed(o: &serde_json::Map<String, serde_json::Value>, original: &Url) -> Option<Embed> {
    let s = |k: &str| o.get(k).and_then(serde_json::Value::as_str).filter(|v| !v.is_empty());
    let i = |k: &str| o.get(k).and_then(serde_json::Value::as_i64).and_then(|n| i32::try_from(n).ok());

    let mut embed = Embed {
        url: Some(original.to_string()),
        ..Embed::default()
    };
    embed.title = s("title").map(|t| t.chars().take(256).collect());

    if let Some(name) = s("provider_name") {
        embed.provider = Some(NamedLink {
            name: Some(name.to_owned()),
            url: s("provider_url").map(str::to_owned),
        });
        embed.site_name = Some(name.to_owned());
    }
    if let Some(name) = s("author_name") {
        embed.author = Some(NamedLink {
            name: Some(name.to_owned()),
            url: s("author_url").map(str::to_owned),
        });
    }
    if let Some(turl) = s("thumbnail_url") {
        let mut thumb = Media::from_url(turl);
        thumb.width = i("thumbnail_width").filter(|w| *w > 0);
        thumb.height = i("thumbnail_height").filter(|h| *h > 0);
        embed.thumbnail = Some(thumb);
    }

    match s("type").map(str::to_ascii_lowercase).as_deref() {
        Some("video" | "rich") => {
            embed.kind = Some("video".to_owned());
            if let Some(src) = s("html").and_then(extract_iframe_src) {
                let mut vid = Media::from_url(src);
                vid.width = i("width").filter(|w| *w > 0);
                vid.height = i("height").filter(|h| *h > 0);
                embed.video = Some(vid);
            }
        }
        Some("photo") => {
            embed.kind = Some("image".to_owned());
            if let Some(purl) = s("url") {
                let mut img = Media::from_url(purl);
                img.width = i("width").filter(|w| *w > 0);
                img.height = i("height").filter(|h| *h > 0);
                embed.image = Some(img);
            }
        }
        _ => embed.kind = Some("link".to_owned()),
    }

    Some(embed)
}

#[allow(clippy::expect_used, reason = "hardcoded regex literal, cannot fail to compile")]
static IFRAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)<iframe[^>]+src\s*=\s*"([^"]+)""#).expect("iframe regex"));

fn extract_iframe_src(html: &str) -> Option<String> {
    let raw = IFRAME_RE.captures(html).and_then(|c| c.get(1))?;
    let src = decode_html_entities(raw.as_str());
    let parsed = Url::parse(&src).ok()?;
    is_safe_url(&parsed).then_some(src)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, reason = "tests panic on failure")]
    use super::*;

    #[test]
    fn matches_known_providers() {
        assert_eq!(
            match_provider(&Url::parse("https://www.youtube.com/watch?v=abc").unwrap()).map(|p| p.name),
            Some("YouTube")
        );
        assert_eq!(
            match_provider(&Url::parse("https://youtu.be/abc").unwrap()).map(|p| p.name),
            Some("YouTube Short")
        );
        assert!(match_provider(&Url::parse("https://example.com/x").unwrap()).is_none());
    }

    #[test]
    fn reddit_og_transform() {
        let out = transform_for_og(&Url::parse("https://www.reddit.com/r/rust/comments/1").unwrap());
        assert_eq!(out.host_str(), Some("old.reddit.com"));
        // Non-reddit URLs pass through unchanged.
        let same = transform_for_og(&Url::parse("https://example.com/x").unwrap());
        assert_eq!(same.host_str(), Some("example.com"));
    }

    #[test]
    fn normalises_video_oembed() {
        let json = serde_json::json!({
            "type": "video",
            "title": "Clip",
            "provider_name": "YouTube",
            "provider_url": "https://youtube.com",
            "author_name": "Chan",
            "thumbnail_url": "https://i.ytimg.com/t.jpg",
            "thumbnail_width": 480,
            "thumbnail_height": 360,
            "html": "<iframe src=\"https://www.youtube.com/embed/abc\" width=\"560\" height=\"315\"></iframe>",
            "width": 560,
            "height": 315
        });
        let e = oembed_to_embed(json.as_object().unwrap(), &Url::parse("https://youtu.be/abc").unwrap())
            .expect("embed");
        assert_eq!(e.kind.as_deref(), Some("video"));
        assert_eq!(e.title.as_deref(), Some("Clip"));
        assert_eq!(e.site_name.as_deref(), Some("YouTube"));
        assert_eq!(e.thumbnail.as_ref().and_then(|m| m.width), Some(480));
        assert_eq!(
            e.video.as_ref().and_then(|m| m.url.as_deref()),
            Some("https://www.youtube.com/embed/abc")
        );
    }
}
