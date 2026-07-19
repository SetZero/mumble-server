//! `OpenGraph` / HTML metadata provider.
//!
//! Parsing is delegated to the [`webpage`] crate (HTML5 parser); we only fetch
//! the page ourselves through the SSRF-gated client and map `webpage`'s parsed
//! metadata onto the server's [`Embed`] contract. Summary and reading-time are
//! light text heuristics over the extracted body text.

use std::collections::HashMap;

use url::Url;
use webpage::HTML;

use crate::embed::{Embed, Media, NamedLink};
use crate::fetch::fetch_text_capped;
use crate::ssrf::is_safe_url;

/// Cap on HTML bytes parsed (mirrors `LinkPreviewPlugin::MAX_RESPONSE_BYTES`).
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

const ACCEPT_HTML: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

/// Fetch a page and extract an [`Embed`]. `None` when no title could be found.
pub async fn fetch_preview(client: &reqwest::Client, url: &Url) -> Option<Embed> {
    let html = match fetch_text_capped(client, url, ACCEPT_HTML, MAX_RESPONSE_BYTES).await {
        Ok(h) => h,
        Err(e) => {
            tracing::debug!(%url, error = %e, "opengraph: fetch failed");
            return None;
        }
    };
    let parsed = HTML::from_string(html, Some(url.to_string())).ok()?;
    let embed = build_embed(&parsed, url);
    if embed.title.as_deref().unwrap_or("").is_empty() {
        return None;
    }
    Some(embed)
}

/// Build an [`Embed`] from already-parsed HTML. Public for unit tests.
#[must_use]
pub fn build_embed(html: &HTML, url: &Url) -> Embed {
    let meta = &html.meta;

    let mut embed = Embed {
        url: Some(url.to_string()),
        fetched_at: Some(now_iso8601()),
        ..Embed::default()
    };

    // Title / description / language come from webpage's convenience fields
    // (which already prefer og:* over <title>/<meta name=description>).
    embed.title = html
        .title
        .as_deref()
        .filter(|t| !t.is_empty())
        .or_else(|| og(html, &["og:title", "twitter:title"]))
        .map(|t| take_chars(t, 256));
    embed.description = html
        .description
        .as_deref()
        .filter(|d| !d.is_empty())
        .or_else(|| og(html, &["og:description", "twitter:description", "description"]))
        .map(|d| take_chars(d, 4096));
    embed.lang = html
        .language
        .as_deref()
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .or_else(|| og(html, &["og:locale"]).map(str::to_owned));

    embed.site_name = Some(og(html, &["og:site_name"]).map_or_else(
        || {
            let host = url.host_str().unwrap_or("");
            host.strip_prefix("www.").unwrap_or(host).to_owned()
        },
        str::to_owned,
    ));

    if let Some(theme) = meta_get(meta, &["theme-color"]) {
        let hex = theme.strip_prefix('#').unwrap_or(theme);
        if let Ok(color) = i32::from_str_radix(hex, 16) {
            embed.color = Some(color);
        }
    }

    populate_media(&mut embed, html, url);
    classify_type(&mut embed, html, meta);

    if let Some(author) = meta_get(meta, &["article:author", "author"]) {
        embed.author = Some(NamedLink {
            name: Some(author.to_owned()),
            url: None,
        });
    }
    if let Some(canonical) = og(html, &["og:url"]) {
        if let Ok(resolved) = url.join(canonical) {
            if is_safe_url(&resolved) {
                embed.canonical_url = Some(resolved.to_string());
            }
        }
    }
    if let Some(p) = meta_get(meta, &["article:published_time", "datepublished"]) {
        embed.published_time = Some(p.to_owned());
    }
    if let Some(m) = meta_get(meta, &["article:modified_time", "datemodified"]) {
        embed.modified_time = Some(m.to_owned());
    }

    populate_keywords(&mut embed, meta);
    populate_nsfw(&mut embed, meta);
    embed.favicon = Some(Media::from_url(default_favicon(url)));
    populate_summary_and_reading_time(&mut embed, &html.text_content);

    embed
}

fn populate_media(embed: &mut Embed, html: &HTML, page_url: &Url) {
    let empty = HashMap::new();
    let image = html
        .opengraph
        .images
        .first()
        .map(|o| (o.url.as_str(), &o.properties))
        .or_else(|| og(html, &["og:image", "og:image:url", "twitter:image"]).map(|u| (u, &empty)));
    if let Some((raw, props)) = image {
        if let Ok(resolved) = page_url.join(raw) {
            if is_safe_url(&resolved) {
                let mut media = Media::from_url(resolved.to_string());
                media.width = og_dim(props, &html.meta, "og:image:width");
                media.height = og_dim(props, &html.meta, "og:image:height");
                embed.image = Some(media.clone());
                embed.thumbnail = Some(media);
            }
        }
    }

    let video = html
        .opengraph
        .videos
        .first()
        .map(|o| (o.url.as_str(), &o.properties))
        .or_else(|| {
            og(html, &["og:video", "og:video:url", "og:video:secure_url", "twitter:player"])
                .map(|u| (u, &empty))
        });
    if let Some((raw, props)) = video {
        if let Ok(resolved) = page_url.join(raw) {
            if is_safe_url(&resolved) {
                let mut media = Media::from_url(resolved.to_string());
                media.width = og_dim(props, &html.meta, "og:video:width");
                media.height = og_dim(props, &html.meta, "og:video:height");
                embed.video = Some(media);
            }
        }
    }
}

fn classify_type(embed: &mut Embed, html: &HTML, meta: &HashMap<String, String>) {
    let og_type = og(html, &["og:type"])
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| html.opengraph.og_type.to_ascii_lowercase());
    let twitter_card = meta_get(meta, &["twitter:card"]).unwrap_or("");
    let kind = if embed.video.is_some() {
        "video"
    } else if og_type == "article" || og_type == "blog" {
        "article"
    } else if twitter_card == "summary_large_image" || og_type.starts_with("image") {
        "image"
    } else {
        "link"
    };
    embed.kind = Some(kind.to_owned());
}

fn populate_keywords(embed: &mut Embed, meta: &HashMap<String, String>) {
    let Some(raw) = meta_get(meta, &["keywords", "news_keywords"]) else {
        return;
    };
    let kw: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .take(16)
        .map(str::to_owned)
        .collect();
    if !kw.is_empty() {
        embed.keywords = kw;
    }
}

fn populate_nsfw(embed: &mut Embed, meta: &HashMap<String, String>) {
    let rating = meta_get(meta, &["rating"]).unwrap_or("").to_ascii_lowercase();
    let restrictions = meta_get(meta, &["og:restrictions:content"])
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(rating.as_str(), "adult" | "mature" | "rta-5042-1996-1400-1577-rta")
        || restrictions.contains("adult")
    {
        embed.nsfw = Some(true);
    }
}

fn populate_summary_and_reading_time(embed: &mut Embed, text: &str) {
    let text = collapse_ws(text);
    if text.is_empty() {
        return;
    }
    let summary = summarise(&text, 800);
    if !summary.is_empty() {
        if embed.description.as_deref().unwrap_or("").is_empty() {
            embed.description = Some(take_chars(&summary, 280));
        }
        embed.summary = Some(summary);
    }
    let rt = reading_time(&text);
    if !rt.is_empty() {
        embed.reading_time = Some(rt);
    }
}

// ---- small helpers --------------------------------------------------------

/// First non-empty value among `keys` in the parsed meta map.
fn meta_get<'a>(meta: &'a HashMap<String, String>, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .filter_map(|k| meta.get(*k))
        .map(String::as_str)
        .find(|v| !v.is_empty())
}

/// Look up an OpenGraph/meta value, checking both `webpage`'s `OpenGraph`
/// properties (which store keys with the `og:` prefix stripped) and the raw
/// meta map (full key), for each candidate in order.
fn og<'a>(html: &'a HTML, keys: &[&str]) -> Option<&'a str> {
    for k in keys {
        let stripped = k.strip_prefix("og:").unwrap_or(k);
        if let Some(v) = html
            .opengraph
            .properties
            .get(stripped)
            .map(String::as_str)
            .filter(|s| !s.is_empty())
        {
            return Some(v);
        }
        if let Some(v) = html.meta.get(*k).map(String::as_str).filter(|s| !s.is_empty()) {
            return Some(v);
        }
    }
    None
}

/// Resolve a media dimension from the `OpenGraph` object's own properties first,
/// then a raw meta fallback.
fn og_dim(props: &HashMap<String, String>, meta: &HashMap<String, String>, meta_key: &str) -> Option<i32> {
    props
        .get("width")
        .or_else(|| props.get("height").filter(|_| meta_key.ends_with("height")))
        .and_then(|s| s.trim().parse::<i32>().ok())
        .or_else(|| meta_get(meta, &[meta_key]).and_then(|s| s.trim().parse::<i32>().ok()))
}

fn default_favicon(page_url: &Url) -> String {
    let mut f = page_url.clone();
    f.set_path("/favicon.ico");
    f.set_query(None);
    f.set_fragment(None);
    f.to_string()
}

fn summarise(text: &str, max_chars: usize) -> String {
    if text.is_empty() {
        return String::new();
    }
    let mut result = String::new();
    let mut sentences = 0;
    // Split into sentences on terminal punctuation (incl. the CJK full stop).
    for sent in text.split_inclusive(['.', '!', '?', '\u{3002}']) {
        if result.chars().count() >= max_chars || sentences >= 4 {
            break;
        }
        let sent = sent.trim();
        if sent.chars().count() < 25 {
            continue;
        }
        if !result.is_empty() {
            result.push(' ');
        }
        result.push_str(sent);
        sentences += 1;
    }
    if result.is_empty() {
        result = text.to_owned();
    }
    take_chars(&result, max_chars)
}

fn reading_time(text: &str) -> String {
    let words = text.split_whitespace().count();
    if words < 80 {
        return String::new();
    }
    let minutes = std::cmp::max(1, (words + 110) / 220); // ~220 wpm
    format!("{minutes} min read")
}

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn take_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Minimal ISO-8601 UTC timestamp without a date dependency (mirrors the C++
/// `QDateTime::currentDateTimeUtc().toString(ISODate)`).
fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let tod = secs % 86_400;
    let (h, mi, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Days-since-epoch -> (year, month, day) (Howard Hinnant's civil algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "tests panic on failure")]
    use super::*;

    fn parse(html: &str, url: &str) -> Embed {
        let parsed = HTML::from_string(html.to_owned(), Some(url.to_owned())).expect("parse");
        build_embed(&parsed, &Url::parse(url).expect("url"))
    }

    #[test]
    fn extracts_core_og_tags() {
        let html = r##"<html lang="en"><head>
            <meta property="og:title" content="Hello World">
            <meta property="og:description" content="A test page">
            <meta property="og:type" content="article">
            <meta property="og:site_name" content="Example">
            <meta property="og:image" content="https://example.com/img/hero.png">
            <meta name="keywords" content="a, b, c">
            <meta name="theme-color" content="#1a2b3c">
            </head><body><p>body</p></body></html>"##;
        let e = parse(html, "https://example.com/article");
        assert_eq!(e.title.as_deref(), Some("Hello World"));
        assert_eq!(e.description.as_deref(), Some("A test page"));
        assert_eq!(e.kind.as_deref(), Some("article"));
        assert_eq!(e.site_name.as_deref(), Some("Example"));
        assert_eq!(e.lang.as_deref(), Some("en"));
        assert_eq!(e.color, Some(0x001a_2b3c));
        assert_eq!(e.keywords, vec!["a", "b", "c"]);
        assert_eq!(
            e.image.as_ref().and_then(|m| m.url.as_deref()),
            Some("https://example.com/img/hero.png")
        );
        assert!(e.favicon.is_some());
    }

    #[test]
    fn site_name_falls_back_to_host_without_www() {
        let e = parse(
            "<html><head><meta property=\"og:title\" content=\"T\"></head></html>",
            "https://www.example.com/x",
        );
        assert_eq!(e.site_name.as_deref(), Some("example.com"));
    }

    #[test]
    fn nsfw_detected_from_rating() {
        let e = parse(
            "<html><head><title>x</title><meta name=\"rating\" content=\"adult\"></head></html>",
            "https://example.com/",
        );
        assert_eq!(e.nsfw, Some(true));
    }

    #[test]
    fn reading_time_threshold() {
        assert_eq!(reading_time("short text"), "");
        assert!(reading_time(&"word ".repeat(300)).ends_with("min read"));
    }
}
