//! Wire contract between this plugin and the C++ server bridge.
//!
//! The server hands the plugin a [`PreviewRequest`] (JSON `{request_id, urls}`)
//! and the plugin returns a [`PreviewResponse`] (JSON `{embeds:[...]}`). The
//! field names of [`Embed`] / [`Media`] mirror the keys that the server's
//! `populateProtoEmbed` reads when packing a `FancyLinkPreviewResponse`, so the
//! existing C++ JSON->protobuf packer consumes this output unchanged. Absent
//! optional fields are omitted (the packer probes with `contains()`).

use serde::{Deserialize, Serialize};

/// Request payload the server sends to the plugin (one per client
/// `FancyLinkPreviewRequest`). `request_id` is echoed back via the
/// request/response bridge for correlation; it is *not* carried in the embed
/// JSON.
#[derive(Debug, Clone, Deserialize)]
pub struct PreviewRequest {
    /// Client-chosen correlation id.
    #[serde(default)]
    pub request_id: String,
    /// URLs to build previews for (already capped/validated client-side; the
    /// plugin re-validates and SSRF-gates each).
    #[serde(default)]
    pub urls: Vec<String>,
}

/// Response payload the plugin hands back to the server bridge.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PreviewResponse {
    /// Resolved embeds, one per successfully previewed URL.
    pub embeds: Vec<Embed>,
}

/// A single link embed. Field names match the server's `populateProtoEmbed`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Embed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// "video" | "image" | "gifv" | "article" | "link" | "rich" | "audio" | "file"
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Dominant theme colour packed as 0xRRGGBB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site_name: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<Media>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<Media>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub video: Option<Media>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub favicon: Option<Media>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<NamedLink>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<NamedLink>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_length: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_duration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsfw: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reading_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetched_at: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keywords: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<Field>,
}

impl Embed {
    /// True when the embed lacks both a description and a summary and would
    /// benefit from a secondary `OpenGraph` enrichment fetch (mirrors the C++
    /// `LinkPreviewManager::needsOgEnrichment`).
    #[must_use]
    pub fn needs_og_enrichment(&self) -> bool {
        self.description.as_deref().unwrap_or("").is_empty()
            && self.summary.as_deref().unwrap_or("").is_empty()
    }
}

/// Media sub-object (thumbnail/image/video/favicon). `preview_data_b64` carries
/// the server-side downscaled JPEG (base64); the server decodes it into the
/// protobuf `preview_data` bytes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Media {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_data_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_mime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_width: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_height: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_size: Option<u64>,
}

impl Media {
    /// Construct a media object from just a URL.
    #[must_use]
    pub fn from_url(url: impl Into<String>) -> Self {
        Self {
            url: Some(url.into()),
            ..Self::default()
        }
    }

    /// True once a downscaled preview has been inlined.
    #[must_use]
    pub fn has_preview(&self) -> bool {
        self.preview_data_b64.is_some()
    }
}

/// `{ name, url }` pair used for `provider` and `author`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NamedLink {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Extra key/value row (`fields` array).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Field {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline: Option<bool>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "tests panic on failure")]
    use super::*;

    #[test]
    fn embed_omits_absent_optionals() {
        let e = Embed { url: Some("https://example.com".into()), title: Some("Example".into()), ..Embed::default() };
        let json = serde_json::to_value(&e).expect("serialize");
        let obj = json.as_object().expect("object");
        // Only the set keys appear; the packer probes with contains().
        assert!(obj.contains_key("url"));
        assert!(obj.contains_key("title"));
        assert!(!obj.contains_key("description"));
        assert!(!obj.contains_key("image"));
        assert!(!obj.contains_key("keywords"));
    }

    #[test]
    fn type_serializes_as_type_key() {
        let e = Embed { kind: Some("article".into()), ..Embed::default() };
        let json = serde_json::to_value(&e).expect("serialize");
        assert_eq!(json.get("type").and_then(|v| v.as_str()), Some("article"));
    }

    #[test]
    fn request_parses_minimal() {
        let req: PreviewRequest =
            serde_json::from_str(r#"{"request_id":"abc","urls":["https://x.y"]}"#).expect("parse");
        assert_eq!(req.request_id, "abc");
        assert_eq!(req.urls, vec!["https://x.y".to_string()]);
    }
}
