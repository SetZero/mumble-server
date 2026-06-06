//! Direct-media provider (highest priority). Recognises URLs that point
//! straight at an image/video/audio/document by file extension. Images are
//! downloaded and downscaled inline; other kinds get a HEAD-described embed.
//! Port of `DirectMediaPlugin.cpp`; per-hop SSRF for redirects is handled by
//! the shared client's resolver, so the manual redirect loop is unnecessary.

use base64::Engine as _;
use url::Url;

use crate::embed::{Embed, Field, Media};
use crate::media_preview::{fetch_and_downscale, DEFAULT_MAX_DIM, JPEG_QUALITY};
use crate::ssrf::is_safe_url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Image,
    Gif,
    Video,
    Audio,
    Document,
    Unknown,
}

fn classify(url: &Url) -> Kind {
    let path = url.path().to_ascii_lowercase();
    let ends = |exts: &[&str]| exts.iter().any(|e| path.ends_with(e));
    if ends(&[".png", ".jpg", ".jpeg", ".webp", ".bmp", ".avif", ".jxl"]) {
        Kind::Image
    } else if ends(&[".gif"]) {
        Kind::Gif
    } else if ends(&[".mp4", ".webm", ".mov", ".mkv", ".m4v"]) {
        Kind::Video
    } else if ends(&[".mp3", ".ogg", ".oga", ".wav", ".flac", ".m4a", ".opus"]) {
        Kind::Audio
    } else if ends(&[
        ".pdf", ".zip", ".tar", ".7z", ".gz", ".xz", ".rar", ".doc", ".docx", ".xls", ".xlsx",
        ".ppt", ".pptx", ".odt", ".epub",
    ]) {
        Kind::Document
    } else {
        Kind::Unknown
    }
}

/// This provider claims safe URLs that point at recognised media by extension.
#[must_use]
pub fn can_handle(url: &Url) -> bool {
    is_safe_url(url) && classify(url) != Kind::Unknown
}

/// Build an embed for a direct-media URL.
pub async fn fetch_preview(client: &reqwest::Client, url: &Url) -> Option<Embed> {
    match classify(url) {
        Kind::Image | Kind::Gif => fetch_image(client, url, classify(url)).await,
        kind => describe_only(client, url, kind).await,
    }
}

async fn fetch_image(client: &reqwest::Client, url: &Url, kind: Kind) -> Option<Embed> {
    let res = fetch_and_downscale(client, url, DEFAULT_MAX_DIM, JPEG_QUALITY).await?;

    let mut image = Media::from_url(url.to_string());
    image.width = Some(res.original_width);
    image.height = Some(res.original_height);
    image.preview_data_b64 = Some(base64::engine::general_purpose::STANDARD.encode(&res.jpeg));
    image.preview_mime = Some(res.mime.clone());
    image.preview_width = Some(res.preview_width);
    image.preview_height = Some(res.preview_height);
    image.original_size = Some(res.original_size);

    let mut fields = vec![
        Field {
            name: Some("Resolution".to_owned()),
            value: Some(format!("{} \u{00d7} {}", res.original_width, res.original_height)),
            inline: Some(true),
        },
        Field {
            name: Some("Size".to_owned()),
            value: Some(human_file_size(res.original_size)),
            inline: Some(true),
        },
    ];
    if !res.content_type.is_empty() {
        fields.push(Field {
            name: Some("Type".to_owned()),
            value: Some(res.content_type.clone()),
            inline: Some(true),
        });
    }

    Some(Embed {
        url: Some(url.to_string()),
        kind: Some(if kind == Kind::Gif { "gifv" } else { "image" }.to_owned()),
        title: Some(filename_of(url)),
        site_name: url.host_str().map(str::to_owned),
        content_type: (!res.content_type.is_empty()).then(|| res.content_type.clone()),
        content_length: Some(res.original_size),
        image: Some(image),
        fields,
        ..Embed::default()
    })
}

async fn describe_only(client: &reqwest::Client, url: &Url, kind: Kind) -> Option<Embed> {
    if !is_safe_url(url) {
        return None;
    }
    // HEAD to learn Content-Type / Content-Length without downloading the body.
    // Redirects are followed + SSRF-gated by the shared client.
    let (content_type, content_length) = match client.head(url.clone()).send().await {
        Ok(resp) => {
            let ct = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.split(';').next().unwrap_or("").trim().to_owned())
                .filter(|s| !s.is_empty());
            (ct, resp.content_length())
        }
        // Best-effort: still emit a minimal embed (filename + kind).
        Err(_) => (None, None),
    };

    let kind_str = match kind {
        Kind::Video => "video",
        Kind::Audio => "audio",
        Kind::Document => "file",
        _ => "link",
    };

    let mut fields = Vec::new();
    if let Some(ct) = &content_type {
        fields.push(Field {
            name: Some("Type".to_owned()),
            value: Some(ct.clone()),
            inline: Some(true),
        });
    }
    if let Some(len) = content_length.filter(|l| *l > 0) {
        fields.push(Field {
            name: Some("Size".to_owned()),
            value: Some(human_file_size(len)),
            inline: Some(true),
        });
    }

    Some(Embed {
        url: Some(url.to_string()),
        kind: Some(kind_str.to_owned()),
        title: Some(filename_of(url)),
        site_name: url.host_str().map(str::to_owned),
        content_type,
        content_length: content_length.filter(|l| *l > 0),
        fields,
        ..Embed::default()
    })
}

fn filename_of(url: &Url) -> String {
    url.path_segments()
        .and_then(|mut s| s.next_back())
        .unwrap_or("")
        .to_owned()
}

fn human_file_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GiB", b / GB)
    } else if b >= MB {
        format!("{:.2} MiB", b / MB)
    } else if b >= KB {
        format!("{:.1} KiB", b / KB)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).expect("url")
    }

    #[test]
    fn classifies_by_extension() {
        assert_eq!(classify(&u("https://x.y/a/b.PNG")), Kind::Image);
        assert_eq!(classify(&u("https://x.y/a.gif")), Kind::Gif);
        assert_eq!(classify(&u("https://x.y/a.mp4")), Kind::Video);
        assert_eq!(classify(&u("https://x.y/a.flac")), Kind::Audio);
        assert_eq!(classify(&u("https://x.y/a.pdf")), Kind::Document);
        assert_eq!(classify(&u("https://x.y/page")), Kind::Unknown);
    }

    #[test]
    fn can_handle_requires_safe_and_known() {
        assert!(can_handle(&u("https://example.com/a.png")));
        assert!(!can_handle(&u("https://example.com/page")));
        assert!(!can_handle(&u("http://127.0.0.1/a.png")));
    }

    #[test]
    fn filename_and_size() {
        assert_eq!(filename_of(&u("https://x.y/dir/pic.png")), "pic.png");
        assert_eq!(human_file_size(512), "512 B");
        assert_eq!(human_file_size(2048), "2.0 KiB");
        assert_eq!(human_file_size(5 * 1024 * 1024), "5.00 MiB");
    }
}
