//! Server-side image preview builder: fetch a remote image, downscale it to a
//! bounded box, and re-encode as JPEG so the client renders a preview without
//! contacting the origin host. Ports `MediaPreviewBuilder`; the `QImage`
//! decode/scale/encode is replaced by the pure-Rust `image` crate (this is what
//! removes the server's `Qt6Gui` dependency).

use std::io::Cursor;

use image::{DynamicImage, ImageFormat, ImageReader};

use crate::fetch::{fetch_capped, FetchError};

/// Hard cap on source bytes downloaded per preview (mirrors C++ `MAX_SOURCE_BYTES`).
pub const MAX_SOURCE_BYTES: usize = 10 * 1024 * 1024;
/// Default longest-side pixel size for hero/thumbnail previews.
pub const DEFAULT_MAX_DIM: u32 = 320;
/// Favicons stay tiny so dozens inline cheaply.
pub const FAVICON_MAX_DIM: u32 = 64;
/// JPEG encoder quality (0-100).
pub const JPEG_QUALITY: u8 = 78;
/// Decoder allocation cap, guarding against decompression bombs (mirrors the
/// old `QImageReader::setAllocationLimit(64)` MiB).
const MAX_DECODE_ALLOC: u64 = 64 * 1024 * 1024;

/// Result of a successful downscale (mirrors `MediaPreviewBuilder::Result`).
#[derive(Debug, Clone)]
pub struct PreviewResult {
    /// JPEG-encoded downscaled image bytes.
    pub jpeg: Vec<u8>,
    /// Downscaled dimensions.
    pub preview_width: i32,
    pub preview_height: i32,
    /// Original (source) dimensions.
    pub original_width: i32,
    pub original_height: i32,
    /// Size in bytes of the original source.
    pub original_size: u64,
    /// MIME of the preview output (always `image/jpeg`).
    pub mime: String,
    /// MIME of the *source* (caller-provided when known, else detected).
    pub content_type: String,
}

/// Fetch `url` and downscale to fit within `max_dim` x `max_dim`, JPEG at
/// `quality`. Returns `None` on any failure (fetch, decode, encode).
pub async fn fetch_and_downscale(
    client: &reqwest::Client,
    url: &url::Url,
    max_dim: u32,
    quality: u8,
) -> Option<PreviewResult> {
    let body = match fetch_capped(client, url, "image/*", MAX_SOURCE_BYTES).await {
        Ok(b) => b,
        Err(FetchError::TooLarge(_)) => {
            tracing::debug!(%url, "media preview: source too large");
            return None;
        }
        Err(e) => {
            tracing::debug!(%url, error = %e, "media preview: fetch failed");
            return None;
        }
    };
    build_from_bytes(&body.bytes, max_dim, quality, body.content_type.as_deref())
}

/// Decode/scale/JPEG-encode already-downloaded bytes.
#[must_use]
pub fn build_from_bytes(
    source: &[u8],
    max_dim: u32,
    quality: u8,
    content_type: Option<&str>,
) -> Option<PreviewResult> {
    if source.is_empty() || max_dim == 0 {
        return None;
    }

    let mut reader = ImageReader::new(Cursor::new(source))
        .with_guessed_format()
        .ok()?;
    let mut limits = image::Limits::default();
    limits.max_alloc = Some(MAX_DECODE_ALLOC);
    reader.limits(limits);

    let detected_mime = mime_for(reader.format());
    let img = reader.decode().ok()?;

    let original_width = img.width();
    let original_height = img.height();
    if original_width == 0 || original_height == 0 {
        return None;
    }

    let scaled = if original_width > max_dim || original_height > max_dim {
        // KeepAspectRatio within the box; Lanczos3 ≈ Qt's SmoothTransformation.
        img.resize(max_dim, max_dim, image::imageops::FilterType::Lanczos3)
    } else {
        img
    };

    // JPEG has no alpha; flatten to RGB for predictable, smaller output.
    let rgb = scaled.to_rgb8();
    let preview_width = rgb.width();
    let preview_height = rgb.height();

    let mut jpeg = Vec::new();
    let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpeg, quality);
    encoder.encode_image(&DynamicImage::ImageRgb8(rgb)).ok()?;
    if jpeg.is_empty() {
        return None;
    }

    let source_mime = content_type
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map_or_else(|| detected_mime.to_owned(), str::to_owned);

    Some(PreviewResult {
        jpeg,
        preview_width: clamp_i32(preview_width),
        preview_height: clamp_i32(preview_height),
        original_width: clamp_i32(original_width),
        original_height: clamp_i32(original_height),
        original_size: source.len() as u64,
        mime: "image/jpeg".to_owned(),
        content_type: source_mime,
    })
}

fn clamp_i32(v: u32) -> i32 {
    i32::try_from(v).unwrap_or(i32::MAX)
}

fn mime_for(format: Option<ImageFormat>) -> &'static str {
    match format {
        Some(ImageFormat::Png) => "image/png",
        Some(ImageFormat::Jpeg) => "image/jpeg",
        Some(ImageFormat::WebP) => "image/webp",
        Some(ImageFormat::Gif) => "image/gif",
        Some(ImageFormat::Bmp) => "image/bmp",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "tests panic on failure")]
    use super::*;
    use image::{ImageFormat, RgbImage};

    fn png_bytes(w: u32, h: u32) -> Vec<u8> {
        let img = RgbImage::from_fn(w, h, |x, y| {
            image::Rgb([(x % 256) as u8, (y % 256) as u8, 128])
        });
        let mut out = Vec::new();
        DynamicImage::ImageRgb8(img)
            .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
            .expect("encode png");
        out
    }

    #[test]
    fn downscales_large_image() {
        let src = png_bytes(800, 600);
        let r = build_from_bytes(&src, 320, JPEG_QUALITY, Some("image/png")).expect("preview");
        assert_eq!(r.original_width, 800);
        assert_eq!(r.original_height, 600);
        assert!(r.preview_width <= 320 && r.preview_height <= 320);
        assert!(r.preview_width == 320 || r.preview_height == 240);
        assert_eq!(r.mime, "image/jpeg");
        assert_eq!(r.content_type, "image/png");
        assert!(!r.jpeg.is_empty());
    }

    #[test]
    fn keeps_small_image_dimensions() {
        let src = png_bytes(100, 50);
        let r = build_from_bytes(&src, 320, JPEG_QUALITY, None).expect("preview");
        assert_eq!(r.preview_width, 100);
        assert_eq!(r.preview_height, 50);
        // Detected from magic bytes when no content-type supplied.
        assert_eq!(r.content_type, "image/png");
    }

    #[test]
    fn rejects_garbage() {
        assert!(build_from_bytes(b"not an image", 320, JPEG_QUALITY, None).is_none());
        assert!(build_from_bytes(&[], 320, JPEG_QUALITY, None).is_none());
    }
}
