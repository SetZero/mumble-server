//! [`UnfurledMediaItem`] - media reference embeddable in [`Thumbnail`],
//! [`MediaGallery`], or [`FileComponent`].
//!
//! Only the `url` field is settable by plugins.  URLs may be:
//!
//! * arbitrary `https://` URLs (rendered as embedded images / videos);
//! * `fancy-file://<file-id>` - references the Fancy Mumble file
//!   store;
//! * `attachment://<filename>` - references a file uploaded in the
//!   same plugin message envelope (matches the Discord convention).
//!
//! [`Thumbnail`]: crate::components::Thumbnail
//! [`MediaGallery`]: crate::components::MediaGallery
//! [`FileComponent`]: crate::components::FileComponent

use serde::{Deserialize, Serialize};

/// Reference to a media resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnfurledMediaItem {
    /// Resource URL.  See module-level docs for accepted schemes.
    pub url: String,
}

impl UnfurledMediaItem {
    /// Build a media item from an arbitrary URL.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }

    /// Build a media item that references a file in the Fancy Mumble
    /// file store by id.
    #[must_use]
    pub fn fancy_file(id: impl AsRef<str>) -> Self {
        Self {
            url: format!("fancy-file://{}", id.as_ref()),
        }
    }

    /// Build a media item that references an in-envelope attachment by
    /// filename (the `attachment://...` convention).
    #[must_use]
    pub fn attachment(name: impl AsRef<str>) -> Self {
        Self {
            url: format!("attachment://{}", name.as_ref()),
        }
    }
}

impl<S: Into<String>> From<S> for UnfurledMediaItem {
    fn from(url: S) -> Self {
        Self::new(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fancy_file_scheme() {
        assert_eq!(UnfurledMediaItem::fancy_file("abc").url, "fancy-file://abc");
    }

    #[test]
    fn attachment_scheme() {
        assert_eq!(
            UnfurledMediaItem::attachment("logo.png").url,
            "attachment://logo.png"
        );
    }
}
