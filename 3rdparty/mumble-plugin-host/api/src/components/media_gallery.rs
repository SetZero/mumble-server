//! [`MediaGallery`] - 1 to 10 media items rendered as a gallery.
//! Discord component type `12`.

use serde::{Deserialize, Serialize};

use super::{Component, UnfurledMediaItem};

/// Gallery of 1-10 media items.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaGallery {
    /// 1-10 items.
    pub items: Vec<MediaGalleryItem>,
}

/// One entry in a [`MediaGallery`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaGalleryItem {
    /// Source media.
    pub media: UnfurledMediaItem,
    /// Alt text (max 1024 chars).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Render blurred until clicked.
    #[serde(default, skip_serializing_if = "is_false")]
    pub spoiler: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl MediaGallery {
    /// Build an empty gallery; chain [`Self::item`] to populate.
    #[must_use]
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Append a single item.
    #[must_use]
    pub fn item(mut self, item: MediaGalleryItem) -> Self {
        self.items.push(item);
        self
    }

    /// Extend with a batch of items.
    #[must_use]
    pub fn items<I: IntoIterator<Item = MediaGalleryItem>>(mut self, iter: I) -> Self {
        self.items.extend(iter);
        self
    }
}

impl Default for MediaGallery {
    fn default() -> Self {
        Self::new()
    }
}

impl MediaGalleryItem {
    /// Build a gallery item from any value convertible into an
    /// [`UnfurledMediaItem`].
    #[must_use]
    pub fn new(media: impl Into<UnfurledMediaItem>) -> Self {
        Self {
            media: media.into(),
            description: None,
            spoiler: false,
        }
    }

    /// Attach alt text.
    #[must_use]
    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.description = Some(d.into());
        self
    }

    /// Mark as a spoiler.
    #[must_use]
    pub fn spoiler(mut self, spoiler: bool) -> Self {
        self.spoiler = spoiler;
        self
    }
}

impl From<MediaGallery> for Component {
    fn from(g: MediaGallery) -> Self {
        Self::MediaGallery(g)
    }
}

/// Build a [`MediaGallery`] from a list of items.
///
/// ```ignore
/// use mumble_plugin_api::{media_gallery, components::MediaGalleryItem};
/// let g = media_gallery![
///     MediaGalleryItem::new("https://a/img.png"),
///     MediaGalleryItem::new("https://b/img.png").description("alt"),
/// ];
/// ```
#[macro_export]
macro_rules! media_gallery {
    [ $($item:expr),* $(,)? ] => {
        $crate::components::MediaGallery::new()$( .item($item) )*
    };
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "tests panic on failure")]
    use super::*;

    #[test]
    fn macro_collects_items() {
        let g = media_gallery![
            MediaGalleryItem::new("a"),
            MediaGalleryItem::new("b").description("alt"),
        ];
        assert_eq!(g.items.len(), 2);
    }
}
