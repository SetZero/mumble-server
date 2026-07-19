//! [`Thumbnail`] - small inline image, typically used as the
//! `accessory` of a [`Section`].  Discord component type `11`.
//!
//! [`Section`]: crate::components::Section

use serde::{Deserialize, Serialize};

use super::{Component, UnfurledMediaItem};

/// Small inline image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thumbnail {
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

impl Thumbnail {
    /// Build a [`Thumbnail`] from any value convertible into an
    /// [`UnfurledMediaItem`] (including a plain URL `&str`/`String`).
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

    /// Mark as a spoiler (blurred until clicked).
    #[must_use]
    pub fn spoiler(mut self, spoiler: bool) -> Self {
        self.spoiler = spoiler;
        self
    }
}

impl From<Thumbnail> for Component {
    fn from(t: Thumbnail) -> Self {
        Self::Thumbnail(t)
    }
}

/// Build a [`Thumbnail`].
///
/// ```ignore
/// use mumble_plugin_api::thumbnail;
/// let t = thumbnail!("https://example.com/img.png", description = "Logo");
/// ```
#[macro_export]
macro_rules! thumbnail {
    ($media:expr $(, $($rest:tt)*)? ) => {{
        #[allow(unused_mut, reason = "macro-generated when no modifiers are given")]
        let mut __t = $crate::components::Thumbnail::new($media);
        $( $crate::__thumbnail_modifier!(__t; $($rest)*); )?
        __t
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __thumbnail_modifier {
    ($t:ident; description = $d:expr $(, $($rest:tt)*)?) => {
        $t = $t.description($d);
        $( $crate::__thumbnail_modifier!($t; $($rest)*); )?
    };
    ($t:ident; spoiler $(, $($rest:tt)*)?) => {
        $t = $t.spoiler(true);
        $( $crate::__thumbnail_modifier!($t; $($rest)*); )?
    };
    ($t:ident;) => {};
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "tests panic on failure")]

    #[test]
    fn macro_attaches_modifiers() {
        let t = thumbnail!("https://example.com/x.png", description = "x", spoiler);
        assert_eq!(t.description.as_deref(), Some("x"));
        assert!(t.spoiler);
    }
}
