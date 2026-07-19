//! [`FileComponent`] - attachment-reference component.  Discord
//! component type `13`.  Renamed from `File` to avoid collision with
//! `std::fs::File`.
//!
//! The `file` field must reference an in-envelope attachment via the
//! `attachment://<filename>` URL scheme, or a Fancy Mumble file via
//! the `fancy-file://<id>` scheme.

use serde::{Deserialize, Serialize};

use super::{Component, UnfurledMediaItem};

/// File attachment reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileComponent {
    /// Source media (`attachment://...` or `fancy-file://...`).
    pub file: UnfurledMediaItem,
    /// Render blurred until clicked.
    #[serde(default, skip_serializing_if = "is_false")]
    pub spoiler: bool,
    /// Display name override.  Ignored by clients that resolve names
    /// from the underlying attachment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// File size in bytes, if known.  Informational.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl FileComponent {
    /// Build a [`FileComponent`] from any value convertible into an
    /// [`UnfurledMediaItem`].
    #[must_use]
    pub fn new(file: impl Into<UnfurledMediaItem>) -> Self {
        Self {
            file: file.into(),
            spoiler: false,
            name: None,
            size: None,
        }
    }

    /// Mark as a spoiler.
    #[must_use]
    pub fn spoiler(mut self, spoiler: bool) -> Self {
        self.spoiler = spoiler;
        self
    }

    /// Override the display name.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Tag with a known file size.
    #[must_use]
    pub fn size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }
}

impl From<FileComponent> for Component {
    fn from(f: FileComponent) -> Self {
        Self::File(f)
    }
}

/// Build a [`FileComponent`].
///
/// ```ignore
/// use mumble_plugin_api::file;
/// let f = file!("attachment://report.pdf", spoiler, name = "Report");
/// ```
#[macro_export]
macro_rules! file {
    ($media:expr $(, $($rest:tt)*)? ) => {{
        #[allow(unused_mut, reason = "macro-generated when no modifiers are given")]
        let mut __f = $crate::components::FileComponent::new($media);
        $( $crate::__file_modifier!(__f; $($rest)*); )?
        __f
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __file_modifier {
    ($f:ident; spoiler $(, $($rest:tt)*)?) => {
        $f = $f.spoiler(true);
        $( $crate::__file_modifier!($f; $($rest)*); )?
    };
    ($f:ident; name = $n:expr $(, $($rest:tt)*)?) => {
        $f = $f.name($n);
        $( $crate::__file_modifier!($f; $($rest)*); )?
    };
    ($f:ident; size = $s:expr $(, $($rest:tt)*)?) => {
        $f = $f.size($s);
        $( $crate::__file_modifier!($f; $($rest)*); )?
    };
    ($f:ident;) => {};
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "tests panic on failure")]
    use super::*;

    #[test]
    fn macro_attaches_modifiers() {
        let f = file!("attachment://r.pdf", spoiler, name = "Report", size = 12u64);
        assert!(f.spoiler);
        assert_eq!(f.name.as_deref(), Some("Report"));
        assert_eq!(f.size, Some(12));
    }

    #[test]
    fn wire_tag() {
        let c: Component = FileComponent::new("attachment://x").into();
        let json = serde_json::to_string(&c).expect("encode");
        assert!(json.contains("\"type\":\"file\""));
    }
}
