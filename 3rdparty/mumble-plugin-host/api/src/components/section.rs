//! [`Section`] - text-plus-accessory layout block.  Discord component
//! type `9`.  Holds 1-3 child components contextually associated with
//! an `accessory` ([`Button`] or [`Thumbnail`]).
//!
//! [`Button`]: crate::components::Button
//! [`Thumbnail`]: crate::components::Thumbnail

use serde::{Deserialize, Serialize};

use super::{Button, Component, Thumbnail};

/// Text-plus-accessory block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    /// 1-3 child components (typically [`TextDisplay`](crate::components::TextDisplay)).
    pub components: Vec<Component>,
    /// Accessory component associated with the section.
    pub accessory: SectionAccessory,
}

/// Accessory slot inside a [`Section`].  The wire form tags the kind
/// at the Discord type level via the underlying [`Component`] tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum SectionAccessory {
    /// A clickable button.
    Button(Button),
    /// An inline image.
    Thumbnail(Thumbnail),
}

impl Section {
    /// Build a section with the given accessory.
    #[must_use]
    pub fn new(accessory: SectionAccessory) -> Self {
        Self {
            components: Vec::new(),
            accessory,
        }
    }

    /// Append a child component (typically a [`TextDisplay`](crate::components::TextDisplay)).
    #[must_use]
    pub fn push(mut self, c: impl Into<Component>) -> Self {
        self.components.push(c.into());
        self
    }
}

impl From<Button> for SectionAccessory {
    fn from(b: Button) -> Self {
        Self::Button(b)
    }
}
impl From<Thumbnail> for SectionAccessory {
    fn from(t: Thumbnail) -> Self {
        Self::Thumbnail(t)
    }
}
impl From<Section> for Component {
    fn from(s: Section) -> Self {
        Self::Section(s)
    }
}

/// Build a [`Section`] from `[children] => accessory`.
///
/// ```ignore
/// use mumble_plugin_api::{section, text_display, components::Thumbnail};
/// let s = section!([text_display!("hello")] => Thumbnail::new("https://x/y.png"));
/// ```
#[macro_export]
macro_rules! section {
    ( [ $($child:expr),* $(,)? ] => $accessory:expr $(,)? ) => {{
        #[allow(unused_mut, reason = "macro-generated when no children are given")]
        let mut __s = $crate::components::Section::new(
            ::core::convert::Into::<$crate::components::SectionAccessory>::into($accessory),
        );
        $( __s = __s.push($child); )*
        __s
    }};
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "tests panic on failure")]
    use super::*;
    use crate::components::TextDisplay;

    #[test]
    fn macro_builds_section() {
        let s = section!([TextDisplay::new("a"), TextDisplay::new("b")]
            => Button::new("ok", "OK"));
        assert_eq!(s.components.len(), 2);
        assert!(matches!(s.accessory, SectionAccessory::Button(_)));
    }

    #[test]
    fn thumbnail_accessory() {
        let s = section!([TextDisplay::new("a")] => Thumbnail::new("https://x"));
        assert!(matches!(s.accessory, SectionAccessory::Thumbnail(_)));
    }
}
