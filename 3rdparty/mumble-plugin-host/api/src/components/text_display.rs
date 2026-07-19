//! [`TextDisplay`] - Markdown text block.  Discord component type `10`.
//! Available in messages and modals.

use serde::{Deserialize, Serialize};

use super::Component;

/// Markdown-formatted text block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextDisplay {
    /// Markdown content rendered like a regular message body.
    pub content: String,
}

impl TextDisplay {
    /// Build a [`TextDisplay`] with the given Markdown content.
    #[must_use]
    pub fn new(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
        }
    }
}

impl From<TextDisplay> for Component {
    fn from(t: TextDisplay) -> Self {
        Self::TextDisplay(t)
    }
}

/// Build a [`TextDisplay`].
///
/// ```ignore
/// use mumble_plugin_api::text_display;
/// let t = text_display!("# Heading\nSome body text");
/// ```
#[macro_export]
macro_rules! text_display {
    ($content:expr $(,)?) => {
        $crate::components::TextDisplay::new($content)
    };
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "tests panic on failure")]
    use super::*;

    #[test]
    fn macro_builds() {
        let t = text_display!("hello");
        assert_eq!(t.content, "hello");
    }

    #[test]
    fn wire_tag() {
        let c: Component = TextDisplay::new("hi").into();
        let json = serde_json::to_string(&c).expect("encode");
        assert!(json.contains("\"type\":\"text-display\""));
    }
}
