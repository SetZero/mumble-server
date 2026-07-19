//! [`Button`] - click target.  Discord component type `2`.
//!
//! Five styles are supported.  `Primary` / `Secondary` / `Success` /
//! `Danger` deliver a [`Component`](crate::InteractionKind::Component)
//! interaction when clicked; `Link` opens a URL client-side and emits
//! no interaction.
//!
//! Discord's `Premium` / SKU style is intentionally omitted - Mumble
//! has no monetisation surface.

use serde::{Deserialize, Serialize};

use super::Component;

/// Click target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Button {
    /// Echoed verbatim back in
    /// [`InteractionKind::Component::custom_id`](crate::InteractionKind::Component).
    /// Optional only for `Link` buttons.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_id: Option<String>,
    /// Visible label.  Up to 80 characters; clients may truncate.
    pub label: String,
    /// Visual style.
    #[serde(default)]
    pub style: ButtonStyle,
    /// When `true`, the button renders but cannot be clicked.
    #[serde(default)]
    pub disabled: bool,
    /// URL opened on click for `Link`-style buttons.  Required iff
    /// [`Self::style`] is [`ButtonStyle::Link`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Visual style of a [`Button`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ButtonStyle {
    /// Filled accent colour.  Use for the safe / primary action.
    #[default]
    Primary,
    /// Subtle outlined button.
    Secondary,
    /// Green; use for confirmations.
    Success,
    /// Red; use for destructive actions.
    Danger,
    /// Renders as a hyperlink that opens [`Button::url`].
    Link,
}

impl Button {
    /// Build a `Primary` button with the given `custom_id` and label.
    #[must_use]
    pub fn new(custom_id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            custom_id: Some(custom_id.into()),
            label: label.into(),
            style: ButtonStyle::default(),
            disabled: false,
            url: None,
        }
    }

    /// Build a `Link` button that navigates to `url`.
    #[must_use]
    pub fn link(label: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            custom_id: None,
            label: label.into(),
            style: ButtonStyle::Link,
            disabled: false,
            url: Some(url.into()),
        }
    }

    /// Override the visual style.
    #[must_use]
    pub fn style(mut self, style: ButtonStyle) -> Self {
        self.style = style;
        self
    }

    /// Render the button as disabled (greyed out, not clickable).
    #[must_use]
    pub fn disabled(mut self, disabled: bool) -> Self {
        self.disabled = disabled;
        self
    }
}

impl From<Button> for Component {
    fn from(b: Button) -> Self {
        Self::Button(b)
    }
}

/// Build a [`Button`].
///
/// Two forms:
///
/// ```ignore
/// button!("custom_id", "Label");
/// button!("custom_id", "Label", Danger, disabled);
/// ```
///
/// The third+ positional arguments are optional and match either a
/// [`crate::components::ButtonStyle`] variant by name or the literal
/// identifier `disabled`.
#[macro_export]
macro_rules! button {
    ($custom_id:expr, $label:expr $(,)?) => {
        $crate::components::Button::new($custom_id, $label)
    };
    ($custom_id:expr, $label:expr, $($modifier:tt)+) => {{
        #[allow(unused_mut, reason = "macro chain may be empty after first modifier")]
        let mut __b = $crate::components::Button::new($custom_id, $label);
        $crate::__button_modifier!(__b; $($modifier)+);
        __b
    }};
}

/// Build a `Link` [`Button`].
#[macro_export]
macro_rules! link_button {
    ($label:expr, $url:expr $(,)?) => {
        $crate::components::Button::link($label, $url)
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __button_modifier {
    ($b:ident; disabled $(, $($rest:tt)*)?) => {
        $b = $b.disabled(true);
        $( $crate::__button_modifier!($b; $($rest)*); )?
    };
    ($b:ident; $style:ident $(, $($rest:tt)*)?) => {
        $b = $b.style($crate::components::ButtonStyle::$style);
        $( $crate::__button_modifier!($b; $($rest)*); )?
    };
    ($b:ident;) => {};
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "tests panic on failure")]
    use super::*;

    #[test]
    fn primary_default() {
        let b = Button::new("ok", "OK");
        assert_eq!(b.style, ButtonStyle::Primary);
        assert_eq!(b.custom_id.as_deref(), Some("ok"));
        assert!(!b.disabled);
    }

    #[test]
    fn link_has_url_no_custom_id() {
        let b = Button::link("Open", "https://example.com");
        assert_eq!(b.style, ButtonStyle::Link);
        assert!(b.custom_id.is_none());
        assert_eq!(b.url.as_deref(), Some("https://example.com"));
    }

    #[test]
    fn macro_basic() {
        let b = button!("ok", "OK");
        assert_eq!(b.label, "OK");
    }

    #[test]
    fn macro_with_modifiers() {
        let b = button!("rm", "Delete", Danger, disabled);
        assert_eq!(b.style, ButtonStyle::Danger);
        assert!(b.disabled);
    }

    #[test]
    fn wire_round_trip() {
        let b = Button::new("ok", "OK").style(ButtonStyle::Success);
        let json = serde_json::to_string(&b).expect("encode");
        let back: Button = serde_json::from_str(&json).expect("decode");
        assert_eq!(back.style, ButtonStyle::Success);
    }
}
