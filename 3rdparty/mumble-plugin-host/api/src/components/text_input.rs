//! [`TextInput`] - free-form text field.  Discord component type `4`.
//! Modal-only.

use serde::{Deserialize, Serialize};

use super::Component;

/// Modal form field accepting free-form text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextInput {
    /// Used as the key in
    /// [`InteractionKind::ModalSubmit::values`](crate::InteractionKind::ModalSubmit).
    pub custom_id: String,
    /// Label rendered above the field.
    pub label: String,
    /// Pre-filled value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Placeholder shown while the field is empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    /// Single-line vs multi-line.
    #[serde(default)]
    pub style: TextInputStyle,
    /// Field is mandatory at submit time.
    #[serde(default = "default_required")]
    pub required: bool,
    /// Maximum character length (0 = unlimited).
    #[serde(default)]
    pub max_length: u32,
    /// Minimum character length (0 = unenforced).
    #[serde(default)]
    pub min_length: u32,
}

fn default_required() -> bool {
    true
}

/// Layout style for a [`TextInput`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum TextInputStyle {
    /// Single-line input.
    #[default]
    Short,
    /// Multi-line text area.
    Paragraph,
}

impl TextInput {
    /// Build a single-line [`TextInput`].
    #[must_use]
    pub fn new(custom_id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            custom_id: custom_id.into(),
            label: label.into(),
            value: None,
            placeholder: None,
            style: TextInputStyle::default(),
            required: true,
            max_length: 0,
            min_length: 0,
        }
    }

    /// Begin a [`TextInputBuilder`] whose `custom_id` is filled in by
    /// the matching `#[modal]` handler's auto-generated field constant.
    #[must_use]
    pub fn label(label: impl Into<String>) -> TextInputBuilder {
        TextInputBuilder {
            label: label.into(),
            value: None,
            placeholder: None,
            style: TextInputStyle::default(),
            required: true,
            max_length: 0,
            min_length: 0,
        }
    }

    /// Pre-fill the field.
    #[must_use]
    pub fn value(mut self, v: impl Into<String>) -> Self {
        self.value = Some(v.into());
        self
    }

    /// Set the empty-state placeholder.
    #[must_use]
    pub fn placeholder(mut self, p: impl Into<String>) -> Self {
        self.placeholder = Some(p.into());
        self
    }

    /// Single-line vs multi-line layout.
    #[must_use]
    pub fn style(mut self, s: TextInputStyle) -> Self {
        self.style = s;
        self
    }

    /// Whether the field must be filled in to submit the modal.
    #[must_use]
    pub fn required(mut self, r: bool) -> Self {
        self.required = r;
        self
    }

    /// Hard limit on the number of characters accepted.  `0` = no cap.
    #[must_use]
    pub fn max_length(mut self, n: u32) -> Self {
        self.max_length = n;
        self
    }

    /// Minimum number of characters required.  `0` = unenforced.
    #[must_use]
    pub fn min_length(mut self, n: u32) -> Self {
        self.min_length = n;
        self
    }
}

impl From<TextInput> for Component {
    fn from(t: TextInput) -> Self {
        Self::TextInput(t)
    }
}

/// Deferred-id builder for [`TextInput`].  Produced by
/// [`TextInput::label`].  The `show_modal!` macro turns it back into a
/// [`TextInput`] via [`Self::build`].
#[derive(Debug, Clone)]
pub struct TextInputBuilder {
    label: String,
    value: Option<String>,
    placeholder: Option<String>,
    style: TextInputStyle,
    required: bool,
    max_length: u32,
    min_length: u32,
}

impl TextInputBuilder {
    /// Pre-fill the field.
    #[must_use]
    pub fn value(mut self, v: impl Into<String>) -> Self {
        self.value = Some(v.into());
        self
    }
    /// Set the empty-state placeholder.
    #[must_use]
    pub fn placeholder(mut self, p: impl Into<String>) -> Self {
        self.placeholder = Some(p.into());
        self
    }
    /// Single-line vs multi-line layout.
    #[must_use]
    pub fn style(mut self, s: TextInputStyle) -> Self {
        self.style = s;
        self
    }
    /// Whether the field must be filled in to submit the modal.
    #[must_use]
    pub fn required(mut self, r: bool) -> Self {
        self.required = r;
        self
    }
    /// Maximum character length.
    #[must_use]
    pub fn max_length(mut self, n: u32) -> Self {
        self.max_length = n;
        self
    }
    /// Minimum character length.
    #[must_use]
    pub fn min_length(mut self, n: u32) -> Self {
        self.min_length = n;
        self
    }
    /// Finalise the builder by attaching a `custom_id`.
    #[must_use]
    pub fn build(self, custom_id: impl Into<String>) -> TextInput {
        TextInput {
            custom_id: custom_id.into(),
            label: self.label,
            value: self.value,
            placeholder: self.placeholder,
            style: self.style,
            required: self.required,
            max_length: self.max_length,
            min_length: self.min_length,
        }
    }
}

/// Build a [`TextInput`].
///
/// ```ignore
/// use mumble_plugin_api::text_input;
/// let f = text_input!("name", "Your name", placeholder = "anonymous");
/// ```
#[macro_export]
macro_rules! text_input {
    ($custom_id:expr, $label:expr $(, $($rest:tt)*)? ) => {{
        #[allow(unused_mut, reason = "macro-generated when no modifiers are given")]
        let mut __t = $crate::components::TextInput::new($custom_id, $label);
        $( $crate::__text_input_modifier!(__t; $($rest)*); )?
        __t
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __text_input_modifier {
    ($t:ident; value = $v:expr $(, $($rest:tt)*)?) => {
        $t = $t.value($v);
        $( $crate::__text_input_modifier!($t; $($rest)*); )?
    };
    ($t:ident; placeholder = $p:expr $(, $($rest:tt)*)?) => {
        $t = $t.placeholder($p);
        $( $crate::__text_input_modifier!($t; $($rest)*); )?
    };
    ($t:ident; max_length = $n:expr $(, $($rest:tt)*)?) => {
        $t = $t.max_length($n);
        $( $crate::__text_input_modifier!($t; $($rest)*); )?
    };
    ($t:ident; min_length = $n:expr $(, $($rest:tt)*)?) => {
        $t = $t.min_length($n);
        $( $crate::__text_input_modifier!($t; $($rest)*); )?
    };
    ($t:ident; required = $r:expr $(, $($rest:tt)*)?) => {
        $t = $t.required($r);
        $( $crate::__text_input_modifier!($t; $($rest)*); )?
    };
    ($t:ident; paragraph $(, $($rest:tt)*)?) => {
        $t = $t.style($crate::components::TextInputStyle::Paragraph);
        $( $crate::__text_input_modifier!($t; $($rest)*); )?
    };
    ($t:ident; short $(, $($rest:tt)*)?) => {
        $t = $t.style($crate::components::TextInputStyle::Short);
        $( $crate::__text_input_modifier!($t; $($rest)*); )?
    };
    ($t:ident;) => {};
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "tests panic on failure")]
    use super::*;

    #[test]
    fn label_builder_round_trip() {
        let ti = TextInput::label("Message").required(false).build("msg");
        assert_eq!(ti.custom_id, "msg");
        assert!(!ti.required);
    }

    #[test]
    fn macro_with_paragraph_modifier() {
        let t = text_input!("body", "Body", paragraph, max_length = 200);
        assert_eq!(t.style, TextInputStyle::Paragraph);
        assert_eq!(t.max_length, 200);
    }
}
