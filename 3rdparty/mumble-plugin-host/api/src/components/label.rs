//! [`Label`] - modal-only wrapper that associates a label and
//! description with a single child component.  Discord component type
//! `18`.
//!
//! Replaces the deprecated pattern of placing a [`TextInput`] inside
//! an [`ActionRow`] in modals.
//!
//! [`TextInput`]: crate::components::TextInput
//! [`ActionRow`]: crate::components::ActionRow

use serde::{Deserialize, Serialize};

use super::Component;

/// Modal-only label wrapping a single child component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Label {
    /// Label text (max 45 characters; clients may truncate).
    pub label: String,
    /// Optional description rendered alongside the label (max 100
    /// characters).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The wrapped component.  Allowed: text input, any select, file
    /// upload, radio group, checkbox group, checkbox.
    pub component: Box<Component>,
}

impl Label {
    /// Build a [`Label`] wrapping `component`.
    #[must_use]
    pub fn new(label: impl Into<String>, component: impl Into<Component>) -> Self {
        Self {
            label: label.into(),
            description: None,
            component: Box::new(component.into()),
        }
    }

    /// Attach an optional description.
    #[must_use]
    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.description = Some(d.into());
        self
    }
}

impl From<Label> for Component {
    fn from(l: Label) -> Self {
        Self::Label(l)
    }
}

/// Build a [`Label`].
///
/// ```ignore
/// use mumble_plugin_api::{label, text_input};
/// let l = label!("Your name", text_input!("name", ""));
/// let l = label!("Your name", text_input!("name", ""); description = "as it appears on the bill");
/// ```
#[macro_export]
macro_rules! label {
    ($label:expr, $component:expr $(,)?) => {
        $crate::components::Label::new($label, $component)
    };
    ($label:expr, $component:expr; description = $d:expr $(,)?) => {
        $crate::components::Label::new($label, $component).description($d)
    };
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "tests panic on failure")]
    use super::*;
    use crate::components::TextInput;

    #[test]
    fn macro_builds_label() {
        let l = label!("Name", TextInput::new("name", ""));
        assert_eq!(l.label, "Name");
        assert!(matches!(*l.component, Component::TextInput(_)));
    }

    #[test]
    fn macro_with_description() {
        let l = label!("Name", TextInput::new("name", ""); description = "Full name");
        assert_eq!(l.description.as_deref(), Some("Full name"));
    }
}
