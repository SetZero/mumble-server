//! [`ModalFieldValue`] — typed value carried back from a modal
//! component on submit.
//!
//! Text inputs report a `String`; checkboxes report a `Bool`;
//! radio groups report a single `String`; checkbox groups and string
//! selects report a list of `String`s; user / channel / role selects
//! report typed id lists; file uploads report a list of Fancy Mumble
//! file ids.
//!
//! Plugins built against the typed `#[modal]` derive macro consume
//! these values via the [`FromField`](crate::FromField) trait.  Legacy
//! plugins keep using the string-only
//! [`InteractionKind::ModalSubmit::values`](crate::InteractionKind::ModalSubmit)
//! map, which the host populates by stringifying applicable
//! `ModalFieldValue`s.

use serde::{Deserialize, Serialize};

/// Typed value returned by a modal component at submit time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ModalFieldValue {
    /// Free-form text (from [`TextInput`](crate::components::TextInput)
    /// or [`RadioGroup`](crate::components::RadioGroup)).
    String {
        /// The submitted text.
        value: String,
    },
    /// Boolean (from [`Checkbox`](crate::components::Checkbox)).
    Bool {
        /// The submitted state.
        value: bool,
    },
    /// Selected string values (from
    /// [`StringSelect`](crate::components::StringSelect) or
    /// [`CheckboxGroup`](crate::components::CheckboxGroup)).
    Strings {
        /// The submitted values.
        values: Vec<String>,
    },
    /// Selected session ids (from
    /// [`UserSelect`](crate::components::UserSelect)).
    Users {
        /// The submitted session ids.
        values: Vec<crate::SessionId>,
    },
    /// Selected channel ids (from
    /// [`ChannelSelect`](crate::components::ChannelSelect)).
    Channels {
        /// The submitted channel ids.
        values: Vec<crate::ChannelId>,
    },
    /// Selected ACL group names (from
    /// [`RoleSelect`](crate::components::RoleSelect)).
    Roles {
        /// The submitted ACL group names.
        values: Vec<String>,
    },
    /// Selected mentionables (from
    /// [`MentionableSelect`](crate::components::MentionableSelect)).
    Mentionables {
        /// The submitted mentionables.
        values: Vec<crate::components::mentionable_select::Mentionable>,
    },
    /// Uploaded file ids (from
    /// [`FileUpload`](crate::components::FileUpload)).  Each entry is
    /// a Fancy Mumble file store id.
    Files {
        /// The uploaded file ids.
        values: Vec<String>,
    },
}

impl ModalFieldValue {
    /// Best-effort flattening for the legacy string-only modal map.
    /// Returns `None` for values whose natural representation isn't a
    /// single string (multi-selects, file uploads, ...).
    #[must_use]
    pub fn as_legacy_string(&self) -> Option<String> {
        match self {
            Self::String { value } => Some(value.clone()),
            Self::Bool { value } => Some(value.to_string()),
            Self::Strings { values } if values.len() == 1 => Some(values[0].clone()),
            Self::Users { values } if values.len() == 1 => Some(values[0].to_string()),
            Self::Channels { values } if values.len() == 1 => Some(values[0].to_string()),
            Self::Roles { values } if values.len() == 1 => Some(values[0].clone()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "tests panic on failure")]
    use super::*;

    #[test]
    fn round_trip_string() {
        let v = ModalFieldValue::String { value: "hi".into() };
        let json = serde_json::to_string(&v).expect("encode");
        assert!(json.contains("\"kind\":\"string\""));
        let back: ModalFieldValue = serde_json::from_str(&json).expect("decode");
        assert!(matches!(back, ModalFieldValue::String { value } if value == "hi"));
    }

    #[test]
    fn legacy_flatten() {
        assert_eq!(
            ModalFieldValue::Bool { value: true }
                .as_legacy_string()
                .as_deref(),
            Some("true")
        );
        assert_eq!(
            ModalFieldValue::Users { values: vec![7] }
                .as_legacy_string()
                .as_deref(),
            Some("7")
        );
        assert!(ModalFieldValue::Users { values: vec![1, 2] }
            .as_legacy_string()
            .is_none());
    }
}
