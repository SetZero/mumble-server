//! [`MentionableSelect`] - pick a mix of users and ACL roles.  Discord
//! component type `7`.  Returned values are tagged with their kind so
//! the receiving plugin can route them correctly.

use serde::{Deserialize, Serialize};

use super::Component;

/// Mixed user-and-role picker auto-populated by the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MentionableSelect {
    /// Echoed in [`InteractionKind::Component::custom_id`](crate::InteractionKind::Component).
    pub custom_id: String,
    /// Placeholder shown when no value is selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    /// Default-selected mentionables.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_values: Vec<Mentionable>,
    /// Minimum picks (default 1).
    #[serde(default = "default_min")]
    pub min_values: u32,
    /// Maximum picks (default 1).
    #[serde(default = "default_max")]
    pub max_values: u32,
    /// Disable (messages only).
    #[serde(default)]
    pub disabled: bool,
    /// Required (modals only).
    #[serde(default = "default_required")]
    pub required: bool,
}

/// A single selected mentionable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Mentionable {
    /// Connected user, identified by session id.
    User {
        /// Mumble session id.
        id: crate::SessionId,
    },
    /// ACL group, identified by name.
    Role {
        /// ACL group name.
        name: String,
    },
}

fn default_min() -> u32 {
    1
}
fn default_max() -> u32 {
    1
}
fn default_required() -> bool {
    true
}

impl MentionableSelect {
    /// Build a single-pick mentionable select.
    #[must_use]
    pub fn new(custom_id: impl Into<String>) -> Self {
        Self {
            custom_id: custom_id.into(),
            placeholder: None,
            default_values: Vec::new(),
            min_values: default_min(),
            max_values: default_max(),
            disabled: false,
            required: default_required(),
        }
    }

    /// Set the empty-state placeholder.
    #[must_use]
    pub fn placeholder(mut self, p: impl Into<String>) -> Self {
        self.placeholder = Some(p.into());
        self
    }

    /// Pre-select these mentionables.
    #[must_use]
    pub fn default_values<I: IntoIterator<Item = Mentionable>>(mut self, items: I) -> Self {
        self.default_values.extend(items);
        self
    }

    /// Minimum picks.
    #[must_use]
    pub fn min_values(mut self, n: u32) -> Self {
        self.min_values = n;
        self
    }

    /// Maximum picks.
    #[must_use]
    pub fn max_values(mut self, n: u32) -> Self {
        self.max_values = n;
        self
    }

    /// Disable (messages only).
    #[must_use]
    pub fn disabled(mut self, disabled: bool) -> Self {
        self.disabled = disabled;
        self
    }

    /// Required (modals only).
    #[must_use]
    pub fn required(mut self, required: bool) -> Self {
        self.required = required;
        self
    }
}

impl From<MentionableSelect> for Component {
    fn from(s: MentionableSelect) -> Self {
        Self::MentionableSelect(s)
    }
}

/// Build a [`MentionableSelect`].  Same modifier set as
/// [`user_select!`](crate::user_select).
#[macro_export]
macro_rules! mentionable_select {
    ($custom_id:expr $(, $($rest:tt)*)? ) => {{
        #[allow(unused_mut, reason = "macro-generated when no modifiers are given")]
        let mut __s = $crate::components::MentionableSelect::new($custom_id);
        $( $crate::__select_modifier!(__s; $($rest)*); )?
        __s
    }};
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "tests panic on failure")]
    use super::*;

    #[test]
    fn mentionable_tags_kind() {
        let m = Mentionable::User { id: 7 };
        let json = serde_json::to_string(&m).expect("encode");
        assert!(json.contains("\"kind\":\"user\""));
        let m = Mentionable::Role {
            name: "admins".into(),
        };
        let json = serde_json::to_string(&m).expect("encode");
        assert!(json.contains("\"kind\":\"role\""));
    }
}
