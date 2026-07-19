//! [`RoleSelect`] - pick one or more roles.  Discord component type
//! `6`.  Mumble has no native role concept; the closest analogue is
//! ACL group membership, so a `RoleSelect` returns ACL group names.

use serde::{Deserialize, Serialize};

use super::Component;

/// Role / ACL-group picker auto-populated by the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleSelect {
    /// Echoed in [`InteractionKind::Component::custom_id`](crate::InteractionKind::Component).
    pub custom_id: String,
    /// Placeholder shown when no value is selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    /// Default-selected ACL group names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_values: Vec<String>,
    /// Minimum number of roles that must be picked (default 1).
    #[serde(default = "default_min")]
    pub min_values: u32,
    /// Maximum number of roles that may be picked (default 1).
    #[serde(default = "default_max")]
    pub max_values: u32,
    /// Disable (messages only).
    #[serde(default)]
    pub disabled: bool,
    /// Required (modals only).
    #[serde(default = "default_required")]
    pub required: bool,
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

impl RoleSelect {
    /// Build a single-pick role select.
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

    /// Pre-select these ACL group names.
    #[must_use]
    pub fn default_values<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.default_values
            .extend(names.into_iter().map(Into::into));
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

impl From<RoleSelect> for Component {
    fn from(s: RoleSelect) -> Self {
        Self::RoleSelect(s)
    }
}

/// Build a [`RoleSelect`].  Accepts the same modifiers as
/// [`user_select!`](crate::user_select).
#[macro_export]
macro_rules! role_select {
    ($custom_id:expr $(, $($rest:tt)*)? ) => {{
        #[allow(unused_mut, reason = "macro-generated when no modifiers are given")]
        let mut __s = $crate::components::RoleSelect::new($custom_id);
        $( $crate::__select_modifier!(__s; $($rest)*); )?
        __s
    }};
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "tests panic on failure")]
    use super::*;

    #[test]
    fn wire_tag_is_role_select() {
        let json = serde_json::to_string(&Component::from(RoleSelect::new("r"))).expect("encode");
        assert!(json.contains("\"type\":\"role-select\""));
    }

    #[test]
    fn macro_chain() {
        let s = role_select!("r", placeholder = "Pick role", max = 2);
        assert_eq!(s.max_values, 2);
    }
}
