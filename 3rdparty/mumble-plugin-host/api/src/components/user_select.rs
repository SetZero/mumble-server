//! [`UserSelect`] - pick one or more connected users.  Discord
//! component type `5`.  Returned values are Mumble `SessionId`s
//! (stringified on the wire).

use serde::{Deserialize, Serialize};

use super::Component;

/// User picker auto-populated by the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSelect {
    /// Echoed verbatim in
    /// [`InteractionKind::Component::custom_id`](crate::InteractionKind::Component).
    pub custom_id: String,
    /// Placeholder shown when no value is selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    /// Default-selected session ids.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_values: Vec<crate::SessionId>,
    /// Minimum number of users that must be picked (default 1).
    #[serde(default = "default_min")]
    pub min_values: u32,
    /// Maximum number of users that may be picked (default 1).
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

impl UserSelect {
    /// Build a single-pick user select.
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

    /// Pre-select these session ids.
    #[must_use]
    pub fn default_values<I: IntoIterator<Item = crate::SessionId>>(mut self, ids: I) -> Self {
        self.default_values.extend(ids);
        self
    }

    /// Minimum number of users that must be picked.
    #[must_use]
    pub fn min_values(mut self, n: u32) -> Self {
        self.min_values = n;
        self
    }

    /// Maximum number of users that may be picked.
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

impl From<UserSelect> for Component {
    fn from(s: UserSelect) -> Self {
        Self::UserSelect(s)
    }
}

/// Build a [`UserSelect`].
///
/// ```ignore
/// use mumble_plugin_api::user_select;
/// let s = user_select!("target", placeholder = "Pick a user", max = 3);
/// ```
#[macro_export]
macro_rules! user_select {
    ($custom_id:expr $(, $($rest:tt)*)? ) => {{
        #[allow(unused_mut, reason = "macro-generated when no modifiers are given")]
        let mut __s = $crate::components::UserSelect::new($custom_id);
        $( $crate::__select_modifier!(__s; $($rest)*); )?
        __s
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __select_modifier {
    ($s:ident; placeholder = $p:expr $(, $($rest:tt)*)?) => {
        $s = $s.placeholder($p);
        $( $crate::__select_modifier!($s; $($rest)*); )?
    };
    ($s:ident; min = $n:expr $(, $($rest:tt)*)?) => {
        $s = $s.min_values($n);
        $( $crate::__select_modifier!($s; $($rest)*); )?
    };
    ($s:ident; max = $n:expr $(, $($rest:tt)*)?) => {
        $s = $s.max_values($n);
        $( $crate::__select_modifier!($s; $($rest)*); )?
    };
    ($s:ident; disabled $(, $($rest:tt)*)?) => {
        $s = $s.disabled(true);
        $( $crate::__select_modifier!($s; $($rest)*); )?
    };
    ($s:ident; required = $r:expr $(, $($rest:tt)*)?) => {
        $s = $s.required($r);
        $( $crate::__select_modifier!($s; $($rest)*); )?
    };
    ($s:ident;) => {};
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "tests panic on failure")]
    use super::*;

    #[test]
    fn macro_with_modifiers() {
        let s = user_select!("target", placeholder = "Pick", min = 1, max = 3);
        assert_eq!(s.placeholder.as_deref(), Some("Pick"));
        assert_eq!(s.max_values, 3);
    }

    #[test]
    fn wire_round_trip() {
        let s: Component = UserSelect::new("u").into();
        let json = serde_json::to_string(&s).expect("encode");
        assert!(json.contains("\"type\":\"user-select\""));
        let back: Component = serde_json::from_str(&json).expect("decode");
        assert!(matches!(back, Component::UserSelect(_)));
    }
}
