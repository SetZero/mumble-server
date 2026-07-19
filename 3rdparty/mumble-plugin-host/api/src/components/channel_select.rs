//! [`ChannelSelect`] - pick one or more Mumble channels.  Discord
//! component type `8`.  Returned values are Mumble `ChannelId`s
//! (stringified on the wire).

use serde::{Deserialize, Serialize};

use super::Component;

/// Channel picker auto-populated by the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelSelect {
    /// Echoed in [`InteractionKind::Component::custom_id`](crate::InteractionKind::Component).
    pub custom_id: String,
    /// Placeholder shown when no value is selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    /// Default-selected channel ids.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_values: Vec<crate::ChannelId>,
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

fn default_min() -> u32 {
    1
}
fn default_max() -> u32 {
    1
}
fn default_required() -> bool {
    true
}

impl ChannelSelect {
    /// Build a single-pick channel select.
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

    /// Pre-select these channel ids.
    #[must_use]
    pub fn default_values<I: IntoIterator<Item = crate::ChannelId>>(mut self, ids: I) -> Self {
        self.default_values.extend(ids);
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

impl From<ChannelSelect> for Component {
    fn from(s: ChannelSelect) -> Self {
        Self::ChannelSelect(s)
    }
}

/// Build a [`ChannelSelect`].  Same modifier set as
/// [`user_select!`](crate::user_select).
#[macro_export]
macro_rules! channel_select {
    ($custom_id:expr $(, $($rest:tt)*)? ) => {{
        #[allow(unused_mut, reason = "macro-generated when no modifiers are given")]
        let mut __s = $crate::components::ChannelSelect::new($custom_id);
        $( $crate::__select_modifier!(__s; $($rest)*); )?
        __s
    }};
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "tests panic on failure")]
    use super::*;

    #[test]
    fn wire_tag() {
        let c: Component = ChannelSelect::new("ch").into();
        let json = serde_json::to_string(&c).expect("encode");
        assert!(json.contains("\"type\":\"channel-select\""));
    }
}
