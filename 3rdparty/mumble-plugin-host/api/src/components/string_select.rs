//! [`StringSelect`] - dropdown of developer-defined string options.
//! Discord component type `3`.
//!
//! Previously named `SelectMenu` in this crate; the rename brings the
//! type in line with the Discord naming.  The wire tag accepts both
//! `"string-select"` (canonical) and `"select-menu"` (legacy alias).

use serde::{Deserialize, Serialize};

use super::Component;

/// Dropdown picker over an explicit set of [`SelectOption`]s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringSelect {
    /// Echoed verbatim in
    /// [`InteractionKind::Component::custom_id`](crate::InteractionKind::Component).
    pub custom_id: String,
    /// Placeholder shown when no value is selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    /// Picker entries; 1 to 25.
    pub options: Vec<SelectOption>,
    /// Minimum number of values the user must pick (default 1).
    #[serde(default = "default_min_values")]
    pub min_values: u32,
    /// Maximum number of values the user may pick (default 1, max 25).
    #[serde(default = "default_max_values")]
    pub max_values: u32,
    /// When `true`, the select renders but cannot be opened.  Ignored
    /// inside modals.
    #[serde(default)]
    pub disabled: bool,
    /// Modal-only: whether the user must answer (defaults to `true`).
    #[serde(default = "default_required")]
    pub required: bool,
}

fn default_min_values() -> u32 {
    1
}
fn default_max_values() -> u32 {
    1
}
fn default_required() -> bool {
    true
}

/// One entry in a [`StringSelect`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectOption {
    /// User-facing label.
    pub label: String,
    /// Dev-defined value returned in the interaction payload.
    pub value: String,
    /// Optional sub-label rendered under the main label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Mark the option as preselected.
    #[serde(default, skip_serializing_if = "is_false")]
    pub default: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl StringSelect {
    /// Build an empty single-select.  Chain [`Self::option`] to populate.
    #[must_use]
    pub fn new(custom_id: impl Into<String>) -> Self {
        Self {
            custom_id: custom_id.into(),
            placeholder: None,
            options: Vec::new(),
            min_values: default_min_values(),
            max_values: default_max_values(),
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

    /// Append a single option.
    #[must_use]
    pub fn option(mut self, option: SelectOption) -> Self {
        self.options.push(option);
        self
    }

    /// Extend with a batch of options.
    #[must_use]
    pub fn options<I: IntoIterator<Item = SelectOption>>(mut self, iter: I) -> Self {
        self.options.extend(iter);
        self
    }

    /// Minimum number of values the user must pick.
    #[must_use]
    pub fn min_values(mut self, n: u32) -> Self {
        self.min_values = n;
        self
    }

    /// Maximum number of values the user may pick.
    #[must_use]
    pub fn max_values(mut self, n: u32) -> Self {
        self.max_values = n;
        self
    }

    /// Disable the menu (messages only).
    #[must_use]
    pub fn disabled(mut self, disabled: bool) -> Self {
        self.disabled = disabled;
        self
    }

    /// Mark as required / optional (modals only).
    #[must_use]
    pub fn required(mut self, required: bool) -> Self {
        self.required = required;
        self
    }
}

impl SelectOption {
    /// Build a [`SelectOption`].
    #[must_use]
    pub fn new(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
            description: None,
            default: false,
        }
    }

    /// Attach a sub-label.
    #[must_use]
    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.description = Some(d.into());
        self
    }

    /// Mark as preselected.
    #[must_use]
    pub fn default(mut self, default: bool) -> Self {
        self.default = default;
        self
    }
}

impl From<StringSelect> for Component {
    fn from(s: StringSelect) -> Self {
        Self::StringSelect(s)
    }
}

/// Source-level alias for backward compatibility with code written
/// against the old `SelectMenu` name.
pub type SelectMenu = StringSelect;

/// Build a [`StringSelect`] from a `custom_id` and a `[label => value]`
/// option list.
///
/// ```ignore
/// use mumble_plugin_api::string_select;
/// let s = string_select!("colour", [
///     "Red"   => "r",
///     "Green" => "g",
///     "Blue"  => "b",
/// ]);
/// ```
#[macro_export]
macro_rules! string_select {
    ($custom_id:expr, [ $($label:expr => $value:expr),* $(,)? ] $(,)?) => {
        $crate::components::StringSelect::new($custom_id)
            $( .option($crate::components::SelectOption::new($label, $value)) )*
    };
    ($custom_id:expr $(,)?) => {
        $crate::components::StringSelect::new($custom_id)
    };
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "tests panic on failure")]
    use super::*;

    #[test]
    fn macro_builds_options() {
        let s = string_select!("c", [
            "Red" => "r",
            "Green" => "g",
        ]);
        assert_eq!(s.options.len(), 2);
        assert_eq!(s.options[0].label, "Red");
    }

    #[test]
    fn wire_accepts_legacy_alias() {
        let legacy = r#"{"type":"select-menu","custom_id":"c","options":[]}"#;
        let parsed: Component = serde_json::from_str(legacy).expect("decode");
        assert!(matches!(parsed, Component::StringSelect(_)));
    }
}
