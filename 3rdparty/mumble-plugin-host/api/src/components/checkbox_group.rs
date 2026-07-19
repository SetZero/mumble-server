//! [`CheckboxGroup`] - multi-choice option set.  Discord component
//! type `22`.  Available in modal forms and in chat-bubble /
//! overlay component trees: the client renders it as a vertical
//! stack of native checkbox inputs in both contexts.

use serde::{Deserialize, Serialize};

use super::Component;

/// Multi-choice option set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckboxGroup {
    /// Echoed in the modal-submit payload.
    pub custom_id: String,
    /// 1-10 options.
    pub options: Vec<CheckboxOption>,
    /// Minimum number of options that must be checked (default 1).
    #[serde(default = "default_min")]
    pub min_values: u32,
    /// Maximum number of options that may be checked (default = number
    /// of options).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_values: Option<u32>,
    /// Whether selection is required (defaults to `true`).
    #[serde(default = "default_required")]
    pub required: bool,
}

/// One option in a [`CheckboxGroup`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckboxOption {
    /// Dev-defined value.
    pub value: String,
    /// User-facing label.
    pub label: String,
    /// Optional description shown under the label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Mark as preselected.
    #[serde(default, skip_serializing_if = "is_false")]
    pub default: bool,
}

fn default_min() -> u32 {
    1
}
fn default_required() -> bool {
    true
}
fn is_false(b: &bool) -> bool {
    !*b
}

impl CheckboxGroup {
    /// Build an empty group.
    #[must_use]
    pub fn new(custom_id: impl Into<String>) -> Self {
        Self {
            custom_id: custom_id.into(),
            options: Vec::new(),
            min_values: default_min(),
            max_values: None,
            required: default_required(),
        }
    }

    /// Append an option.
    #[must_use]
    pub fn option(mut self, option: CheckboxOption) -> Self {
        self.options.push(option);
        self
    }

    /// Extend with a batch of options.
    #[must_use]
    pub fn options<I: IntoIterator<Item = CheckboxOption>>(mut self, iter: I) -> Self {
        self.options.extend(iter);
        self
    }

    /// Minimum number of checks required.
    #[must_use]
    pub fn min_values(mut self, n: u32) -> Self {
        self.min_values = n;
        self
    }

    /// Maximum number of checks allowed.
    #[must_use]
    pub fn max_values(mut self, n: u32) -> Self {
        self.max_values = Some(n);
        self
    }

    /// Mark required / optional.
    #[must_use]
    pub fn required(mut self, required: bool) -> Self {
        self.required = required;
        self
    }
}

impl CheckboxOption {
    /// Build a [`CheckboxOption`].
    #[must_use]
    pub fn new(value: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            label: label.into(),
            description: None,
            default: false,
        }
    }

    /// Attach a description.
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

impl From<CheckboxGroup> for Component {
    fn from(c: CheckboxGroup) -> Self {
        Self::CheckboxGroup(c)
    }
}

/// Build a [`CheckboxGroup`].
///
/// ```ignore
/// use mumble_plugin_api::checkbox_group;
/// let g = checkbox_group!("topics", [
///     "rust"  => "Rust",
///     "audio" => "Audio",
/// ]);
/// ```
#[macro_export]
macro_rules! checkbox_group {
    ($custom_id:expr, [ $($value:expr => $label:expr),* $(,)? ] $(,)?) => {
        $crate::components::CheckboxGroup::new($custom_id)
            $( .option($crate::components::CheckboxOption::new($value, $label)) )*
    };
}

#[cfg(test)]
mod tests {

    #[test]
    fn macro_builds_options() {
        let g = checkbox_group!("t", ["a" => "A", "b" => "B"]);
        assert_eq!(g.options.len(), 2);
    }
}
