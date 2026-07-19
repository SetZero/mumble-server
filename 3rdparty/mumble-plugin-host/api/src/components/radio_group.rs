//! [`RadioGroup`] - single-choice option set.  Discord component
//! type `21`.  Available in modal forms and in chat-bubble /
//! overlay component trees: the client renders it as a vertical
//! stack of native radio inputs in both contexts.

use serde::{Deserialize, Serialize};

use super::Component;

/// Single-choice option set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadioGroup {
    /// Echoed in the modal-submit payload.
    pub custom_id: String,
    /// 2-10 options.
    pub options: Vec<RadioOption>,
    /// Whether a selection is required (defaults to `true`).
    #[serde(default = "default_required")]
    pub required: bool,
}

/// One option in a [`RadioGroup`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadioOption {
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

fn default_required() -> bool {
    true
}
fn is_false(b: &bool) -> bool {
    !*b
}

impl RadioGroup {
    /// Build an empty radio group.  Chain [`Self::option`] to populate.
    #[must_use]
    pub fn new(custom_id: impl Into<String>) -> Self {
        Self {
            custom_id: custom_id.into(),
            options: Vec::new(),
            required: default_required(),
        }
    }

    /// Append an option.
    #[must_use]
    pub fn option(mut self, option: RadioOption) -> Self {
        self.options.push(option);
        self
    }

    /// Extend with a batch of options.
    #[must_use]
    pub fn options<I: IntoIterator<Item = RadioOption>>(mut self, iter: I) -> Self {
        self.options.extend(iter);
        self
    }

    /// Mark required / optional.
    #[must_use]
    pub fn required(mut self, required: bool) -> Self {
        self.required = required;
        self
    }
}

impl RadioOption {
    /// Build a [`RadioOption`].
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

impl From<RadioGroup> for Component {
    fn from(r: RadioGroup) -> Self {
        Self::RadioGroup(r)
    }
}

/// Build a [`RadioGroup`].
///
/// ```ignore
/// use mumble_plugin_api::radio_group;
/// let r = radio_group!("priority", [
///     "low"  => "Low",
///     "med"  => "Medium",
///     "high" => "High",
/// ]);
/// ```
#[macro_export]
macro_rules! radio_group {
    ($custom_id:expr, [ $($value:expr => $label:expr),* $(,)? ] $(,)?) => {
        $crate::components::RadioGroup::new($custom_id)
            $( .option($crate::components::RadioOption::new($value, $label)) )*
    };
}

#[cfg(test)]
mod tests {

    #[test]
    fn macro_builds_options() {
        let r = radio_group!("p", [
            "low"  => "Low",
            "high" => "High",
        ]);
        assert_eq!(r.options.len(), 2);
    }
}
