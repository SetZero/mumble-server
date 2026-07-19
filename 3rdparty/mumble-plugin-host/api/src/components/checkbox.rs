//! [`Checkbox`] - modal-only single yes/no checkbox.  Discord
//! component type `23`.

use serde::{Deserialize, Serialize};

use super::Component;

/// Single boolean checkbox (modal-only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkbox {
    /// Echoed in the modal-submit payload.
    pub custom_id: String,
    /// Initial checked state.
    #[serde(default, skip_serializing_if = "is_false")]
    pub default: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl Checkbox {
    /// Build an unchecked [`Checkbox`].
    #[must_use]
    pub fn new(custom_id: impl Into<String>) -> Self {
        Self {
            custom_id: custom_id.into(),
            default: false,
        }
    }

    /// Initial checked state.
    #[must_use]
    pub fn default(mut self, default: bool) -> Self {
        self.default = default;
        self
    }
}

impl From<Checkbox> for Component {
    fn from(c: Checkbox) -> Self {
        Self::Checkbox(c)
    }
}

/// Build a [`Checkbox`].
///
/// ```ignore
/// use mumble_plugin_api::checkbox;
/// let c = checkbox!("agree");
/// let c = checkbox!("agree", checked);
/// ```
#[macro_export]
macro_rules! checkbox {
    ($custom_id:expr $(,)?) => {
        $crate::components::Checkbox::new($custom_id)
    };
    ($custom_id:expr, checked $(,)?) => {
        $crate::components::Checkbox::new($custom_id).default(true)
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn macro_default_unchecked() {
        let c = checkbox!("a");
        assert!(!c.default);
    }

    #[test]
    fn macro_checked() {
        let c = checkbox!("a", checked);
        assert!(c.default);
    }
}
