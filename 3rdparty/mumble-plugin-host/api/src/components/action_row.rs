//! [`ActionRow`] - horizontal container for up to five interactive
//! components.
//!
//! Mirrors Discord's component type `1`.  Used both at message
//! top-level (button row, single select) and inside [`Container`].
//!
//! [`Container`]: crate::components::Container

use serde::{Deserialize, Serialize};

use super::Component;

/// Horizontal row of interactive components.
///
/// Discord limits: up to 5 buttons, **or** a single select-style
/// component (string / user / role / mentionable / channel).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActionRow {
    /// Components rendered left-to-right inside this row.
    pub components: Vec<Component>,
}

impl ActionRow {
    /// Build an empty row.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a single component.
    #[must_use]
    pub fn push(mut self, component: impl Into<Component>) -> Self {
        self.components.push(component.into());
        self
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "tests panic on failure")]
    use super::*;
    use crate::components::Button;

    #[test]
    fn push_chains() {
        let row = ActionRow::new()
            .push(Button::new("a", "A"))
            .push(Button::new("b", "B"));
        assert_eq!(row.components.len(), 2);
    }

    #[test]
    fn serializes_components_array() {
        let row = ActionRow::new().push(Button::new("a", "A"));
        let json = serde_json::to_string(&row).expect("encode");
        assert!(json.contains("\"components\""));
        assert!(json.contains("\"type\":\"button\""));
    }
}
