//! [`Container`] - layout wrapper with optional accent colour.
//! Discord component type `17`.

use serde::{Deserialize, Serialize};

use super::Component;

/// Visual grouping around a list of components.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Container {
    /// Child components (action rows, text displays, sections, ...).
    pub components: Vec<Component>,
    /// 24-bit RGB accent colour (`0x000000`–`0xFFFFFF`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accent_color: Option<u32>,
    /// Render blurred until clicked.
    #[serde(default, skip_serializing_if = "is_false")]
    pub spoiler: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl Container {
    /// Build an empty container.
    #[must_use]
    pub fn new() -> Self {
        Self {
            components: Vec::new(),
            accent_color: None,
            spoiler: false,
        }
    }

    /// Append a child component.
    #[must_use]
    pub fn push(mut self, c: impl Into<Component>) -> Self {
        self.components.push(c.into());
        self
    }

    /// Set the accent colour (24-bit RGB).
    #[must_use]
    pub fn accent_color(mut self, color: u32) -> Self {
        self.accent_color = Some(color);
        self
    }

    /// Mark the container as a spoiler.
    #[must_use]
    pub fn spoiler(mut self, spoiler: bool) -> Self {
        self.spoiler = spoiler;
        self
    }
}

impl Default for Container {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Container> for Component {
    fn from(c: Container) -> Self {
        Self::Container(c)
    }
}

/// Build a [`Container`] with a comma-separated list of children.
///
/// ```ignore
/// use mumble_plugin_api::{container, text_display, separator, button};
/// let c = container![
///     text_display!("# Header"),
///     separator!(),
///     button!("ok", "OK");
///     accent_color = 0xff_aa_00,
///     spoiler,
/// ];
/// ```
///
/// Children appear before the optional `;` delimiter; container-level
/// modifiers follow it.
#[macro_export]
macro_rules! container {
    [ $($child:expr),* $(,)? $(; $($modifier:tt)+ )? ] => {{
        #[allow(unused_mut, reason = "macro-generated when no children/modifiers are given")]
        let mut __c = $crate::components::Container::new();
        $( __c = __c.push($child); )*
        $( $crate::__container_modifier!(__c; $($modifier)+); )?
        __c
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __container_modifier {
    ($c:ident; accent_color = $color:expr $(, $($rest:tt)*)?) => {
        $c = $c.accent_color($color);
        $( $crate::__container_modifier!($c; $($rest)*); )?
    };
    ($c:ident; spoiler $(, $($rest:tt)*)?) => {
        $c = $c.spoiler(true);
        $( $crate::__container_modifier!($c; $($rest)*); )?
    };
    ($c:ident;) => {};
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "tests panic on failure")]
    use crate::components::TextDisplay;

    #[test]
    fn macro_children_only() {
        let c = container![TextDisplay::new("hi")];
        assert_eq!(c.components.len(), 1);
        assert!(c.accent_color.is_none());
    }

    #[test]
    fn macro_with_modifiers() {
        let c = container![TextDisplay::new("hi"); accent_color = 0xff00ff, spoiler];
        assert_eq!(c.accent_color, Some(0x00ff_00ff));
        assert!(c.spoiler);
    }
}
