//! [`Separator`] - vertical spacer / divider.  Discord component
//! type `14`.

use serde::{Deserialize, Serialize};

use super::Component;

/// Vertical spacer between components.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Separator {
    /// Render a visible divider line in the spacer.  Defaults to `true`.
    #[serde(default = "default_divider")]
    pub divider: bool,
    /// Padding amount.  Defaults to [`SeparatorSpacing::Small`].
    #[serde(default)]
    pub spacing: SeparatorSpacing,
}

fn default_divider() -> bool {
    true
}

/// Padding amount for a [`Separator`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SeparatorSpacing {
    /// Small padding.
    #[default]
    Small,
    /// Large padding.
    Large,
}

impl Separator {
    /// Build a default [`Separator`] (divider on, small spacing).
    #[must_use]
    pub fn new() -> Self {
        Self {
            divider: default_divider(),
            spacing: SeparatorSpacing::default(),
        }
    }

    /// Toggle the divider line.
    #[must_use]
    pub fn divider(mut self, divider: bool) -> Self {
        self.divider = divider;
        self
    }

    /// Set the padding amount.
    #[must_use]
    pub fn spacing(mut self, spacing: SeparatorSpacing) -> Self {
        self.spacing = spacing;
        self
    }
}

impl Default for Separator {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Separator> for Component {
    fn from(s: Separator) -> Self {
        Self::Separator(s)
    }
}

/// Build a [`Separator`].
///
/// ```ignore
/// use mumble_plugin_api::separator;
/// let s = separator!();                       // default
/// let s = separator!(no_divider);             // spacer-only
/// let s = separator!(spacing = Large);        // large padding
/// ```
#[macro_export]
macro_rules! separator {
    () => {
        $crate::components::Separator::new()
    };
    ( $($rest:tt)+ ) => {{
        #[allow(unused_mut, reason = "macro-generated when no modifiers are given")]
        let mut __s = $crate::components::Separator::new();
        $crate::__separator_modifier!(__s; $($rest)+);
        __s
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __separator_modifier {
    ($s:ident; no_divider $(, $($rest:tt)*)?) => {
        $s = $s.divider(false);
        $( $crate::__separator_modifier!($s; $($rest)*); )?
    };
    ($s:ident; spacing = $sp:ident $(, $($rest:tt)*)?) => {
        $s = $s.spacing($crate::components::SeparatorSpacing::$sp);
        $( $crate::__separator_modifier!($s; $($rest)*); )?
    };
    ($s:ident;) => {};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macro_defaults() {
        let s = separator!();
        assert!(s.divider);
        assert_eq!(s.spacing, SeparatorSpacing::Small);
    }

    #[test]
    fn macro_no_divider() {
        let s = separator!(no_divider, spacing = Large);
        assert!(!s.divider);
        assert_eq!(s.spacing, SeparatorSpacing::Large);
    }
}
