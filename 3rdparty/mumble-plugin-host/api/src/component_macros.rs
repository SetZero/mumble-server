//! Declarative `macro_rules!` macros for building component-laden
//! [`InteractionResponse`](crate::InteractionResponse) values.
//!
//! These are pure sugar over the builders in [`crate::client_manifest`]
//! and [`crate::commands`].  They exist so the common shape of a
//! plugin response - a Markdown body plus a handful of buttons or a
//! modal form - can be written without repeating `InteractionResponse::`
//! and `Vec::new()` everywhere.
//!
//! Each macro returns an `InteractionResponse` (or, for [`row!`], an
//! `ActionRow`), so they compose with the regular builders via method
//! chaining:
//!
//! ```ignore
//! use mumble_plugin_api::{message, row, Button, ButtonStyle};
//! let resp = message!(
//!     "Pick one:",
//!     row![
//!         Button::new("ok",     "OK").style(ButtonStyle::Success),
//!         Button::new("cancel", "Cancel").style(ButtonStyle::Danger),
//!     ],
//! )
//! .ephemeral();
//! ```
//!
//! The `show_modal!` macro additionally wires up auto-generated ids from a
//! `#[modal]`-annotated handler method, so the response and the
//! handler share a single source of truth for the wire `custom_id`
//! and per-field keys.  See the [`mumble_plugin_api_derive::modal`]
//! attribute for the matching handler-side syntax.

/// Build a single [`crate::ActionRow`] from a comma-separated list of
/// components.  Each component must implement
/// `Into<`[`crate::Component`]`>` - i.e. anything produced by
/// [`crate::Button::new`], [`crate::SelectMenu::new`], or
/// [`crate::TextInput::new`].
///
/// ```ignore
/// use mumble_plugin_api::{row, Button, ButtonStyle};
/// let r = row![
///     Button::new("ok", "OK").style(ButtonStyle::Primary),
///     Button::new("no", "No"),
/// ];
/// ```
#[macro_export]
macro_rules! row {
    [ $($c:expr),* $(,)? ] => {
        $crate::ActionRow {
            components: ::std::vec![
                $( ::core::convert::Into::<$crate::Component>::into($c) ),*
            ],
        }
    };
}

/// Build a `Message`-kind [`crate::InteractionResponse`] from a body
/// and zero or more [`crate::ActionRow`]s.
///
/// The first argument is the Markdown body (`impl Into<String>`); the
/// remaining arguments are rows, typically produced by the [`row!`]
/// macro.  Returns an `InteractionResponse` so callers can chain
/// `.ephemeral()`, `.with_correlation_id(...)`, etc.
///
/// ```ignore
/// use mumble_plugin_api::{message, row, Button};
/// let resp = message!(
///     "Hello, world",
///     row![ Button::new("again", "Again") ],
/// )
/// .ephemeral();
/// ```
#[macro_export]
macro_rules! message {
    ($content:expr $(, $row:expr)* $(,)?) => {{
        #[allow(unused_mut, reason = "macro-generated when no rows are given")]
        let mut __r = $crate::InteractionResponse::message($content);
        $( __r = __r.row($row); )*
        __r
    }};
}

/// Build a `Toast`-kind [`crate::InteractionResponse`].
///
/// One-arg form uses [`crate::ToastLevel::Info`]; two-arg form takes
/// an explicit level.
///
/// ```ignore
/// use mumble_plugin_api::{toast, ToastLevel};
/// return toast!("Saved.");
/// return toast!(format!("Error: {e}"), ToastLevel::Error);
/// ```
#[macro_export]
macro_rules! toast {
    ($body:expr $(,)?) => {
        $crate::InteractionResponse::toast($body)
    };
    ($body:expr, $level:expr $(,)?) => {
        $crate::InteractionResponse::toast($body).with_toast_level($level)
    };
}

/// Build an `UpdateMessage`-kind [`crate::InteractionResponse`] from a
/// `message_id` and an optional list of mutations.
///
/// Recognised mutations (comma-separated, in any order):
///
/// * `content = <expr>` - replace the message body.
/// * `clear_components` - clear all existing component rows.
/// * an `ActionRow` expression (typically `row![...]`) - append it.
///
/// Leaving content / components out of the macro means "do not
/// change".  An explicit `clear_components` is required to drop the
/// existing rows in one shot; appending new rows on top of cleared
/// rows is fine - just put `clear_components` first.
///
/// ```ignore
/// use mumble_plugin_api::{update_message, row, Button};
/// // Replace body, keep components:
/// return update_message!(mid, content = "Acknowledged.");
/// // Swap out all components:
/// return update_message!(mid,
///     clear_components,
///     row![ Button::new("undo", "Undo") ],
/// );
/// ```
#[macro_export]
macro_rules! update_message {
    ($id:expr $(, $($rest:tt)*)? ) => {{
        #[allow(unused_mut, reason = "macro-generated when no mutations are given")]
        let mut __r = $crate::InteractionResponse::update_message($id);
        $( $crate::__update_message_apply!(__r; $($rest)*); )?
        __r
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __update_message_apply {
    ($r:ident; content = $content:expr $(, $($rest:tt)*)?) => {
        $r = $r.update_content($content);
        $( $crate::__update_message_apply!($r; $($rest)*); )?
    };
    ($r:ident; clear_components $(, $($rest:tt)*)?) => {
        $r = $r.clear_components();
        $( $crate::__update_message_apply!($r; $($rest)*); )?
    };
    ($r:ident; $row:expr $(, $($rest:tt)*)?) => {
        $r = $r.row($row);
        $( $crate::__update_message_apply!($r; $($rest)*); )?
    };
    ($r:ident; ) => {};
    ($r:ident;) => {};
}

/// Build an `UpdatePanel`-kind [`crate::InteractionResponse`] that
/// replaces the entire row list of a [`crate::SettingsPanel`].
///
/// ```ignore
/// use mumble_plugin_api::{update_panel, PanelRow};
/// return update_panel!("audio", [
///     PanelRow::new("Input gain",  "1.4x"),
///     PanelRow::new("Sample rate", "48 kHz"),
/// ]);
/// ```
#[macro_export]
macro_rules! update_panel {
    ($panel_id:expr, [ $($row:expr),* $(,)? ] $(,)?) => {
        $crate::InteractionResponse::update_panel(
            $panel_id,
            ::std::vec![ $($row),* ],
        )
    };
}

/// Internal helper used by the [`show_modal!`](mumble_plugin_api_derive::show_modal)
/// proc-macro to apply a deferred-id [`crate::TextInputBuilder`] with
/// the auto-generated field id.
///
/// Plugin authors should not call this directly; use
/// [`show_modal!`](mumble_plugin_api_derive::show_modal) or
/// [`crate::TextInput::new`] instead.
#[doc(hidden)]
#[must_use]
pub fn __text_input_with_id(
    custom_id: &'static str,
    builder: crate::TextInputBuilder,
) -> crate::TextInput {
    builder.build(custom_id)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "tests panic on failure")]

    use crate::{
        ActionRow, Button, ButtonStyle, Component, PanelRow, ResponseKind, SelectMenu,
        SelectOption, TextInput, ToastLevel,
    };

    #[test]
    fn row_macro_wraps_components_via_into() {
        let r: ActionRow = row![
            Button::new("a", "A"),
            SelectMenu::new("s").option(SelectOption::new("x", "X")),
        ];
        assert_eq!(r.components.len(), 2);
        assert!(matches!(r.components[0], Component::Button(_)));
        assert!(matches!(r.components[1], Component::StringSelect(_)));
    }

    #[test]
    fn message_macro_attaches_rows_and_chains() {
        let resp = message!(
            "hi",
            row![Button::new("ok", "OK").style(ButtonStyle::Success)],
        )
        .ephemeral();
        let ResponseKind::Message {
            content,
            components,
            ephemeral,
            ..
        } = resp.kind
        else {
            panic!("expected Message");
        };
        assert_eq!(content, "hi");
        assert_eq!(components.len(), 1);
        assert!(ephemeral);
    }

    #[test]
    fn message_macro_zero_rows_compiles() {
        let resp = message!("hi");
        let ResponseKind::Message { components, .. } = resp.kind else {
            panic!("expected Message");
        };
        assert!(components.is_empty());
    }

    #[test]
    fn toast_macro_levels() {
        let info = toast!("done");
        let err = toast!("oops", ToastLevel::Error);
        match info.kind {
            ResponseKind::Toast { level, .. } => assert_eq!(level, ToastLevel::Info),
            _ => panic!(),
        }
        match err.kind {
            ResponseKind::Toast { level, message } => {
                assert_eq!(level, ToastLevel::Error);
                assert_eq!(message, "oops");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn update_message_macro_content_only() {
        let resp = update_message!("m1", content = "new body");
        let ResponseKind::UpdateMessage {
            message_id,
            content,
            components,
        } = resp.kind
        else {
            panic!("expected UpdateMessage");
        };
        assert_eq!(message_id, "m1");
        assert_eq!(content.as_deref(), Some("new body"));
        assert!(components.is_none());
    }

    #[test]
    fn update_message_macro_clear_and_append() {
        let resp = update_message!("m1", clear_components, row![Button::new("undo", "Undo")],);
        let ResponseKind::UpdateMessage {
            content,
            components,
            ..
        } = resp.kind
        else {
            panic!("expected UpdateMessage");
        };
        assert!(content.is_none());
        let rows = components.expect("components Some");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].components.len(), 1);
    }

    #[test]
    fn update_message_macro_id_only() {
        let resp = update_message!("m1");
        let ResponseKind::UpdateMessage {
            content,
            components,
            ..
        } = resp.kind
        else {
            panic!("expected UpdateMessage");
        };
        assert!(content.is_none());
        assert!(components.is_none());
    }

    #[test]
    fn update_panel_macro_replaces_rows() {
        let resp = update_panel!(
            "audio",
            [PanelRow::new("Gain", "1.4x"), PanelRow::new("Rate", "48k"),]
        );
        let ResponseKind::UpdatePanel { panel_id, rows } = resp.kind else {
            panic!("expected UpdatePanel");
        };
        assert_eq!(panel_id, "audio");
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn text_input_label_builder_round_trip() {
        let ti = TextInput::label("Message").required(false).build("msg");
        assert_eq!(ti.custom_id, "msg");
        assert_eq!(ti.label, "Message");
        assert!(!ti.required);
    }

    // The `show_modal!` macro is exercised end-to-end in the api-derive
    // crate's integration tests, since it requires a `#[modal]`
    // handler to provide the `__fancy_ids` consts it references.
}
