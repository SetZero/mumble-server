//! Typed slash-command runtime used by the `#[command]` and
//! `#[fancy_plugin]` proc-macros.
//!
//! Plugin authors normally do not interact with these types directly -
//! the macros emit calls into this module.  See
//! `mumble_plugin_api_derive` for the user-facing attributes.

use std::collections::BTreeMap;

use abi_stable::std_types::{RArc, RNone, RString, RVec};

use crate::client_manifest::{Interaction, InteractionResponse, OptionValue};
use crate::plugin::{PluginContext_TO, PluginMessageIn, PluginMessageOut};
use crate::INTERACTION_RESPONSE_PAYLOAD_TYPE;

// ---------------------------------------------------------------------------
// FromOption: typed extraction from the wire `OptionValue` bag
// ---------------------------------------------------------------------------

/// Errors produced by [`FromOption`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum OptionExtractError {
    /// The interaction did not supply this required option.
    #[error("required option `{name}` missing from interaction payload")]
    Missing {
        /// Option name that was missing.
        name: &'static str,
    },
    /// The interaction supplied this option, but with the wrong type.
    #[error("option `{name}` has wrong type: expected {expected}, got {actual}")]
    TypeMismatch {
        /// Option name.
        name: &'static str,
        /// Type the function signature requires.
        expected: &'static str,
        /// Type the wire payload supplied.
        actual: &'static str,
    },
}

/// Convert a wire [`OptionValue`] into a typed function argument.
/// Implemented by the framework for the small set of types accepted in
/// `#[command]` parameter positions.
pub trait FromOption: Sized {
    /// `true` when a missing wire entry should fall through to
    /// [`Self::missing`] instead of raising
    /// [`OptionExtractError::Missing`].  Overridden by `Option<T>`.
    const ALLOWS_MISSING: bool = false;

    /// Value returned when [`Self::ALLOWS_MISSING`] is `true` and the
    /// option is absent on the wire.  Default impl errors; only
    /// `Option<T>` needs to override.
    fn missing(name: &'static str) -> Result<Self, OptionExtractError> {
        Err(OptionExtractError::Missing { name })
    }

    /// Convert the supplied value.
    fn extract(name: &'static str, value: &OptionValue) -> Result<Self, OptionExtractError>;
}

impl FromOption for String {
    fn extract(name: &'static str, value: &OptionValue) -> Result<Self, OptionExtractError> {
        match value {
            OptionValue::String(s) => Ok(s.clone()),
            other => Err(OptionExtractError::TypeMismatch {
                name,
                expected: "String",
                actual: value_kind(other),
            }),
        }
    }
}

impl FromOption for bool {
    fn extract(name: &'static str, value: &OptionValue) -> Result<Self, OptionExtractError> {
        match value {
            OptionValue::Boolean(b) => Ok(*b),
            other => Err(OptionExtractError::TypeMismatch {
                name,
                expected: "bool",
                actual: value_kind(other),
            }),
        }
    }
}

impl FromOption for i64 {
    fn extract(name: &'static str, value: &OptionValue) -> Result<Self, OptionExtractError> {
        match value {
            OptionValue::Integer(n) => Ok(*n),
            other => Err(OptionExtractError::TypeMismatch {
                name,
                expected: "i64",
                actual: value_kind(other),
            }),
        }
    }
}

impl FromOption for u32 {
    fn extract(name: &'static str, value: &OptionValue) -> Result<Self, OptionExtractError> {
        match value {
            // User / Channel picker values arrive as strings on the wire.
            OptionValue::String(s) => {
                s.parse::<u32>()
                    .map_err(|_| OptionExtractError::TypeMismatch {
                        name,
                        expected: "u32",
                        actual: "non-numeric String",
                    })
            }
            OptionValue::Integer(n) if *n >= 0 && *n <= i64::from(u32::MAX) =>
            {
                #[allow(
                    clippy::cast_sign_loss,
                    clippy::cast_possible_truncation,
                    reason = "bounds checked on the match arm"
                )]
                Ok(*n as u32)
            }
            other => Err(OptionExtractError::TypeMismatch {
                name,
                expected: "u32",
                actual: value_kind(other),
            }),
        }
    }
}

impl<T: FromOption> FromOption for Option<T> {
    const ALLOWS_MISSING: bool = true;

    fn missing(_name: &'static str) -> Result<Self, OptionExtractError> {
        Ok(None)
    }

    fn extract(name: &'static str, value: &OptionValue) -> Result<Self, OptionExtractError> {
        T::extract(name, value).map(Some)
    }
}

fn value_kind(v: &OptionValue) -> &'static str {
    match v {
        OptionValue::String(_) => "String",
        OptionValue::Integer(_) => "Integer",
        OptionValue::Boolean(_) => "Boolean",
    }
}

/// Helper called from macro-generated dispatch code: look up an
/// option by name and extract it with the requested [`FromOption`]
/// type.
pub fn extract_option<T: FromOption>(
    opts: &BTreeMap<String, OptionValue>,
    name: &'static str,
) -> Result<T, OptionExtractError> {
    match opts.get(name) {
        Some(v) => T::extract(name, v),
        None if T::ALLOWS_MISSING => T::missing(name),
        None => Err(OptionExtractError::Missing { name }),
    }
}

// ---------------------------------------------------------------------------
// FromField: typed extraction from modal `values` (BTreeMap<String,String>)
// ---------------------------------------------------------------------------

/// Errors produced by [`FromField`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum FieldExtractError {
    /// The modal submission did not include this required field.
    #[error("required modal field `{name}` missing from submission")]
    Missing {
        /// Field name that was missing.
        name: &'static str,
    },
    /// The field was present but could not be parsed into the
    /// requested type.
    #[error("modal field `{name}` failed to parse as {expected}: {detail}")]
    Parse {
        /// Field name.
        name: &'static str,
        /// Type the function signature requires.
        expected: &'static str,
        /// Underlying parse error message.
        detail: String,
    },
}

/// Convert a modal field's wire-side string value into a typed
/// function argument.  Implemented by the framework for the small set
/// of types accepted in `#[modal]` parameter positions.
pub trait FromField: Sized {
    /// `true` when an absent field should fall through to
    /// [`Self::missing`] instead of raising [`FieldExtractError::Missing`].
    /// Overridden by `Option<T>`.
    const ALLOWS_MISSING: bool = false;

    /// Value returned when [`Self::ALLOWS_MISSING`] is `true` and the
    /// field is absent.  Default impl errors; only `Option<T>` needs
    /// to override.
    fn missing(name: &'static str) -> Result<Self, FieldExtractError> {
        Err(FieldExtractError::Missing { name })
    }

    /// Convert the supplied string value.
    fn extract(name: &'static str, value: &str) -> Result<Self, FieldExtractError>;
}

impl FromField for String {
    fn extract(_name: &'static str, value: &str) -> Result<Self, FieldExtractError> {
        Ok(value.to_owned())
    }
}

impl<T: FromField> FromField for Option<T> {
    const ALLOWS_MISSING: bool = true;

    fn missing(_name: &'static str) -> Result<Self, FieldExtractError> {
        Ok(None)
    }

    fn extract(name: &'static str, value: &str) -> Result<Self, FieldExtractError> {
        T::extract(name, value).map(Some)
    }
}

/// Helper called from macro-generated modal dispatch code: look up a
/// field by name and extract it with the requested [`FromField`]
/// type.
pub fn extract_field<T: FromField>(
    values: &BTreeMap<String, String>,
    name: &'static str,
) -> Result<T, FieldExtractError> {
    match values.get(name) {
        Some(v) => T::extract(name, v),
        None if T::ALLOWS_MISSING => T::missing(name),
        None => Err(FieldExtractError::Missing { name }),
    }
}

// ---------------------------------------------------------------------------
// Dispatch-side helpers used by macro-generated `__fancy_dispatch`
// ---------------------------------------------------------------------------

/// Deserialise the [`Interaction`] payload out of an inbound message.
///
/// Returns `None` (with a stderr log line) for malformed payloads so
/// the surrounding dispatcher can short-circuit cleanly.
#[must_use]
pub fn parse_interaction(msg: &PluginMessageIn) -> Option<Interaction> {
    match serde_json::from_slice(msg.payload.as_slice()) {
        Ok(v) => Some(v),
        Err(e) => {
            log_warn(&format!("dropping malformed Interaction payload: {e}"));
            None
        }
    }
}

/// Wrap an [`InteractionResponse`] into a `PluginMessage` envelope and
/// ship it back to the originating session via
/// [`PluginContext::send_plugin_message`](crate::PluginContext::send_plugin_message).
pub fn send_interaction_response(
    ctx: &PluginContext_TO<RArc<()>>,
    msg: &PluginMessageIn,
    response: InteractionResponse,
) {
    let bytes = match serde_json::to_vec(&response) {
        Ok(b) => b,
        Err(e) => {
            log_warn(&format!(
                "dropping InteractionResponse: serialize failed: {e}"
            ));
            return;
        }
    };
    let mut targets: RVec<crate::SessionId> = RVec::new();
    targets.push(msg.sender_session);
    let out = PluginMessageOut {
        server_id: msg.server_id,
        plugin_name: msg.plugin_name.clone(),
        payload_type: RString::from(INTERACTION_RESPONSE_PAYLOAD_TYPE),
        payload: RVec::from(bytes),
        target_sessions: targets,
        channel_id: RNone,
    };
    if let abi_stable::std_types::RResult::RErr(e) = ctx.send_plugin_message(out) {
        log_warn(&format!("send_plugin_message failed: {e:?}"));
    }
}

fn log_warn(msg: &str) {
    // The api crate has no logging dep; print to stderr so misbehaving
    // commands still leave a trace.  Real plugins typically embed a
    // tracing subscriber so this fallback is only seen during very
    // early load or framework-internal failures.
    eprintln!("[mumble-plugin-api] {msg}");
}

// ---------------------------------------------------------------------------
// Response builders
// ---------------------------------------------------------------------------

impl InteractionResponse {
    /// Build a plain chat-style message response with no components.
    /// Generates a random `message_id`; use [`Self::message_with_id`]
    /// if you need to update the same card later via
    /// [`crate::ResponseKind::UpdateMessage`].
    #[must_use]
    pub fn message(body: impl Into<String>) -> Self {
        Self::message_with_id(random_message_id(), body)
    }

    /// Build a chat-style message with a caller-chosen `message_id`.
    /// Required if you intend to update this message via a later
    /// [`crate::ResponseKind::UpdateMessage`].
    #[must_use]
    pub fn message_with_id(message_id: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            correlation_id: None,
            kind: crate::ResponseKind::Message {
                message_id: message_id.into(),
                content: body.into(),
                components: Vec::new(),
                ephemeral: false,
            },
        }
    }

    /// Build a transient toast response with severity
    /// [`crate::ToastLevel::Info`].  Chain [`Self::with_toast_level`]
    /// to change it.
    #[must_use]
    pub fn toast(body: impl Into<String>) -> Self {
        Self {
            correlation_id: None,
            kind: crate::ResponseKind::Toast {
                message: body.into(),
                level: crate::ToastLevel::Info,
            },
        }
    }

    /// Override the toast severity level.  No-op on non-toast
    /// responses.
    #[must_use]
    pub fn with_toast_level(mut self, level: crate::ToastLevel) -> Self {
        if let crate::ResponseKind::Toast { level: l, .. } = &mut self.kind {
            *l = level;
        }
        self
    }

    /// Mark a chat message as ephemeral (only visible to the
    /// originating user).  No-op on non-Message responses.
    #[must_use]
    pub fn ephemeral(mut self) -> Self {
        if let crate::ResponseKind::Message { ephemeral, .. } = &mut self.kind {
            *ephemeral = true;
        }
        self
    }

    /// Attach a correlation id (echoed by the client to route async
    /// replies back to the originating UI).  The dispatcher in the
    /// macro-generated code sets this automatically from the inbound
    /// interaction; manual callers can override.
    #[must_use]
    pub fn with_correlation_id(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }

    /// Append an [`ActionRow`] of components to a `Message` response.
    /// No-op (with a `debug_assert`) on other response kinds.
    #[must_use]
    pub fn row(mut self, row: crate::ActionRow) -> Self {
        match &mut self.kind {
            crate::ResponseKind::Message { components, .. } => components.push(row),
            crate::ResponseKind::UpdateMessage { components, .. } => {
                components.get_or_insert_with(Vec::new).push(row);
            }
            other => {
                debug_assert!(
                    false,
                    "InteractionResponse::row called on non-Message kind: {other:?}"
                );
            }
        }
        self
    }

    /// Build a `ShowModal` response with no fields.  Chain
    /// [`Self::field`] to populate the form.
    #[must_use]
    pub fn show_modal(custom_id: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            correlation_id: None,
            kind: crate::ResponseKind::ShowModal {
                custom_id: custom_id.into(),
                title: title.into(),
                components: Vec::new(),
            },
        }
    }

    /// Append a [`crate::TextInput`] field (wrapped in its own
    /// [`crate::ActionRow`], as modals require) to a `ShowModal`
    /// response.  No-op on other kinds.
    #[must_use]
    pub fn field(mut self, input: crate::TextInput) -> Self {
        if let crate::ResponseKind::ShowModal { components, .. } = &mut self.kind {
            components.push(crate::ActionRow {
                components: vec![crate::Component::TextInput(input)],
            });
        }
        self
    }

    /// Build an `UpdateMessage` response targeting a previously sent
    /// message.  Content and components both start out as `None`
    /// (unchanged); use [`Self::update_content`] and [`Self::row`] /
    /// [`Self::clear_components`] to populate them.
    #[must_use]
    pub fn update_message(message_id: impl Into<String>) -> Self {
        Self {
            correlation_id: None,
            kind: crate::ResponseKind::UpdateMessage {
                message_id: message_id.into(),
                content: None,
                components: None,
            },
        }
    }

    /// Set the replacement message body on an `UpdateMessage`
    /// response.  No-op on other kinds.
    #[must_use]
    pub fn update_content(mut self, content: impl Into<String>) -> Self {
        if let crate::ResponseKind::UpdateMessage { content: c, .. } = &mut self.kind {
            *c = Some(content.into());
        }
        self
    }

    /// Explicitly clear all components on an `UpdateMessage` response
    /// (distinct from leaving them unchanged).  No-op on other kinds.
    #[must_use]
    pub fn clear_components(mut self) -> Self {
        if let crate::ResponseKind::UpdateMessage { components, .. } = &mut self.kind {
            *components = Some(Vec::new());
        }
        self
    }

    /// Build an `UpdatePanel` response that replaces every row of a
    /// settings panel in one shot.
    #[must_use]
    pub fn update_panel<I: IntoIterator<Item = crate::PanelRow>>(
        panel_id: impl Into<String>,
        rows: I,
    ) -> Self {
        Self {
            correlation_id: None,
            kind: crate::ResponseKind::UpdatePanel {
                panel_id: panel_id.into(),
                rows: rows.into_iter().collect(),
            },
        }
    }
}

fn random_message_id() -> String {
    // Cheap, dependency-free unique id: nanos since UNIX_EPOCH +
    // a per-process counter.  Good enough to disambiguate messages
    // within a single plugin instance.
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("msg-{nanos:x}-{n:x}")
}
