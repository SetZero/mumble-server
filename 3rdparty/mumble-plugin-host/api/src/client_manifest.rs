//! Tier-1 client extension schema.
//!
//! Plugins ship a [`ClientManifest`] inside [`crate::PluginInfo`] so the
//! client can render plugin-provided UI (slash commands, buttons,
//! modals, settings panels) without any plugin-specific JavaScript.
//! Runtime interaction uses two reserved `payload_type` strings on the
//! generic `PluginMessage` envelope (wire ID 200):
//!
//! * [`INTERACTION_PAYLOAD_TYPE`] - client to plugin: a user invoked a
//!   slash command, clicked a component, or submitted a modal.
//! * [`INTERACTION_RESPONSE_PAYLOAD_TYPE`] - plugin to client: render a
//!   message with components, open a modal, update an existing message,
//!   or show a toast.
//!
//! Payloads are JSON-encoded for parity with the rest of the Fancy
//! plugin ecosystem and so manifest contents remain human-inspectable
//! in `info_json` dumps.
//!
//! The per-component types (button, selects, file uploads, layout
//! primitives, etc.) live in [`crate::components`]; this module
//! re-exports the ones used in the wire types below for convenience.

use serde::{Deserialize, Serialize};

// Re-export every wire-relevant component type so existing imports
// from `crate::client_manifest::*` keep working post-refactor.
pub use crate::components::{
    ActionRow, Button, ButtonStyle, ChannelSelect, Checkbox, CheckboxGroup, CheckboxOption,
    Component, Container, FileComponent, FileUpload, Label, MediaGallery, MediaGalleryItem,
    MentionableSelect, ModalFieldValue, RadioGroup, RadioOption, RoleSelect, Section,
    SectionAccessory, SelectMenu, SelectOption, Separator, SeparatorSpacing, StringSelect,
    TextDisplay, TextInput, TextInputBuilder, TextInputStyle, Thumbnail, UnfurledMediaItem,
    UserSelect,
};

/// Reserved `payload_type` for inbound client-originated interactions.
///
/// Carries a serialised [`Interaction`].
pub const INTERACTION_PAYLOAD_TYPE: &str = "Interaction";

/// Reserved `payload_type` for outbound plugin-originated responses.
///
/// Carries a serialised [`InteractionResponse`].
pub const INTERACTION_RESPONSE_PAYLOAD_TYPE: &str = "InteractionResponse";

/// Schema version stamped on every [`ClientManifest`].
///
/// Bumped to **2** when the Discord-aligned component vocabulary
/// landed (typed selects, layout primitives, modal radio/checkbox/file
/// upload).  Schema-1 manifests still deserialise verbatim: every new
/// component variant is additive and every new field on existing
/// variants has a `#[serde(default)]`.
pub const CLIENT_MANIFEST_SCHEMA_VERSION: u32 = 2;

/// Top-level descriptor of every UI affordance a plugin contributes to
/// the client.  Serialised into [`crate::PluginInfo::client_manifest`]
/// and shipped through the `PluginRegistry`'s `info_json` blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientManifest {
    /// Schema version this manifest targets.  Default and current is
    /// [`CLIENT_MANIFEST_SCHEMA_VERSION`].
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// Slash commands available to all users on this server.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub slash_commands: Vec<SlashCommand>,
    /// Coarse-grained capability tags surfaced in the trust prompt.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<Capability>,
    /// Settings panels shown under `Settings > Plugins`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub settings_panels: Vec<SettingsPanel>,
}

impl Default for ClientManifest {
    fn default() -> Self {
        Self {
            schema_version: CLIENT_MANIFEST_SCHEMA_VERSION,
            slash_commands: Vec::new(),
            capabilities: Vec::new(),
            settings_panels: Vec::new(),
        }
    }
}

fn default_schema_version() -> u32 {
    CLIENT_MANIFEST_SCHEMA_VERSION
}

/// Coarse capability tag used by the client-side trust prompt.
///
/// Plugins are expected to be honest; the client enforces that the
/// capabilities a plugin actually exercises at runtime are a subset of
/// what was declared at install time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    /// Plugin can register slash commands invoked from the composer.
    SlashCommands,
    /// Plugin can open modal dialogs that grab focus.
    Modals,
    /// Plugin can send messages with interactive components (buttons,
    /// select menus) attached.
    Components,
    /// Plugin can surface toast/snackbar notifications.
    Notifications,
    /// Plugin can render a settings panel under Settings > Plugins.
    SettingsPanel,
    /// Plugin uses rich-layout primitives (containers, sections,
    /// thumbnails, media galleries, file references).  Always allowed
    /// at runtime; declared purely so the trust prompt can surface it
    /// alongside the other capabilities for transparency.
    RichLayout,
}

/// A slash command surfaced in the chat composer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashCommand {
    /// Lowercase identifier without the leading `/`.  Must be unique
    /// within a single plugin's manifest.
    pub name: String,
    /// One-line description shown in the composer's command palette.
    pub description: String,
    /// Ordered list of arguments the command accepts.  Required
    /// options must precede optional ones.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<SlashCommandOption>,
}

/// A single named argument to a [`SlashCommand`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashCommandOption {
    /// Argument name (used as the key in [`InteractionKind::SlashCommand::options`]).
    pub name: String,
    /// Short description rendered next to the input.
    pub description: String,
    /// Value type accepted by this option.
    #[serde(rename = "type")]
    pub option_type: OptionType,
    /// If `false`, the option may be omitted at submit time.
    #[serde(default = "default_true")]
    pub required: bool,
    /// Pre-baked choices.  When non-empty the client renders a picker
    /// instead of a free-form input.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<OptionChoice>,
}

fn default_true() -> bool {
    true
}

/// Pre-defined value choice for a [`SlashCommandOption`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptionChoice {
    /// Label shown in the picker.
    pub label: String,
    /// Value sent back in the interaction (string-encoded regardless of
    /// option type; the client coerces).
    pub value: String,
}

/// Value type accepted by a [`SlashCommandOption`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OptionType {
    /// Single-line UTF-8 string.
    String,
    /// Signed 64-bit integer.
    Integer,
    /// `true` / `false`.
    Boolean,
    /// Mumble user session ID (rendered as a user picker).
    User,
    /// Mumble channel ID (rendered as a channel picker).
    Channel,
}

/// Settings panel surfaced under `Settings > Plugins > <plugin-name>`.
///
/// Tier 1 keeps panels declarative: each panel is a list of read-only
/// rows the plugin can refresh via component updates.  Tier 2 will
/// allow webview-backed panels for richer UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsPanel {
    /// Stable identifier referenced in [`ResponseKind::UpdatePanel`].
    pub id: String,
    /// Title shown in the settings tab.
    pub title: String,
    /// Initial rows rendered when the panel opens.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rows: Vec<PanelRow>,
}

/// One row inside a [`SettingsPanel`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelRow {
    /// Left-column label.
    pub label: String,
    /// Right-column value.
    pub value: String,
}

impl PanelRow {
    /// Build a label/value row for a [`SettingsPanel`].
    #[must_use]
    pub fn new(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Interactions (inbound: client -> plugin)
// ---------------------------------------------------------------------------

/// Envelope carrying a user-originated UI event back to the plugin.
///
/// Sent as the JSON body of a `PluginMessage` whose `payload_type` is
/// [`INTERACTION_PAYLOAD_TYPE`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interaction {
    /// Client-generated correlation id, echoed in the matching
    /// [`InteractionResponse::correlation_id`] so the plugin can
    /// route asynchronous replies back to the originating UI.
    pub correlation_id: String,
    /// Channel the user was viewing when the interaction fired, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<u32>,
    /// What the user actually did.
    #[serde(flatten)]
    pub kind: InteractionKind,
}

/// Concrete shape of an [`Interaction`].
///
/// `serde` tags variants with `"kind"` so the wire form is
/// `{"kind":"slash-command", ...rest}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum InteractionKind {
    /// User invoked a slash command from the composer.
    SlashCommand {
        /// Command name (matches [`SlashCommand::name`]).
        name: String,
        /// Submitted argument values keyed by [`SlashCommandOption::name`].
        ///
        /// Missing keys mean the option was omitted (only valid when
        /// [`SlashCommandOption::required`] is `false`).
        #[serde(default)]
        options: std::collections::BTreeMap<String, OptionValue>,
    },
    /// User activated a component (button click, select menu pick).
    Component {
        /// Plugin-assigned identifier carried on the originating
        /// component (e.g. [`Button::custom_id`]).
        custom_id: String,
        /// Selected values, for components that produce them
        /// (e.g. [`SelectMenu`]).  Empty for plain buttons.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        values: Vec<String>,
    },
    /// User submitted a modal previously opened by the plugin.
    ModalSubmit {
        /// `custom_id` from the originating
        /// [`ResponseKind::ShowModal`].
        custom_id: String,
        /// Submitted field values keyed by [`TextInput::custom_id`].
        ///
        /// Carries the legacy string-only encoding; new code should
        /// prefer [`Self::ModalSubmit::fields`].
        #[serde(default)]
        values: std::collections::BTreeMap<String, String>,
        /// Typed field values keyed by component `custom_id`.
        ///
        /// Populated alongside [`Self::ModalSubmit::values`] for modal
        /// components whose natural representation is not a single
        /// string (checkboxes, multi-selects, file uploads).
        #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
        fields: std::collections::BTreeMap<String, ModalFieldValue>,
    },
}

/// Type-tagged value of a [`SlashCommandOption`] at submit time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OptionValue {
    /// String, user picker (session id as string), channel picker
    /// (channel id as string), or any choice value.
    String(String),
    /// Numeric value for [`OptionType::Integer`].
    Integer(i64),
    /// Boolean value for [`OptionType::Boolean`].
    Boolean(bool),
}

// ---------------------------------------------------------------------------
// Interaction responses (outbound: plugin -> client)
// ---------------------------------------------------------------------------

/// Envelope carrying a plugin-originated UI update back to the client.
///
/// Sent as the JSON body of a `PluginMessage` whose `payload_type` is
/// [`INTERACTION_RESPONSE_PAYLOAD_TYPE`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractionResponse {
    /// Correlation id from the originating [`Interaction`], when this
    /// response is a direct reply.  Server-initiated responses (e.g. a
    /// background-pushed component message) leave this `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// What the client should render.
    #[serde(flatten)]
    pub kind: ResponseKind,
}

/// What the client should do in response to an [`Interaction`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ResponseKind {
    /// Open a modal form or floating card.
    ///
    /// A unified "overlay" response: the client renders a transient,
    /// non-persistent surface on top of the chat.  When `components`
    /// contains only modal-eligible inputs (text inputs, file uploads,
    /// selects, ...), the client treats it as a *modal dialog* and the
    /// user's submission is delivered back as an
    /// [`InteractionKind::ModalSubmit`] keyed by `custom_id`.  When
    /// `components` includes display-only or button-style content, the
    /// client renders the same payload as a floating *card* and clicks
    /// arrive as [`InteractionKind::Component`] events.
    ///
    /// This variant subsumes the legacy `Message` kind: pass an empty
    /// `title` to drop the title bar, leave `components` empty for a
    /// content-only banner, or skip both for a plain text overlay.
    ShowModal {
        /// Echoed verbatim back in the matching
        /// [`InteractionKind::ModalSubmit::custom_id`] (modal flow)
        /// or accepted by [`Self::UpdateMessage::message_id`] (card
        /// patch flow).  Use a UUID; the client treats it as opaque.
        custom_id: String,
        /// Window / card title.  May be empty for a chrome-less card.
        #[serde(default)]
        title: String,
        /// Markdown body shown above the components.  May be empty
        /// when the payload is component-only or title-only.
        #[serde(default)]
        content: String,
        /// Form rows or layout components.  Modals accept any
        /// modal-eligible component (text input, [`Label`]-wrapped
        /// child, file upload, radio/checkbox group, single
        /// checkbox, any select); cards accept the full layout
        /// vocabulary (containers, sections, separators, text
        /// displays, buttons, ...).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        components: Vec<ActionRow>,
        /// When `true`, only the originating user sees the overlay.
        /// Always treated as `true` when
        /// [`InteractionResponse::correlation_id`] is `None`, since
        /// there is no other recipient to fan out to.
        #[serde(default)]
        ephemeral: bool,
    },
    /// Inject a *literal* chat message into the client's chat
    /// history, exactly like a [`mumble_protocol::proto::mumble_tcp::TextMessage`]
    /// authored by the plugin.
    ///
    /// Unlike [`Self::ShowModal`] (which renders as a transient
    /// floating overlay / modal), `ChatMessage` is persisted in the
    /// channel/DM message list and participates in scroll, quoting,
    /// pinning, and history just like a user-sent message.  Optional
    /// [`ActionRow`] components are rendered inside the chat bubble
    /// below the markdown body.
    ChatMessage {
        /// Stable identifier so later [`Self::UpdateMessage`] responses
        /// can target this exact message.  Use a UUID; the client
        /// treats the value as opaque.
        message_id: String,
        /// Target channel ids.  When empty, the client routes the
        /// message to the chat tab the originating interaction came
        /// from (i.e. the currently-viewed channel or DM).  Supply
        /// more than one entry to fan the same bubble out to several
        /// channels at once.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        channel_ids: Vec<u32>,
        /// Markdown body shown inside the chat bubble.  May be empty
        /// when the payload is component-only.
        #[serde(default)]
        content: String,
        /// Top-level rows / layout components rendered below the body
        /// inside the same chat bubble.  Same vocabulary as
        /// [`Self::ShowModal::components`].
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        components: Vec<ActionRow>,
        /// When `true`, only the originating user sees the message.
        /// Always `true` when [`InteractionResponse::correlation_id`]
        /// is `None`, since there is no other recipient.
        #[serde(default)]
        ephemeral: bool,
    },
    /// Patch an existing message previously sent via
    /// [`Self::ShowModal`] (card patch) or [`Self::ChatMessage`]
    /// (chat bubble patch).
    UpdateMessage {
        /// `custom_id` from the original [`Self::ShowModal`] or
        /// `message_id` from the original [`Self::ChatMessage`].
        message_id: String,
        /// New content; `None` keeps the existing body.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        content: Option<String>,
        /// New component rows; `None` keeps the existing rows.  Pass
        /// `Some(vec![])` to clear them.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        components: Option<Vec<ActionRow>>,
    },
    /// Refresh a [`SettingsPanel`] in place.
    UpdatePanel {
        /// `id` from the originating [`SettingsPanel::id`].
        panel_id: String,
        /// Replacement rows.
        rows: Vec<PanelRow>,
    },
    /// Show a transient toast.  Not associated with any message.
    Toast {
        /// Message body.
        message: String,
        /// Visual severity hint.
        #[serde(default)]
        level: ToastLevel,
    },
}

/// Severity hint for [`ResponseKind::Toast`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ToastLevel {
    /// Plain informational toast.
    #[default]
    Info,
    /// Operation succeeded.
    Success,
    /// Soft warning.
    Warning,
    /// Hard error.
    Error,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "tests panic on failure")]
    use super::*;

    #[test]
    fn manifest_round_trips_through_json() {
        let manifest = ClientManifest {
            schema_version: CLIENT_MANIFEST_SCHEMA_VERSION,
            slash_commands: vec![SlashCommand {
                name: "greet".into(),
                description: "Send a greeting".into(),
                options: vec![SlashCommandOption {
                    name: "target".into(),
                    description: "Who to greet".into(),
                    option_type: OptionType::User,
                    required: false,
                    choices: vec![],
                }],
            }],
            capabilities: vec![Capability::SlashCommands, Capability::Modals],
            settings_panels: vec![],
        };
        let json = serde_json::to_string(&manifest).expect("encode");
        let back: ClientManifest = serde_json::from_str(&json).expect("decode");
        assert_eq!(back.slash_commands.len(), 1);
        assert_eq!(back.slash_commands[0].name, "greet");
        assert!(back.capabilities.contains(&Capability::Modals));
    }

    #[test]
    fn empty_manifest_has_no_optional_fields_in_json() {
        let json = serde_json::to_string(&ClientManifest::default()).expect("encode");
        assert!(!json.contains("slash_commands"));
        assert!(!json.contains("capabilities"));
        assert!(!json.contains("settings_panels"));
    }

    #[test]
    fn interaction_slash_command_wire_shape() {
        let interaction = Interaction {
            correlation_id: "abc-123".into(),
            channel_id: Some(42),
            kind: InteractionKind::SlashCommand {
                name: "greet".into(),
                options: [("target".to_owned(), OptionValue::String("7".into()))]
                    .into_iter()
                    .collect(),
            },
        };
        let json = serde_json::to_string(&interaction).expect("encode");
        assert!(json.contains("\"kind\":\"slash-command\""));
        assert!(json.contains("\"correlation_id\":\"abc-123\""));
        assert!(json.contains("\"target\":\"7\""));
        let back: Interaction = serde_json::from_str(&json).expect("decode");
        match back.kind {
            InteractionKind::SlashCommand { name, options } => {
                assert_eq!(name, "greet");
                assert_eq!(options.len(), 1);
            }
            _ => panic!("expected SlashCommand"),
        }
    }

    #[test]
    fn response_message_with_buttons() {
        let resp = InteractionResponse {
            correlation_id: Some("abc-123".into()),
            kind: ResponseKind::ShowModal {
                custom_id: "m1".into(),
                title: String::new(),
                content: "Choose one".into(),
                components: vec![ActionRow::new()
                    .push(Button::new("yes", "Yes").style(ButtonStyle::Success))
                    .push(Button::new("no", "No").style(ButtonStyle::Danger))],
                ephemeral: false,
            },
        };
        let json = serde_json::to_string(&resp).expect("encode");
        assert!(json.contains("\"kind\":\"show-modal\""));
        assert!(json.contains("\"type\":\"button\""));
        let back: InteractionResponse = serde_json::from_str(&json).expect("decode");
        match back.kind {
            ResponseKind::ShowModal { components, .. } => {
                assert_eq!(components.len(), 1);
                assert_eq!(components[0].components.len(), 2);
            }
            _ => panic!("expected ShowModal"),
        }
    }

    #[test]
    fn chat_message_response_round_trip() {
        let resp = InteractionResponse {
            correlation_id: Some("cid".into()),
            kind: ResponseKind::ChatMessage {
                message_id: "mid".into(),
                channel_ids: vec![7, 11],
                content: "hello chat".into(),
                components: vec![ActionRow::new()
                    .push(Button::new("ok", "OK").style(ButtonStyle::Primary))],
                ephemeral: false,
            },
        };
        let json = serde_json::to_string(&resp).expect("encode");
        assert!(json.contains("\"kind\":\"chat-message\""));
        assert!(json.contains("\"channel_ids\":[7,11]"));
        let back: InteractionResponse = serde_json::from_str(&json).expect("decode");
        match back.kind {
            ResponseKind::ChatMessage {
                message_id,
                channel_ids,
                content,
                components,
                ephemeral,
            } => {
                assert_eq!(message_id, "mid");
                assert_eq!(channel_ids, vec![7, 11]);
                assert_eq!(content, "hello chat");
                assert_eq!(components.len(), 1);
                assert!(!ephemeral);
            }
            _ => panic!("expected ChatMessage"),
        }
    }

    #[test]
    fn chat_message_response_omits_empty_channels() {
        let resp = InteractionResponse {
            correlation_id: None,
            kind: ResponseKind::ChatMessage {
                message_id: "mid".into(),
                channel_ids: vec![],
                content: "body".into(),
                components: vec![],
                ephemeral: false,
            },
        };
        let json = serde_json::to_string(&resp).expect("encode");
        assert!(!json.contains("channel_ids"));
        assert!(!json.contains("components"));
    }

    #[test]
    fn modal_submit_round_trip() {
        let interaction = Interaction {
            correlation_id: "modal-1".into(),
            channel_id: None,
            kind: InteractionKind::ModalSubmit {
                custom_id: "greet-form".into(),
                values: [("text".to_owned(), "hello".to_owned())]
                    .into_iter()
                    .collect(),
                fields: std::collections::BTreeMap::new(),
            },
        };
        let json = serde_json::to_string(&interaction).expect("encode");
        let back: Interaction = serde_json::from_str(&json).expect("decode");
        match back.kind {
            InteractionKind::ModalSubmit {
                custom_id,
                values,
                fields,
            } => {
                assert_eq!(custom_id, "greet-form");
                assert_eq!(values.get("text").map(String::as_str), Some("hello"));
                assert!(fields.is_empty());
            }
            _ => panic!("expected ModalSubmit"),
        }
    }

    #[test]
    fn modal_submit_legacy_payload_deserialises() {
        // Schema-1 payload: no `fields` key, only string `values`.
        let legacy = r#"{
            "kind":"modal-submit",
            "correlation_id":"c",
            "custom_id":"f",
            "values":{"name":"alice"}
        }"#;
        let parsed: Interaction = serde_json::from_str(legacy).expect("decode");
        match parsed.kind {
            InteractionKind::ModalSubmit { values, fields, .. } => {
                assert_eq!(values["name"], "alice");
                assert!(fields.is_empty());
            }
            _ => panic!("expected ModalSubmit"),
        }
    }

    #[test]
    fn schema_version_is_two() {
        assert_eq!(CLIENT_MANIFEST_SCHEMA_VERSION, 2);
        assert_eq!(ClientManifest::default().schema_version, 2);
    }

    #[test]
    fn rich_layout_capability_round_trips() {
        let manifest = ClientManifest {
            capabilities: vec![Capability::RichLayout],
            ..ClientManifest::default()
        };
        let json = serde_json::to_string(&manifest).expect("encode");
        assert!(json.contains("\"rich-layout\""));
        let back: ClientManifest = serde_json::from_str(&json).expect("decode");
        assert!(back.capabilities.contains(&Capability::RichLayout));
    }
}
