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
//! # Trust gating
//!
//! [`ClientManifest::capabilities`] lets a plugin declare the broad
//! categories of UI it wants to surface.  The client uses this list at
//! install time to ask the user "Server X wants to enable plugin Y
//! with the following capabilities: ...".  See the design doc for the
//! intended UX; this crate only defines the data shape.

use serde::{Deserialize, Serialize};

/// Reserved `payload_type` for inbound client-originated interactions.
///
/// Carries a serialised [`Interaction`].
pub const INTERACTION_PAYLOAD_TYPE: &str = "Interaction";

/// Reserved `payload_type` for outbound plugin-originated responses.
///
/// Carries a serialised [`InteractionResponse`].
pub const INTERACTION_RESPONSE_PAYLOAD_TYPE: &str = "InteractionResponse";

/// Schema version stamped on every [`ClientManifest`].  Bumped whenever
/// a non-additive change is made; clients refuse to render manifests
/// declaring a version above the one they were built against.
pub const CLIENT_MANIFEST_SCHEMA_VERSION: u32 = 1;

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
        #[serde(default)]
        values: std::collections::BTreeMap<String, String>,
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
    /// Render a (chat-style) message with optional interactive
    /// components attached.
    Message {
        /// Stable identifier so later [`Self::UpdateMessage`] responses
        /// can target this exact card.  Use a UUID; the client treats
        /// the value as opaque.
        message_id: String,
        /// Markdown body shown above the components.  May be empty.
        #[serde(default)]
        content: String,
        /// Up to five rows of components.  Empty for plain text.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        components: Vec<ActionRow>,
        /// When `true`, only the originating user sees the message.
        /// Always `true` when [`InteractionResponse::correlation_id`]
        /// is `None`, since there is no other recipient.
        #[serde(default)]
        ephemeral: bool,
    },
    /// Open a modal form.  The client returns the submitted values as
    /// an [`InteractionKind::ModalSubmit`].
    ShowModal {
        /// Echoed verbatim back in the matching
        /// [`InteractionKind::ModalSubmit::custom_id`].
        custom_id: String,
        /// Window title.
        title: String,
        /// Form rows.  Modals support [`Component::TextInput`] only.
        components: Vec<ActionRow>,
    },
    /// Patch an existing message previously sent via [`Self::Message`].
    UpdateMessage {
        /// `message_id` from the original [`Self::Message`].
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

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

/// Horizontal row of interactive components.  Mirrors Discord: max five
/// rows per message; max five buttons per row; select menus and text
/// inputs occupy a whole row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRow {
    /// Components rendered left-to-right inside this row.
    pub components: Vec<Component>,
}

/// A single interactive component.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Component {
    /// Button.  Click delivers an [`InteractionKind::Component`].
    Button(Button),
    /// Dropdown/multi-select picker.
    SelectMenu(SelectMenu),
    /// Single-line or multi-line text input.  Only valid inside a
    /// [`ResponseKind::ShowModal`].
    TextInput(TextInput),
}

/// Click target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Button {
    /// Echoed verbatim back in
    /// [`InteractionKind::Component::custom_id`].
    pub custom_id: String,
    /// Button label.
    pub label: String,
    /// Visual style.
    #[serde(default)]
    pub style: ButtonStyle,
    /// When `true`, the button renders but cannot be clicked.
    #[serde(default)]
    pub disabled: bool,
}

/// Visual style for a [`Button`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ButtonStyle {
    /// Filled accent colour.  Use for the safe / primary action.
    #[default]
    Primary,
    /// Subtle outlined button.
    Secondary,
    /// Green; use for confirmations.
    Success,
    /// Red; use for destructive actions.
    Danger,
}

/// Dropdown picker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectMenu {
    /// Echoed verbatim back in
    /// [`InteractionKind::Component::custom_id`].
    pub custom_id: String,
    /// Placeholder when no value is selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    /// Picker entries.
    pub options: Vec<SelectOption>,
    /// Minimum number of values the user must pick (default 1).
    #[serde(default = "default_min_values")]
    pub min_values: u32,
    /// Maximum number of values the user may pick (default 1).
    #[serde(default = "default_max_values")]
    pub max_values: u32,
}

fn default_min_values() -> u32 {
    1
}

fn default_max_values() -> u32 {
    1
}

/// Entry in a [`SelectMenu`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectOption {
    /// Label shown to the user.
    pub label: String,
    /// Value returned in [`InteractionKind::Component::values`] when
    /// chosen.
    pub value: String,
    /// Optional sub-label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Modal form field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextInput {
    /// Used as the key in
    /// [`InteractionKind::ModalSubmit::values`].
    pub custom_id: String,
    /// Label rendered above the field.
    pub label: String,
    /// Pre-filled value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Placeholder shown while the field is empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    /// Single-line vs multi-line.
    #[serde(default)]
    pub style: TextInputStyle,
    /// Field is mandatory at submit time.
    #[serde(default = "default_true")]
    pub required: bool,
    /// Maximum character length (0 = unlimited).
    #[serde(default)]
    pub max_length: u32,
}

/// Layout style for a [`TextInput`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum TextInputStyle {
    /// Single-line input.
    #[default]
    Short,
    /// Multi-line text area.
    Paragraph,
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
            kind: ResponseKind::Message {
                message_id: "m1".into(),
                content: "Choose one".into(),
                components: vec![ActionRow {
                    components: vec![
                        Component::Button(Button {
                            custom_id: "yes".into(),
                            label: "Yes".into(),
                            style: ButtonStyle::Success,
                            disabled: false,
                        }),
                        Component::Button(Button {
                            custom_id: "no".into(),
                            label: "No".into(),
                            style: ButtonStyle::Danger,
                            disabled: false,
                        }),
                    ],
                }],
                ephemeral: false,
            },
        };
        let json = serde_json::to_string(&resp).expect("encode");
        assert!(json.contains("\"kind\":\"message\""));
        assert!(json.contains("\"type\":\"button\""));
        let back: InteractionResponse = serde_json::from_str(&json).expect("decode");
        match back.kind {
            ResponseKind::Message { components, .. } => {
                assert_eq!(components.len(), 1);
                assert_eq!(components[0].components.len(), 2);
            }
            _ => panic!("expected Message"),
        }
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
            },
        };
        let json = serde_json::to_string(&interaction).expect("encode");
        let back: Interaction = serde_json::from_str(&json).expect("decode");
        match back.kind {
            InteractionKind::ModalSubmit { custom_id, values } => {
                assert_eq!(custom_id, "greet-form");
                assert_eq!(values.get("text").map(String::as_str), Some("hello"));
            }
            _ => panic!("expected ModalSubmit"),
        }
    }

    #[test]
    fn default_schema_version_is_one() {
        assert_eq!(CLIENT_MANIFEST_SCHEMA_VERSION, 1);
        assert_eq!(ClientManifest::default().schema_version, 1);
    }
}
