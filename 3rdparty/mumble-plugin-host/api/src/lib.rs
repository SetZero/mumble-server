//! Public, ABI-stable trait definitions for Mumble server plugins.
//!
//! Plugins are compiled as `cdylib` crates and loaded at runtime by the
//! `mumble-plugin-host`.  The boundary uses [`abi_stable`] so plugins
//! remain compatible across `rustc` versions and minor host upgrades.
//!
//! # Async model
//!
//! Cross-FFI trait calls are deliberately **synchronous**.  Each plugin
//! owns its private `tokio` runtime and `block_on`s inside the trait
//! impls.  Lifecycle hooks fire at human-scale frequencies (client
//! connect, plugin-data message) so the per-call cost is negligible,
//! and this gives strong fault isolation: a plugin runtime panicking
//! cannot poison the host.
//!
//! # Wire-level plugin info
//!
//! Every plugin advertises a typed [`PluginInfo`] block which the host
//! serialises to JSON, optionally compresses with `zstd`, and ships to
//! connected clients as `fancy-plugin-info` plugin-data.  Payloads are
//! hard-capped at [`PLUGIN_INFO_MAX_BYTES`] uncompressed.

#![warn(missing_docs)]

use abi_stable::{
    declare_root_module_statics, library::RootModule, package_version_strings,
    sabi_types::VersionStrings, std_types::RString, StableAbi,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod client_manifest;
pub mod commands;
pub mod component_macros;
pub mod components;
pub mod host_facade;
pub mod info_macros;
pub mod permissions;
pub mod plugin;

pub use crate::client_manifest::{
    ActionRow, Button, ButtonStyle, Capability, ChannelSelect, Checkbox, CheckboxGroup,
    CheckboxOption, ClientManifest, Component, Container, FileComponent, FileUpload, Interaction,
    InteractionKind, InteractionResponse, Label, MediaGallery, MediaGalleryItem, MentionableSelect,
    ModalFieldValue, OptionChoice, OptionType, OptionValue, PanelRow, RadioGroup, RadioOption,
    ResponseKind, RoleSelect, Section, SectionAccessory, SelectMenu, SelectOption, Separator,
    SeparatorSpacing, SettingsPanel, SlashCommand, SlashCommandOption, StringSelect, TextDisplay,
    TextInput, TextInputBuilder, TextInputStyle, Thumbnail, ToastLevel, UnfurledMediaItem,
    UserSelect, CLIENT_MANIFEST_SCHEMA_VERSION, INTERACTION_PAYLOAD_TYPE,
    INTERACTION_RESPONSE_PAYLOAD_TYPE,
};
pub use crate::commands::{
    extract_field, extract_option, parse_interaction, send_interaction_response,
    send_interaction_response_to_channel, send_interaction_response_to_sessions, FieldExtractError,
    FromField, FromOption, OptionExtractError,
};
#[doc(hidden)]
pub use crate::component_macros::__text_input_with_id;
pub use crate::host_facade::{Caller, Host};
pub use crate::permissions::Permissions;
pub use crate::plugin::{
    MumblePlugin, MumblePlugin_TO, PluginContext, PluginContext_TO, PluginMessageIn,
    PluginMessageOut,
};

// Re-export the proc-macros so plugin authors only need a single
// `mumble-plugin-api` dependency.  See the `info_macros` module for
// the declarative `plugin_info!` companion.
pub use mumble_plugin_api_derive::{
    command, component, fancy_plugin, field, handler_id, modal, show_modal,
};

/// Magic constant identifying the on-wire shape of [`MumblePlugin`] and
/// [`PluginContext`].  Bumped whenever method signatures change.
///
/// The host refuses to load any cdylib that exposes a different value
/// from its [`FancyPluginMod::abi_version`] field.
pub const PLUGIN_ABI_VERSION: u32 = 2;

/// Name of the plain C-ABI function every plugin cdylib exports via
/// [`fancy_export_plugin!`].  The host reads this *before* performing any
/// `abi_stable` layout cast: a cdylib built against an incompatible
/// `mumble-plugin-api` can have a vtable/layout so different that the typed
/// `abi_stable` cast segfaults instead of returning an error, so the host
/// gates on this layout-independent `u32` first.
///
/// Signature: `extern "C" fn() -> u32` returning [`PLUGIN_ABI_VERSION`].
pub const PLUGIN_ABI_VERSION_SYMBOL: &str = "__mumble_plugin_abi_version";

/// Hard cap on the uncompressed size of a plugin's [`PluginInfo`] JSON.
///
/// Enforced by the host at load time and again before broadcasting.
/// 64 KiB is generous for hundreds of debug rows while preventing a
/// rogue plugin from clogging the control channel.
pub const PLUGIN_INFO_MAX_BYTES: usize = 64 * 1024;

/// Plugin-data id used to broadcast [`PluginInfo`] payloads to clients.
pub const PLUGIN_INFO_DATA_ID: &str = "fancy-plugin-info";

/// Identifier for a Mumble virtual server within a single murmur process.
pub type ServerId = u32;

/// Identifier for a connected client session within a virtual server.
pub type SessionId = u32;

/// Identifier for a channel within a virtual server.
pub type ChannelId = u32;

/// Snapshot of information about a newly connected client.
#[repr(C)]
#[derive(Debug, Clone, StableAbi)]
pub struct ClientInfo {
    /// Virtual server the client connected to.
    pub server_id: ServerId,
    /// Session id assigned to this client by the server.
    pub session_id: SessionId,
    /// Username the client authenticated as.
    pub username: RString,
    /// Hex-encoded SHA-1 hash of the client's TLS certificate, or empty
    /// string if the client did not present one.
    pub cert_hash: RString,
}

/// Errors that may be returned from plugin lifecycle and event hooks.
#[repr(u8)]
#[derive(Debug, Clone, Error, StableAbi)]
pub enum PluginError {
    /// Plugin configuration was invalid or required keys were missing.
    #[error("invalid plugin configuration: {0}")]
    Config(RString),

    /// I/O error during plugin operation.
    #[error("plugin i/o error: {0}")]
    Io(RString),

    /// Plugin attempted to use the context after it was disposed.
    #[error("plugin context has been disposed")]
    ContextDisposed,

    /// Catch-all for plugin-specific errors.
    #[error("plugin error: {0}")]
    Other(RString),
}

impl From<std::io::Error> for PluginError {
    fn from(e: std::io::Error) -> Self {
        PluginError::Io(RString::from(e.to_string()))
    }
}

/// Result alias used throughout the FFI surface.
pub type PluginResult<T> = abi_stable::std_types::RResult<T, PluginError>;

/// Free-form key/value pair surfaced in the developer Server Info panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugRow {
    /// Short label shown in the left column.
    pub label: String,
    /// Value shown in the right column.  Plugins should redact secrets
    /// themselves; the host does not inspect this string.
    pub value: String,
}

/// Typed information a plugin advertises about itself.
///
/// The host serialises this to JSON, optionally compresses with `zstd`,
/// and forwards it to connected clients.  The client renders the typed
/// top-level fields with localised labels and falls back to a generic
/// `label / value` table for [`Self::debug_rows`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    /// One-line human-readable description of what the plugin does.
    pub description: String,
    /// Optional author/maintainer attribution.
    pub author: Option<String>,
    /// Optional homepage / source-repository URL.
    pub homepage: Option<String>,
    /// Short feature tags ("http", "websocket", "persistence", ...).
    pub tags: Vec<String>,
    /// Free-form runtime stats (listening ports, active session counts,
    /// feature flags) for the developer panel.
    pub debug_rows: Vec<DebugRow>,
    /// Tier-1 client extension manifest.  When set, the Fancy Mumble
    /// client renders the declared slash commands, settings panels, and
    /// component vocabulary.  Omitted from the JSON envelope when
    /// `None`, so legacy plugins remain wire-compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_manifest: Option<ClientManifest>,
}

impl PluginInfo {
    /// Serialise to JSON and verify the result fits within
    /// [`PLUGIN_INFO_MAX_BYTES`].  Returns the JSON bytes ready to ship.
    pub fn to_validated_json(&self) -> Result<Vec<u8>, PluginInfoError> {
        let bytes = serde_json::to_vec(self).map_err(PluginInfoError::Encode)?;
        if bytes.len() > PLUGIN_INFO_MAX_BYTES {
            return Err(PluginInfoError::TooLarge {
                size: bytes.len(),
                limit: PLUGIN_INFO_MAX_BYTES,
            });
        }
        Ok(bytes)
    }

    /// Encode as JSON and wrap in an [`RString`] suitable for direct
    /// return from [`MumblePlugin::info_json`].  Falls back to `"{}"` on
    /// validation failure (oversize or non-encodable struct) so a
    /// misbehaving plugin still loads instead of returning garbage.
    /// Use [`Self::to_validated_json`] directly if you want to inspect
    /// the error.
    pub fn to_rstring(&self) -> RString {
        match self.to_validated_json() {
            Ok(bytes) => RString::from(String::from_utf8_lossy(&bytes).into_owned()),
            Err(_) => RString::from("{}"),
        }
    }
}

/// Errors produced by [`PluginInfo::to_validated_json`].
#[derive(Debug, Error)]
pub enum PluginInfoError {
    /// Serialisation failure (should not happen for well-formed structs).
    #[error("plugin info json encode failed: {0}")]
    Encode(serde_json::Error),
    /// Payload exceeds the per-plugin size cap.
    #[error("plugin info payload {size} B exceeds limit of {limit} B")]
    TooLarge {
        /// Actual payload size in bytes.
        size: usize,
        /// Configured limit ([`PLUGIN_INFO_MAX_BYTES`]).
        limit: usize,
    },
}

/// Stable C-ABI root module exported by every plugin cdylib.
///
/// Plugin authors usually wrap the export with the [`fancy_export_plugin`]
/// macro rather than handwriting the symbol.
#[repr(C)]
#[derive(StableAbi)]
#[sabi(kind(Prefix(prefix_ref = FancyPluginModRef)))]
#[sabi(missing_field(panic))]
pub struct FancyPluginMod {
    /// ABI version this plugin was built against.  Must equal
    /// [`PLUGIN_ABI_VERSION`] or the host will refuse to load.
    pub abi_version: u32,
    /// Factory that constructs the plugin instance.  Called exactly once
    /// per cdylib load.
    #[sabi(last_prefix_field)]
    pub create_plugin: extern "C" fn() -> MumblePlugin_TO<abi_stable::std_types::RBox<()>>,
}

impl RootModule for FancyPluginModRef {
    declare_root_module_statics! {FancyPluginModRef}
    const BASE_NAME: &'static str = "fancy_plugin";
    const NAME: &'static str = "fancy_plugin";
    const VERSION_STRINGS: VersionStrings = package_version_strings!();
}

impl std::fmt::Debug for FancyPluginMod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FancyPluginMod")
            .field("abi_version", &self.abi_version)
            .field("create_plugin", &"<fn>")
            .finish()
    }
}

/// Internal re-export so [`fancy_export_plugin!`] callers do not need to
/// add `abi_stable` to their own `Cargo.toml`.
#[doc(hidden)]
pub mod abi_stable_reexport {
    pub use abi_stable::*;
}

/// Convenience macro for plugin crates: export the `cdylib` factory
/// symbol with the right name, ABI version, and trait-object wrapping.
///
/// ```ignore
/// fancy_export_plugin!(MyPlugin::new);
/// ```
#[macro_export]
macro_rules! fancy_export_plugin {
    ($factory:expr) => {
        // The macro expansion lives in its own private module so that
        // the inner `#![allow(missing_docs)]` covers the undocumented
        // `pub static` that `abi_stable`'s `#[export_root_module]`
        // proc-macro emits.  Without the module wrapper, the
        // suppression would not reach the generated static and every
        // downstream plugin would have to add its own `#[allow]`.
        // Private module: `missing_docs` only fires on publicly reachable
        // items, so keeping this module private is the correct fix.
        // `#[no_mangle]` C symbols generated by `#[export_root_module]`
        // are exported at the C-ABI level regardless of Rust visibility.
        #[doc(hidden)]
        mod _fancy_plugin_export {

            // Make every item in the caller's crate root visible so the
            // user-supplied factory expression (e.g. `MyPlugin::new`)
            // resolves the same way it would at the macro call site.
            use super::*;

            #[$crate::abi_stable_reexport::export_root_module]
            pub fn _fancy_plugin_root_module() -> $crate::FancyPluginModRef {
                use $crate::abi_stable_reexport::prefix_type::PrefixTypeTrait;
                $crate::FancyPluginMod {
                    abi_version: $crate::PLUGIN_ABI_VERSION,
                    create_plugin: _fancy_plugin_create,
                }
                .leak_into_prefix()
            }

            // Plain C-ABI version probe the host reads *before* any
            // `abi_stable` typed cast (see
            // [`$crate::PLUGIN_ABI_VERSION_SYMBOL`]).  Reading a bare
            // `u32` is layout-independent, so the host can reject a
            // mismatched plugin without risking the segfault that a
            // typed vtable cast against an incompatible binary causes.
            #[no_mangle]
            pub extern "C" fn __mumble_plugin_abi_version() -> u32 {
                $crate::PLUGIN_ABI_VERSION
            }

            extern "C" fn _fancy_plugin_create(
            ) -> $crate::MumblePlugin_TO<$crate::abi_stable_reexport::std_types::RBox<()>> {
                let plugin = ($factory)();
                $crate::MumblePlugin_TO::from_value(
                    plugin,
                    $crate::abi_stable_reexport::sabi_trait::TD_Opaque,
                )
            }
        }
    };
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "tests panic on failure")]

    use super::*;

    #[test]
    fn plugin_info_json_roundtrip() {
        let info = PluginInfo {
            description: "test".into(),
            author: Some("nobody".into()),
            homepage: None,
            tags: vec!["http".into(), "ws".into()],
            debug_rows: vec![DebugRow {
                label: "port".into(),
                value: "8080".into(),
            }],
            client_manifest: None,
        };
        let bytes = info.to_validated_json().expect("encode");
        let back: PluginInfo = serde_json::from_slice(&bytes).expect("decode");
        assert_eq!(back.description, info.description);
        assert_eq!(back.tags, info.tags);
        assert_eq!(back.debug_rows.len(), 1);
        assert!(back.client_manifest.is_none());
    }

    #[test]
    fn plugin_info_too_large_rejected() {
        let huge = "x".repeat(PLUGIN_INFO_MAX_BYTES + 1);
        let info = PluginInfo {
            description: huge,
            author: None,
            homepage: None,
            tags: vec![],
            debug_rows: vec![],
            client_manifest: None,
        };
        let err = info.to_validated_json().expect_err("must reject");
        assert!(matches!(err, PluginInfoError::TooLarge { .. }));
    }

    #[test]
    fn plugin_info_with_client_manifest_roundtrip() {
        let manifest = ClientManifest {
            schema_version: CLIENT_MANIFEST_SCHEMA_VERSION,
            slash_commands: vec![SlashCommand {
                name: "greet".into(),
                description: "Send a greeting".into(),
                options: vec![],
            }],
            capabilities: vec![Capability::SlashCommands],
            settings_panels: vec![],
        };
        let info = PluginInfo {
            description: "with manifest".into(),
            author: None,
            homepage: None,
            tags: vec![],
            debug_rows: vec![],
            client_manifest: Some(manifest),
        };
        let bytes = info.to_validated_json().expect("encode");
        let back: PluginInfo = serde_json::from_slice(&bytes).expect("decode");
        let m = back.client_manifest.expect("manifest present");
        assert_eq!(m.slash_commands.len(), 1);
        assert_eq!(m.slash_commands[0].name, "greet");
    }

    #[test]
    fn plugin_info_omits_manifest_when_none() {
        let info = PluginInfo {
            description: "legacy".into(),
            author: None,
            homepage: None,
            tags: vec![],
            debug_rows: vec![],
            client_manifest: None,
        };
        let bytes = info.to_validated_json().expect("encode");
        let json = std::str::from_utf8(&bytes).expect("utf8");
        assert!(!json.contains("client_manifest"));
    }

    #[test]
    fn abi_version_is_two() {
        assert_eq!(PLUGIN_ABI_VERSION, 2);
    }

    #[test]
    fn plugin_info_macro_minimal() {
        // description-only invocation; everything else should default.
        let info = plugin_info! {
            description: "minimal",
        };
        assert_eq!(info.description, "minimal");
        assert!(info.author.is_none());
        assert!(info.homepage.is_none());
        assert!(info.tags.is_empty());
        assert!(info.debug_rows.is_empty());
        assert!(info.client_manifest.is_none());
    }

    #[test]
    fn plugin_info_macro_with_simple_fields() {
        let sessions: usize = 7;
        let port: u16 = 8080;
        let info = plugin_info! {
            description: "x",
            author: "nobody",
            homepage: "https://example.invalid",
            tags: ["a", "b", "c"],
            debug_info: {
                "active_sessions" => sessions,
                "http_port" => port,
            },
        };
        assert_eq!(info.description, "x");
        assert_eq!(info.author.as_deref(), Some("nobody"));
        assert_eq!(info.homepage.as_deref(), Some("https://example.invalid"));
        assert_eq!(info.tags, vec!["a", "b", "c"]);
        assert_eq!(info.debug_rows.len(), 2);
        assert_eq!(info.debug_rows[0].label, "active_sessions");
        assert_eq!(info.debug_rows[0].value, "7");
        assert_eq!(info.debug_rows[1].value, "8080");
        assert!(info.client_manifest.is_none());
    }

    #[test]
    fn plugin_info_macro_with_inline_manifest() {
        let info = plugin_info! {
            description: "demo",
            manifest: {
                capabilities: [SlashCommands, Components, Modals],
                slash_commands: [
                    {
                        name: "greet",
                        description: "Send a friendly greeting",
                        options: [
                            { name: "who",  description: "target",    type: String,  required: true },
                            { name: "loud", description: "uppercase", type: Boolean, required: false },
                        ],
                    },
                ],
                settings_panels: [
                    {
                        id: "status",
                        title: "Greeter status",
                        rows: [
                            "template" => "Welcome, {username}!",
                            "demo"     => "Try /greet",
                        ],
                    },
                ],
            },
        };
        let m = info.client_manifest.expect("manifest present");
        assert_eq!(m.schema_version, CLIENT_MANIFEST_SCHEMA_VERSION);
        assert_eq!(m.capabilities.len(), 3);
        assert!(m.capabilities.contains(&Capability::SlashCommands));
        assert_eq!(m.slash_commands.len(), 1);
        assert_eq!(m.slash_commands[0].name, "greet");
        assert_eq!(m.slash_commands[0].options.len(), 2);
        assert_eq!(
            m.slash_commands[0].options[0].option_type,
            OptionType::String
        );
        assert_eq!(
            m.slash_commands[0].options[1].option_type,
            OptionType::Boolean
        );
        assert!(m.slash_commands[0].options[0].required);
        assert!(!m.slash_commands[0].options[1].required);
        assert_eq!(m.settings_panels.len(), 1);
        assert_eq!(m.settings_panels[0].rows.len(), 2);
        assert_eq!(m.settings_panels[0].rows[0].label, "template");
    }

    #[test]
    fn plugin_info_macro_accepts_external_manifest_value() {
        let prebuilt = ClientManifest {
            schema_version: CLIENT_MANIFEST_SCHEMA_VERSION,
            slash_commands: vec![],
            capabilities: vec![Capability::Notifications],
            settings_panels: vec![],
        };
        let info = plugin_info! {
            description: "demo",
            client_manifest: prebuilt,
        };
        let m = info.client_manifest.expect("manifest present");
        assert!(m.capabilities.contains(&Capability::Notifications));
    }

    #[test]
    fn plugin_info_to_rstring_roundtrips() {
        let info = plugin_info! {
            description: "rstring",
            author: "nobody",
        };
        let s = info.to_rstring();
        let back: PluginInfo = serde_json::from_str(s.as_str()).expect("decode");
        assert_eq!(back.description, "rstring");
        assert_eq!(back.author.as_deref(), Some("nobody"));
    }

    #[test]
    fn plugin_info_macro_accepts_dynamic_debug_rows() {
        // Build the rows imperatively (e.g. conditional on runtime state)
        // and hand the Vec to the macro via `debug_info:`.
        let mut rows = Vec::new();
        for (label, n) in [("a", 1usize), ("b", 2)] {
            rows.push(DebugRow {
                label: label.into(),
                value: n.to_string(),
            });
        }
        let info = plugin_info! {
            description: "dyn",
            debug_info: rows,
        };
        assert_eq!(info.debug_rows.len(), 2);
        assert_eq!(info.debug_rows[0].label, "a");
        assert_eq!(info.debug_rows[1].value, "2");
    }

    #[test]
    fn plugin_info_to_rstring_falls_back_on_oversize() {
        let info = plugin_info! {
            description: "x".repeat(PLUGIN_INFO_MAX_BYTES + 1),
        };
        assert_eq!(info.to_rstring().as_str(), "{}");
    }
}
