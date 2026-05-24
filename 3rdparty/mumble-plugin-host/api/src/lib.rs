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
    StableAbi, declare_root_module_statics, library::RootModule, package_version_strings,
    sabi_types::VersionStrings, std_types::RString,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod permissions;
pub mod plugin;

pub use crate::plugin::{
    MumblePlugin, MumblePlugin_TO, PluginContext, PluginContext_TO, PluginMessageIn,
    PluginMessageOut,
};

/// Magic constant identifying the on-wire shape of [`MumblePlugin`] and
/// [`PluginContext`].  Bumped whenever method signatures change.
///
/// The host refuses to load any cdylib that exposes a different value
/// from its [`FancyPluginMod::abi_version`] field.
pub const PLUGIN_ABI_VERSION: u32 = 2;

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
    /// Short capability tags ("http", "websocket", "persistence", ...).
    pub capabilities: Vec<String>,
    /// Free-form runtime stats (listening ports, active session counts,
    /// feature flags) for the developer panel.
    pub debug_rows: Vec<DebugRow>,
}

impl PluginInfo {
    /// Serialise to JSON and verify the result fits within
    /// [`PLUGIN_INFO_MAX_BYTES`].  Returns the JSON bytes ready to ship.
    pub fn to_validated_json(&self) -> Result<Vec<u8>, PluginInfoError> {
        let bytes = serde_json::to_vec(self).map_err(PluginInfoError::Encode)?;
        if bytes.len() > PLUGIN_INFO_MAX_BYTES {
            return Err(PluginInfoError::TooLarge { size: bytes.len(), limit: PLUGIN_INFO_MAX_BYTES });
        }
        Ok(bytes)
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
    pub create_plugin:
        extern "C" fn() -> MumblePlugin_TO<abi_stable::std_types::RBox<()>>,
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
        #[doc(hidden)]
        #[$crate::abi_stable_reexport::export_root_module]
        pub fn _fancy_plugin_root_module() -> $crate::FancyPluginModRef {
            use $crate::abi_stable_reexport::prefix_type::PrefixTypeTrait;
            $crate::FancyPluginMod {
                abi_version: $crate::PLUGIN_ABI_VERSION,
                create_plugin: _fancy_plugin_create,
            }
            .leak_into_prefix()
        }

        #[doc(hidden)]
        extern "C" fn _fancy_plugin_create() -> $crate::MumblePlugin_TO<
            $crate::abi_stable_reexport::std_types::RBox<()>,
        > {
            let plugin = ($factory)();
            $crate::MumblePlugin_TO::from_value(
                plugin,
                $crate::abi_stable_reexport::sabi_trait::TD_Opaque,
            )
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
            capabilities: vec!["http".into(), "ws".into()],
            debug_rows: vec![DebugRow { label: "port".into(), value: "8080".into() }],
        };
        let bytes = info.to_validated_json().expect("encode");
        let back: PluginInfo = serde_json::from_slice(&bytes).expect("decode");
        assert_eq!(back.description, info.description);
        assert_eq!(back.capabilities, info.capabilities);
        assert_eq!(back.debug_rows.len(), 1);
    }

    #[test]
    fn plugin_info_too_large_rejected() {
        let huge = "x".repeat(PLUGIN_INFO_MAX_BYTES + 1);
        let info = PluginInfo {
            description: huge,
            author: None,
            homepage: None,
            capabilities: vec![],
            debug_rows: vec![],
        };
        let err = info.to_validated_json().expect_err("must reject");
        assert!(matches!(err, PluginInfoError::TooLarge { .. }));
    }

    #[test]
    fn abi_version_is_two() {
        assert_eq!(PLUGIN_ABI_VERSION, 2);
    }
}
