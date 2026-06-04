//! `mumble-plugin-host` - cdylib loaded by the C++ Mumble server.
//!
//! Discovers plugin cdylibs at startup, loads them via
//! [`abi_stable`], and dispatches synchronous lifecycle events to each.
//! Plugins own their internal `tokio` runtime; the host has none.

mod context;
mod ffi;
mod host;
mod info;
mod install;
mod loader;
#[cfg(feature = "wasm-plugins")]
mod wasm;

pub use context::PluginHostCallbacks;
pub use ffi::{
    plugin_host_create, plugin_host_destroy, plugin_host_free_string,
    plugin_host_get_registry_json, plugin_host_install_plugin, plugin_host_list_plugins,
    plugin_host_on_client_connected, plugin_host_on_client_disconnected,
    plugin_host_on_plugin_data, plugin_host_on_plugin_message, plugin_host_set_plugin_enabled,
    plugin_host_uninstall_plugin, PluginHostHandle,
};

/// Fuzzing-only entry points into the marketplace-install parsers.
///
/// The install flow ingests three attacker-influenced byte streams: the
/// manifest JSON, and the bytes of a downloaded `zip` / `tar.gz` archive
/// (whose member sizes drive allocations during extraction).  These wrappers
/// return plain `bool`/`Option` so no internal types leak through the public
/// API.  Compiled only under the `fuzzing` feature; never enable in
/// production.
#[cfg(feature = "fuzzing")]
pub mod fuzz {
    /// Parse a marketplace manifest from raw bytes; `true` on success.
    #[must_use]
    pub fn parse_manifest(data: &[u8]) -> bool {
        crate::install::parse_manifest_bytes(data).is_ok()
    }

    /// Extract a cdylib named `"plugin"` from a zip archive; `true` on success.
    #[must_use]
    pub fn extract_zip(data: &[u8]) -> bool {
        crate::install::extract_zip(data, "plugin").is_ok()
    }

    /// Extract a cdylib named `"plugin"` from a tar.gz archive; `true` on success.
    #[must_use]
    pub fn extract_tar_gz(data: &[u8]) -> bool {
        crate::install::extract_tar_gz(data, "plugin").is_ok()
    }
}
