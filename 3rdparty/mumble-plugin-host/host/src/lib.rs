//! `mumble-plugin-host` - cdylib loaded by the C++ Mumble server.
//!
//! Discovers plugin cdylibs at startup, loads them via
//! [`abi_stable`], and dispatches synchronous lifecycle events to each.
//! Plugins own their internal `tokio` runtime; the host has none.

mod context;
mod ffi;
mod host;
mod info;
mod loader;

pub use context::PluginHostCallbacks;
pub use ffi::{
    plugin_host_create, plugin_host_destroy, plugin_host_free_string,
    plugin_host_get_registry_json, plugin_host_on_client_connected,
    plugin_host_on_client_disconnected, plugin_host_on_plugin_data, plugin_host_on_plugin_message,
    PluginHostHandle,
};
