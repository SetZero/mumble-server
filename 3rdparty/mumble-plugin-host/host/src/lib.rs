//! `mumble-plugin-host` - cdylib loaded by the C++ Mumble server.
//!
//! Bridges the synchronous C ABI used by the server to the async
//! [`mumble_plugin_api::MumblePlugin`] trait. All built-in plugins are
//! statically linked into this crate so deployment is a single shared
//! library file.

mod context;
mod ffi;
mod host;

pub use context::PluginHostCallbacks;
pub use ffi::{
    plugin_host_create, plugin_host_destroy, plugin_host_on_client_connected,
    plugin_host_on_client_disconnected, plugin_host_on_plugin_data, PluginHostHandle,
};
