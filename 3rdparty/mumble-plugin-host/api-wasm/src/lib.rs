//! Guest-side authoring bindings for **WebAssembly Mumble plugins**.
//!
//! A WASM plugin is a WebAssembly *component* implementing the `plugin-world`
//! world from [`../../wit/world.wit`](../../wit/world.wit). The host
//! (`mumble-plugin-host`) loads such a component and drives it through the
//! exact same lifecycle as a native cdylib plugin, so a single server can run
//! native and WASM plugins side by side.
//!
//! This crate re-exports the generated bindings so plugin authors can write a
//! component against safe Rust types:
//!
//! - [`Guest`] - the trait your plugin type implements (the lifecycle/event
//!   hooks mirroring the native `MumblePlugin` trait). Exports take no `ctx`
//!   argument; call the [`host`] functions directly instead.
//! - [`host`] - free functions you call back into the server with (the mirror
//!   of the native `PluginContext` trait). These are the *only* capabilities a
//!   guest has: there is no WASI, filesystem, clock, or network.
//! - [`export_plugin!`] - registers your `Guest` implementation as the
//!   component's exports.
//!
//! # Example
//!
//! ```ignore
//! use mumble_plugin_api_wasm::{export_plugin, host, Guest, PluginMessageIn};
//!
//! struct Greeter;
//!
//! impl Guest for Greeter {
//!     fn abi_version() -> u32 {
//!         mumble_plugin_api_wasm::PLUGIN_ABI_VERSION
//!     }
//!     fn name() -> String {
//!         "greeter".into()
//!     }
//!     fn version() -> String {
//!         "0.1.0".into()
//!     }
//!     fn info_json() -> String {
//!         "{}".into()
//!     }
//!     fn on_plugin_message(msg: PluginMessageIn) -> Result<(), PluginError> {
//!         // Echo the payload straight back to the sender.
//!         let _ = host::send_plugin_data(
//!             msg.server_id,
//!             msg.sender_session,
//!             "greeter-echo",
//!             &msg.payload,
//!         );
//!         Ok(())
//!     }
//!     // ... remaining hooks fall back to the trait defaults ...
//! }
//!
//! export_plugin!(Greeter);
//! ```
//!
//! Build the component for the `wasm32-unknown-unknown` target and convert it
//! to a component with `wasm-tools component new` (see the sample plugin's
//! README), then drop the resulting `*.wasm` into a Mumble plugin directory.

/// ABI version this binding crate targets. The host rejects a component whose
/// `abi-version` export does not equal its own `PLUGIN_ABI_VERSION`; return
/// this value from [`Guest::abi_version`].
pub const PLUGIN_ABI_VERSION: u32 = 3;

// Component bindings generated from the shared WIT. Emitted at the crate root
// (not a private module) so the re-exported `export_plugin!` macro can resolve
// the generated component glue through this crate's path in downstream plugin
// crates. `pub_export_macro` makes the export macro `#[macro_export]` and
// `export_macro_name` renames it so it does not collide with other components.
wit_bindgen::generate!({
    world: "plugin-world",
    path: "../wit",
    generate_all,
    pub_export_macro: true,
    export_macro_name: "export_plugin",
    default_bindings_module: "mumble_plugin_api_wasm",
});

pub use exports::mumble::plugin::guest::Guest;
pub use exports::mumble::plugin::ui_guest::Guest as UiGuest;
pub use mumble::plugin::host;
pub use mumble::plugin::types::{ClientInfo, PluginError, PluginMessageIn, PluginMessageOut};
pub use mumble::plugin::ui_host;

/// Typed Tier-1 UI vocabulary (slash commands, components, modals, toasts)
/// shared with the host.  Build these native values instead of hand-writing the
/// client JSON; see [`UiGuest`] for the hooks that consume and produce them and
/// [`ui_host::send_interaction_response`] for dispatching a response.
pub use mumble::plugin::ui_types as ui;
