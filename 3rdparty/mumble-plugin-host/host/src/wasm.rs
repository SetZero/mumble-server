//! WASM component plugin backend.
//!
//! This module lets a plugin shipped as a WebAssembly **component**
//! (`*.wasm`, implementing the `plugin-world` world from
//! [`../../wit/world.wit`](../../wit/world.wit)) be loaded and driven through
//! the *exact same* [`MumblePlugin_TO`] trait object the native cdylib loader
//! produces. The rest of the host ([`crate::host`], [`crate::ffi`]) therefore
//! treats WASM and native plugins identically — the polymorphism lives in the
//! `abi_stable` trait object, not in the host.
//!
//! ## Sandbox
//!
//! Components are instantiated with a [`Linker`] that exposes the `host`
//! interface (the [`PluginContext`](mumble_plugin_api::PluginContext) mirror).
//! With the `wasm-wasi` feature (on by default) a **locked-down** WASI is also
//! linked so guests whose toolchain embeds a WASI-dependent runtime (notably
//! JavaScript plugins built with `ComponentizeJS`) can instantiate. That WASI
//! context grants no filesystem, network, environment or argument access — only
//! the deterministic capabilities the embedded engine needs (clock, entropy);
//! `stderr` is inherited so guest diagnostics surface in the server log. Pure
//! components (e.g. Rust guests built with `wit-bindgen`) simply do not import
//! any WASI and are unaffected. Disable the `wasm-wasi` feature to link the
//! `host` interface alone.
//!
//! ## Context plumbing
//!
//! WIT component exports take no `ctx` parameter; the imported `host` functions
//! *are* the context. Before each exported call the active
//! [`PluginContext_TO`] is installed into the [`Store`]'s [`HostState`], and the
//! imported host functions forward to it. The slot is cleared again afterwards
//! so a guest can never retain a context across calls.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use abi_stable::sabi_trait::TD_Opaque;
use abi_stable::std_types::{RArc, RErr, ROk, ROption, RResult, RSlice, RStr, RString, RVec};
use mumble_plugin_api::client_manifest as ncm;
use mumble_plugin_api::{
    ClientInfo, MumblePlugin, MumblePlugin_TO, PluginContext_TO, PluginError, PluginMessageIn,
    PluginMessageOut, PluginResult, ServerId, SessionId, PLUGIN_ABI_VERSION,
};
use mumble_plugin_api::{INTERACTION_PAYLOAD_TYPE, INTERACTION_RESPONSE_PAYLOAD_TYPE};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};

use crate::loader::{LoadError, LoadedPlugin};

/// Native [`Interaction`](mumble_plugin_api::Interaction) decoded from an
/// inbound "Interaction" payload before it is mapped onto the typed WIT record.
type NativeInteraction = ncm::Interaction;

// Generated component bindings. Kept in a PRIVATE module so the (undocumented)
// public items wit-bindgen emits are not reachable from the crate root and thus
// do not trip the crate's `missing_docs = "deny"` lint.
mod bindings {
    wasmtime::component::bindgen!({
        world: "plugin-world",
        path: "../wit",
    });
}

use bindings::exports::mumble::plugin::guest::{
    ClientInfo as WitClientInfo, PluginMessageIn as WitPluginMessageIn,
};
use bindings::mumble::plugin::host::Host as HostImports;
use bindings::mumble::plugin::types::{
    PluginError as WitError, PluginMessageOut as WitPluginMessageOut,
};
use bindings::mumble::plugin::ui_host::Host as UiHostImports;
use bindings::mumble::plugin::ui_types as wit_ui;
use bindings::PluginWorld;

/// Process-wide wasmtime engine. Components are cheap to share across plugins;
/// only one engine (and its JIT/compilation context) is needed.
fn engine() -> Result<&'static Engine, LoadError> {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    if let Some(existing) = ENGINE.get() {
        return Ok(existing);
    }
    let mut cfg = Config::new();
    let _ = cfg.wasm_component_model(true);
    let built = Engine::new(&cfg).map_err(|e| LoadError::Invalid {
        path: PathBuf::new(),
        message: format!("wasmtime engine init failed: {e}"),
    })?;
    // A racing thread may have initialised first; `get_or_init` keeps the
    // winner and drops our spare engine.
    Ok(ENGINE.get_or_init(|| built))
}

/// Per-store state holding the [`PluginContext`](mumble_plugin_api::PluginContext)
/// active for the duration of the current exported call.
struct HostState {
    /// Borrowed context installed for the in-flight export call.
    ///
    /// [`PluginContext_TO`] is not `Clone`, and the host hands every hook
    /// (except `on_load`) only a `&PluginContext_TO`, so we cannot store an
    /// owned copy. Instead we stash a raw pointer to the borrow for the
    /// strictly synchronous duration of one [`WasmPlugin::run`] call and reset
    /// it to null before returning.
    active_ctx: ContextPtr,
    /// Stable name of the loaded plugin, stamped onto the outbound envelopes
    /// the typed UI bridge ([`UiHostImports::send_interaction_response`])
    /// produces so the guest never has to repeat it.
    plugin_name: String,
    /// Sandboxed WASI context (no filesystem, network, env or args). Present
    /// only when the `wasm-wasi` feature links WASI into the component linker.
    #[cfg(feature = "wasm-wasi")]
    wasi: wasmtime_wasi::WasiCtx,
    /// Resource table backing the WASI host implementation.
    #[cfg(feature = "wasm-wasi")]
    table: wasmtime_wasi::ResourceTable,
}

#[cfg(feature = "wasm-wasi")]
impl wasmtime_wasi::WasiView for HostState {
    fn ctx(&mut self) -> &mut wasmtime_wasi::WasiCtx {
        &mut self.wasi
    }

    fn table(&mut self) -> &mut wasmtime_wasi::ResourceTable {
        &mut self.table
    }
}

impl HostState {
    /// The context borrowed for the current export call, if any.
    fn ctx(&self) -> Option<&PluginContext_TO<RArc<()>>> {
        // SAFETY: `active_ctx` is only ever set to a live `&ctx` borrow for the
        // synchronous span of one `run()` call (during which the referent is
        // alive) and is reset to null before `run` returns. Host imports run
        // on the same thread inside that span, so the pointer is valid here and
        // never observed from another thread or after the borrow ends. We only
        // ever produce shared references, so there is no aliasing conflict with
        // the original borrow.
        unsafe { self.active_ctx.0.as_ref() }
    }
}

/// A raw pointer to the borrowed [`PluginContext_TO`] active during an export
/// call. See [`HostState::active_ctx`] for the safety contract.
struct ContextPtr(*const PluginContext_TO<RArc<()>>);

// SAFETY: the pointer is only set to a valid borrow for the synchronous
// duration of a single `run()` call and reset to null before `run` returns, so
// it is never dereferenced from another thread or after the borrow ends. The
// `Send` bound is required only so the enclosing `Store<HostState>` stays
// `Send`; the pointer is always null while the store is idle between calls.
unsafe impl Send for ContextPtr {}

/// A loaded WASM component presented to the host as a [`MumblePlugin`].
struct WasmPlugin {
    /// Cached `name` export result (so [`MumblePlugin::name`] can borrow it).
    name: String,
    /// Cached `version` export result.
    version: String,
    /// Cached `info-json` export result.
    info_json: String,
    /// Typed accessors for the component's `plugin` exports.
    bindings: PluginWorld,
    /// Component instance store. Wrapped in a [`Mutex`] because
    /// [`MumblePlugin`] is `Sync` but a wasmtime [`Store`] is not.
    store: Mutex<Store<HostState>>,
}

impl WasmPlugin {
    /// Install `ctx` as the active context, run `f` against the guest exports,
    /// then clear the context and translate the result into a [`PluginResult`].
    fn run(
        &self,
        ctx: &PluginContext_TO<RArc<()>>,
        f: impl FnOnce(&Self, &mut Store<HostState>) -> wasmtime::Result<Result<(), WitError>>,
    ) -> PluginResult<()> {
        let mut guard = self.store.lock().unwrap_or_else(|p| p.into_inner());
        guard.data_mut().active_ctx = ContextPtr(ctx as *const _);
        let result = f(self, &mut guard);
        guard.data_mut().active_ctx = ContextPtr(std::ptr::null());
        match result {
            Ok(Ok(())) => ROk(()),
            Ok(Err(e)) => RErr(wit_err_to_native(e)),
            Err(trap) => RErr(PluginError::Other(RString::from(format!(
                "wasm trap: {trap}"
            )))),
        }
    }
}

impl MumblePlugin for WasmPlugin {
    fn name(&self) -> RStr<'_> {
        RStr::from(self.name.as_str())
    }

    fn version(&self) -> RStr<'_> {
        RStr::from(self.version.as_str())
    }

    fn info_json(&self) -> RString {
        RString::from(self.info_json.as_str())
    }

    fn on_load(&self, ctx: PluginContext_TO<RArc<()>>) -> PluginResult<()> {
        self.run(&ctx, |me, store| {
            me.bindings.mumble_plugin_guest().call_on_load(store)
        })
    }

    fn on_unload(&self, ctx: &PluginContext_TO<RArc<()>>) -> PluginResult<()> {
        self.run(ctx, |me, store| {
            me.bindings.mumble_plugin_guest().call_on_unload(store)
        })
    }

    fn on_client_connected(
        &self,
        ctx: &PluginContext_TO<RArc<()>>,
        info: ClientInfo,
    ) -> PluginResult<()> {
        let wit = native_client_info_to_wit(&info);
        self.run(ctx, move |me, store| {
            me.bindings
                .mumble_plugin_guest()
                .call_on_client_connected(store, &wit)
        })
    }

    fn on_client_disconnected(
        &self,
        ctx: &PluginContext_TO<RArc<()>>,
        server_id: ServerId,
        session: SessionId,
    ) -> PluginResult<()> {
        self.run(ctx, move |me, store| {
            me.bindings
                .mumble_plugin_guest()
                .call_on_client_disconnected(store, server_id, session)
        })
    }

    fn on_plugin_data(
        &self,
        ctx: &PluginContext_TO<RArc<()>>,
        server_id: ServerId,
        sender: SessionId,
        data_id: RStr<'_>,
        data: RSlice<'_, u8>,
    ) -> PluginResult<()> {
        let did = data_id.as_str().to_owned();
        let bytes = data.as_slice().to_vec();
        self.run(ctx, move |me, store| {
            me.bindings
                .mumble_plugin_guest()
                .call_on_plugin_data(store, server_id, sender, &did, &bytes)
        })
    }

    fn on_plugin_message(
        &self,
        ctx: &PluginContext_TO<RArc<()>>,
        msg: PluginMessageIn,
    ) -> PluginResult<()> {
        // Route inbound Tier-1 interactions through the typed `on-interaction`
        // hook so guests receive native values instead of raw JSON. Anything
        // that is not a well-formed "Interaction" falls through to the generic
        // `on-plugin-message` hook unchanged.
        if msg.payload_type.as_str() == INTERACTION_PAYLOAD_TYPE {
            if let Ok(interaction) =
                serde_json::from_slice::<NativeInteraction>(msg.payload.as_slice())
            {
                let server_id = msg.server_id;
                let sender = msg.sender_session;
                let wit = native_interaction_to_wit(interaction);
                return self.run(ctx, move |me, store| {
                    me.bindings
                        .mumble_plugin_ui_guest()
                        .call_on_interaction(store, server_id, sender, &wit)
                });
            }
        }
        let wit = native_message_in_to_wit(&msg);
        self.run(ctx, move |me, store| {
            me.bindings
                .mumble_plugin_guest()
                .call_on_plugin_message(store, &wit)
        })
    }
}

impl HostImports for HostState {
    fn send_plugin_data(
        &mut self,
        server_id: u32,
        target_session: u32,
        data_id: String,
        data: Vec<u8>,
    ) -> Result<(), WitError> {
        let Some(ctx) = self.ctx() else {
            return Err(WitError::ContextDisposed);
        };
        native_result_to_wit(ctx.send_plugin_data(
            server_id,
            target_session,
            RStr::from(data_id.as_str()),
            RSlice::from(data.as_slice()),
        ))
    }

    fn is_session_active(&mut self, server_id: u32, session: u32) -> bool {
        self.ctx()
            .is_some_and(|ctx| ctx.is_session_active(server_id, session))
    }

    fn user_has_channel_access(&mut self, server_id: u32, session: u32, channel: u32) -> bool {
        self.ctx()
            .is_some_and(|ctx| ctx.user_has_channel_access(server_id, session, channel))
    }

    fn has_permission(
        &mut self,
        server_id: u32,
        session: u32,
        channel: u32,
        permission_flags: u32,
    ) -> bool {
        self.ctx()
            .is_some_and(|ctx| ctx.has_permission(server_id, session, channel, permission_flags))
    }

    fn current_channel(&mut self, server_id: u32, session: u32) -> Option<u32> {
        self.ctx()
            .and_then(|ctx| ropt(ctx.current_channel(server_id, session)))
    }

    fn get_config(&mut self, key: String) -> Option<String> {
        self.ctx()
            .and_then(|ctx| ropt(ctx.get_config(RStr::from(key.as_str()))))
            .map(String::from)
    }

    fn send_plugin_message(&mut self, msg: WitPluginMessageOut) -> Result<(), WitError> {
        let Some(ctx) = self.ctx() else {
            return Err(WitError::ContextDisposed);
        };
        native_result_to_wit(ctx.send_plugin_message(wit_message_out_to_native(msg)))
    }

    fn sessions_in_channel(&mut self, server_id: u32, channel: u32) -> Vec<u32> {
        self.ctx()
            .map(|ctx| {
                ctx.sessions_in_channel(server_id, channel)
                    .into_iter()
                    .collect()
            })
            .unwrap_or_default()
    }

    fn all_sessions(&mut self, server_id: u32) -> Vec<u32> {
        self.ctx()
            .map(|ctx| ctx.all_sessions(server_id).into_iter().collect())
            .unwrap_or_default()
    }

    fn find_session_by_name(&mut self, server_id: u32, name: String) -> Option<u32> {
        self.ctx()
            .and_then(|ctx| ropt(ctx.find_session_by_name(server_id, RStr::from(name.as_str()))))
    }
}

impl UiHostImports for HostState {
    fn send_interaction_response(
        &mut self,
        server_id: u32,
        targets: Vec<u32>,
        channel: Option<u32>,
        response: wit_ui::InteractionResponse,
    ) -> Result<(), WitError> {
        // Clone the plugin name before borrowing the context, so the immutable
        // borrow `ctx()` returns does not overlap the field read.
        let plugin_name = self.plugin_name.clone();
        let Some(ctx) = self.ctx() else {
            return Err(WitError::ContextDisposed);
        };
        let payload = match serde_json::to_vec(&wit_response_to_native(response)) {
            Ok(bytes) => bytes,
            Err(e) => return Err(WitError::Other(format!("encode interaction-response: {e}"))),
        };
        let out = PluginMessageOut {
            server_id,
            plugin_name: RString::from(plugin_name),
            payload_type: RString::from(INTERACTION_RESPONSE_PAYLOAD_TYPE),
            payload: RVec::from(payload),
            target_sessions: RVec::from(targets),
            channel_id: match channel {
                Some(c) => ROption::RSome(c),
                None => ROption::RNone,
            },
        };
        native_result_to_wit(ctx.send_plugin_message(out))
    }
}

/// Load a `.wasm` component plugin and wrap it as a [`MumblePlugin_TO`] so the
/// host can drive it exactly like a native cdylib plugin.
pub fn load_wasm_plugin(path: &Path) -> Result<LoadedPlugin, LoadError> {
    let engine = engine()?;
    let component = Component::from_file(engine, path).map_err(|e| LoadError::Invalid {
        path: path.to_path_buf(),
        message: format!("not a valid wasm component: {e}"),
    })?;

    let mut linker = Linker::new(engine);
    #[cfg(feature = "wasm-wasi")]
    wasmtime_wasi::add_to_linker_sync(&mut linker).map_err(|e| LoadError::Invalid {
        path: path.to_path_buf(),
        message: format!("failed to link WASI imports: {e}"),
    })?;
    bindings::mumble::plugin::host::add_to_linker::<_, HostState>(&mut linker, |s| s).map_err(
        |e| LoadError::Invalid {
            path: path.to_path_buf(),
            message: format!("failed to link host imports: {e}"),
        },
    )?;
    bindings::mumble::plugin::ui_host::add_to_linker::<_, HostState>(&mut linker, |s| s).map_err(
        |e| LoadError::Invalid {
            path: path.to_path_buf(),
            message: format!("failed to link ui-host imports: {e}"),
        },
    )?;

    let mut store = Store::new(
        engine,
        HostState {
            active_ctx: ContextPtr(std::ptr::null()),
            plugin_name: String::new(),
            // A deliberately empty WASI context: no preopened directories, no
            // network, no environment and no CLI args. `stderr` is inherited so a
            // misbehaving guest's diagnostics reach the server log.
            #[cfg(feature = "wasm-wasi")]
            wasi: wasmtime_wasi::WasiCtxBuilder::new()
                .inherit_stderr()
                .build(),
            #[cfg(feature = "wasm-wasi")]
            table: wasmtime_wasi::ResourceTable::new(),
        },
    );
    let world = PluginWorld::instantiate(&mut store, &component, &linker).map_err(|e| {
        LoadError::Invalid {
            path: path.to_path_buf(),
            message: format!("failed to instantiate component: {e}"),
        }
    })?;

    let guest = world.mumble_plugin_guest();
    let abi = guest
        .call_abi_version(&mut store)
        .map_err(|e| LoadError::Invalid {
            path: path.to_path_buf(),
            message: format!("abi-version export trapped: {e}"),
        })?;
    if abi != PLUGIN_ABI_VERSION {
        return Err(LoadError::AbiMismatch {
            path: path.to_path_buf(),
            found: abi,
            expected: PLUGIN_ABI_VERSION,
        });
    }

    let name = call_string_export(path, "name", guest.call_name(&mut store))?;
    let version = call_string_export(path, "version", guest.call_version(&mut store))?;
    let info_json = call_string_export(path, "info-json", guest.call_info_json(&mut store))?;

    // Stamp the plugin name so the typed UI bridge can address outbound
    // envelopes without the guest repeating it on every call.
    store.data_mut().plugin_name = name.clone();

    // Fold the optional typed `ui-guest.manifest()` into the PluginInfo, so a
    // guest can declare its client manifest with native types instead of
    // hand-building the `client_manifest` JSON inside `info-json`.
    let info_json = merge_manifest_into_info(path, &world, &mut store, info_json)?;

    let plugin = WasmPlugin {
        name,
        version,
        info_json,
        bindings: world,
        store: Mutex::new(store),
    };
    Ok(LoadedPlugin {
        path: path.to_path_buf(),
        plugin: MumblePlugin_TO::from_value(plugin, TD_Opaque),
    })
}

/// Translate a trapped/successful string export into a `LoadError` on failure.
fn call_string_export(
    path: &Path,
    which: &str,
    result: wasmtime::Result<String>,
) -> Result<String, LoadError> {
    result.map_err(|e| LoadError::Invalid {
        path: path.to_path_buf(),
        message: format!("{which} export trapped: {e}"),
    })
}

/// Convert an `abi_stable` [`ROption`] into a std [`Option`].
fn ropt<T>(value: ROption<T>) -> Option<T> {
    value.into_option()
}

/// Map a native [`PluginResult`] onto the WIT `result<_, plugin-error>`.
fn native_result_to_wit(result: PluginResult<()>) -> Result<(), WitError> {
    match result {
        RResult::ROk(()) => Ok(()),
        RResult::RErr(e) => Err(native_err_to_wit(e)),
    }
}

/// Convert a native [`PluginError`] into its WIT counterpart.
fn native_err_to_wit(err: PluginError) -> WitError {
    match err {
        PluginError::Config(s) => WitError::Config(String::from(s)),
        PluginError::Io(s) => WitError::Io(String::from(s)),
        PluginError::ContextDisposed => WitError::ContextDisposed,
        PluginError::Other(s) => WitError::Other(String::from(s)),
    }
}

/// Convert a WIT `plugin-error` into the native [`PluginError`].
fn wit_err_to_native(err: WitError) -> PluginError {
    match err {
        WitError::Config(s) => PluginError::Config(RString::from(s)),
        WitError::Io(s) => PluginError::Io(RString::from(s)),
        WitError::ContextDisposed => PluginError::ContextDisposed,
        WitError::Other(s) => PluginError::Other(RString::from(s)),
    }
}

/// Convert a native [`ClientInfo`] into the WIT record.
fn native_client_info_to_wit(info: &ClientInfo) -> WitClientInfo {
    WitClientInfo {
        server_id: info.server_id,
        session_id: info.session_id,
        username: info.username.as_str().to_owned(),
        cert_hash: info.cert_hash.as_str().to_owned(),
    }
}

/// Convert a native [`PluginMessageIn`] into the WIT record.
fn native_message_in_to_wit(msg: &PluginMessageIn) -> WitPluginMessageIn {
    WitPluginMessageIn {
        server_id: msg.server_id,
        sender_session: msg.sender_session,
        sender_name: msg.sender_name.as_str().to_owned(),
        plugin_name: msg.plugin_name.as_str().to_owned(),
        payload_type: msg.payload_type.as_str().to_owned(),
        payload: msg.payload.as_slice().to_vec(),
        channel_id: ropt(msg.channel_id),
    }
}

/// Convert a WIT `plugin-message-out` into the native [`PluginMessageOut`].
fn wit_message_out_to_native(msg: WitPluginMessageOut) -> PluginMessageOut {
    PluginMessageOut {
        server_id: msg.server_id,
        plugin_name: RString::from(msg.plugin_name),
        payload_type: RString::from(msg.payload_type),
        payload: RVec::from(msg.payload),
        target_sessions: RVec::from(msg.target_sessions),
        channel_id: match msg.channel_id {
            Some(c) => ROption::RSome(c),
            None => ROption::RNone,
        },
    }
}

// ---------------------------------------------------------------------------
// Typed UI bridge
//
// The host owns the single canonical translation between the typed `ui-types`
// WIT values and the native `mumble-plugin-api` wire types (which serialise to
// the exact JSON the client expects). Guests therefore work with native,
// type-checked values in their own language and never touch the wire JSON.
// ---------------------------------------------------------------------------

/// Call the guest's optional typed `manifest()` and, when present, fold it into
/// the `client_manifest` field of the plugin's `info-json` so the rest of the
/// host ships it exactly like a hand-authored manifest.
fn merge_manifest_into_info(
    path: &Path,
    world: &PluginWorld,
    store: &mut Store<HostState>,
    info_json: String,
) -> Result<String, LoadError> {
    let manifest = world
        .mumble_plugin_ui_guest()
        .call_manifest(&mut *store)
        .map_err(|e| LoadError::Invalid {
            path: path.to_path_buf(),
            message: format!("manifest export trapped: {e}"),
        })?;
    let Some(manifest) = manifest else {
        return Ok(info_json);
    };

    let manifest_value =
        serde_json::to_value(wit_manifest_to_native(manifest)).map_err(|e| LoadError::Invalid {
            path: path.to_path_buf(),
            message: format!("encode client manifest: {e}"),
        })?;
    let mut info: serde_json::Value =
        serde_json::from_str(&info_json).map_err(|e| LoadError::Invalid {
            path: path.to_path_buf(),
            message: format!("info-json is not valid JSON: {e}"),
        })?;
    let Some(map) = info.as_object_mut() else {
        return Err(LoadError::Invalid {
            path: path.to_path_buf(),
            message: "info-json must be a JSON object to attach a manifest".to_owned(),
        });
    };
    // `insert` returns the previous value; there is never one for a freshly
    // inserted manifest key, and the crate denies unused results.
    let _previous = map.insert("client_manifest".to_owned(), manifest_value);
    serde_json::to_string(&info).map_err(|e| LoadError::Invalid {
        path: path.to_path_buf(),
        message: format!("re-encode info-json: {e}"),
    })
}

/// WIT `client-manifest` -> native [`ClientManifest`](ncm::ClientManifest).
fn wit_manifest_to_native(m: wit_ui::ClientManifest) -> ncm::ClientManifest {
    ncm::ClientManifest {
        schema_version: m.schema_version,
        slash_commands: m
            .slash_commands
            .into_iter()
            .map(wit_slash_command_to_native)
            .collect(),
        capabilities: m
            .capabilities
            .into_iter()
            .map(wit_capability_to_native)
            .collect(),
        settings_panels: Vec::new(),
    }
}

fn wit_slash_command_to_native(c: wit_ui::SlashCommand) -> ncm::SlashCommand {
    ncm::SlashCommand {
        name: c.name,
        description: c.description,
        options: c
            .options
            .into_iter()
            .map(wit_slash_option_to_native)
            .collect(),
    }
}

fn wit_slash_option_to_native(o: wit_ui::SlashCommandOption) -> ncm::SlashCommandOption {
    ncm::SlashCommandOption {
        name: o.name,
        description: o.description,
        option_type: wit_option_type_to_native(o.option_type),
        required: o.required,
        choices: o
            .choices
            .into_iter()
            .map(|c| ncm::OptionChoice {
                label: c.label,
                value: c.value,
            })
            .collect(),
    }
}

fn wit_option_type_to_native(t: wit_ui::OptionType) -> ncm::OptionType {
    match t {
        wit_ui::OptionType::String => ncm::OptionType::String,
        wit_ui::OptionType::Integer => ncm::OptionType::Integer,
        wit_ui::OptionType::Boolean => ncm::OptionType::Boolean,
        wit_ui::OptionType::User => ncm::OptionType::User,
        wit_ui::OptionType::Channel => ncm::OptionType::Channel,
    }
}

fn wit_capability_to_native(c: wit_ui::Capability) -> ncm::Capability {
    match c {
        wit_ui::Capability::SlashCommands => ncm::Capability::SlashCommands,
        wit_ui::Capability::Modals => ncm::Capability::Modals,
        wit_ui::Capability::Components => ncm::Capability::Components,
        wit_ui::Capability::Notifications => ncm::Capability::Notifications,
        wit_ui::Capability::SettingsPanel => ncm::Capability::SettingsPanel,
        wit_ui::Capability::RichLayout => ncm::Capability::RichLayout,
    }
}

/// Native [`Interaction`](ncm::Interaction) -> WIT `interaction`.
fn native_interaction_to_wit(i: NativeInteraction) -> wit_ui::Interaction {
    wit_ui::Interaction {
        correlation_id: i.correlation_id,
        channel_id: i.channel_id,
        kind: native_interaction_kind_to_wit(i.kind),
    }
}

fn native_interaction_kind_to_wit(kind: ncm::InteractionKind) -> wit_ui::InteractionKind {
    match kind {
        ncm::InteractionKind::SlashCommand { name, options } => {
            wit_ui::InteractionKind::SlashCommand(wit_ui::SlashCommandInteraction {
                name,
                args: options
                    .into_iter()
                    .map(|(name, value)| wit_ui::CommandArg {
                        name,
                        value: native_option_value_to_wit(value),
                    })
                    .collect(),
            })
        }
        ncm::InteractionKind::Component { custom_id, values } => {
            wit_ui::InteractionKind::Component(wit_ui::ComponentInteraction { custom_id, values })
        }
        ncm::InteractionKind::ModalSubmit {
            custom_id, values, ..
        } => wit_ui::InteractionKind::ModalSubmit(wit_ui::ModalSubmitInteraction {
            custom_id,
            fields: values
                .into_iter()
                .map(|(name, value)| wit_ui::CommandArg {
                    name,
                    value: wit_ui::OptionValue::Text(value),
                })
                .collect(),
        }),
    }
}

fn native_option_value_to_wit(v: ncm::OptionValue) -> wit_ui::OptionValue {
    match v {
        ncm::OptionValue::String(s) => wit_ui::OptionValue::Text(s),
        ncm::OptionValue::Integer(i) => wit_ui::OptionValue::Integer(i),
        ncm::OptionValue::Boolean(b) => wit_ui::OptionValue::Boolean(b),
    }
}

/// WIT `interaction-response` -> native [`InteractionResponse`](ncm::InteractionResponse).
fn wit_response_to_native(r: wit_ui::InteractionResponse) -> ncm::InteractionResponse {
    ncm::InteractionResponse {
        correlation_id: r.correlation_id,
        kind: wit_response_kind_to_native(r.kind),
    }
}

fn wit_response_kind_to_native(k: wit_ui::ResponseKind) -> ncm::ResponseKind {
    match k {
        wit_ui::ResponseKind::ChatMessage(m) => ncm::ResponseKind::ChatMessage {
            message_id: m.message_id,
            channel_ids: m.channel_ids,
            content: m.content,
            components: m
                .components
                .into_iter()
                .map(wit_action_row_to_native)
                .collect(),
            ephemeral: m.ephemeral,
        },
        wit_ui::ResponseKind::UpdateMessage(m) => ncm::ResponseKind::UpdateMessage {
            message_id: m.message_id,
            content: m.content,
            components: m
                .components
                .map(|rows| rows.into_iter().map(wit_action_row_to_native).collect()),
        },
        wit_ui::ResponseKind::ShowModal(m) => ncm::ResponseKind::ShowModal {
            custom_id: m.custom_id,
            title: m.title,
            content: m.content,
            components: m
                .components
                .into_iter()
                .map(wit_action_row_to_native)
                .collect(),
            ephemeral: m.ephemeral,
        },
        wit_ui::ResponseKind::Toast(t) => ncm::ResponseKind::Toast {
            message: t.message,
            level: wit_toast_level_to_native(t.level),
        },
    }
}

fn wit_action_row_to_native(row: wit_ui::ActionRow) -> ncm::ActionRow {
    ncm::ActionRow {
        components: row
            .components
            .into_iter()
            .map(wit_component_to_native)
            .collect(),
    }
}

fn wit_component_to_native(c: wit_ui::Component) -> ncm::Component {
    match c {
        wit_ui::Component::Button(b) => ncm::Component::Button(ncm::Button {
            custom_id: b.custom_id,
            label: b.label,
            style: wit_button_style_to_native(b.style),
            disabled: b.disabled,
            url: b.url,
        }),
        wit_ui::Component::TextDisplay(t) => {
            ncm::Component::TextDisplay(ncm::TextDisplay { content: t.content })
        }
    }
}

fn wit_button_style_to_native(s: wit_ui::ButtonStyle) -> ncm::ButtonStyle {
    match s {
        wit_ui::ButtonStyle::Primary => ncm::ButtonStyle::Primary,
        wit_ui::ButtonStyle::Secondary => ncm::ButtonStyle::Secondary,
        wit_ui::ButtonStyle::Success => ncm::ButtonStyle::Success,
        wit_ui::ButtonStyle::Danger => ncm::ButtonStyle::Danger,
        wit_ui::ButtonStyle::Link => ncm::ButtonStyle::Link,
    }
}

fn wit_toast_level_to_native(l: wit_ui::ToastLevel) -> ncm::ToastLevel {
    match l {
        wit_ui::ToastLevel::Info => ncm::ToastLevel::Info,
        wit_ui::ToastLevel::Success => ncm::ToastLevel::Success,
        wit_ui::ToastLevel::Warning => ncm::ToastLevel::Warning,
        wit_ui::ToastLevel::Error => ncm::ToastLevel::Error,
    }
}

#[cfg(test)]
mod tests {
    // Test-only relaxations: assertions and fixture setup use `unwrap`/`expect`
    // and lock poisoning is irrelevant in a single-threaded test.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test fixtures and assertions; failures should panic"
    )]

    use std::sync::{Arc, Mutex as StdMutex};

    use abi_stable::sabi_trait::TD_Opaque;
    use abi_stable::std_types::{RArc, RNone, RResult};
    use mumble_plugin_api::{ChannelId, PluginContext, PluginContext_TO};

    use super::*;

    /// Captures every host call the guest makes so the test can assert on them.
    #[derive(Default)]
    struct Recorded {
        sends: Vec<(ServerId, SessionId, String, Vec<u8>)>,
    }

    /// Minimal [`PluginContext`] that records `send_plugin_data` invocations.
    struct RecordingCtx {
        recorded: Arc<StdMutex<Recorded>>,
    }

    impl PluginContext for RecordingCtx {
        fn send_plugin_data(
            &self,
            server_id: ServerId,
            target_session: SessionId,
            data_id: RStr<'_>,
            data: RSlice<'_, u8>,
        ) -> PluginResult<()> {
            self.recorded.lock().unwrap().sends.push((
                server_id,
                target_session,
                data_id.as_str().to_owned(),
                data.as_slice().to_vec(),
            ));
            ROk(())
        }

        fn is_session_active(&self, _server_id: ServerId, _session: SessionId) -> bool {
            true
        }

        fn user_has_channel_access(
            &self,
            _server_id: ServerId,
            _session: SessionId,
            _channel: ChannelId,
        ) -> bool {
            true
        }

        fn has_permission(
            &self,
            _server_id: ServerId,
            _session: SessionId,
            _channel: ChannelId,
            _permission_flags: u32,
        ) -> bool {
            true
        }

        fn current_channel(&self, _server_id: ServerId, _session: SessionId) -> ROption<ChannelId> {
            RNone
        }

        fn get_config(&self, _key: RStr<'_>) -> ROption<RString> {
            RNone
        }

        fn send_plugin_message(&self, _msg: PluginMessageOut) -> PluginResult<()> {
            ROk(())
        }
    }

    /// Drive a prebuilt greeter component through `on_plugin_message` and assert
    /// it echoes the payload back via the `send_plugin_data` host import.
    ///
    /// Ignored by default: it needs a built component whose path is supplied in
    /// the `MUMBLE_TEST_WASM_PLUGIN` environment variable (see the
    /// `greeter-wasm` example's README).
    #[test]
    #[ignore = "requires a prebuilt wasm component path in MUMBLE_TEST_WASM_PLUGIN"]
    fn wasm_greeter_echoes_plugin_message() {
        let path = std::env::var("MUMBLE_TEST_WASM_PLUGIN")
            .expect("set MUMBLE_TEST_WASM_PLUGIN to a built greeter component");
        let loaded = load_wasm_plugin(Path::new(&path)).expect("load wasm plugin");
        assert_eq!(loaded.plugin.name().as_str(), "greeter-wasm");

        let recorded = Arc::new(StdMutex::new(Recorded::default()));
        let ctx: PluginContext_TO<RArc<()>> = PluginContext_TO::from_ptr(
            RArc::new(RecordingCtx {
                recorded: Arc::clone(&recorded),
            }),
            TD_Opaque,
        );

        let msg = PluginMessageIn {
            server_id: 1,
            sender_session: 42,
            sender_name: RString::from("alice"),
            plugin_name: RString::from("greeter-wasm"),
            payload_type: RString::from("ping"),
            payload: RVec::from(vec![1u8, 2, 3]),
            channel_id: RNone,
        };

        let res = loaded.plugin.on_plugin_message(&ctx, msg);
        assert!(matches!(res, RResult::ROk(())), "hook returned {res:?}");

        let rec = recorded.lock().unwrap();
        assert_eq!(rec.sends.len(), 1, "guest should echo exactly once");
        let (server_id, session, data_id, payload) = &rec.sends[0];
        assert_eq!(*server_id, 1);
        assert_eq!(*session, 42);
        assert_eq!(data_id, "greeter-echo");
        assert_eq!(payload, &vec![1u8, 2, 3]);
    }
}
