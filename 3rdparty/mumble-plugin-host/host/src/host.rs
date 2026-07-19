//! Plugin host: discovers cdylibs at startup, loads each via
//! [`crate::loader`], dispatches lifecycle events, and ships the
//! per-plugin `fancy-plugin-info` envelope to every newly connected
//! client.

use std::collections::HashMap;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use abi_stable::std_types::{RArc, RNone, RSlice, RSome, RStr, RVec};
use mumble_plugin_api::{
    ChannelId, ClientInfo, PluginContext_TO, PluginMessageIn, ServerId, SessionId,
    PLUGIN_ABI_VERSION, PLUGIN_INFO_DATA_ID,
};
use serde::Serialize;

use crate::context::{HostContext, ScopedContext};
use crate::info::{encode, PluginInfoRecord};
use crate::install;
use crate::loader::{discover_plugin_dirs, load_plugin, scan_dir, LoadedPlugin};

/// Configuration key listing comma-separated plugin names that are part of the
/// server distribution and cannot be removed via the admin UI.
const CONFIG_KEY_BUILTIN_PLUGINS: &str = "builtin_plugins";

/// Configuration key the host reads from the server to find the plugin
/// directory.
const CONFIG_KEY_PLUGINS_DIR: &str = "plugins_dir";

/// Per-plugin configuration key (under the `plugin.<name>.` namespace)
/// that gates whether the plugin is loaded.  The host reads this
/// before invoking [`mumble_plugin_api::MumblePlugin::on_load`] so
/// individual plugins do not need to perform the check themselves.
const CONFIG_KEY_ENABLED: &str = "enabled";

/// `PluginMessage.payload_type` values the host broadcasts when a plugin's
/// loaded state changes at runtime, so connected clients can drop (or restore)
/// that plugin's UI gracefully.  Kept as plain strings on the wire — the
/// generic `payload_type` field is intentionally plugin/agnostic (see
/// `Mumble.proto`); the client mirrors these in its `PluginPayloadType` enum.
const PAYLOAD_TYPE_PLUGIN_ACTIVATED: &str = "PluginActivated";
const PAYLOAD_TYPE_PLUGIN_DEACTIVATED: &str = "PluginDeactivated";

/// Per-plugin key persisting the marketplace ID the plugin was
/// installed from (set by the marketplace install flow).
const CONFIG_KEY_MARKETPLACE_ID: &str = "marketplace_id";

/// Per-plugin key persisting the wall-clock millis when the
/// marketplace flow last installed/upgraded the plugin.
const CONFIG_KEY_INSTALLED_AT: &str = "installed_at";

/// Backend a plugin is loaded through.  Purely informational — it is
/// surfaced to the admin UI but never influences dispatch, which goes
/// through the uniform [`MumblePlugin`](mumble_plugin_api::MumblePlugin)
/// trait object regardless of backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum PluginKind {
    /// Native `abi_stable` cdylib (`.so`/`.dll`/`.dylib`).
    Native,
    /// WebAssembly component (`.wasm`).
    Wasm,
}

impl PluginKind {
    /// Classify a plugin file by its extension.
    fn from_path(path: &std::path::Path) -> Self {
        match path.extension().and_then(|e| e.to_str()) {
            Some(e) if e.eq_ignore_ascii_case("wasm") => PluginKind::Wasm,
            _ => PluginKind::Native,
        }
    }

    /// Stable lowercase label used in the admin JSON.
    fn as_str(self) -> &'static str {
        match self {
            PluginKind::Native => "native",
            PluginKind::Wasm => "wasm",
        }
    }
}

/// One plugin known to the host, loaded or merely discovered.
struct Entry {
    name: String,
    version: String,
    /// Already-framed `fancy-plugin-info` envelope, or `None` if the
    /// plugin failed to advertise valid JSON (logged once at load).
    info_envelope: Option<Vec<u8>>,
    plugin: LoadedPlugin,
    /// Per-plugin `PluginContext_TO` owned by the host.  Populated
    /// alongside [`Entry::loaded`] flipping to `true`; cleared on
    /// unload.  Every callback dispatched into the plugin passes a
    /// reference into this slot so the plugin never has to store the
    /// context itself.
    ctx: Option<PluginContext_TO<RArc<()>>>,
    /// `true` once `on_load` has been invoked; flipped back to `false`
    /// by [`Drop`] or [`Host::set_enabled`].  Dispatch skips entries
    /// with `loaded == false`.
    loaded: bool,
    marketplace_id: Option<String>,
    installed_at: Option<u64>,
    /// True when the plugin's `.so` is NOT in the user-writable
    /// install directory, i.e. it ships with the server distribution.
    builtin: bool,
    /// Backend the plugin was loaded through (native cdylib vs WASM).
    kind: PluginKind,
}

/// Plugin that was discovered on disk but could not be loaded (ABI mismatch,
/// missing symbols, `on_load` failure, etc.).  Tracked so the admin UI can
/// list and delete broken files even when the host cannot introspect them.
#[derive(Debug)]
struct FailedPlugin {
    /// Identifier exposed in the admin API.  For binary-level failures
    /// (ABI mismatch, missing symbol) this is the file stem; for
    /// `on_load` failures we have the real plugin name.
    name: String,
    path: PathBuf,
    error: String,
    builtin: bool,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("loaded", &self.loaded)
            .field(
                "info_envelope_len",
                &self.info_envelope.as_ref().map(Vec::len),
            )
            .field("path", &self.plugin.path)
            .finish()
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        // RAII unload: every path that removes an Entry (uninstall,
        // hot toggle, full host teardown via Vec drop) funnels through
        // here, so plugins always see exactly one on_unload matching
        // their on_load.
        if self.loaded {
            if let Some(ctx) = self.ctx.as_ref() {
                if let abi_stable::std_types::RResult::RErr(e) = self.plugin.plugin.on_unload(ctx) {
                    tracing::warn!(plugin = %self.name, error = %e, "on_unload failed");
                }
            }
            self.loaded = false;
            self.ctx = None;
        }
    }
}

/// Summary of one plugin returned to the C++ side as JSON; the C++
/// layer maps it onto the `FancyPluginAdminEntry` wire message.
#[derive(Debug, Serialize)]
pub(crate) struct PluginAdminInfo {
    pub plugin_name: String,
    pub version: String,
    pub enabled: bool,
    pub loaded: bool,
    pub path: String,
    pub info_json: String,
    pub marketplace_id: Option<String>,
    pub installed_at: Option<u64>,
    pub builtin: bool,
    /// Backend the plugin loaded through (`"native"` or `"wasm"`).
    pub kind: &'static str,
    /// Set when the plugin could not be loaded; contains the error message.
    pub load_error: Option<String>,
}

/// JSON-serialisable result envelope returned from every mutable FFI
/// call so the C++ side can surface a uniform error string.
#[derive(Debug, Serialize)]
pub(crate) struct FfiResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl FfiResult {
    pub(crate) fn ok() -> Self {
        Self {
            ok: true,
            error: None,
        }
    }

    pub(crate) fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
        }
    }
}

/// The plugin host: owns every loaded plugin and the shared context.
#[derive(Debug)]
pub struct Host {
    base_context: Arc<HostContext>,
    plugins: Vec<Entry>,
    /// Plugins that were discovered but could not be loaded.
    failed_plugins: Vec<FailedPlugin>,
    /// First configured plugins directory; used as the install target
    /// for marketplace downloads.  None if neither configured nor
    /// supplied via `MUMBLE_PLUGIN_DIRS`.
    install_dir: Option<PathBuf>,
    /// Currently-connected client sessions (keyed by `(server, session)`,
    /// valued by the full `ClientInfo`), so a runtime plugin enable/disable can
    /// be broadcast to every one of them - and a re-enabled plugin can be
    /// re-announced (its `on_client_connected` re-run).  Mutated from `&self`
    /// callbacks (connect/disconnect), hence the interior `Mutex`.
    sessions: Mutex<HashMap<(ServerId, SessionId), ClientInfo>>,
}

impl Host {
    /// Build a new host: read the configured plugin directory list,
    /// load every cdylib in those directories, call `on_load` on each.
    pub(crate) fn new(context: HostContext) -> Result<Self, std::io::Error> {
        let base_context = Arc::new(context);
        let dirs = configured_dirs(&base_context);
        // The install target is the INI `plugins_dir` key only --
        // MUMBLE_PLUGIN_DIRS can list read-only system directories first,
        // so dirs.first() is not a reliable install target.
        let install_dir: Option<PathBuf> = CString::new(CONFIG_KEY_PLUGINS_DIR)
            .ok()
            .and_then(|k| read_config_string(&base_context, k.as_c_str()))
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);
        let builtin_names: Vec<String> = CString::new(CONFIG_KEY_BUILTIN_PLUGINS)
            .ok()
            .and_then(|k| read_config_string(&base_context, k.as_c_str()))
            .map(|s| {
                s.split(',')
                    .map(|n| n.trim().to_owned())
                    .filter(|n| !n.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        tracing::info!(
            dir_count = dirs.len(),
            dirs = ?dirs,
            "plugin host initialising"
        );

        // Bridge the live-doc persistence to the file-server *before* any
        // plugin loads, so both read the wired-up config in their
        // `on_load`.  Without this the operator would have to manually
        // share an admin token between the two namespaces and live
        // documents would silently never persist.
        provision_live_doc_bridge(
            |key| read_config_plain(&base_context, key),
            |key, value| match base_context.set_config(key, value) {
                Ok(()) => true,
                Err(err) => {
                    tracing::warn!(%err, key, "live-doc bridge: set_config failed");
                    false
                }
            },
        );

        let mut plugins = Vec::new();
        let mut failed_plugins: Vec<FailedPlugin> = Vec::new();
        for dir in &dirs {
            let candidates = scan_dir(dir);
            tracing::debug!(
                dir = %dir.display(),
                candidate_count = candidates.len(),
                "scanning plugin directory"
            );
            for path in candidates {
                match load_plugin(&path) {
                    Ok(loaded) => match build_entry(&base_context, loaded) {
                        Ok(mut e) => {
                            e.builtin = builtin_names.contains(&e.name);
                            tracing::info!(
                                plugin = %e.name,
                                version = %e.version,
                                loaded = e.loaded,
                                path = %e.plugin.path.display(),
                                "plugin discovered"
                            );
                            plugins.push(e);
                        }
                        Err(BuildEntryError::OnLoad { name, error }) => {
                            let is_builtin = builtin_names.contains(&name);
                            tracing::error!(plugin = %name, error = %error, path = %path.display(), "plugin build failed");
                            failed_plugins.push(FailedPlugin {
                                name,
                                path,
                                error,
                                builtin: is_builtin,
                            });
                        }
                    },
                    Err(e) => {
                        let stem = path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("unknown")
                            .to_owned();
                        tracing::error!(plugin = %stem, error = %e, path = %path.display(), "plugin load failed");
                        failed_plugins.push(FailedPlugin {
                            name: stem,
                            path,
                            error: e.to_string(),
                            builtin: false,
                        });
                    }
                }
            }
        }
        tracing::info!(
            discovered = plugins.len() + failed_plugins.len(),
            loaded = plugins.iter().filter(|e| e.loaded).count(),
            failed = failed_plugins.len(),
            "plugin host ready"
        );
        Ok(Self {
            base_context,
            plugins,
            failed_plugins,
            install_dir,
            sessions: Mutex::new(HashMap::new()),
        })
    }

    /// Dispatch a client-connected event to every loaded plugin, then
    /// ship each plugin's `fancy-plugin-info` envelope to the session.
    pub(crate) fn on_client_connected(&self, info: ClientInfo) {
        if let Ok(mut sessions) = self.sessions.lock() {
            let _ = sessions.insert((info.server_id, info.session_id), info.clone());
        }
        for entry in self.plugins.iter().filter(|e| e.loaded) {
            let Some(ctx) = entry.ctx.as_ref() else {
                continue;
            };
            if let abi_stable::std_types::RResult::RErr(e) =
                entry.plugin.plugin.on_client_connected(ctx, info.clone())
            {
                tracing::warn!(plugin = %entry.name, error = %e, "on_client_connected failed");
            }
            if let Some(envelope) = &entry.info_envelope {
                if let abi_stable::std_types::RResult::RErr(e) =
                    self.base_context.send_plugin_data_raw(
                        info.server_id,
                        info.session_id,
                        PLUGIN_INFO_DATA_ID,
                        envelope,
                    )
                {
                    tracing::warn!(plugin = %entry.name, error = %e, "plugin-info delivery failed");
                }
            }
        }
    }

    /// Dispatch a client-disconnected event.
    pub(crate) fn on_client_disconnected(&self, server_id: ServerId, session: SessionId) {
        if let Ok(mut sessions) = self.sessions.lock() {
            let _ = sessions.remove(&(server_id, session));
        }
        for entry in self.plugins.iter().filter(|e| e.loaded) {
            let Some(ctx) = entry.ctx.as_ref() else {
                continue;
            };
            if let abi_stable::std_types::RResult::RErr(e) = entry
                .plugin
                .plugin
                .on_client_disconnected(ctx, server_id, session)
            {
                tracing::warn!(plugin = %entry.name, error = %e, "on_client_disconnected failed");
            }
        }
    }

    /// Dispatch a plugin-data event.
    pub(crate) fn on_plugin_data(
        &self,
        server_id: ServerId,
        sender: SessionId,
        data_id: String,
        data: Vec<u8>,
    ) {
        let id = RStr::from(data_id.as_str());
        let bytes = RSlice::from(data.as_slice());
        for entry in self.plugins.iter().filter(|e| e.loaded) {
            let Some(ctx) = entry.ctx.as_ref() else {
                continue;
            };
            if let abi_stable::std_types::RResult::RErr(e) = entry
                .plugin
                .plugin
                .on_plugin_data(ctx, server_id, sender, id, bytes)
            {
                tracing::warn!(plugin = %entry.name, error = %e, "on_plugin_data failed");
            }
        }
    }

    /// Route an inbound generic `PluginMessage` (wire ID 200) to the
    /// single plugin whose [`mumble_plugin_api::MumblePlugin::name`]
    /// equals `plugin_name`.  Unknown / disabled names are dropped.
    pub(crate) fn on_plugin_message(&self, args: PluginMessageInArgs) {
        let Some(entry) = self
            .plugins
            .iter()
            .find(|e| e.loaded && e.name == args.plugin_name)
        else {
            tracing::debug!(plugin = %args.plugin_name, "no plugin registered for inbound PluginMessage");
            return;
        };
        let msg = PluginMessageIn {
            server_id: args.server_id,
            sender_session: args.sender,
            sender_name: args.sender_name.into(),
            plugin_name: args.plugin_name.clone().into(),
            payload_type: args.payload_type.into(),
            payload: RVec::from(args.payload),
            channel_id: args.channel_id.map_or(RNone, RSome),
        };
        let _ = args.target_sessions; // routing happens server-side; ignored here
        let Some(ctx) = entry.ctx.as_ref() else {
            return;
        };
        if let abi_stable::std_types::RResult::RErr(e) =
            entry.plugin.plugin.on_plugin_message(ctx, msg)
        {
            tracing::warn!(plugin = %args.plugin_name, error = %e, "on_plugin_message failed");
        }
    }

    /// Build the per-server `PluginRegistry` payload as JSON.  Each
    /// entry: `{"plugin_name":..,"version":..,"plugin_slot":i,"info_json":".."}`.
    /// The C++ side wraps this into the protobuf `PluginRegistry`
    /// message and ships it right after `ServerSync`.
    pub(crate) fn registry_json(&self) -> String {
        let entries: Vec<serde_json::Value> = self
            .plugins
            .iter()
            .filter(|e| e.loaded)
            .enumerate()
            .map(|(slot, e)| {
                serde_json::json!({
                    "plugin_name": e.name,
                    "version": e.version,
                    "plugin_slot": slot as u32,
                    "info_json": e.plugin.plugin.info_json().as_str().to_owned(),
                })
            })
            .collect();
        serde_json::to_string(&serde_json::json!({ "plugins": entries }))
            .unwrap_or_else(|_| "{\"plugins\":[]}".to_owned())
    }

    /// Plugin-admin: snapshot every known plugin plus the install
    /// directory used by the marketplace flow.  Failed plugins are
    /// included so the admin can identify and remove broken files.
    pub(crate) fn list_plugins(&self) -> (Vec<PluginAdminInfo>, Option<String>) {
        let mut out: Vec<PluginAdminInfo> = self
            .plugins
            .iter()
            .map(|e| PluginAdminInfo {
                plugin_name: e.name.clone(),
                version: e.version.clone(),
                enabled: e.loaded,
                loaded: e.loaded,
                path: e.plugin.path.display().to_string(),
                info_json: e.plugin.plugin.info_json().as_str().to_owned(),
                marketplace_id: e.marketplace_id.clone(),
                installed_at: e.installed_at,
                builtin: e.builtin,
                kind: e.kind.as_str(),
                load_error: None,
            })
            .collect();
        for f in &self.failed_plugins {
            out.push(PluginAdminInfo {
                plugin_name: f.name.clone(),
                version: String::new(),
                enabled: false,
                loaded: false,
                path: f.path.display().to_string(),
                info_json: "{}".to_owned(),
                marketplace_id: None,
                installed_at: None,
                builtin: f.builtin,
                kind: PluginKind::from_path(&f.path).as_str(),
                load_error: Some(f.error.clone()),
            });
        }
        let dir = self.install_dir.as_ref().map(|p| p.display().to_string());
        (out, dir)
    }

    /// Plugin-admin: toggle a plugin's enabled state, persisting
    /// `plugin.<name>.enabled` so the change survives restart.
    pub(crate) fn set_enabled(&mut self, name: &str, enabled: bool) -> Result<(), String> {
        let idx = self
            .plugins
            .iter()
            .position(|e| e.name == name)
            .ok_or_else(|| format!("plugin '{name}' not found"))?;
        let value = if enabled { "true" } else { "false" };
        self.base_context
            .set_config(&format!("plugin.{name}.{CONFIG_KEY_ENABLED}"), value)?;
        let entry = &mut self.plugins[idx];
        if enabled == entry.loaded {
            return Ok(());
        }
        if enabled {
            let prefix = format!("plugin.{name}");
            // Build two independent trait objects backed by
            // equivalent ScopedContexts: one is handed by value to
            // `on_load` so the plugin can retain it across threads,
            // the other stays in `Entry` so later callbacks (which
            // take `&ctx`) and `on_unload` can be dispatched without
            // depending on whether the plugin held on to its copy.
            let host_ctx_to = PluginContext_TO::from_ptr(
                RArc::new(ScopedContext::new(
                    Arc::clone(&self.base_context),
                    prefix.clone(),
                )),
                abi_stable::sabi_trait::TD_Opaque,
            );
            let plugin_ctx_to = PluginContext_TO::from_ptr(
                RArc::new(ScopedContext::new(Arc::clone(&self.base_context), prefix)),
                abi_stable::sabi_trait::TD_Opaque,
            );
            entry.ctx = Some(host_ctx_to);
            if let abi_stable::std_types::RResult::RErr(e) =
                entry.plugin.plugin.on_load(plugin_ctx_to)
            {
                entry.ctx = None;
                return Err(format!("on_load failed: {e}"));
            }
            entry.loaded = true;
        } else {
            let result = entry
                .ctx
                .as_ref()
                .map(|ctx| entry.plugin.plugin.on_unload(ctx))
                .unwrap_or(abi_stable::std_types::RResult::ROk(()));
            entry.loaded = false;
            entry.ctx = None;
            if let abi_stable::std_types::RResult::RErr(e) = result {
                return Err(format!("on_unload failed: {e}"));
            }
        }
        // The `entry` borrow has ended; tell every connected client so they can
        // drop (or restore) this plugin's UI gracefully.  On enable, re-announce
        // the plugin first so its per-plugin config (e.g. the file-server
        // config) re-flows to already-connected sessions.
        if enabled {
            self.reannounce_plugin(idx);
        }
        self.broadcast_plugin_status(name, enabled);
        Ok(())
    }

    /// Broadcast a plugin enable/disable `PluginMessage` (wire ID 200) to every
    /// connected session, grouped by virtual server.  The `payload_type`
    /// carries the new state; the payload is empty.
    fn broadcast_plugin_status(&self, name: &str, active: bool) {
        let payload_type = if active {
            PAYLOAD_TYPE_PLUGIN_ACTIVATED
        } else {
            PAYLOAD_TYPE_PLUGIN_DEACTIVATED
        };
        let mut by_server: HashMap<ServerId, Vec<SessionId>> = HashMap::new();
        match self.sessions.lock() {
            Ok(sessions) => {
                for (server_id, session) in sessions.keys() {
                    by_server.entry(*server_id).or_default().push(*session);
                }
            }
            Err(_) => return,
        }
        for (server_id, targets) in by_server {
            if let abi_stable::std_types::RResult::RErr(e) = self
                .base_context
                .send_plugin_message_raw(server_id, name, payload_type, &[], &targets)
            {
                tracing::warn!(plugin = %name, error = %e, "plugin-status broadcast failed");
            }
        }
    }

    /// Re-deliver a single plugin's connect announcement (its
    /// `on_client_connected` callback + `fancy-plugin-info` envelope) to every
    /// currently-connected session.  Used when a plugin is re-enabled at
    /// runtime so it re-announces its per-plugin config to already-connected
    /// clients (which the normal connect path would otherwise only do for new
    /// connections).
    fn reannounce_plugin(&self, idx: usize) {
        let infos: Vec<ClientInfo> = match self.sessions.lock() {
            Ok(sessions) => sessions.values().cloned().collect(),
            Err(_) => return,
        };
        let Some(entry) = self.plugins.get(idx) else {
            return;
        };
        if !entry.loaded {
            return;
        }
        let Some(ctx) = entry.ctx.as_ref() else {
            return;
        };
        for info in infos {
            if let abi_stable::std_types::RResult::RErr(e) =
                entry.plugin.plugin.on_client_connected(ctx, info.clone())
            {
                tracing::warn!(plugin = %entry.name, error = %e, "re-announce on_client_connected failed");
            }
            if let Some(envelope) = &entry.info_envelope {
                if let abi_stable::std_types::RResult::RErr(e) = self.base_context.send_plugin_data_raw(
                    info.server_id,
                    info.session_id,
                    PLUGIN_INFO_DATA_ID,
                    envelope,
                ) {
                    tracing::warn!(plugin = %entry.name, error = %e, "re-announce info delivery failed");
                }
            }
        }
    }

    /// Plugin-admin: download a plugin from the marketplace, persist
    /// `plugin.<name>.*` keys, and register the new binary in a
    /// disabled state.  The admin issues a follow-up `SetEnabled`.
    pub(crate) fn install_plugin(
        &mut self,
        marketplace_id: &str,
        version: &str,
        manifest_url: &str,
        expected_sha256: Option<&str>,
    ) -> Result<String, String> {
        let dest_dir = self
            .install_dir
            .clone()
            .ok_or_else(|| "no plugins_dir configured; cannot install".to_owned())?;
        let manifest =
            install::fetch_manifest(manifest_url, expected_sha256).map_err(|e| e.to_string())?;
        if !manifest.marketplace_id.eq_ignore_ascii_case(marketplace_id) {
            return Err(format!(
                "manifest marketplace_id '{}' does not match request '{marketplace_id}'",
                manifest.marketplace_id
            ));
        }
        if !version.is_empty() && manifest.version != version {
            return Err(format!(
                "manifest version '{}' does not match requested '{version}'",
                manifest.version
            ));
        }
        if let Some(required) = manifest.required_abi_version {
            if required != PLUGIN_ABI_VERSION {
                return Err(format!(
                    "plugin requires API version {required} but this server has {PLUGIN_ABI_VERSION}; \
                     update the server or install a compatible plugin version"
                ));
            }
        }
        let artifact = install::pick_artifact(&manifest).map_err(|e| e.to_string())?;
        let installed =
            install::download_and_extract(artifact, &dest_dir).map_err(|e| e.to_string())?;
        tracing::info!(
            marketplace_id = %marketplace_id,
            cdylib = %installed.cdylib_path.display(),
            sha256 = %installed.sha256,
            ini_snippet_len = installed.ini_snippet.as_ref().map(String::len).unwrap_or(0),
            "marketplace artifact extracted"
        );
        // From here on the cdylib exists on disk.  Any failure must remove
        // it again: a half-installed binary left behind would be rediscovered
        // and load-attempted on the next startup, turning a one-off install
        // failure into a permanent crash/restart loop.
        let loaded = match load_plugin(&installed.cdylib_path) {
            Ok(loaded) => loaded,
            Err(e) => {
                remove_failed_install(&installed.cdylib_path);
                return Err(e.to_string());
            }
        };
        let name = loaded.plugin.name().as_str().to_owned();

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        // Persist the install metadata.  If any write fails, roll back the
        // on-disk binary and whatever keys were already written so a partial
        // install cannot survive to crash the next startup scan.
        let write_config = (|| {
            self.base_context.set_config(
                &format!("plugin.{name}.{CONFIG_KEY_MARKETPLACE_ID}"),
                marketplace_id,
            )?;
            self.base_context.set_config(
                &format!("plugin.{name}.{CONFIG_KEY_INSTALLED_AT}"),
                &now_ms.to_string(),
            )?;
            // New plugins start disabled; admin issues SetEnabled to activate.
            self.base_context
                .set_config(&format!("plugin.{name}.{CONFIG_KEY_ENABLED}"), "false")
        })();
        if let Err(e) = write_config {
            remove_failed_install(&installed.cdylib_path);
            let _ = self
                .base_context
                .delete_config_prefix(&format!("plugin.{name}."));
            return Err(e);
        }

        // Drop any previous entry for this plugin name (RAII unloads it)
        // before pushing the freshly-loaded one.
        if let Some(idx) = self.plugins.iter().position(|e| e.name == name) {
            let _ = self.plugins.swap_remove(idx);
        }
        let mut entry = match build_entry(&self.base_context, loaded) {
            Ok(entry) => entry,
            Err(e) => {
                // The plugin's binary loaded but `on_load` (or info
                // encoding) failed.  Roll back disk and config so the
                // broken install does not poison the next startup.
                remove_failed_install(&installed.cdylib_path);
                let _ = self
                    .base_context
                    .delete_config_prefix(&format!("plugin.{name}."));
                return Err(e.to_string());
            }
        };
        entry.marketplace_id = Some(marketplace_id.to_owned());
        entry.installed_at = Some(now_ms);
        let installed_name = entry.name.clone();
        self.plugins.push(entry);
        Ok(installed_name)
    }

    /// Plugin-admin: drop the entry (RAII unloads it), remove the
    /// cdylib from disk, and strip `plugin.<name>.*` from the server
    /// config.  Also handles broken plugins that are tracked in
    /// `failed_plugins` rather than `plugins`.
    pub(crate) fn uninstall_plugin(&mut self, name: &str) -> Result<(), String> {
        // Try loaded plugins first.
        if let Some(idx) = self.plugins.iter().position(|e| e.name == name) {
            let path = self.plugins[idx].plugin.path.clone();
            let _ = self.plugins.swap_remove(idx);
            if path.exists() {
                std::fs::remove_file(&path)
                    .map_err(|e| format!("failed to delete {}: {e}", path.display()))?;
            }
            self.base_context
                .delete_config_prefix(&format!("plugin.{name}."))?;
            return Ok(());
        }
        // Fall back to broken (failed-to-load) plugins.
        if let Some(idx) = self.failed_plugins.iter().position(|f| f.name == name) {
            let path = self.failed_plugins.swap_remove(idx).path;
            if path.exists() {
                std::fs::remove_file(&path)
                    .map_err(|e| format!("failed to delete {}: {e}", path.display()))?;
            }
            // Best-effort config cleanup: the registered name may differ from
            // the file stem for binary-level failures, so ignore any error.
            let _ = self
                .base_context
                .delete_config_prefix(&format!("plugin.{name}."));
            return Ok(());
        }
        Err(format!("plugin '{name}' not found"))
    }
}

// `Drop for Host` is intentionally omitted: `Vec<Entry>` drops each
// `Entry`, and `Drop for Entry` invokes `on_unload` for any plugin
// still in the loaded state.  Centralising teardown in `Entry` means
// uninstall, hot-toggle, and full shutdown share one code path.

/// Best-effort removal of a cdylib left on disk by a failed install.
///
/// A binary that downloaded and extracted but failed to load (ABI
/// mismatch, crash-on-load, `on_load` error) must not survive: the
/// startup directory scan would rediscover it and retry the load every
/// boot, turning a transient install failure into a crash loop.
fn remove_failed_install(cdylib_path: &Path) {
    if let Err(e) = std::fs::remove_file(cdylib_path) {
        tracing::warn!(
            cdylib = %cdylib_path.display(),
            error = %e,
            "failed to remove cdylib after unsuccessful install; \
             it may be retried on next startup scan"
        );
    }
}

fn configured_dirs(ctx: &Arc<HostContext>) -> Vec<PathBuf> {
    let key = match CString::new(CONFIG_KEY_PLUGINS_DIR) {
        Ok(k) => k,
        Err(_) => return discover_plugin_dirs(None),
    };
    let configured = read_config_string(ctx, &key);
    discover_plugin_dirs(configured.as_deref())
}

fn read_config_string(ctx: &Arc<HostContext>, key: &std::ffi::CStr) -> Option<String> {
    let get = ctx.callbacks.get_config?;
    let free = ctx.callbacks.free_string?;
    // SAFETY: callbacks non-null per the option check; `key` lives until return.
    let raw = unsafe { get(ctx.callbacks.user_data, key.as_ptr()) };
    if raw.is_null() {
        return None;
    }
    // SAFETY: host promises NUL-terminated UTF-8.
    let value = unsafe { std::ffi::CStr::from_ptr(raw) }
        .to_str()
        .ok()
        .map(str::to_owned);
    // SAFETY: pointer returned by get_config; freed exactly once.
    unsafe { free(ctx.callbacks.user_data, raw) };
    value
}

fn read_config_u64(ctx: &Arc<HostContext>, key: &str) -> Option<u64> {
    let cstr = CString::new(key).ok()?;
    read_config_string(ctx, &cstr).and_then(|v| v.trim().parse().ok())
}

fn read_config_plain(ctx: &Arc<HostContext>, key: &str) -> Option<String> {
    let cstr = CString::new(key).ok()?;
    read_config_string(ctx, &cstr)
}

/// Config namespace of the file-server plugin.
const FILE_SERVER_PREFIX: &str = "plugin.fancy-file-server";
/// Config namespace of the live-doc plugin.
const LIVE_DOC_PREFIX: &str = "plugin.fancy-live-doc";
/// Default port the file-server binds to (mirrors its own config default).
const DEFAULT_FILE_SERVER_PORT: u16 = 64739;

/// Generate a 256-bit random bearer token, hex-encoded (64 chars).
fn generate_admin_token() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    let mut out = String::with_capacity(buf.len() * 2);
    for b in buf {
        use std::fmt::Write as _;
        // Hex formatting into a String never fails.
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Wire the live-doc plugin's document persistence to the file-server.
///
/// Live documents are stored as opaque blobs through the file-server's
/// token-gated `/admin/*` API.  Because every plugin only sees its own
/// `plugin.<name>.*` config namespace, the two plugins cannot discover
/// each other's settings; the host is the only component that can read
/// and write across namespaces, so it bridges them here:
///
///  1. ensure the file-server has an `admin_token` (generate a strong one
///     and persist it when the operator did not configure one),
///  2. point live-doc's `file_server_url` at the local file-server, and
///  3. copy the admin token into live-doc's `file_server_admin_token`.
///
/// Existing operator-provided values are never overwritten, and the work
/// is idempotent across restarts (after the first run every key is set).
/// Generic over config get/set so the logic is unit-testable without the
/// C FFI layer.
fn provision_live_doc_bridge(
    get: impl Fn(&str) -> Option<String>,
    mut set: impl FnMut(&str, &str) -> bool,
) {
    let nonempty = |v: Option<String>| v.filter(|s| !s.is_empty());

    // 1. Shared admin token (generate + persist if absent).
    let admin_token = match nonempty(get(&format!("{FILE_SERVER_PREFIX}.admin_token"))) {
        Some(tok) => tok,
        None => {
            let tok = generate_admin_token();
            if !set(&format!("{FILE_SERVER_PREFIX}.admin_token"), &tok) {
                tracing::warn!(
                    "could not provision file-server admin token; live documents will not persist"
                );
                return;
            }
            tracing::info!("generated shared file-server admin token for live-doc persistence");
            tok
        }
    };

    // 2. live-doc -> file-server URL (default to the local file-server).
    if nonempty(get(&format!("{LIVE_DOC_PREFIX}.file_server_url"))).is_none() {
        let port = nonempty(get(&format!("{FILE_SERVER_PREFIX}.port")))
            .and_then(|p| p.trim().parse::<u16>().ok())
            .unwrap_or(DEFAULT_FILE_SERVER_PORT);
        let _ = set(
            &format!("{LIVE_DOC_PREFIX}.file_server_url"),
            &format!("http://127.0.0.1:{port}"),
        );
    }

    // 3. Share the admin token with live-doc.
    if nonempty(get(&format!("{LIVE_DOC_PREFIX}.file_server_admin_token"))).is_none() {
        let _ = set(
            &format!("{LIVE_DOC_PREFIX}.file_server_admin_token"),
            &admin_token,
        );
    }
}

fn build_entry(
    base_context: &Arc<HostContext>,
    loaded: LoadedPlugin,
) -> Result<Entry, BuildEntryError> {
    let name = loaded.plugin.name().as_str().to_owned();
    let version = loaded.plugin.version().as_str().to_owned();
    let prefix = format!("plugin.{name}");
    let info_envelope = build_info_envelope(&name, &version, &loaded);
    let marketplace_id = read_config_plain(
        base_context,
        &format!("{prefix}.{CONFIG_KEY_MARKETPLACE_ID}"),
    );
    let installed_at =
        read_config_u64(base_context, &format!("{prefix}.{CONFIG_KEY_INSTALLED_AT}"));
    let enabled = plugin_is_enabled(base_context, &prefix);
    let kind = PluginKind::from_path(&loaded.path);
    let mut entry = Entry {
        name,
        version,
        info_envelope,
        plugin: loaded,
        ctx: None,
        loaded: false,
        marketplace_id,
        installed_at,
        builtin: false,
        kind,
    };
    if enabled {
        // Build two independent trait objects backed by equivalent
        // ScopedContexts (see [`HostState::set_enabled`] for the
        // rationale): one is given to the plugin's `on_load`, the
        // other is kept in `Entry.ctx` for borrowed-reference
        // callbacks and `on_unload`.
        let host_ctx_to = PluginContext_TO::from_ptr(
            RArc::new(ScopedContext::new(Arc::clone(base_context), prefix.clone())),
            abi_stable::sabi_trait::TD_Opaque,
        );
        let plugin_ctx_to = PluginContext_TO::from_ptr(
            RArc::new(ScopedContext::new(Arc::clone(base_context), prefix)),
            abi_stable::sabi_trait::TD_Opaque,
        );
        entry.ctx = Some(host_ctx_to);
        if let abi_stable::std_types::RResult::RErr(e) = entry.plugin.plugin.on_load(plugin_ctx_to)
        {
            return Err(BuildEntryError::OnLoad {
                name: entry.name.clone(),
                error: format!("on_load failed: {e}"),
            });
        }
        entry.loaded = true;
    } else {
        tracing::info!(
            plugin = %entry.name,
            "plugin discovered but not enabled; set plugin.{}.{CONFIG_KEY_ENABLED}=true to load",
            entry.name
        );
    }
    Ok(entry)
}

/// Read `plugin.<name>.enabled` from the host's config callback.  An
/// absent or non-truthy value disables the plugin.  Truthy values
/// follow the same convention used elsewhere in `mumble-server.ini`:
/// `true`, `1`, `yes`, `on` (case-insensitive).
fn plugin_is_enabled(base_context: &Arc<HostContext>, prefix: &str) -> bool {
    let key = format!("{prefix}.{CONFIG_KEY_ENABLED}");
    let Ok(cstr) = CString::new(key) else {
        return false;
    };
    let Some(value) = read_config_string(base_context, &cstr) else {
        return false;
    };
    is_truthy_enabled_value(&value)
}

fn is_truthy_enabled_value(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "yes" | "on"
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "tests panic on failure")]
    use super::{
        generate_admin_token, is_truthy_enabled_value, provision_live_doc_bridge,
        DEFAULT_FILE_SERVER_PORT,
    };
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[test]
    fn enabled_truthy_variants() {
        for v in ["true", "TRUE", "True", "1", "yes", "YES", "on", "  on  "] {
            assert!(is_truthy_enabled_value(v), "expected {v:?} truthy");
        }
    }

    #[test]
    fn enabled_falsy_variants() {
        for v in ["", " ", "false", "0", "no", "off", "disabled", "maybe"] {
            assert!(!is_truthy_enabled_value(v), "expected {v:?} falsy");
        }
    }

    #[test]
    fn admin_token_is_64_hex_chars() {
        let tok = generate_admin_token();
        assert_eq!(tok.len(), 64);
        assert!(tok.bytes().all(|b| b.is_ascii_hexdigit()));
        // Two draws must differ (overwhelmingly likely for 256 bits).
        assert_ne!(tok, generate_admin_token());
    }

    /// Helper running the bridge against an in-memory config store.
    fn run_bridge(initial: &[(&str, &str)]) -> HashMap<String, String> {
        let store = RefCell::new(
            initial
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect::<HashMap<String, String>>(),
        );
        provision_live_doc_bridge(
            |k| store.borrow().get(k).cloned(),
            |k, v| {
                let _ = store.borrow_mut().insert(k.to_owned(), v.to_owned());
                true
            },
        );
        store.into_inner()
    }

    #[test]
    fn bridge_generates_token_and_wires_both_plugins() {
        let cfg = run_bridge(&[]);
        let token = cfg
            .get("plugin.fancy-file-server.admin_token")
            .expect("admin token generated");
        assert_eq!(token.len(), 64);
        assert_eq!(
            cfg.get("plugin.fancy-live-doc.file_server_url").map(String::as_str),
            Some(format!("http://127.0.0.1:{DEFAULT_FILE_SERVER_PORT}").as_str())
        );
        // live-doc must receive the same token the file-server uses.
        assert_eq!(
            cfg.get("plugin.fancy-live-doc.file_server_admin_token"),
            Some(token)
        );
    }

    #[test]
    fn bridge_reuses_existing_admin_token_and_honours_port() {
        let cfg = run_bridge(&[
            ("plugin.fancy-file-server.admin_token", "operator-token"),
            ("plugin.fancy-file-server.port", "9000"),
        ]);
        // Existing token reused, not regenerated.
        assert_eq!(
            cfg.get("plugin.fancy-file-server.admin_token").map(String::as_str),
            Some("operator-token")
        );
        assert_eq!(
            cfg.get("plugin.fancy-live-doc.file_server_url").map(String::as_str),
            Some("http://127.0.0.1:9000")
        );
        assert_eq!(
            cfg.get("plugin.fancy-live-doc.file_server_admin_token").map(String::as_str),
            Some("operator-token")
        );
    }

    #[test]
    fn bridge_never_overwrites_operator_overrides() {
        let cfg = run_bridge(&[
            ("plugin.fancy-file-server.admin_token", "tok"),
            ("plugin.fancy-live-doc.file_server_url", "http://files.example:7000"),
            ("plugin.fancy-live-doc.file_server_admin_token", "custom"),
        ]);
        assert_eq!(
            cfg.get("plugin.fancy-live-doc.file_server_url").map(String::as_str),
            Some("http://files.example:7000")
        );
        assert_eq!(
            cfg.get("plugin.fancy-live-doc.file_server_admin_token").map(String::as_str),
            Some("custom")
        );
    }
}

fn build_info_envelope(name: &str, version: &str, loaded: &LoadedPlugin) -> Option<Vec<u8>> {
    let raw = loaded.plugin.info_json();
    let raw_str = raw.as_str();
    let parsed: serde_json::Value = match serde_json::from_str(raw_str) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(plugin = %name, error = %e, "plugin info_json was not valid json; skipping envelope");
            return None;
        }
    };
    match encode(&PluginInfoRecord {
        name,
        version,
        info: &parsed,
    }) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            tracing::warn!(plugin = %name, error = %e, "failed to encode plugin info envelope");
            None
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum BuildEntryError {
    #[error("on_load failed: {error}")]
    OnLoad { name: String, error: String },
}

/// Owned parameters for [`Host::on_plugin_message`].  Grouping these
/// into a struct keeps the dispatcher under clippy's argument-count
/// threshold and makes the FFI translation site (`ffi.rs`) explicit.
#[derive(Debug, Clone)]
pub(crate) struct PluginMessageInArgs {
    pub server_id: ServerId,
    pub sender: SessionId,
    pub sender_name: String,
    pub plugin_name: String,
    pub payload_type: String,
    pub payload: Vec<u8>,
    pub target_sessions: Vec<SessionId>,
    pub channel_id: Option<ChannelId>,
}
