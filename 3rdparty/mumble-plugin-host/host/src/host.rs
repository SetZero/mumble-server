//! Plugin host: discovers cdylibs at startup, loads each via
//! [`crate::loader`], dispatches lifecycle events, and ships the
//! per-plugin `fancy-plugin-info` envelope to every newly connected
//! client.

use std::ffi::CString;
use std::path::PathBuf;
use std::sync::Arc;

use abi_stable::std_types::{RArc, RNone, RSlice, RSome, RStr, RVec};
use mumble_plugin_api::{
    ChannelId, ClientInfo, PluginContext_TO, PluginMessageIn, ServerId, SessionId,
    PLUGIN_INFO_DATA_ID,
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

/// Per-plugin key persisting the marketplace ID the plugin was
/// installed from (set by the marketplace install flow).
const CONFIG_KEY_MARKETPLACE_ID: &str = "marketplace_id";

/// Per-plugin key persisting the wall-clock millis when the
/// marketplace flow last installed/upgraded the plugin.
const CONFIG_KEY_INSTALLED_AT: &str = "installed_at";

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
                if let abi_stable::std_types::RResult::RErr(e) = self.plugin.plugin.on_unload(ctx)
                {
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
    /// First configured plugins directory; used as the install target
    /// for marketplace downloads.  None if neither configured nor
    /// supplied via `MUMBLE_PLUGIN_DIRS`.
    install_dir: Option<PathBuf>,
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
        let mut plugins = Vec::new();
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
                        Err(e) => {
                            tracing::error!(error = %e, path = %path.display(), "plugin build failed");
                        }
                    },
                    Err(e) => {
                        tracing::error!(error = %e, path = %path.display(), "plugin load failed");
                    }
                }
            }
        }
        tracing::info!(
            discovered = plugins.len(),
            loaded = plugins.iter().filter(|e| e.loaded).count(),
            "plugin host ready"
        );
        Ok(Self {
            base_context,
            plugins,
            install_dir,
        })
    }

    /// Dispatch a client-connected event to every loaded plugin, then
    /// ship each plugin's `fancy-plugin-info` envelope to the session.
    pub(crate) fn on_client_connected(&self, info: ClientInfo) {
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
    /// directory used by the marketplace flow.
    pub(crate) fn list_plugins(&self) -> (Vec<PluginAdminInfo>, Option<String>) {
        let out: Vec<PluginAdminInfo> = self
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
            })
            .collect();
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
                RArc::new(ScopedContext::new(Arc::clone(&self.base_context), prefix.clone())),
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
        Ok(())
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
        let loaded = load_plugin(&installed.cdylib_path).map_err(|e| e.to_string())?;
        let name = loaded.plugin.name().as_str().to_owned();

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
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
            .set_config(&format!("plugin.{name}.{CONFIG_KEY_ENABLED}"), "false")?;

        // Drop any previous entry for this plugin name (RAII unloads it)
        // before pushing the freshly-loaded one.
        if let Some(idx) = self.plugins.iter().position(|e| e.name == name) {
            let _ = self.plugins.swap_remove(idx);
        }
        let mut entry = build_entry(&self.base_context, loaded).map_err(|e| e.to_string())?;
        entry.marketplace_id = Some(marketplace_id.to_owned());
        entry.installed_at = Some(now_ms);
        let installed_name = entry.name.clone();
        self.plugins.push(entry);
        Ok(installed_name)
    }

    /// Plugin-admin: drop the entry (RAII unloads it), remove the
    /// cdylib from disk, and strip `plugin.<name>.*` from the server
    /// config.
    pub(crate) fn uninstall_plugin(&mut self, name: &str) -> Result<(), String> {
        let idx = self
            .plugins
            .iter()
            .position(|e| e.name == name)
            .ok_or_else(|| format!("plugin '{name}' not found"))?;
        let path = self.plugins[idx].plugin.path.clone();
        let _ = self.plugins.swap_remove(idx);
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| format!("failed to delete {}: {e}", path.display()))?;
        }
        self.base_context
            .delete_config_prefix(&format!("plugin.{name}."))?;
        Ok(())
    }
}

// `Drop for Host` is intentionally omitted: `Vec<Entry>` drops each
// `Entry`, and `Drop for Entry` invokes `on_unload` for any plugin
// still in the loaded state.  Centralising teardown in `Entry` means
// uninstall, hot-toggle, and full shutdown share one code path.

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
        if let abi_stable::std_types::RResult::RErr(e) =
            entry.plugin.plugin.on_load(plugin_ctx_to)
        {
            return Err(BuildEntryError::OnLoad(e.to_string()));
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
    use super::is_truthy_enabled_value;

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
    #[error("on_load failed: {0}")]
    OnLoad(String),
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
