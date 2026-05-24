//! Plugin host: discovers cdylibs at startup, loads each via
//! [`crate::loader`], dispatches lifecycle events, and ships the
//! per-plugin `fancy-plugin-info` envelope to every newly connected
//! client.

use std::ffi::CString;
use std::path::PathBuf;
use std::sync::Arc;

use abi_stable::std_types::{RArc, RNone, RSlice, RSome, RStr, RVec};
use mumble_plugin_api::{
    ChannelId, ClientInfo, PLUGIN_INFO_DATA_ID, PluginContext_TO, PluginMessageIn, ServerId,
    SessionId,
};

use crate::context::{HostContext, ScopedContext};
use crate::info::{encode, PluginInfoRecord};
use crate::loader::{discover_plugin_dirs, load_plugin, scan_dir, LoadedPlugin};

/// Configuration key the host reads from the server to find the plugin
/// directory.
const CONFIG_KEY_PLUGINS_DIR: &str = "plugins_dir";

/// Per-plugin configuration key (under the `plugin.<name>.` namespace)
/// that gates whether the plugin is loaded.  The host reads this
/// before invoking [`mumble_plugin_api::MumblePlugin::on_load`] so
/// individual plugins do not need to perform the check themselves.
const CONFIG_KEY_ENABLED: &str = "enabled";

/// One plugin that finished loading, with its precomputed metadata.
struct Entry {
    name: String,
    version: String,
    /// Already-framed `fancy-plugin-info` envelope, or `None` if the
    /// plugin failed to advertise valid JSON (logged once at load).
    info_envelope: Option<Vec<u8>>,
    plugin: LoadedPlugin,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("info_envelope_len", &self.info_envelope.as_ref().map(Vec::len))
            .field("path", &self.plugin.path)
            .finish()
    }
}

/// The plugin host: owns every loaded plugin and the shared context.
#[derive(Debug)]
pub struct Host {
    base_context: Arc<HostContext>,
    plugins: Vec<Entry>,
}

impl Host {
    /// Build a new host: read the configured plugin directory list,
    /// load every cdylib in those directories, call `on_load` on each.
    pub(crate) fn new(context: HostContext) -> Result<Self, std::io::Error> {
        let base_context = Arc::new(context);
        let dirs = configured_dirs(&base_context);
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
                        Ok(Some(e)) => {
                            tracing::info!(
                                plugin = %e.name,
                                version = %e.version,
                                path = %e.plugin.path.display(),
                                "plugin loaded"
                            );
                            plugins.push(e);
                        }
                        Ok(None) => {
                            // Plugin discovered but disabled via
                            // `plugin.<name>.enabled`; build_entry
                            // already logged the skip.
                        }
                        Err(e) => tracing::error!(error = %e, path = %path.display(), "plugin build failed"),
                    },
                    Err(e) => tracing::error!(error = %e, path = %path.display(), "plugin load failed"),
                }
            }
        }
        tracing::info!(
            loaded = plugins.len(),
            "plugin host ready"
        );
        Ok(Self { base_context, plugins })
    }

    /// Dispatch a client-connected event to every loaded plugin, then
    /// ship each plugin's `fancy-plugin-info` envelope to the session.
    pub(crate) fn on_client_connected(&self, info: ClientInfo) {
        for entry in &self.plugins {
            if let abi_stable::std_types::RResult::RErr(e) =
                entry.plugin.plugin.on_client_connected(info.clone())
            {
                tracing::warn!(plugin = %entry.name, error = %e, "on_client_connected failed");
            }
            if let Some(envelope) = &entry.info_envelope {
                if let abi_stable::std_types::RResult::RErr(e) = self.base_context.send_plugin_data_raw(
                    info.server_id,
                    info.session_id,
                    PLUGIN_INFO_DATA_ID,
                    envelope,
                ) {
                    tracing::warn!(plugin = %entry.name, error = %e, "plugin-info delivery failed");
                }
            }
        }
    }

    /// Dispatch a client-disconnected event.
    pub(crate) fn on_client_disconnected(&self, server_id: ServerId, session: SessionId) {
        for entry in &self.plugins {
            if let abi_stable::std_types::RResult::RErr(e) =
                entry.plugin.plugin.on_client_disconnected(server_id, session)
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
        for entry in &self.plugins {
            if let abi_stable::std_types::RResult::RErr(e) =
                entry.plugin.plugin.on_plugin_data(server_id, sender, id, bytes)
            {
                tracing::warn!(plugin = %entry.name, error = %e, "on_plugin_data failed");
            }
        }
    }

    /// Route an inbound generic `PluginMessage` (wire ID 200) to the
    /// single plugin whose [`mumble_plugin_api::MumblePlugin::name`]
    /// equals `plugin_name`.  Unknown names are logged and dropped.
    pub(crate) fn on_plugin_message(&self, args: PluginMessageInArgs) {
        let Some(entry) = self.plugins.iter().find(|e| e.name == args.plugin_name) else {
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
        if let abi_stable::std_types::RResult::RErr(e) =
            entry.plugin.plugin.on_plugin_message(msg)
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
}

impl Drop for Host {
    fn drop(&mut self) {
        for entry in &self.plugins {
            if let abi_stable::std_types::RResult::RErr(e) = entry.plugin.plugin.on_unload() {
                tracing::warn!(plugin = %entry.name, error = %e, "on_unload failed");
            }
        }
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

fn build_entry(
    base_context: &Arc<HostContext>,
    loaded: LoadedPlugin,
) -> Result<Option<Entry>, BuildEntryError> {
    let name = loaded.plugin.name().as_str().to_owned();
    let version = loaded.plugin.version().as_str().to_owned();
    let prefix = format!("plugin.{name}");
    if !plugin_is_enabled(base_context, &prefix) {
        tracing::info!(
            plugin = %name,
            "plugin discovered but not enabled; set {prefix}.{CONFIG_KEY_ENABLED}=true to load"
        );
        return Ok(None);
    }
    let info_envelope = build_info_envelope(&name, &version, &loaded);
    let scoped = ScopedContext::new(Arc::clone(base_context), prefix);
    let ctx_to = PluginContext_TO::from_ptr(RArc::new(scoped), abi_stable::sabi_trait::TD_Opaque);
    if let abi_stable::std_types::RResult::RErr(e) = loaded.plugin.on_load(ctx_to) {
        return Err(BuildEntryError::OnLoad(e.to_string()));
    }
    Ok(Some(Entry { name, version, info_envelope, plugin: loaded }))
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
    match encode(&PluginInfoRecord { name, version, info: &parsed }) {
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
