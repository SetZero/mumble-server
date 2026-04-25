//! Owns the loaded plugins and the tokio runtime that drives their
//! async lifecycle hooks.

use std::sync::Arc;

use mumble_plugin_api::{ClientInfo, MumblePlugin, PluginContext, ServerId, SessionId};
use tokio::runtime::{Builder, Runtime};

use crate::context::HostContext;

/// Owns the runtime, the plugin set, and the shared context handed to
/// each plugin on load.
#[derive(Debug)]
pub struct Host {
    runtime: Runtime,
    plugins: Vec<Arc<dyn MumblePlugin>>,
}

impl Host {
    /// Build a new host backed by the supplied [`HostContext`] and load
    /// all built-in plugins.
    pub(crate) fn new(context: HostContext) -> Result<Self, std::io::Error> {
        let runtime = Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("mumble-plugin-host")
            .build()?;

        let context: Arc<dyn PluginContext> = Arc::new(context);
        let plugins = builtin_plugins();

        for plugin in &plugins {
            let ctx = Arc::clone(&context);
            let p = Arc::clone(plugin);
            if let Err(e) = runtime.block_on(async move { p.on_load(ctx).await }) {
                tracing::error!(plugin = %plugin.name(), error = %e, "plugin on_load failed");
            }
        }

        Ok(Self { runtime, plugins })
    }

    /// Dispatch a client-connected event to every loaded plugin.
    pub(crate) fn on_client_connected(&self, info: ClientInfo) {
        for plugin in &self.plugins {
            let p = Arc::clone(plugin);
            let info = info.clone();
            if let Err(e) = self
                .runtime
                .block_on(async move { p.on_client_connected(info).await })
            {
                tracing::warn!(plugin = %plugin.name(), error = %e, "on_client_connected failed");
            }
        }
    }

    /// Dispatch a client-disconnected event to every loaded plugin.
    pub(crate) fn on_client_disconnected(&self, server_id: ServerId, session: SessionId) {
        for plugin in &self.plugins {
            let p = Arc::clone(plugin);
            if let Err(e) = self
                .runtime
                .block_on(async move { p.on_client_disconnected(server_id, session).await })
            {
                tracing::warn!(plugin = %plugin.name(), error = %e, "on_client_disconnected failed");
            }
        }
    }

    /// Dispatch a plugin-data event to every loaded plugin.
    pub(crate) fn on_plugin_data(
        &self,
        server_id: ServerId,
        sender: SessionId,
        data_id: String,
        data: Vec<u8>,
    ) {
        for plugin in &self.plugins {
            let p = Arc::clone(plugin);
            let id = data_id.clone();
            let bytes = data.clone();
            if let Err(e) = self.runtime.block_on(async move {
                p.on_plugin_data(server_id, sender, &id, &bytes).await
            }) {
                tracing::warn!(plugin = %plugin.name(), error = %e, "on_plugin_data failed");
            }
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        for plugin in &self.plugins {
            let p = Arc::clone(plugin);
            if let Err(e) = self.runtime.block_on(async move { p.on_unload().await }) {
                tracing::warn!(plugin = %plugin.name(), error = %e, "on_unload failed");
            }
        }
    }
}

fn builtin_plugins() -> Vec<Arc<dyn MumblePlugin>> {
    vec![Arc::new(mumble_file_server::FileServerPlugin::new())]
}
