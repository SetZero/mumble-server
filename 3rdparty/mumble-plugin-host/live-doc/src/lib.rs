//! `mumble-live-doc` - real-time collaborative document plugin for Mumble.
//!
//! Provides:
//! * A `LiveDocPlugin` implementing [`mumble_plugin_api::MumblePlugin`].
//! * An axum-based `WebSocket` endpoint that brokers Yjs CRDT updates
//!   between connected clients.
//! * Channel-scoped permission gating via [`HostFacade::has_permission`].
//! * JWT-based handshake authentication (token is delivered through
//!   the generic `PluginMessage` envelope, wire ID 200, with
//!   `payload_type = "Invite"`).
//! * Persistence bridge to the `file-server` plugin: closed documents
//!   are uploaded as a markdown file and re-fetched on next open.

use std::sync::{Arc, Mutex};

use abi_stable::std_types::{RArc, ROk, RSlice, RStr, RString};
use mumble_plugin_api::{
    plugin_info, ChannelId, ClientInfo, DebugRow, MumblePlugin, PluginContext_TO, PluginError,
    PluginMessageIn, PluginResult, ServerId, SessionId,
};

pub mod announce;
pub mod auth;
pub mod config;
pub mod doc;
pub mod host_facade;
pub mod persistence;
pub mod state;
pub mod ws;

use crate::announce::{handle_open_request, handle_open_request_typed};
use crate::config::LiveDocConfig;
use crate::host_facade::{HostFacade, SabiHostCtx};
use crate::state::AppState;
use crate::ws::ServerHandle;

/// Default JWT TTL for WS handshake tokens (5 minutes - users can
/// reconnect within this window without re-fetching).
pub const HANDSHAKE_JWT_TTL_SECS: u64 = 5 * 60;

pub(crate) const PLUGIN_NAME: &str = "fancy-live-doc";
const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Live-doc plugin entry point.
#[derive(Default)]
pub struct LiveDocPlugin {
    inner: Mutex<Option<RunningState>>,
}

struct RunningState {
    handle: Option<ServerHandle>,
    runtime: tokio::runtime::Runtime,
    state: AppState,
}

impl LiveDocPlugin {
    /// Construct a new (not-yet-loaded) plugin instance.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot debug rows reflecting current runtime state.  Empty
    /// before [`Self::on_load`] populates `inner`.
    fn debug_info(&self) -> Vec<DebugRow> {
        let mut rows = Vec::new();
        if let Ok(guard) = self.inner.lock() {
            if let Some(running) = guard.as_ref() {
                let c = running.state.cfg();
                rows.push(DebugRow {
                    label: "bind".into(),
                    value: c.bind.to_string(),
                });
                if let Some(url) = &c.public_url {
                    rows.push(DebugRow {
                        label: "public_url".into(),
                        value: url.clone(),
                    });
                }
                rows.push(DebugRow {
                    label: "max_update_bytes".into(),
                    value: c.max_update_bytes.to_string(),
                });
                rows.push(DebugRow {
                    label: "snapshot_idle_secs".into(),
                    value: c.snapshot_idle_secs.to_string(),
                });
            }
        }
        rows
    }
}

impl std::fmt::Debug for LiveDocPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveDocPlugin").finish_non_exhaustive()
    }
}

impl MumblePlugin for LiveDocPlugin {
    fn name(&self) -> RStr<'_> {
        RStr::from(PLUGIN_NAME)
    }

    fn version(&self) -> RStr<'_> {
        RStr::from(PLUGIN_VERSION)
    }

    fn info_json(&self) -> RString {
        plugin_info! {
            description: "Real-time collaborative documents over WebSocket (Yjs CRDT).",
            author: "Fancy Mumble",
            tags: ["http", "websocket", "live-doc"],
            debug_info: self.debug_info(),
        }
        .to_rstring()
    }

    fn on_load(&self, ctx: PluginContext_TO<RArc<()>>) -> PluginResult<()> {
        init_tracing();
        let facade: Arc<dyn HostFacade> = Arc::new(SabiHostCtx::new(ctx));
        match build_running_state(facade) {
            Ok(running) => {
                if let Ok(mut guard) = self.inner.lock() {
                    *guard = Some(running);
                }
                ROk(())
            }
            Err(e) => PluginResult::RErr(e),
        }
    }

    fn on_unload(&self, _ctx: &PluginContext_TO<RArc<()>>) -> PluginResult<()> {
        let Some(mut running) = self.inner.lock().ok().and_then(|mut g| g.take()) else {
            return ROk(());
        };
        let state = running.state.clone();
        let handle = running.handle.take();
        // Tear down doc state and the WS server on the same runtime, and
        // await the server task so the listening socket is fully released
        // before this returns (otherwise a quick re-enable could hit
        // EADDRINUSE when on_load re-binds the port).
        running.runtime.block_on(async move {
            state.shutdown().await;
            if let Some(handle) = handle {
                handle.shutdown().await;
            }
        });
        ROk(())
    }

    fn on_client_connected(
        &self,
        _ctx: &PluginContext_TO<RArc<()>>,
        info: ClientInfo,
    ) -> PluginResult<()> {
        // Configuration is advertised via `fancy-plugin-info` (info_json), so
        // there is nothing to send out per-client here.  We do cache the
        // client's identity so a document can be attributed to its creator.
        let Ok(guard) = self.inner.lock() else {
            return ROk(());
        };
        let Some(running) = guard.as_ref() else {
            return ROk(());
        };
        running.state.record_client(
            info.server_id,
            info.session_id,
            info.username.into_string(),
            info.cert_hash.into_string(),
        );
        ROk(())
    }

    fn on_client_disconnected(
        &self,
        _ctx: &PluginContext_TO<RArc<()>>,
        server_id: ServerId,
        session: SessionId,
    ) -> PluginResult<()> {
        let Ok(guard) = self.inner.lock() else {
            return ROk(());
        };
        let Some(running) = guard.as_ref() else {
            return ROk(());
        };
        running.state.forget_client(server_id, session);
        let state = running.state.clone();
        running
            .runtime
            .block_on(async move { state.handle_client_gone(server_id, session).await });
        ROk(())
    }

    fn on_plugin_data(
        &self,
        _ctx: &PluginContext_TO<RArc<()>>,
        server_id: ServerId,
        sender: SessionId,
        data_id: RStr<'_>,
        data: RSlice<'_, u8>,
    ) -> PluginResult<()> {
        if data_id.as_str() != "fancy-live-doc/open" {
            return ROk(());
        }
        let Ok(guard) = self.inner.lock() else {
            return ROk(());
        };
        let Some(running) = guard.as_ref() else {
            return ROk(());
        };
        let state = running.state.clone();
        let payload = data.to_vec();
        running.runtime.block_on(async move {
            handle_open_request(&state, server_id, sender, &payload).await;
        });
        ROk(())
    }

    fn on_plugin_message(
        &self,
        _ctx: &PluginContext_TO<RArc<()>>,
        msg: PluginMessageIn,
    ) -> PluginResult<()> {
        if msg.payload_type.as_str() != "OpenRequest" {
            return ROk(());
        }
        let Ok(guard) = self.inner.lock() else {
            return ROk(());
        };
        let Some(running) = guard.as_ref() else {
            return ROk(());
        };
        let state = running.state.clone();
        let server_id = msg.server_id;
        let sender = msg.sender_session;
        let payload = msg.payload.as_slice().to_vec();
        let Some((channel_id, slug, title)) = parse_open_request(&payload) else {
            return ROk(());
        };
        let _ = (msg.plugin_name, msg.channel_id, msg.sender_name);
        running.runtime.block_on(async move {
            handle_open_request_typed(&state, server_id, sender, channel_id, &slug, &title).await;
        });
        ROk(())
    }
}

/// Lightweight parser for the live-doc `OpenRequest` JSON shape used
/// inside [`MumblePlugin::on_plugin_message`].  Accepts both camelCase
/// (`channelId`/`slug`/`title`) and the legacy `snake_case` form.
fn parse_open_request(payload: &[u8]) -> Option<(ChannelId, String, String)> {
    let v: serde_json::Value = serde_json::from_slice(payload).ok()?;
    let channel_id = v
        .get("channelId")
        .or_else(|| v.get("channel_id"))
        .and_then(serde_json::Value::as_u64)?;
    let slug = v
        .get("slug")
        .and_then(serde_json::Value::as_str)?
        .to_owned();
    let title = v
        .get("title")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_owned();
    Some((channel_id as ChannelId, slug, title))
}

fn build_running_state(facade: Arc<dyn HostFacade>) -> Result<RunningState, PluginError> {
    let cfg = LiveDocConfig::from_context(facade.as_ref())
        .map_err(|e| PluginError::Config(e.to_string().into()))?;
    let cfg = Arc::new(cfg);

    // Make a "documents don't persist" surprise impossible to miss: warn once
    // at start-up if the file-server-backed persistence is not configured.
    persistence::warn_if_persistence_disabled(&cfg);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("fancy-live-doc")
        .build()
        .map_err(|e| PluginError::Other(format!("tokio runtime: {e}").into()))?;

    let state = AppState::new(cfg.clone(), facade);
    let handle = runtime
        .block_on(ws::serve(state.clone()))
        .map_err(|e| PluginError::Other(format!("ws server: {e}").into()))?;

    tracing::info!(
        port = cfg.port,
        "live-doc plugin listening on {}",
        handle.local_addr()
    );

    Ok(RunningState {
        handle: Some(handle),
        runtime,
        state,
    })
}

fn init_tracing() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_env("MUMBLE_PLUGIN_LOG")
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .try_init();
    });
}

mod plugin_export {
    use super::LiveDocPlugin;
    mumble_plugin_api::fancy_export_plugin!(LiveDocPlugin::new);
}
