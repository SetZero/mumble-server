//! `mumble-live-doc` - real-time collaborative document plugin for Mumble.
//!
//! Provides:
//! * A `LiveDocPlugin` implementing [`mumble_plugin_api::MumblePlugin`].
//! * An axum-based WebSocket endpoint that brokers Yjs CRDT updates
//!   between connected clients.
//! * Channel-scoped permission gating via [`PluginContext::has_permission`].
//! * JWT-based handshake authentication (token is delivered via the native
//!   `FancyLiveDocInvite` proto message, wire ID 142).
//! * Persistence bridge to the `file-server` plugin: closed documents
//!   are uploaded as a markdown file and re-fetched on next open.
//!
//! Architectural notes:
//!
//! * Each `(server_id, channel_id, doc_slug)` triple maps to one
//!   [`doc::DocRoom`].  Rooms are spawned lazily on first open and
//!   torn down ~30 s after the last subscriber disconnects (grace
//!   window so quick refreshes don't trigger persistence churn).
//! * The wire format inside the WebSocket is the standard
//!   `y-protocols`/`y-websocket` framing: sync step messages and
//!   awareness updates, identical to what browser Yjs produces.
//! * Revisions are TODO - see [`persistence`] for the seam.

use std::sync::Arc;

use async_trait::async_trait;
use mumble_plugin_api::{
    ChannelId, ClientInfo, MumblePlugin, PluginContext, PluginError, Result as PluginResult,
    ServerId, SessionId,
};
use tokio::sync::Mutex;

pub mod announce;
pub mod auth;
pub mod config;
pub mod doc;
pub mod persistence;
pub mod state;
pub mod ws;

use crate::announce::{handle_open_request, handle_open_request_typed};
use crate::config::LiveDocConfig;
use crate::state::AppState;
use crate::ws::ServerHandle;

/// Default JWT TTL for WS handshake tokens (5 minutes - users can
/// reconnect within this window without re-fetching).
pub const HANDSHAKE_JWT_TTL_SECS: u64 = 5 * 60;

/// Live-doc plugin entry point.
#[derive(Debug, Default)]
pub struct LiveDocPlugin {
    inner: Mutex<Option<RunningState>>,
}

#[derive(Debug)]
struct RunningState {
    handle: ServerHandle,
    state: AppState,
}

impl LiveDocPlugin {
    /// Create a new (not-yet-loaded) plugin instance.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl MumblePlugin for LiveDocPlugin {
    fn name(&self) -> &'static str {
        "fancy-live-doc"
    }

    async fn on_load(&self, ctx: Arc<dyn PluginContext>) -> PluginResult<()> {
        let cfg = LiveDocConfig::from_context(ctx.as_ref())
            .map_err(|e| PluginError::Config(e.to_string()))?;
        if !cfg.enabled {
            tracing::info!("live-doc disabled by config");
            return Ok(());
        }
        let cfg = Arc::new(cfg);

        let state = AppState::new(cfg.clone(), ctx.clone());
        let handle = ws::serve(state.clone())
            .await
            .map_err(|e| PluginError::Other(format!("ws server: {e}")))?;

        tracing::info!(
            port = cfg.port,
            "live-doc plugin listening on {}",
            handle.local_addr()
        );

        *self.inner.lock().await = Some(RunningState { handle, state });
        Ok(())
    }

    async fn on_unload(&self) -> PluginResult<()> {
        if let Some(running) = self.inner.lock().await.take() {
            running.state.shutdown().await;
            running.handle.shutdown();
        }
        Ok(())
    }

    async fn on_client_disconnected(
        &self,
        server_id: ServerId,
        session: SessionId,
    ) -> PluginResult<()> {
        if let Some(running) = self.inner.lock().await.as_ref() {
            running.state.handle_client_gone(server_id, session).await;
        }
        Ok(())
    }

    async fn on_client_connected(&self, info: ClientInfo) -> PluginResult<()> {
        let _ = info;
        Ok(())
    }

    async fn on_plugin_data(
        &self,
        server_id: ServerId,
        sender: SessionId,
        data_id: &str,
        data: &[u8],
    ) -> PluginResult<()> {
        if data_id != "fancy-live-doc/open" {
            return Ok(());
        }
        let Some(running) = self.inner.lock().await.as_ref().map(|r| r.state.clone()) else {
            return Ok(());
        };
        handle_open_request(&running, server_id, sender, data).await;
        Ok(())
    }

    async fn on_fancy_live_doc_open(
        &self,
        server_id: ServerId,
        sender: SessionId,
        channel_id: ChannelId,
        slug: &str,
        title: &str,
    ) -> PluginResult<()> {
        let Some(running) = self.inner.lock().await.as_ref().map(|r| r.state.clone()) else {
            return Ok(());
        };
        handle_open_request_typed(&running, server_id, sender, channel_id, slug, title).await;
        Ok(())
    }
}
