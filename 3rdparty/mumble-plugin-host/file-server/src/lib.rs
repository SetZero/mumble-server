//! `mumble-file-server` - HTTP file sharing plugin for Mumble.
//!
//! This crate provides:
//! * A `FileServerPlugin` implementing [`mumble_plugin_api::MumblePlugin`].
//! * An axum-based HTTP server that handles upload, ticket-exchange and
//!   signed-URL download.
//! * SQLite-backed metadata storage with on-disk blobs.
//! * Three access modes: `public`, `password`, `session`.
//!
//! Architectural notes are in `doc/architecture.md` of the workspace.

use std::sync::Arc;

use async_trait::async_trait;
use mumble_plugin_api::{
    permissions, ClientInfo, MumblePlugin, PluginContext, PluginError, Result as PluginResult,
    ServerId, SessionId,
};
use rand::RngCore;
use tokio::sync::Mutex;

pub mod auth;
pub mod config;
pub mod documents;
pub mod emotes;
pub mod http;
pub mod rate_limit;
pub mod server;
pub mod session;
pub mod signing;
pub mod state;
pub mod storage;
pub mod tickets;

use crate::auth::issue_session_jwt;
use crate::config::FileServerConfig;
use crate::rate_limit::RateLimiter;
use crate::server::ServerHandle;
use crate::session::{SessionInfo, SessionMap};
use crate::state::AppState;
use crate::storage::{load_or_create_signing_secret, Storage};
use crate::tickets::TicketStore;

/// Plugin data id used to advertise the file server to clients.
pub const FILE_SERVER_DATA_ID: &str = "fancy-file-server-config";
/// Plugin data id used to share an uploaded-file announcement in chat.
pub const FILE_ATTACHMENT_DATA_ID: &str = "fancy-file-attachment";

/// Default JWT TTL for session-mode authentication tokens (24 hours).
const SESSION_JWT_TTL_SECS: u64 = 24 * 3600;

/// File-server plugin entry point.
#[derive(Debug, Default)]
pub struct FileServerPlugin {
    inner: Mutex<Option<RunningState>>,
}

#[derive(Debug)]
struct RunningState {
    handle: ServerHandle,
    state: AppState,
}

impl FileServerPlugin {
    /// Create a new (not-yet-loaded) plugin instance.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl MumblePlugin for FileServerPlugin {
    fn name(&self) -> &'static str {
        "fancy-file-server"
    }

    async fn on_load(&self, ctx: Arc<dyn PluginContext>) -> PluginResult<()> {
        let cfg = FileServerConfig::from_context(ctx.as_ref())
            .map_err(|e| PluginError::Config(e.to_string()))?;
        if !cfg.enabled {
            tracing::info!("file server disabled by config");
            return Ok(());
        }
        let cfg = Arc::new(cfg);

        std::fs::create_dir_all(&cfg.storage_path)?;

        let storage = Storage::open(&cfg.storage_path, cfg.max_total_storage_bytes)
            .map_err(|e| PluginError::Other(format!("storage: {e}")))?;
        let storage = Arc::new(storage);

        let documents = documents::DocumentsStore::open(&cfg.storage_path)
            .map_err(|e| PluginError::Other(format!("documents: {e}")))?;
        let documents = Arc::new(documents);

        let signing_secret = load_or_create_signing_secret(&cfg.storage_path)
            .map_err(|e| PluginError::Other(format!("signing secret: {e}")))?;

        let app_state = AppState {
            storage,
            documents,
            tickets: Arc::new(TicketStore::new()),
            sessions: Arc::new(SessionMap::new()),
            auth_rate_limiter: Arc::new(RateLimiter::new()),
            signing_secret: Arc::new(signing_secret),
            config: cfg,
            plugin_ctx: ctx,
        };

        let handle = server::start(app_state.clone())
            .await
            .map_err(PluginError::Io)?;

        *self.inner.lock().await = Some(RunningState {
            handle,
            state: app_state,
        });
        Ok(())
    }

    async fn on_unload(&self) -> PluginResult<()> {
        if let Some(running) = self.inner.lock().await.take() {
            running.handle.shutdown().await;
        }
        Ok(())
    }

    async fn on_client_connected(&self, info: ClientInfo) -> PluginResult<()> {
        let guard = self.inner.lock().await;
        let Some(running) = guard.as_ref() else { return Ok(()); };

        let upload_token = generate_token_hex();
        let session_jwt = issue_session_jwt(
            running.state.signing_secret.as_ref(),
            &info.cert_hash,
            info.session_id,
            info.server_id,
            SESSION_JWT_TTL_SECS,
        )
        .map_err(|e| PluginError::Other(format!("issue jwt: {e}")))?;

        running.state.sessions.insert(
            info.session_id,
            SessionInfo {
                cert_hash: info.cert_hash.clone(),
                upload_token: upload_token.clone(),
            },
        );

        let payload = serde_json::json!({
            "type": "file-server-config",
            "base_url": running.state.config.base_url,
            "session_id": info.session_id,
            "upload_token": upload_token,
            "session_jwt": session_jwt,
            "max_file_size_bytes": running.state.config.max_file_size_bytes,
            "delete_on_ttl": running.state.config.delete_on_ttl,
            "ttl_seconds": running.state.config.ttl.as_secs(),
            "delete_on_download": running.state.config.delete_on_download,
            "delete_on_disconnect": running.state.config.delete_on_disconnect,
            "can_manage_emotes": running.state.plugin_ctx.has_permission(
                info.server_id,
                info.session_id,
                0,
                permissions::MANAGE_EMOTES,
            ),
            // Best-effort UI hint: root-channel permission only.  The
            // server enforces the actual per-channel permission when
            // an upload is attempted.
            "can_share_files": running.state.plugin_ctx.has_permission(
                info.server_id,
                info.session_id,
                0,
                permissions::SHARE_FILES,
            ),
            "can_share_files_public": running.state.plugin_ctx.has_permission(
                info.server_id,
                info.session_id,
                0,
                permissions::SHARE_FILES_PUBLIC,
            ),
        });
        let bytes = serde_json::to_vec(&payload)
            .map_err(|e| PluginError::Other(format!("serialize: {e}")))?;
        running
            .state
            .plugin_ctx
            .send_plugin_data(
                info.server_id,
                info.session_id,
                FILE_SERVER_DATA_ID,
                &bytes,
            )?;

        http::emotes::send_emotes_to_session(
            &running.state,
            info.server_id,
            info.session_id,
        );
        Ok(())
    }

    async fn on_client_disconnected(
        &self,
        _server: ServerId,
        session: SessionId,
    ) -> PluginResult<()> {
        let guard = self.inner.lock().await;
        let Some(running) = guard.as_ref() else { return Ok(()); };
        let removed = running.state.sessions.remove(session);
        if let Some(info) = removed.as_ref() {
            running.state.tickets.invalidate_for(&info.cert_hash);
        }
        if running.state.config.delete_on_disconnect {
            // Spawn the (potentially expensive) per-session cleanup so
            // we don't block the disconnect path (L-3).
            let state = running.state.clone();
            drop(tokio::spawn(async move {
                cleanup_session_files(&state, session);
            }));
        }
        Ok(())
    }
}

fn cleanup_session_files(state: &AppState, session: SessionId) {
    match state.storage.list_for_session(session) {
        Ok(ids) => {
            for id in ids {
                if let Err(e) = state.storage.delete(&id) {
                    tracing::warn!(file_id = %id, error = %e, "delete-on-disconnect failed");
                }
            }
        }
        Err(e) => tracing::warn!(error = %e, "list_for_session failed"),
    }
}

fn generate_token_hex() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Re-export the time-helper used by tests.
pub use signing::now_unix_seconds;
