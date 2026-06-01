//! `mumble-file-server` - HTTP file sharing plugin for Mumble.
//!
//! This crate provides:
//! * A [`FileServerPlugin`] implementing
//!   [`mumble_plugin_api::MumblePlugin`] (loaded as a dynamic cdylib).
//! * An axum-based HTTP server that handles upload, ticket-exchange and
//!   signed-URL download.
//! * SQLite-backed metadata storage with on-disk blobs.
//! * Three access modes: `public`, `password`, `session`.

use std::sync::{Arc, Mutex};

use abi_stable::std_types::{RArc, ROk, RSlice, RStr, RString};
use mumble_plugin_api::{
    plugin_info, ClientInfo, DebugRow, MumblePlugin, Permissions, PluginContext_TO, PluginError,
    PluginResult, ServerId, SessionId,
};
use rand::RngCore;

pub mod auth;
pub mod config;
pub mod documents;
pub mod emotes;
pub mod host_facade;
pub mod http;
pub mod private_store;
pub mod rate_limit;
pub mod server;
pub mod session;
pub mod signing;
pub mod state;
pub mod storage;
pub mod tickets;

use crate::auth::issue_session_jwt;
use crate::config::FileServerConfig;
use crate::host_facade::{HostFacade, SabiHostCtx};
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

const PLUGIN_NAME: &str = "fancy-file-server";
const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

/// File-server plugin entry point.
#[derive(Default)]
pub struct FileServerPlugin {
    inner: Mutex<Option<RunningState>>,
}

struct RunningState {
    handle: Option<ServerHandle>,
    runtime: tokio::runtime::Runtime,
    state: AppState,
}

impl FileServerPlugin {
    /// Construct a new (not-yet-loaded) plugin instance.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl std::fmt::Debug for FileServerPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileServerPlugin").finish_non_exhaustive()
    }
}

impl MumblePlugin for FileServerPlugin {
    fn name(&self) -> RStr<'_> {
        RStr::from(PLUGIN_NAME)
    }

    fn version(&self) -> RStr<'_> {
        RStr::from(PLUGIN_VERSION)
    }

    fn info_json(&self) -> RString {
        plugin_info! {
            description: "HTTP file sharing with signed URLs and per-channel ACLs.",
            author: "Fancy Mumble",
            tags: ["http", "files", "emotes"],
            debug_info: self.runtime_debug_rows(),
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
        if let Some(handle) = running.handle.take() {
            running.runtime.block_on(handle.shutdown());
        }
        ROk(())
    }

    fn on_client_connected(
        &self,
        _ctx: &PluginContext_TO<RArc<()>>,
        info: ClientInfo,
    ) -> PluginResult<()> {
        let Ok(guard) = self.inner.lock() else {
            return PluginResult::RErr(PluginError::Other("file-server state poisoned".into()));
        };
        let Some(running) = guard.as_ref() else {
            return ROk(());
        };
        let server_id: ServerId = info.server_id;
        let session_id: SessionId = info.session_id;
        let user_id: i64 = info.user_id;
        let cert_hash: String = info.cert_hash.into_string();
        let username: String = info.username.into_string();
        if let Err(e) = announce_to_client(running, server_id, session_id, &cert_hash, user_id) {
            tracing::warn!(
                session = session_id,
                user = %username,
                error = %e,
                "file-server: failed to announce to client"
            );
            return PluginResult::RErr(PluginError::Other(e.into()));
        }
        http::emotes::send_emotes_to_session(&running.state, server_id, session_id);
        ROk(())
    }

    fn on_client_disconnected(
        &self,
        _ctx: &PluginContext_TO<RArc<()>>,
        _server: ServerId,
        session: SessionId,
    ) -> PluginResult<()> {
        let Ok(guard) = self.inner.lock() else {
            return ROk(());
        };
        let Some(running) = guard.as_ref() else {
            return ROk(());
        };
        let removed = running.state.sessions.remove(session);
        if let Some(info) = removed.as_ref() {
            running.state.tickets.invalidate_for(&info.cert_hash);
        }
        if running.state.config.delete_on_disconnect {
            let state = running.state.clone();
            drop(running.runtime.spawn(async move {
                cleanup_session_files(&state, session);
            }));
        }
        ROk(())
    }

    fn on_plugin_data(
        &self,
        _ctx: &PluginContext_TO<RArc<()>>,
        _server: ServerId,
        _sender: SessionId,
        _data_id: RStr<'_>,
        _data: RSlice<'_, u8>,
    ) -> PluginResult<()> {
        ROk(())
    }
}

impl FileServerPlugin {
    /// Snapshot debug rows reflecting current runtime state.  Empty
    /// before [`Self::on_load`] populates `inner`.
    fn runtime_debug_rows(&self) -> Vec<DebugRow> {
        let mut rows = Vec::new();
        if let Ok(guard) = self.inner.lock() {
            if let Some(running) = guard.as_ref() {
                let c = &running.state.config;
                rows.push(DebugRow {
                    label: "base_url".into(),
                    value: c.base_url.clone(),
                });
                rows.push(DebugRow {
                    label: "bind".into(),
                    value: format!("{}:{}", c.bind_address, c.port),
                });
                rows.push(DebugRow {
                    label: "max_file_size_bytes".into(),
                    value: c.max_file_size_bytes.to_string(),
                });
                rows.push(DebugRow {
                    label: "delete_on_ttl".into(),
                    value: c.delete_on_ttl.to_string(),
                });
            }
        }
        rows
    }
}

fn build_running_state(facade: Arc<dyn HostFacade>) -> Result<RunningState, PluginError> {
    let cfg = FileServerConfig::from_context(facade.as_ref())
        .map_err(|e| PluginError::Config(e.to_string().into()))?;
    let cfg = Arc::new(cfg);

    std::fs::create_dir_all(&cfg.storage_path)
        .map_err(|e| PluginError::Io(format!("create storage dir: {e}").into()))?;

    let storage = Storage::open(&cfg.storage_path, cfg.max_total_storage_bytes)
        .map_err(|e| PluginError::Other(format!("storage: {e}").into()))?;

    let documents = documents::DocumentsStore::open(&cfg.storage_path)
        .map_err(|e| PluginError::Other(format!("documents: {e}").into()))?;

    let private_store = private_store::PrivateStore::open(&cfg.storage_path)
        .map_err(|e| PluginError::Other(format!("private store: {e}").into()))?;

    let signing_secret = load_or_create_signing_secret(&cfg.storage_path)
        .map_err(|e| PluginError::Other(format!("signing secret: {e}").into()))?;

    let app_state = AppState {
        storage: Arc::new(storage),
        documents: Arc::new(documents),
        private_store: Arc::new(private_store),
        tickets: Arc::new(TicketStore::new()),
        sessions: Arc::new(SessionMap::new()),
        auth_rate_limiter: Arc::new(RateLimiter::new()),
        signing_secret: Arc::new(signing_secret),
        config: cfg,
        plugin_ctx: facade,
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("fancy-file-server")
        .build()
        .map_err(|e| PluginError::Other(format!("tokio runtime: {e}").into()))?;

    let handle = runtime
        .block_on(server::start(app_state.clone()))
        .map_err(|e| PluginError::Io(format!("http server start: {e}").into()))?;

    Ok(RunningState {
        handle: Some(handle),
        runtime,
        state: app_state,
    })
}

fn announce_to_client(
    running: &RunningState,
    server_id: ServerId,
    session_id: SessionId,
    cert_hash: &str,
    user_id: i64,
) -> Result<(), String> {
    let upload_token = generate_token_hex();
    let session_jwt = issue_session_jwt(
        running.state.signing_secret.as_ref(),
        cert_hash,
        session_id,
        server_id,
        user_id,
        SESSION_JWT_TTL_SECS,
    )
    .map_err(|e| format!("issue jwt: {e}"))?;

    running.state.sessions.insert(
        session_id,
        SessionInfo {
            cert_hash: cert_hash.to_owned(),
            upload_token: upload_token.clone(),
        },
    );

    let payload = serde_json::json!({
        "type": "file-server-config",
        "base_url": running.state.config.base_url,
        "session_id": session_id,
        "upload_token": upload_token,
        "session_jwt": session_jwt,
        "max_file_size_bytes": running.state.config.max_file_size_bytes,
        "delete_on_ttl": running.state.config.delete_on_ttl,
        "ttl_seconds": running.state.config.ttl.as_secs(),
        "delete_on_download": running.state.config.delete_on_download,
        "delete_on_disconnect": running.state.config.delete_on_disconnect,
        "registered": user_id >= 0,
        "can_manage_emotes": running.state.plugin_ctx.has_permission(
            server_id, session_id, 0, Permissions::MANAGE_EMOTES,
        ),
        "can_share_files": running.state.plugin_ctx.has_permission(
            server_id, session_id, 0, Permissions::SHARE_FILES,
        ),
        "can_share_files_public": running.state.plugin_ctx.has_permission(
            server_id, session_id, 0, Permissions::SHARE_FILES_PUBLIC,
        ),
    });
    let bytes = serde_json::to_vec(&payload).map_err(|e| format!("serialize: {e}"))?;
    running
        .state
        .plugin_ctx
        .send_plugin_data(server_id, session_id, FILE_SERVER_DATA_ID, &bytes)
        .map_err(|e| format!("send_plugin_data: {e}"))
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
    use super::FileServerPlugin;
    mumble_plugin_api::fancy_export_plugin!(FileServerPlugin::new);
}
