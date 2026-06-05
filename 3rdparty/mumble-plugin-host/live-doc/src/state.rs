//! Process-global state shared by the WS server and the plugin
//! lifecycle hooks.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use mumble_plugin_api::{ChannelId, ServerId, SessionId};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::config::LiveDocConfig;
use crate::doc::{DocKey, DocRoom};
use crate::host_facade::HostFacade;
use crate::persistence::{persist_room, try_seed_room};

/// Wallclock state shared across the plugin.
#[derive(Debug, Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

/// Stable identity of a connected client, cached from the Mumble
/// `on_client_connected` hook so the plugin can attribute a document to
/// its creator without a host round-trip.
#[derive(Debug, Clone)]
pub struct ClientIdentity {
    /// Display name at connect time.
    pub username: String,
    /// Hex-encoded certificate hash (stable per user), or empty.
    pub cert_hash: String,
}

#[derive(Debug)]
struct AppStateInner {
    cfg: Arc<LiveDocConfig>,
    ctx: Arc<dyn HostFacade>,
    jwt_secret: Vec<u8>,
    /// Shared HTTP client used for all file-server I/O.  Configured
    /// with a tight per-request timeout so a slow / unreachable
    /// file-server can't wedge the live-doc state machine.
    http_client: reqwest::Client,
    rooms: Mutex<HashMap<DocKey, RoomEntry>>,
    /// Connected clients by `(server, session)`, used to attribute a new
    /// document to the session that first opened it.
    clients: std::sync::Mutex<HashMap<(ServerId, SessionId), ClientIdentity>>,
}

#[derive(Debug)]
struct RoomEntry {
    room: Arc<DocRoom>,
    /// Sessions currently editing this doc.  Cleared when the WS
    /// drops or the client disconnects from Mumble.
    sessions: Vec<SessionId>,
    /// Identity of the first session to open the room - persisted as the
    /// document owner on its first revision.
    creator: Option<ClientIdentity>,
    /// Background teardown task scheduled when the last subscriber
    /// left.  Reset to `None` if someone re-joins inside the grace
    /// window.
    teardown_task: Option<JoinHandle<()>>,
}

/// Maximum time a single file-server request is allowed to take
/// before reqwest aborts it.  Tight on purpose so a stuck file-server
/// can't stall the whole plugin.
const FILE_SERVER_TIMEOUT_SECS: u64 = 5;
/// Maximum time we allow for the initial TCP connect to the
/// file-server.  Separate from the overall request timeout so that
/// "host unreachable" fails fast instead of eating the full budget.
const FILE_SERVER_CONNECT_TIMEOUT_SECS: u64 = 2;

impl AppState {
    /// Construct fresh state and load (or generate) the JWT secret.
    pub fn new(cfg: Arc<LiveDocConfig>, ctx: Arc<dyn HostFacade>) -> Self {
        let jwt_secret = cfg
            .jwt_secret
            .as_ref()
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_else(generate_secret);
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(FILE_SERVER_TIMEOUT_SECS))
            .connect_timeout(Duration::from_secs(FILE_SERVER_CONNECT_TIMEOUT_SECS))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            inner: Arc::new(AppStateInner {
                cfg,
                ctx,
                jwt_secret,
                http_client,
                rooms: Mutex::new(HashMap::new()),
                clients: std::sync::Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Cache a connected client's identity (from `on_client_connected`).
    pub fn record_client(
        &self,
        server_id: ServerId,
        session: SessionId,
        username: String,
        cert_hash: String,
    ) {
        if let Ok(mut clients) = self.inner.clients.lock() {
            let _ = clients.insert(
                (server_id, session),
                ClientIdentity {
                    username,
                    cert_hash,
                },
            );
        }
    }

    /// Forget a disconnected client's identity (from `on_client_disconnected`).
    pub fn forget_client(&self, server_id: ServerId, session: SessionId) {
        if let Ok(mut clients) = self.inner.clients.lock() {
            let _ = clients.remove(&(server_id, session));
        }
    }

    fn lookup_client(&self, server_id: ServerId, session: SessionId) -> Option<ClientIdentity> {
        self.inner
            .clients
            .lock()
            .ok()?
            .get(&(server_id, session))
            .cloned()
    }

    /// Configuration handle.
    pub fn cfg(&self) -> &LiveDocConfig {
        &self.inner.cfg
    }

    /// JWT signing secret bytes.
    pub fn jwt_secret(&self) -> &[u8] {
        &self.inner.jwt_secret
    }

    /// Plugin context handle.
    pub fn ctx(&self) -> &Arc<dyn HostFacade> {
        &self.inner.ctx
    }

    /// Get-or-create a room for the given key.
    ///
    /// On creation, the room is inserted into the registry *before*
    /// seeding so the registry mutex isn't held across the
    /// file-server HTTP call.  Concurrent callers all observe the
    /// same Arc<DocRoom>; the seed and any client edits are
    /// applied to the shared doc and commute via Yjs CRDT semantics,
    /// so it does not matter which happens first.
    pub async fn ensure_room(&self, key: DocKey) -> Arc<DocRoom> {
        let (room, needs_seed) = {
            let mut rooms = self.inner.rooms.lock().await;
            if let Some(existing) = rooms.get_mut(&key) {
                if let Some(t) = existing.teardown_task.take() {
                    t.abort();
                }
                (existing.room.clone(), false)
            } else {
                let room = Arc::new(DocRoom::new(key.clone()));
                let _ = rooms.insert(
                    key,
                    RoomEntry {
                        room: room.clone(),
                        sessions: Vec::new(),
                        creator: None,
                        teardown_task: None,
                    },
                );
                (room, true)
            }
        };
        if needs_seed {
            try_seed_room(&self.inner.cfg, &self.inner.http_client, &room).await;
        }
        room
    }

    /// Mark a session as actively subscribed to a room.  Idempotent.
    pub async fn register_session(&self, key: &DocKey, session: SessionId) {
        // Resolve identity before taking the rooms lock so we never hold the
        // clients and rooms locks at the same time.
        let identity = self.lookup_client(key.server_id, session);
        let mut rooms = self.inner.rooms.lock().await;
        let Some(entry) = rooms.get_mut(key) else {
            return;
        };
        if !entry.sessions.contains(&session) {
            entry.sessions.push(session);
        }
        // The first session to open the room is recorded as its creator.
        if entry.creator.is_none() {
            entry.creator = identity;
        }
        if let Some(t) = entry.teardown_task.take() {
            t.abort();
        }
    }

    /// Unregister a session.  If the room becomes empty, schedules a
    /// teardown after [`LiveDocConfig::teardown_grace_secs`] which
    /// persists the final snapshot and evicts the room.
    pub async fn unregister_session(&self, key: &DocKey, session: SessionId) {
        let mut rooms = self.inner.rooms.lock().await;
        let Some(entry) = rooms.get_mut(key) else {
            return;
        };
        entry.sessions.retain(|s| *s != session);
        if entry.sessions.is_empty() && entry.teardown_task.is_none() {
            entry.teardown_task = Some(self.spawn_teardown(key.clone()));
        }
    }

    /// Drop sessions belonging to a disconnected client across every
    /// room.  Called from the Mumble `on_client_disconnected` hook.
    pub async fn handle_client_gone(&self, server_id: ServerId, session: SessionId) {
        let mut to_teardown: Vec<DocKey> = Vec::new();
        let mut rooms = self.inner.rooms.lock().await;
        for (key, entry) in rooms.iter_mut() {
            if key.server_id != server_id {
                continue;
            }
            entry.sessions.retain(|s| *s != session);
            if entry.sessions.is_empty() && entry.teardown_task.is_none() {
                to_teardown.push(key.clone());
            }
        }
        drop(rooms);
        for key in to_teardown {
            let mut rooms = self.inner.rooms.lock().await;
            if let Some(entry) = rooms.get_mut(&key) {
                entry.teardown_task = Some(self.spawn_teardown(key.clone()));
            }
        }
    }

    /// Returns `true` if the session is allowed to access the doc.
    pub fn session_can_access(
        &self,
        server_id: ServerId,
        session: SessionId,
        channel_id: ChannelId,
    ) -> bool {
        use mumble_plugin_api::Permissions;
        let ctx = &self.inner.ctx;
        ctx.is_session_active(server_id, session)
            && ctx.has_permission(
                server_id,
                session,
                channel_id,
                Permissions::ENTER | Permissions::TEXT_MESSAGE,
            )
    }

    /// Persist every active room and forget them.  Called on plugin
    /// unload.
    pub async fn shutdown(&self) {
        let mut rooms = self.inner.rooms.lock().await;
        let to_persist: Vec<(Arc<DocRoom>, Option<ClientIdentity>)> = rooms
            .values()
            .map(|e| (e.room.clone(), e.creator.clone()))
            .collect();
        rooms.clear();
        drop(rooms);
        for (room, creator) in to_persist {
            let owner = creator
                .as_ref()
                .map(|c| (c.username.as_str(), c.cert_hash.as_str()));
            persist_room(&self.inner.cfg, &self.inner.http_client, &room, owner).await;
        }
    }

    fn spawn_teardown(&self, key: DocKey) -> JoinHandle<()> {
        let state = self.clone();
        let grace = Duration::from_secs(state.inner.cfg.teardown_grace_secs);
        tokio::spawn(async move {
            tokio::time::sleep(grace).await;
            state.teardown_room(&key).await;
        })
    }

    async fn teardown_room(&self, key: &DocKey) {
        let captured = {
            let mut rooms = self.inner.rooms.lock().await;
            let Some(entry) = rooms.get(key) else {
                return;
            };
            if !entry.sessions.is_empty() {
                return;
            }
            rooms.remove(key).map(|e| (e.room, e.creator))
        };
        if let Some((room, creator)) = captured {
            let owner = creator
                .as_ref()
                .map(|c| (c.username.as_str(), c.cert_hash.as_str()));
            persist_room(&self.inner.cfg, &self.inner.http_client, &room, owner).await;
            tracing::info!(?key, "live-doc room torn down");
        }
    }
}

fn generate_secret() -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}
