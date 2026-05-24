//! axum WebSocket endpoint for live-doc clients.
//!
//! Route layout:
//!
//! * `GET /ws/{server_id}/{channel_id}/{slug}?token=...` - WS upgrade
//!   bound to a single document.  The token is a JWT minted via
//!   [`crate::auth::issue_handshake_jwt`] and delivered to the
//!   client over `PluginDataTransmission`.
//!
//! Each WS task forwards inbound binary frames to the room and
//! relays broadcast frames from the room back to the socket.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::broadcast::error::RecvError;
use tokio::task::JoinHandle;

use crate::auth::verify_handshake_jwt;
use crate::doc::{DocKey, Frame, Origin};
use crate::state::AppState;

/// Lifetime handle returned by [`serve`].
#[derive(Debug)]
pub struct ServerHandle {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl ServerHandle {
    /// Local socket address the WS server is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }
    /// Abort the WS server task.  Active connections are dropped.
    pub fn shutdown(self) {
        self.task.abort();
    }
}

/// Spawn the WS server on the configured bind address.
pub async fn serve(state: AppState) -> std::io::Result<ServerHandle> {
    let listener = TcpListener::bind(state.cfg().bind).await?;
    let addr = listener.local_addr()?;
    let router = Router::new()
        .route(
            "/ws/{server_id}/{channel_id}/{slug}",
            get(handle_upgrade),
        )
        .with_state(state);

    let task = tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, router).await {
            tracing::error!(?err, "live-doc ws server stopped");
        }
    });
    Ok(ServerHandle { addr, task })
}

#[derive(Debug, Deserialize)]
struct HandshakeQuery {
    token: String,
}

async fn handle_upgrade(
    Path((server_id, channel_id, slug)): Path<(u32, u32, String)>,
    Query(q): Query<HandshakeQuery>,
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
) -> Response {
    let claims = match verify_handshake_jwt(state.jwt_secret(), &q.token) {
        Ok(c) => c,
        Err(err) => {
            tracing::debug!(?err, "ws handshake rejected: invalid jwt");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };
    if claims.server_id != server_id || claims.channel_id != channel_id || claims.doc_slug != slug {
        tracing::debug!("ws handshake rejected: token doesn't match path");
        return StatusCode::FORBIDDEN.into_response();
    }
    if !state.session_can_access(server_id, claims.session_id, channel_id) {
        tracing::debug!(
            session = claims.session_id,
            channel_id,
            "ws handshake rejected: session no longer authorised"
        );
        return StatusCode::FORBIDDEN.into_response();
    }

    let key = DocKey {
        server_id,
        channel_id,
        slug,
    };
    let session = claims.session_id;
    ws.on_upgrade(move |socket| run_session(state, key, session, socket))
}

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

async fn run_session(state: AppState, key: DocKey, session: u32, socket: WebSocket) {
    let connection_id = NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
    let room = state.ensure_room(key.clone()).await;
    state.register_session(&key, session).await;

    let (mut sender, mut receiver) = socket.split();

    // Push the initial sync-step-1 so the client knows our state vector.
    let initial = room.initial_sync_frame().await;
    if sender.send(WsMessage::Binary(initial.into())).await.is_err() {
        state.unregister_session(&key, session).await;
        return;
    }

    let mut bcast = room.subscribe();
    let max_update = state.cfg().max_update_bytes;
    let send_loop = {
        async move {
            loop {
                match bcast.recv().await {
                    Ok(Frame { bytes, origin }) => {
                        if matches!(origin, Origin::Client(id) if id == connection_id) {
                            continue;
                        }
                        if sender.send(WsMessage::Binary(bytes.to_vec().into())).await.is_err() {
                            break;
                        }
                    }
                    Err(RecvError::Lagged(_)) => continue,
                    Err(RecvError::Closed) => break,
                }
            }
            let _ = sender.close().await;
        }
    };

    // Shared map of Yjs clientID -> highest seen clock, written by
    // recv_loop and read after both loops complete to broadcast removal.
    let seen_awareness: Arc<Mutex<HashMap<u64, u32>>> = Arc::new(Mutex::new(HashMap::new()));

    let recv_loop = {
        let room = room.clone();
        let seen_awareness = seen_awareness.clone();
        async move {
            while let Some(Ok(msg)) = receiver.next().await {
                match msg {
                    WsMessage::Binary(bytes) => {
                        if bytes.len() > max_update {
                            tracing::warn!(
                                size = bytes.len(),
                                "live-doc dropping oversized client update"
                            );
                            continue;
                        }
                        match room.apply_client_message(connection_id, &bytes).await {
                            Ok((_, awareness)) => {
                                    let mut map = match seen_awareness.lock() {
                                        Ok(g) => g,
                                        Err(p) => p.into_inner(),
                                    };
                                    for (cid, clock) in awareness {
                                        let slot = map.entry(cid).or_insert(0);
                                        *slot = (*slot).max(clock);
                                    }
                                }
                            Err(err) => {
                                tracing::warn!(?err, "live-doc invalid client message");
                            }
                        }
                    }
                    WsMessage::Ping(_) | WsMessage::Pong(_) | WsMessage::Text(_) => {}
                    WsMessage::Close(_) => break,
                }
            }
        }
    };

    tokio::select! {
        _ = send_loop => {}
        _ = recv_loop => {}
    }

    // Broadcast awareness removal for all Yjs clients this connection
    // had registered, so peers immediately see them as gone rather than
    // waiting for the ~30 s Yjs awareness timeout to fire.
    let removals = match seen_awareness.lock() {
        Ok(m) => m.clone(),
        Err(p) => p.into_inner().clone(),
    };
    room.broadcast_awareness_removal(&removals).await;

    state.unregister_session(&key, session).await;
    let _ = room;
}

