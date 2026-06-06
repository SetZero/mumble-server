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
use std::time::Duration;

use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

use crate::auth::verify_handshake_jwt;
use crate::doc::{DocKey, DocRoom, Frame, Origin};
use crate::state::AppState;

/// Lifetime handle returned by [`serve`].
#[derive(Debug)]
pub struct ServerHandle {
    addr: SocketAddr,
    task: JoinHandle<()>,
    autosave: JoinHandle<()>,
}

impl ServerHandle {
    /// Local socket address the WS server is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }
    /// Abort the WS server task and wait for it to fully terminate so
    /// the bound `TcpListener` is dropped before we return.  Without the
    /// `await`, a fast disable->enable cycle could call `on_load` (which
    /// re-binds the same port) before the aborted task released the
    /// socket, producing an `EADDRINUSE` error.  Active connections are
    /// dropped.
    pub async fn shutdown(self) {
        self.autosave.abort();
        self.task.abort();
        // The join resolves with `Err(Cancelled)` once the task's future
        // (and thus the listener) has been dropped; that is exactly the
        // signal we want, so the error is intentionally ignored.
        let _ = self.task.await;
        let _ = self.autosave.await;
    }
}

/// Spawn the WS server on the configured bind address.
pub async fn serve(state: AppState) -> std::io::Result<ServerHandle> {
    let listener = TcpListener::bind(state.cfg().bind).await?;
    let addr = listener.local_addr()?;
    let router = Router::new()
        .route("/ws/{server_id}/{slug}", get(handle_upgrade))
        .with_state(state.clone());

    let task = tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, router).await {
            tracing::error!(?err, "live-doc ws server stopped");
        }
    });
    let autosave = tokio::spawn(autosave_loop(state));
    Ok(ServerHandle {
        addr,
        task,
        autosave,
    })
}

/// Periodically flush every room that has changed since its last save,
/// so document content survives a crash / file-server outage and a
/// rejoining client always reloads the latest state.
async fn autosave_loop(state: AppState) {
    let interval = Duration::from_secs(state.cfg().snapshot_idle_secs.max(1));
    loop {
        tokio::time::sleep(interval).await;
        state.persist_dirty_rooms().await;
    }
}

#[derive(Debug, Deserialize)]
struct HandshakeQuery {
    token: String,
}

async fn handle_upgrade(
    Path((server_id, slug)): Path<(u32, String)>,
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
    if claims.server_id != server_id || claims.doc_slug != slug {
        tracing::debug!("ws handshake rejected: token doesn't match path");
        return StatusCode::FORBIDDEN.into_response();
    }

    let key = DocKey { server_id, slug };
    let session = claims.session_id;

    // Ensure the room (hydrates owner / shared-with from the file-server)
    // before the access check so membership can be evaluated.
    let room = state.ensure_room(key.clone()).await;
    if !state.session_can_connect(server_id, session, &key).await {
        tracing::debug!(
            session,
            slug = %key.slug,
            "ws handshake rejected: session is not owner or share recipient"
        );
        return StatusCode::FORBIDDEN.into_response();
    }

    ws.on_upgrade(move |socket| run_session(state, key, session, room, socket))
}

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

async fn run_session(
    state: AppState,
    key: DocKey,
    session: u32,
    room: Arc<DocRoom>,
    socket: WebSocket,
) {
    let connection_id = NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
    state.register_session(&key, session).await;

    let (mut sender, receiver) = socket.split();

    // Personal (non-broadcast) frames destined only for this client -
    // notably the sync-step-2 reply carrying the full document state in
    // response to the client's initial sync-step-1.  Without this the
    // reconnecting client would never receive the stored content and the
    // doc would appear empty after a page reload or panel re-open.
    let (personal_tx, personal_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Push the initial sync-step-1 so the client knows our state vector.
    let initial = room.initial_sync_frame().await;
    if sender
        .send(WsMessage::Binary(initial.into()))
        .await
        .is_err()
    {
        state.unregister_session(&key, session).await;
        return;
    }

    // Shared map of Yjs clientID -> highest seen clock, written by the
    // recv loop and read after both loops complete to broadcast removal.
    let seen_awareness: Arc<Mutex<HashMap<u64, u32>>> = Arc::new(Mutex::new(HashMap::new()));

    let send = run_send_loop(
        sender,
        personal_rx,
        room.subscribe(),
        connection_id,
        room.clone(),
    );
    let recv = run_recv_loop(RecvLoop {
        receiver,
        room: room.clone(),
        seen_awareness: seen_awareness.clone(),
        personal_tx,
        connection_id,
        max_update: state.cfg().max_update_bytes,
    });

    tokio::select! {
        _ = send => {}
        _ = recv => {}
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

/// Relay loop: forwards per-client sync replies and broadcast frames to
/// this socket.  Personal replies are prioritised so a freshly-connected
/// client receives the full document state before incremental updates.
async fn run_send_loop(
    mut sender: SplitSink<WebSocket, WsMessage>,
    mut personal_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    mut bcast: broadcast::Receiver<Frame>,
    connection_id: u64,
    room: Arc<DocRoom>,
) {
    loop {
        tokio::select! {
            biased;
            personal = personal_rx.recv() => {
                match personal {
                    Some(bytes) => {
                        if sender
                            .send(WsMessage::Binary(bytes.into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    // recv loop ended and dropped its sender; the session
                    // is closing, so stop relaying.
                    None => break,
                }
            }
            frame = bcast.recv() => {
                match frame {
                    Ok(Frame { bytes, origin }) => {
                        if matches!(origin, Origin::Client(id) if id == connection_id) {
                            continue;
                        }
                        if sender
                            .send(WsMessage::Binary(bytes.to_vec().into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    // This subscriber fell behind the broadcast buffer and
                    // missed updates.  Silently continuing would leave it
                    // permanently desynced, so instead push a fresh
                    // sync-step-1: the client replies and the room sends it
                    // the full catch-up state, re-converging it.  This keeps
                    // many-editor sessions correct under load.
                    Err(RecvError::Lagged(skipped)) => {
                        tracing::debug!(connection_id, skipped, "live-doc subscriber lagged; re-syncing");
                        let resync = room.initial_sync_frame().await;
                        if sender
                            .send(WsMessage::Binary(resync.into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        }
    }
    let _ = sender.close().await;
}

/// Inputs for [`run_recv_loop`], grouped to keep the signature small.
struct RecvLoop {
    receiver: SplitStream<WebSocket>,
    room: Arc<DocRoom>,
    seen_awareness: Arc<Mutex<HashMap<u64, u32>>>,
    personal_tx: mpsc::UnboundedSender<Vec<u8>>,
    connection_id: u64,
    max_update: usize,
}

/// Inbound loop: applies client messages to the room and routes any
/// per-client sync reply back through the send loop's personal channel.
async fn run_recv_loop(mut ctx: RecvLoop) {
    while let Some(Ok(msg)) = ctx.receiver.next().await {
        match msg {
            WsMessage::Binary(bytes) => {
                if bytes.len() > ctx.max_update {
                    tracing::warn!(
                        size = bytes.len(),
                        "live-doc dropping oversized client update"
                    );
                    continue;
                }
                match ctx
                    .room
                    .apply_client_message(ctx.connection_id, &bytes)
                    .await
                {
                    Ok((reply, awareness)) => {
                        // Forward the per-client sync reply (e.g. the
                        // sync-step-2 carrying the full document state) back
                        // to this socket.  If the send loop is gone the
                        // session is closing.
                        if let Some(reply_bytes) = reply {
                            if ctx.personal_tx.send(reply_bytes).is_err() {
                                break;
                            }
                        }
                        let mut map = match ctx.seen_awareness.lock() {
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test assertions")]
    use super::*;
    use crate::auth::issue_handshake_jwt;
    use crate::config::LiveDocConfig;
    use crate::host_facade::{FacadeResult, HostFacade, PluginMessageArgs};
    use mumble_plugin_api::Permissions;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::Message as TMessage;
    use yrs::sync::{Message, MessageReader, SyncMessage};
    use yrs::updates::decoder::{Decode, DecoderV1};
    use yrs::updates::encoder::{Encode, Encoder, EncoderV1};
    use yrs::{Doc, GetString, ReadTxn, StateVector, Text, Transact};

    /// Host stub that authorises every request - the access control is
    /// covered elsewhere; here we only care about the sync wiring.
    #[derive(Debug)]
    struct AllowCtx;

    impl HostFacade for AllowCtx {
        fn send_plugin_data(&self, _: u32, _: u32, _: &str, _: &[u8]) -> FacadeResult<()> {
            Ok(())
        }
        fn is_session_active(&self, _: u32, _: u32) -> bool {
            true
        }
        fn user_has_channel_access(&self, _: u32, _: u32, _: u32) -> bool {
            true
        }
        fn has_permission(&self, _: u32, _: u32, _: u32, perm: Permissions) -> bool {
            // Grant ordinary channel permissions, but not admin (root Write),
            // so the ACL under test isn't masked by the admin-override path.
            !perm.intersects(Permissions::WRITE)
        }
        fn get_config(&self, _: &str) -> Option<String> {
            None
        }
        fn send_plugin_message(&self, _: PluginMessageArgs<'_>) -> FacadeResult<()> {
            Ok(())
        }
    }

    fn test_state() -> AppState {
        let cfg = LiveDocConfig {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            public_url: None,
            jwt_secret: Some("test-secret-0123456789abcdef0123456789".to_owned()),
            state_path: std::env::temp_dir(),
            max_update_bytes: 4 * 1024 * 1024,
            snapshot_idle_secs: 60,
            teardown_grace_secs: 30,
            file_server_url: None,
            file_server_admin_token: None,
            port: 0,
        };
        AppState::new(Arc::new(cfg), Arc::new(AllowCtx))
    }

    fn encode_message(msg: &Message) -> Vec<u8> {
        let mut enc = EncoderV1::new();
        msg.encode(&mut enc);
        enc.to_vec()
    }

    fn apply_sync_frames(doc: &Doc, bytes: &[u8]) {
        let mut decoder = DecoderV1::from(bytes);
        let reader = MessageReader::new(&mut decoder);
        for msg in reader.flatten() {
            if let Message::Sync(SyncMessage::SyncStep2(u) | SyncMessage::Update(u)) = msg {
                if let Ok(update) = yrs::Update::decode_v1(&u) {
                    let mut txn = doc.transact_mut();
                    let _ = txn.apply_update(update);
                }
            }
        }
    }

    /// A client that connects after a page reload (fresh empty Y.Doc) must
    /// receive the stored document content from the server via the
    /// sync-step-2 reply.  Before the personal-channel fix the server
    /// computed but discarded that reply, leaving the reconnecting client
    /// with an empty document.
    #[tokio::test]
    async fn reconnecting_client_receives_stored_content() {
        use crate::doc::{DocKey, DocMeta};
        use crate::state::Identity;

        let state = test_state();
        let secret = state.jwt_secret().to_vec();

        let server_id = 1u32;
        let slug = "notes";

        // Establish ownership + share so the connect-time membership check
        // passes (in production this is set up by the OpenRequest flow).
        let ident = |cert: &str, session: u32| Identity {
            cert_hash: cert.to_owned(),
            user_id: session as i64,
            name: format!("user-{session}"),
        };
        state.set_identity(server_id, 10, ident("owner-cert", 10)).await;
        state.set_identity(server_id, 11, ident("member-cert", 11)).await;
        let key = DocKey {
            server_id,
            slug: slug.to_owned(),
        };
        let room = state.ensure_room(key.clone()).await;
        room.set_meta(DocMeta {
            owner_cert_hash: "owner-cert".into(),
            owner_user_id: None,
            title: "Notes".into(),
            bound_channel: None,
            visibility: crate::doc::Visibility::Private,
        })
        .await;
        room.add_member("member-cert".into()).await;
        drop(room);

        let handle = serve(state).await.unwrap();
        let addr = handle.local_addr();

        let mint =
            |session: u32| issue_handshake_jwt(&secret, server_id, session, slug, 300).unwrap();

        let url1 = format!("ws://{addr}/ws/{server_id}/{slug}?token={}", mint(10));
        let (mut ws1, _) = connect_async(url1.as_str()).await.unwrap();

        let writer = Doc::new();
        {
            let text = writer.get_or_insert_text("content");
            let mut txn = writer.transact_mut();
            text.push(&mut txn, "hello world");
        }
        let update = writer
            .transact()
            .encode_state_as_update_v1(&StateVector::default());
        let payload = encode_message(&Message::Sync(SyncMessage::Update(update)));
        ws1.send(TMessage::Binary(payload.into())).await.unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = ws1.close(None).await;
        drop(ws1);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let url2 = format!("ws://{addr}/ws/{server_id}/{slug}?token={}", mint(11));
        let (mut ws2, _) = connect_async(url2.as_str()).await.unwrap();

        let reader_doc = Doc::new();
        let reader_text = reader_doc.get_or_insert_text("content");
        let sv = reader_doc.transact().state_vector();
        let step1 = encode_message(&Message::Sync(SyncMessage::SyncStep1(sv)));
        ws2.send(TMessage::Binary(step1.into())).await.unwrap();

        let got_content = tokio::time::timeout(Duration::from_secs(2), async {
            while let Some(Ok(msg)) = ws2.next().await {
                if let TMessage::Binary(bytes) = msg {
                    apply_sync_frames(&reader_doc, &bytes);
                    if reader_text.get_string(&reader_doc.transact()) == "hello world" {
                        return true;
                    }
                }
            }
            false
        })
        .await
        .unwrap_or(false);

        assert!(
            got_content,
            "reconnecting client must receive stored document content"
        );

        handle.shutdown().await;
    }

    /// The connect-time membership check must admit the owner and recorded
    /// share recipients, and reject everyone else (including sessions with
    /// no captured identity).
    #[tokio::test]
    async fn connect_requires_owner_or_member() {
        use crate::doc::{DocKey, DocMeta, Visibility};
        use crate::state::Identity;

        let state = test_state();
        let server_id = 1u32;
        let ident = |cert: &str| Identity {
            cert_hash: cert.to_owned(),
            user_id: 1,
            name: "u".into(),
        };
        state.set_identity(server_id, 1, ident("owner-cert")).await;
        state.set_identity(server_id, 2, ident("member-cert")).await;
        state.set_identity(server_id, 3, ident("stranger-cert")).await;

        let key = DocKey {
            server_id,
            slug: "doc".into(),
        };
        let room = state.ensure_room(key.clone()).await;
        room.set_meta(DocMeta {
            owner_cert_hash: "owner-cert".into(),
            owner_user_id: None,
            title: "Doc".into(),
            bound_channel: None,
            visibility: Visibility::Private,
        })
        .await;
        room.add_member("member-cert".into()).await;

        assert!(state.session_can_connect(server_id, 1, &key).await, "owner");
        assert!(state.session_can_connect(server_id, 2, &key).await, "member");
        assert!(
            !state.session_can_connect(server_id, 3, &key).await,
            "stranger rejected"
        );
        assert!(
            !state.session_can_connect(server_id, 9, &key).await,
            "unknown session rejected"
        );
    }
}
