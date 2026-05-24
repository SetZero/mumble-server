//! `DocRoom` - per-document coordination actor.
//!
//! Each room owns a [`yrs::Doc`] and a broadcast channel of binary
//! Yjs sync messages.  Subscribers (WS connections) pull from the
//! broadcast and forward to their socket.  Inbound messages flow
//! back into the room via [`DocRoom::apply_client_message`].
//!
//! The wire format inside the broadcast is the standard Yjs sync /
//! awareness protocol framing - see <https://docs.yjs.dev/api/y.doc>.
//!
//! Note: `yrs::Awareness` is intentionally NOT stored here because its
//! observer callbacks (`Box<dyn Fn(...)>`) make it `!Send + !Sync`,
//! which would break axum's multi-threaded runtime.  Awareness updates
//! are stateless from the room's perspective: we relay the raw bytes
//! to all other subscribers and let each client maintain its own view.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, RwLock};
use yrs::sync::awareness::AwarenessUpdateEntry;
use yrs::sync::{AwarenessUpdate, Message, MessageReader, SyncMessage};
use yrs::updates::decoder::{Decode, DecoderV1};
use yrs::updates::encoder::{Encode, Encoder, EncoderV1};
use yrs::{Doc, ReadTxn, StateVector, Transact};

/// Identifier for a document, scoped to a Mumble virtual server.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct DocKey {
    /// Mumble virtual server id.
    pub server_id: u32,
    /// Channel id the document belongs to.
    pub channel_id: u32,
    /// Slug within the channel (URL-safe, max 64 chars).
    pub slug: String,
}

impl DocKey {
    /// File-server-friendly stable filename for this doc.
    pub fn as_filename(&self) -> String {
        format!(
            "live-doc-{}-{}-{}.md",
            self.server_id, self.channel_id, self.slug
        )
    }
}

/// Why a broadcast message is being sent (used by subscribers to
/// filter out their own echoes if needed).
#[derive(Debug, Clone, Copy)]
pub enum Origin {
    /// Server-side seed (initial state, persistence reload).
    Server,
    /// Inbound message from a specific subscriber id - that subscriber
    /// should not be sent its own update back.
    Client(u64),
}

/// Broadcast frame carried over the per-room channel.
#[derive(Debug, Clone)]
pub struct Frame {
    /// Raw Yjs-protocol bytes ready to forward over the WebSocket.
    pub bytes: Arc<[u8]>,
    /// Where the frame came from.
    pub origin: Origin,
}

/// Per-document state owned by the WS server.
#[derive(Debug)]
pub struct DocRoom {
    key: DocKey,
    doc: Arc<Doc>,
    tx: broadcast::Sender<Frame>,
    last_activity: RwLock<Instant>,
}

impl DocRoom {
    /// Construct a new empty room.  Apply persisted state by calling
    /// [`DocRoom::seed_from_snapshot`] before exposing the room.
    pub fn new(key: DocKey) -> Self {
        let doc = Arc::new(Doc::new());
        let (tx, _) = broadcast::channel(256);
        Self {
            key,
            doc,
            tx,
            last_activity: RwLock::new(Instant::now()),
        }
    }

    /// Document key.
    pub fn key(&self) -> &DocKey {
        &self.key
    }

    /// Subscriber count (active WebSocket connections).
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }

    /// Subscribe to the broadcast channel.  The returned receiver
    /// yields Yjs protocol frames as they arrive from peers and
    /// from the server itself.
    pub fn subscribe(&self) -> broadcast::Receiver<Frame> {
        self.tx.subscribe()
    }

    /// Apply a binary y-protocol message from a specific client
    /// connection.  Returns an optional reply frame the caller must
    /// send back to that same client (e.g. the matching sync-step-2
    /// response to a sync-step-1 query), plus a map of every Yjs
    /// clientID -> highest clock seen in awareness updates (used by
    /// the caller to broadcast a removal on disconnect).
    pub async fn apply_client_message(
        &self,
        connection_id: u64,
        bytes: &[u8],
    ) -> Result<(Option<Vec<u8>>, HashMap<u64, u32>), DocError> {
        *self.last_activity.write().await = Instant::now();

        let mut decoder = DecoderV1::from(bytes);
        let reader = MessageReader::new(&mut decoder);
        let mut reply: Option<Vec<u8>> = None;
        let mut awareness_seen: HashMap<u64, u32> = HashMap::new();

        for msg in reader {
            let msg = msg.map_err(|e| DocError::Decode(e.to_string()))?;
            match msg {
                Message::Sync(sync) => {
                    let response = self.handle_sync(sync).await?;
                    if let Some(resp) = response {
                        match &mut reply {
                            Some(buf) => buf.extend_from_slice(&resp),
                            None => reply = Some(resp),
                        }
                    }
                }
                Message::Awareness(update) => {
                    for (&cid, entry) in &update.clients {
                        let slot = awareness_seen.entry(cid).or_insert(0);
                        *slot = (*slot).max(entry.clock);
                    }
                    self.apply_awareness(update, connection_id).await?;
                }
                Message::AwarenessQuery => {
                    // No shared Awareness state is maintained (yrs::Awareness is
                    // !Send+!Sync).  Existing clients re-broadcast their awareness
                    // when they detect a new subscriber, so no explicit snapshot
                    // is needed here.
                }
                Message::Auth(_) | Message::Custom(_, _) => {
                    // No auth challenge or custom protocol - ignored.
                }
            }
        }
        Ok((reply, awareness_seen))
    }

    /// Broadcast an awareness removal for the given set of Yjs clients.
    /// Each entry maps a Yjs clientID to the last clock seen for that
    /// client; the removal uses `clock + 1` so peers accept it.
    pub async fn broadcast_awareness_removal(&self, removals: &HashMap<u64, u32>) {
        if removals.is_empty() {
            return;
        }
        let update = AwarenessUpdate {
            clients: removals
                .iter()
                .map(|(&cid, &clock)| {
                    (
                        cid,
                        AwarenessUpdateEntry {
                            clock: clock.saturating_add(1),
                            json: "null".to_string().into(),
                        },
                    )
                })
                .collect(),
        };
        let mut enc = EncoderV1::new();
        Message::Awareness(update).encode(&mut enc);
        let _ = self.tx.send(Frame {
            bytes: Arc::<[u8]>::from(enc.to_vec()),
            origin: Origin::Server,
        });
    }

    async fn handle_sync(&self, msg: SyncMessage) -> Result<Option<Vec<u8>>, DocError> {
        match msg {
            SyncMessage::SyncStep1(remote_sv) => {
                let txn = self.doc.transact();
                let update = txn.encode_state_as_update_v1(&remote_sv);
                let server_sv = txn.state_vector();
                drop(txn);

                let mut enc = EncoderV1::new();
                Message::Sync(SyncMessage::SyncStep2(update)).encode(&mut enc);
                Message::Sync(SyncMessage::SyncStep1(server_sv)).encode(&mut enc);
                Ok(Some(enc.to_vec()))
            }
            SyncMessage::SyncStep2(update_bytes) | SyncMessage::Update(update_bytes) => {
                self.apply_update(&update_bytes).await?;
                Ok(None)
            }
        }
    }

    async fn apply_update(&self, update_bytes: &[u8]) -> Result<(), DocError> {
        // Decode and apply the update synchronously in an inner block so that
        // `yrs::Update` (which is `!Send`) is dropped before the first `.await`.
        {
            let update = yrs::Update::decode_v1(update_bytes)
                .map_err(|e| DocError::Decode(e.to_string()))?;
            let mut txn = self.doc.transact_mut();
            txn.apply_update(update)
                .map_err(|e| DocError::Apply(e.to_string()))?;
        }

        *self.last_activity.write().await = Instant::now();

        let mut enc = EncoderV1::new();
        Message::Sync(SyncMessage::Update(update_bytes.to_vec())).encode(&mut enc);
        let _ = self.tx.send(Frame {
            bytes: Arc::<[u8]>::from(enc.to_vec()),
            origin: Origin::Server,
        });
        Ok(())
    }

    async fn apply_awareness(
        &self,
        update: AwarenessUpdate,
        from_connection: u64,
    ) -> Result<(), DocError> {
        *self.last_activity.write().await = Instant::now();

        let mut enc = EncoderV1::new();
        Message::Awareness(update).encode(&mut enc);
        let _ = self.tx.send(Frame {
            bytes: Arc::<[u8]>::from(enc.to_vec()),
            origin: Origin::Client(from_connection),
        });
        Ok(())
    }

    /// Build the initial sync-step-1 frame the server pushes to a
    /// newly connected client.  Together with the client's reply
    /// this brings the client to a state-vector match.
    pub async fn initial_sync_frame(&self) -> Vec<u8> {
        let sv = self.doc.transact().state_vector();
        let mut enc = EncoderV1::new();
        Message::Sync(SyncMessage::SyncStep1(sv)).encode(&mut enc);
        enc.to_vec()
    }

    /// Hydrate the room from a previously-persisted Yjs update blob.
    pub async fn seed_from_snapshot(&self, update_bytes: &[u8]) -> Result<(), DocError> {
        self.apply_update(update_bytes).await
    }

    /// Encode the current doc state as a Yjs v1 update suitable for
    /// persisting and re-seeding.
    pub async fn encode_snapshot(&self) -> Vec<u8> {
        self.doc
            .transact()
            .encode_state_as_update_v1(&StateVector::default())
    }

    /// True when the last broadcast activity was more than `idle`
    /// ago.  Used by the persistence loop to decide whether to flush.
    pub async fn is_idle_for(&self, idle: Duration) -> bool {
        self.last_activity.read().await.elapsed() >= idle
    }
}

/// Errors raised by document operations.
#[derive(Debug, thiserror::Error)]
pub enum DocError {
    /// Yjs decoding error.
    #[error("yjs decode: {0}")]
    Decode(String),
    /// Yjs apply error.
    #[error("yjs apply: {0}")]
    Apply(String),
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test assertions")]
    use super::*;
    use yrs::{GetString, Text};

    #[tokio::test]
    async fn snapshot_round_trip() {
        let key = DocKey {
            server_id: 1,
            channel_id: 2,
            slug: "notes".into(),
        };
        let room = DocRoom::new(key.clone());

        // Mutate the doc directly to produce an update.
        {
            let doc = &room.doc;
            let txt = doc.get_or_insert_text("body");
            let mut txn = doc.transact_mut();
            txt.push(&mut txn, "Hello, Mumble!");
        }

        let snapshot = room.encode_snapshot().await;
        assert!(!snapshot.is_empty(), "snapshot must contain bytes");

        // New room hydrated from snapshot must observe the same text.
        let restored = DocRoom::new(key);
        restored.seed_from_snapshot(&snapshot).await.unwrap();
        let body = restored.doc.get_or_insert_text("body");
        let txn = restored.doc.transact();
        assert_eq!(body.get_string(&txn), "Hello, Mumble!");
    }
}
