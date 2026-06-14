//! `mumble-calendar` - calendar/scheduling relay plugin.
//!
//! Clients persist their own calendar in the file-server per-user private store
//! and exchange *shared* meeting data over the generic `PluginMessage` envelope
//! (wire ID 200). This plugin is a stateless-on-disk relay/sync hub:
//!
//! * `calendar.upsert`  - an organiser created/changed a meeting; routed to every
//!   participant's online sessions and remembered so late joiners get it.
//! * `calendar.delete`  - meeting removed; routed to participants.
//! * `calendar.publish` - on connect a client re-publishes the meetings it owns so
//!   the in-memory index survives a plugin restart.
//! * `calendar.availability` - a user's free/busy blocks; broadcast to everyone on
//!   the virtual server and remembered for connect-time catch-up.
//!
//! Personal fields (RSVP, show-as, reminder, colour overrides) never leave the
//! owning client; only the shared meeting body is relayed.
#![allow(
    unreachable_pub,
    reason = "internal cdylib: cross-module items use `pub` for ergonomics, not as a library API"
)]

use std::collections::HashMap;
use std::sync::Mutex;

use abi_stable::std_types::ROption::RNone;
use abi_stable::std_types::RResult::{RErr, ROk};
use abi_stable::std_types::{RArc, RStr, RString, RVec};
use mumble_plugin_api::{
    ClientInfo, MumblePlugin, PluginContext_TO, PluginInfo, PluginMessageIn, PluginMessageOut,
    PluginResult, ServerId, SessionId,
};

const PLUGIN_NAME: &str = "fancy-calendar";
const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

const MSG_UPSERT: &str = "calendar.upsert";
const MSG_DELETE: &str = "calendar.delete";
const MSG_PUBLISH: &str = "calendar.publish";
const MSG_AVAILABILITY: &str = "calendar.availability";

/// A meeting the relay knows about (enough to route + replay it).
struct StoredEvent {
    server_id: ServerId,
    organizer_uid: i64,
    participant_uids: Vec<i64>,
    /// Raw shared-event JSON, relayed verbatim.
    payload: Vec<u8>,
}

#[derive(Default)]
struct State {
    /// eventId -> stored meeting.
    events: HashMap<String, StoredEvent>,
    /// uid -> (server, raw `calendar.availability` payload) for connect catch-up.
    availability: HashMap<i64, (ServerId, Vec<u8>)>,
    /// (server, session) -> registered `user_id` (-1 for guests).
    sessions: HashMap<(ServerId, SessionId), i64>,
}

struct CalendarPlugin {
    state: Mutex<State>,
}

impl CalendarPlugin {
    fn new() -> Self {
        Self {
            state: Mutex::new(State::default()),
        }
    }
}

fn lock(m: &Mutex<State>) -> std::sync::MutexGuard<'_, State> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Send `payload` to an explicit set of sessions on `server_id`.
fn send_to(
    ctx: &PluginContext_TO<RArc<()>>,
    server_id: ServerId,
    sessions: Vec<SessionId>,
    payload_type: &str,
    payload: &[u8],
) {
    if sessions.is_empty() {
        return;
    }
    let out = PluginMessageOut {
        server_id,
        plugin_name: RString::from(PLUGIN_NAME),
        payload_type: RString::from(payload_type),
        payload: RVec::from(payload.to_vec()),
        target_sessions: RVec::from(sessions),
        channel_id: RNone,
    };
    if let RErr(e) = ctx.send_plugin_message(out) {
        tracing::warn!(error = %e, "calendar: send_plugin_message failed");
    }
}

/// Online sessions of any user in `uids` on `server_id`, excluding `except`.
fn sessions_for_uids(
    state: &State,
    server_id: ServerId,
    uids: &[i64],
    except: SessionId,
) -> Vec<SessionId> {
    state
        .sessions
        .iter()
        .filter(|((srv, sess), uid)| {
            *srv == server_id && *sess != except && **uid > 0 && uids.contains(uid)
        })
        .map(|((_, sess), _)| *sess)
        .collect()
}

/// All online sessions on `server_id` except `except`.
fn all_sessions(state: &State, server_id: ServerId, except: SessionId) -> Vec<SessionId> {
    state
        .sessions
        .iter()
        .filter(|((srv, sess), _)| *srv == server_id && *sess != except)
        .map(|((_, sess), _)| *sess)
        .collect()
}

/// Pull `id` / `organizerId` / `participants[].userId` out of an event JSON.
fn routing_of(v: &serde_json::Value) -> Option<(String, i64, Vec<i64>)> {
    let id = v.get("id")?.as_str()?.to_string();
    let organizer = v.get("organizerId").and_then(serde_json::Value::as_i64).unwrap_or(-1);
    let participants = v
        .get("participants")
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|p| p.get("userId").and_then(serde_json::Value::as_i64))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Some((id, organizer, participants))
}

impl MumblePlugin for CalendarPlugin {
    fn name(&self) -> RStr<'_> {
        RStr::from_str(PLUGIN_NAME)
    }

    fn version(&self) -> RStr<'_> {
        RStr::from_str(PLUGIN_VERSION)
    }

    fn info_json(&self) -> RString {
        PluginInfo {
            description: "Relays calendar meetings, invites and free/busy between \
                          participants; calendars are stored per-user in the file-server."
                .to_owned(),
            author: Some("Fancy Mumble Developers".to_owned()),
            homepage: None,
            tags: vec!["calendar".to_owned(), "scheduling".to_owned()],
            debug_rows: Vec::new(),
            client_manifest: None,
        }
        .to_rstring()
    }

    fn on_load(&self, _ctx: PluginContext_TO<RArc<()>>) -> PluginResult<()> {
        init_tracing();
        tracing::info!("calendar plugin loaded");
        ROk(())
    }

    fn on_unload(&self, _ctx: &PluginContext_TO<RArc<()>>) -> PluginResult<()> {
        *lock(&self.state) = State::default();
        ROk(())
    }

    fn on_client_connected(
        &self,
        ctx: &PluginContext_TO<RArc<()>>,
        info: ClientInfo,
    ) -> PluginResult<()> {
        let server_id = info.server_id;
        let session = info.session_id;
        let uid = info.user_id;
        let mut catch_up: Vec<Vec<u8>> = Vec::new();
        let mut availability: Vec<Vec<u8>> = Vec::new();
        {
            let mut st = lock(&self.state);
            let _ = st.sessions.insert((server_id, session), uid);
            if uid > 0 {
                for ev in st.events.values() {
                    if ev.server_id == server_id
                        && (ev.organizer_uid == uid || ev.participant_uids.contains(&uid))
                    {
                        catch_up.push(ev.payload.clone());
                    }
                }
            }
            for (srv, payload) in st.availability.values() {
                if *srv == server_id {
                    availability.push(payload.clone());
                }
            }
        }
        for payload in &catch_up {
            send_to(ctx, server_id, vec![session], MSG_UPSERT, payload);
        }
        for payload in &availability {
            send_to(ctx, server_id, vec![session], MSG_AVAILABILITY, payload);
        }
        ROk(())
    }

    fn on_client_disconnected(
        &self,
        _ctx: &PluginContext_TO<RArc<()>>,
        server_id: ServerId,
        session: SessionId,
    ) -> PluginResult<()> {
        let _ = lock(&self.state).sessions.remove(&(server_id, session));
        ROk(())
    }

    fn on_plugin_message(
        &self,
        ctx: &PluginContext_TO<RArc<()>>,
        msg: PluginMessageIn,
    ) -> PluginResult<()> {
        let server_id = msg.server_id;
        let sender = msg.sender_session;
        let bytes = msg.payload.as_slice();

        match msg.payload_type.as_str() {
            MSG_UPSERT => {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) {
                    if let Some((id, organizer, participants)) = routing_of(&v) {
                        let mut uids = participants.clone();
                        uids.push(organizer);
                        let targets = {
                            let mut st = lock(&self.state);
                            let _ = st.events.insert(
                                id,
                                StoredEvent {
                                    server_id,
                                    organizer_uid: organizer,
                                    participant_uids: participants,
                                    payload: bytes.to_vec(),
                                },
                            );
                            sessions_for_uids(&st, server_id, &uids, sender)
                        };
                        send_to(ctx, server_id, targets, MSG_UPSERT, bytes);
                    }
                }
            }
            MSG_DELETE => {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) {
                    if let Some(id) = v.get("id").and_then(serde_json::Value::as_str) {
                        let targets = {
                            let mut st = lock(&self.state);
                            match st.events.remove(id) {
                                Some(ev) => {
                                    let mut uids = ev.participant_uids;
                                    uids.push(ev.organizer_uid);
                                    sessions_for_uids(&st, server_id, &uids, sender)
                                }
                                None => Vec::new(),
                            }
                        };
                        send_to(ctx, server_id, targets, MSG_DELETE, bytes);
                    }
                }
            }
            MSG_PUBLISH => {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) {
                    if let Some(events) = v.get("events").and_then(serde_json::Value::as_array) {
                        for ev in events {
                            let Some((id, organizer, participants)) = routing_of(ev) else {
                                continue;
                            };
                            let payload = serde_json::to_vec(ev).unwrap_or_default();
                            let mut uids = participants.clone();
                            uids.push(organizer);
                            let targets = {
                                let mut st = lock(&self.state);
                                let _ = st.events.insert(
                                    id,
                                    StoredEvent {
                                        server_id,
                                        organizer_uid: organizer,
                                        participant_uids: participants,
                                        payload: payload.clone(),
                                    },
                                );
                                sessions_for_uids(&st, server_id, &uids, sender)
                            };
                            send_to(ctx, server_id, targets, MSG_UPSERT, &payload);
                        }
                    }
                }
            }
            MSG_AVAILABILITY => {
                let targets = {
                    let mut st = lock(&self.state);
                    let uid = st.sessions.get(&(server_id, sender)).copied().unwrap_or(-1);
                    if uid > 0 {
                        let _ = st.availability.insert(uid, (server_id, bytes.to_vec()));
                    }
                    all_sessions(&st, server_id, sender)
                };
                send_to(ctx, server_id, targets, MSG_AVAILABILITY, bytes);
            }
            _ => {}
        }
        ROk(())
    }
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
    use super::CalendarPlugin;
    mumble_plugin_api::fancy_export_plugin!(CalendarPlugin::new);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test code - panics are acceptable")]
mod tests {
    use super::{ServerId, State, all_sessions, routing_of, sessions_for_uids};

    fn state_with(sessions: &[(ServerId, u32, i64)]) -> State {
        let mut st = State::default();
        for &(srv, sess, uid) in sessions {
            let _ = st.sessions.insert((srv, sess), uid);
        }
        st
    }

    #[test]
    fn routing_of_extracts_id_organizer_and_participants() {
        let v = serde_json::json!({
            "id": "ev-1",
            "organizerId": 7,
            "participants": [{ "userId": 8 }, { "userId": 9 }, { "name": "guest" }],
        });
        let (id, organizer, participants) = routing_of(&v).unwrap();
        assert_eq!(id, "ev-1");
        assert_eq!(organizer, 7);
        assert_eq!(participants, vec![8, 9]);
    }

    #[test]
    fn routing_of_requires_id_and_defaults_missing_fields() {
        assert!(routing_of(&serde_json::json!({ "organizerId": 1 })).is_none());
        let (id, organizer, participants) =
            routing_of(&serde_json::json!({ "id": "ev-2" })).unwrap();
        assert_eq!(id, "ev-2");
        assert_eq!(organizer, -1);
        assert!(participants.is_empty());
    }

    #[test]
    fn sessions_for_uids_targets_invitees_excluding_sender_and_guests() {
        // server 1: 10->uid7 (organiser/sender), 11+12->uid8 (invited, two devices),
        //           13->guest, 14->uid9 (uninvited). server 2 must be ignored entirely.
        let st = state_with(&[
            (1, 10, 7),
            (1, 11, 8),
            (1, 12, 8),
            (1, 13, -1),
            (1, 14, 9),
            (2, 20, 8),
        ]);
        let mut got = sessions_for_uids(&st, 1, &[7, 8], 10);
        got.sort_unstable();
        // sender (10) excluded, uid9 not invited, guest excluded, server 2 excluded.
        assert_eq!(got, vec![11, 12]);
    }

    #[test]
    fn all_sessions_returns_every_peer_on_server_except_sender() {
        let st = state_with(&[(1, 10, 7), (1, 11, 8), (1, 12, -1), (2, 20, 9)]);
        let mut got = all_sessions(&st, 1, 11);
        got.sort_unstable();
        // availability broadcasts to everyone (guests included); sender + other
        // virtual server excluded.
        assert_eq!(got, vec![10, 12]);
    }
}
