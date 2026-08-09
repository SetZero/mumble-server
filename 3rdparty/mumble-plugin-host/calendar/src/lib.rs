//! `mumble-calendar` - calendar/scheduling relay **and meeting-room** plugin.
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
//! On top of the relay it also **provisions the actual meeting rooms**: a
//! detached (parentless, Fancy-only, tree-invisible) end-to-end-encrypted
//! (`signal_v1`) channel, created server-authoritatively when a meeting's start
//! time arrives (a background scheduler thread) or when the first participant
//! asks to join (`calendar.join`).
//! Rooms inherit an absolute expiry so they self-destruct ~1 week after the meeting.
//! Organisers can mint a Teams-style invite link (`calendar.inviteLink`) carrying an
//! HMAC token that admits any *registered* user. A participant can drop a room
//! from their own channel list with `calendar.leave` (access revoked, event
//! participation kept - `calendar.join` re-admits them).
//!
//! Personal fields (RSVP, show-as, reminder, colour overrides) never leave the
//! owning client; only the shared meeting body is relayed.
#![allow(
    unreachable_pub,
    reason = "internal cdylib: cross-module items use `pub` for ergonomics, not as a library API"
)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use abi_stable::std_types::ROption::RNone;
use abi_stable::std_types::RResult::{RErr, ROk};
use abi_stable::std_types::{RArc, RSlice, RStr, RString, RVec};
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use mumble_plugin_api::{
    ClientInfo, MumblePlugin, PluginContext_TO, PluginInfo, PluginMessageIn, PluginMessageOut,
    PluginResult, ServerId, SessionId,
};
use sha2::Sha256;
use subtle::ConstantTimeEq;

const PLUGIN_NAME: &str = "fancy-calendar";
const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

const MSG_UPSERT: &str = "calendar.upsert";
const MSG_DELETE: &str = "calendar.delete";
const MSG_PUBLISH: &str = "calendar.publish";
const MSG_AVAILABILITY: &str = "calendar.availability";
/// A client asks to join a meeting's room (create-on-demand + access grant).
const MSG_JOIN: &str = "calendar.join";
/// A client asks to leave a meeting's room: their access is revoked and the
/// room disappears from their channel list (event participation is kept, so
/// they can rejoin from the calendar).
const MSG_LEAVE: &str = "calendar.leave";
/// Server -> client: the room channel id for a meeting.
const MSG_ROOM: &str = "calendar.room";
/// Organiser asks for / receives a shareable invite link.
const MSG_INVITE_LINK: &str = "calendar.inviteLink";

/// Keep a meeting room around this long after the meeting *ends* before the
/// server's expiry reaper deletes it.
const MEETING_RETENTION_SECS: i64 = 7 * 24 * 60 * 60;
/// Nominal parent passed to `create_channel` for a meeting room. Detached channels
/// are parentless, so this is ignored by the host; kept as the server's root (0).
const ROOT_CHANNEL_ID: u32 = 0;
/// `signal_v1` persistent-chat protocol selector (Signal sender-key group E2E).
const PCHAT_SIGNAL_V1: u32 = 4;
/// Absolute channel-expiry mode (removed at `created_at` + duration).
const EXPIRY_ABSOLUTE: u32 = 1;
/// Upper bound on how long the scheduler sleeps between scans (heartbeat); new
/// or changed meetings wake it sooner via the condvar.
const SCHED_HEARTBEAT: Duration = Duration::from_secs(3600);
/// Retry delay after a failed room-creation attempt (e.g. host doesn't yet
/// implement the meeting-channel callbacks).
const SCHED_RETRY: Duration = Duration::from_secs(60);
/// Truncate long meeting titles when deriving a channel name.
const MAX_TITLE_LEN: usize = 60;

/// A meeting the relay knows about (enough to route, replay and provision it).
struct StoredEvent {
    server_id: ServerId,
    organizer_uid: i64,
    participant_uids: Vec<i64>,
    /// Meeting start / end as UTC epoch millis (0 when unknown).
    start_ms: i64,
    end_ms: i64,
    title: String,
    /// The provisioned room channel id, once created (idempotency guard).
    channel_id: Option<u32>,
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

/// State shared between the plugin callbacks and the background scheduler thread.
struct Shared {
    state: Mutex<State>,
    /// Signalled whenever the meeting set changes so the scheduler re-evaluates.
    sched_cv: Condvar,
    /// Host call-back handle, populated in `on_load`.
    ctx: OnceLock<PluginContext_TO<RArc<()>>>,
    /// Set on unload to stop the scheduler thread.
    stop: AtomicBool,
    /// Ensures the scheduler thread is spawned exactly once.
    started: AtomicBool,
    /// Per-process secret for invite-link HMAC tokens.
    token_secret: [u8; 32],
}

impl Shared {
    fn new() -> Self {
        use rand::Rng;
        let mut secret = [0u8; 32];
        rand::rng().fill_bytes(&mut secret);
        Self {
            state: Mutex::new(State::default()),
            sched_cv: Condvar::new(),
            ctx: OnceLock::new(),
            stop: AtomicBool::new(false),
            started: AtomicBool::new(false),
            token_secret: secret,
        }
    }
}

struct CalendarPlugin {
    shared: Arc<Shared>,
}

impl CalendarPlugin {
    fn new() -> Self {
        Self {
            shared: Arc::new(Shared::new()),
        }
    }
}

fn lock(m: &Mutex<State>) -> std::sync::MutexGuard<'_, State> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Current wall-clock time as UTC epoch milliseconds.
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
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
            // Registered users (incl. SuperUser, uid 0) are >= 0; guests are -1.
            // `uids` only ever holds registered participant ids, so >= 0 keeps
            // guests out while letting SuperUser be a routable participant.
            *srv == server_id && *sess != except && **uid >= 0 && uids.contains(uid)
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
    let organizer = v
        .get("organizerId")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(-1);
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

/// Read a numeric JSON field as i64 (accepts integer or float encodings).
fn json_i64(v: &serde_json::Value, key: &str) -> i64 {
    v.get(key)
        .and_then(|n| n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)))
        .unwrap_or(0)
}

/// Pull scheduling fields (`start`, `end` UTC ms; `title`) out of an event JSON.
fn times_of(v: &serde_json::Value) -> (i64, i64, String) {
    let start = json_i64(v, "start");
    let end = json_i64(v, "end");
    let title = v
        .get("title")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();
    (start, end, title)
}

/// Registered invitee uids for a meeting (participants + organiser, guests
/// stripped), suitable for the room ACL.
fn invitee_uids(ev: &StoredEvent) -> Vec<u32> {
    let mut uids: Vec<u32> = ev
        .participant_uids
        .iter()
        .chain(std::iter::once(&ev.organizer_uid))
        .filter(|u| **u >= 0)
        .map(|u| *u as u32)
        .collect();
    uids.sort_unstable();
    uids.dedup();
    uids
}

/// Derive a human-readable, collision-resistant room name from a meeting.
fn room_name(title: &str, id: &str) -> String {
    let trimmed = title.trim();
    let base: String = if trimmed.is_empty() {
        "Meeting".to_string()
    } else {
        trimmed.chars().take(MAX_TITLE_LEN).collect()
    };
    let short: String = id.chars().take(8).collect();
    format!("{base} [{short}]")
}

/// Mint an invite-link token: base64url(HMAC-SHA256(secret, eventId)[..16]).
#[allow(
    clippy::expect_used,
    reason = "HMAC-SHA256 accepts keys of any length, so new_from_slice cannot fail here"
)]
fn make_token(secret: &[u8; 32], event_id: &str) -> String {
    let mut mac = <Hmac<Sha256>>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(event_id.as_bytes());
    let tag = mac.finalize().into_bytes();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&tag[..16])
}

/// Constant-time validation of an invite-link token for `event_id`.
fn verify_token(secret: &[u8; 32], event_id: &str, token: &str) -> bool {
    let expected = make_token(secret, event_id);
    expected.as_bytes().ct_eq(token.as_bytes()).into()
}

/// Read `eventId` (falling back to `id`) from a control-message JSON body.
fn event_id_of(v: &serde_json::Value) -> Option<String> {
    v.get("eventId")
        .or_else(|| v.get("id"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

/// Ensure the meeting room for `event_id` exists, creating it as a detached
/// (parentless) channel if needed.  Idempotent: returns the existing channel id
/// when already provisioned.  Returns `None` when the host could not create the
/// channel (e.g. an older server without the callbacks).
fn ensure_room(
    shared: &Shared,
    ctx: &PluginContext_TO<RArc<()>>,
    server_id: ServerId,
    event_id: &str,
) -> Option<u32> {
    // Snapshot what we need without holding the lock across the (possibly
    // blocking) host calls.
    let (name, invitees, expiry_secs) = {
        let st = lock(&shared.state);
        let ev = st.events.get(event_id)?;
        if let Some(cid) = ev.channel_id {
            return Some(cid);
        }
        let now = now_ms();
        let remaining_ms = (ev.end_ms.max(now) - now).max(0);
        let expiry = remaining_ms / 1000 + MEETING_RETENTION_SECS;
        let expiry_secs = expiry.clamp(0, i64::from(u32::MAX)) as u32;
        (
            room_name(&ev.title, event_id),
            invitee_uids(ev),
            expiry_secs,
        )
    };

    // Create the meeting room as a DETACHED channel: parentless (like the root),
    // only ever sent to Fancy clients, and never shown in the channel tree. It is
    // a Signal-E2E (`signal_v1`), absolutely-expiring, invitee-gated private
    // channel. No container node is needed - the host/server ascribe no meaning to
    // "meetings"; the detached flag plus the invitee ACLs do all the work. The
    // parent argument is ignored for detached channels.
    //
    // HIDDEN, not merely detached: the server's visibility policy short-circuits
    // for non-hidden channels, so a non-hidden room's ChannelState would reach
    // every out-of-tree-capable client - everyone would list everyone's meetings.
    // Hidden makes visibility follow the invitee ACLs (SeeChannel), which is also
    // what lets `calendar.leave` remove the room from just the leaver's client.
    let cid = ctx
        .create_channel(
            server_id,
            ROOT_CHANNEL_ID,
            RStr::from_str(&name),
            true,  // hidden (visible only with SeeChannel, i.e. to invitees)
            false, // registered_can_manage
            true,  // detached
            PCHAT_SIGNAL_V1,
            EXPIRY_ABSOLUTE,
            expiry_secs,
            RSlice::from_slice(&invitees),
        )
        .into_option()?;

    // Re-acquire and store the id, honouring a concurrent winner.
    let mut st = lock(&shared.state);
    if let Some(ev) = st.events.get_mut(event_id) {
        if let Some(existing) = ev.channel_id {
            return Some(existing);
        }
        ev.channel_id = Some(cid);
    }
    Some(cid)
}

/// Tell a meeting's participants which channel hosts their room.
fn notify_room(
    shared: &Shared,
    ctx: &PluginContext_TO<RArc<()>>,
    server_id: ServerId,
    event_id: &str,
    channel_id: u32,
) {
    let sessions = {
        let st = lock(&shared.state);
        let Some(ev) = st.events.get(event_id) else {
            return;
        };
        let mut uids = ev.participant_uids.clone();
        uids.push(ev.organizer_uid);
        sessions_for_uids(&st, server_id, &uids, SessionId::MAX)
    };
    let payload = serde_json::json!({ "eventId": event_id, "channelId": channel_id });
    send_to(
        ctx,
        server_id,
        sessions,
        MSG_ROOM,
        &serde_json::to_vec(&payload).unwrap_or_default(),
    );
}

/// Background loop that provisions rooms as meeting start times arrive.
fn run_scheduler(shared: &Shared) {
    let Some(ctx) = shared.ctx.get() else {
        return;
    };
    loop {
        if shared.stop.load(Ordering::SeqCst) {
            return;
        }
        let now = now_ms();
        // Collect meetings whose start has passed but have no room yet, plus
        // the earliest future start, in a single pass under the lock.
        let mut due: Vec<(String, ServerId)> = Vec::new();
        let mut earliest_future: Option<i64> = None;
        {
            let st = lock(&shared.state);
            for (id, ev) in &st.events {
                if ev.channel_id.is_some() {
                    continue;
                }
                if ev.start_ms <= now {
                    due.push((id.clone(), ev.server_id));
                } else {
                    earliest_future = Some(match earliest_future {
                        Some(t) => t.min(ev.start_ms),
                        None => ev.start_ms,
                    });
                }
            }
        }

        let mut any_failed = false;
        for (id, server_id) in due {
            match ensure_room(shared, ctx, server_id, &id) {
                Some(cid) => notify_room(shared, ctx, server_id, &id, cid),
                None => any_failed = true,
            }
        }

        let wait = if any_failed {
            SCHED_RETRY
        } else {
            match earliest_future {
                Some(t) => Duration::from_millis((t - now_ms()).max(0) as u64).min(SCHED_HEARTBEAT),
                None => SCHED_HEARTBEAT,
            }
        };

        let guard = lock(&shared.state);
        if shared.stop.load(Ordering::SeqCst) {
            return;
        }
        let _ = shared.sched_cv.wait_timeout(guard, wait);
    }
}

impl CalendarPlugin {
    /// Handle `calendar.join`: create-or-find the room and grant the caller
    /// access (registered users only; either a participant or a valid token).
    fn handle_join(&self, ctx: &PluginContext_TO<RArc<()>>, msg: &PluginMessageIn) {
        let server_id = msg.server_id;
        let sender = msg.sender_session;
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(msg.payload.as_slice()) else {
            return;
        };
        let Some(event_id) = event_id_of(&v) else {
            return;
        };
        let token = v.get("token").and_then(serde_json::Value::as_str);

        let (uid, is_participant) = {
            let st = lock(&self.shared.state);
            let uid = st.sessions.get(&(server_id, sender)).copied().unwrap_or(-1);
            let is_participant = st
                .events
                .get(&event_id)
                .is_some_and(|ev| ev.organizer_uid == uid || ev.participant_uids.contains(&uid));
            (uid, is_participant)
        };
        // Registered users only; guests (-1) are never admitted.
        if uid < 0 {
            return;
        }
        let token_ok = token.is_some_and(|t| verify_token(&self.shared.token_secret, &event_id, t));
        if !is_participant && !token_ok {
            return;
        }

        let Some(cid) = ensure_room(&self.shared, ctx, server_id, &event_id) else {
            return;
        };
        // Grant unconditionally (idempotent host-side): token joiners were
        // never in the creation ACL, and a participant who LEFT the room
        // (`calendar.leave` revoked their entry) must be re-admitted when they
        // rejoin from the calendar.
        let _ = ctx.grant_channel_access(server_id, cid, uid as u32);
        if !is_participant {
            let mut st = lock(&self.shared.state);
            if let Some(ev) = st.events.get_mut(&event_id) {
                if !ev.participant_uids.contains(&uid) {
                    ev.participant_uids.push(uid);
                }
            }
        }
        let payload = serde_json::json!({ "eventId": event_id, "channelId": cid });
        send_to(
            ctx,
            server_id,
            vec![sender],
            MSG_ROOM,
            &serde_json::to_vec(&payload).unwrap_or_default(),
        );
    }

    /// Handle `calendar.leave`: revoke the sender's access to a meeting room
    /// they no longer want listed. Only channels this plugin provisioned are
    /// ever touched (the id must map to a known meeting), so a client cannot
    /// use this to strip its ACLs from arbitrary channels. Event participation
    /// is unchanged - the meeting stays on their calendar and `calendar.join`
    /// re-admits them.
    fn handle_leave(&self, ctx: &PluginContext_TO<RArc<()>>, msg: &PluginMessageIn) {
        let server_id = msg.server_id;
        let sender = msg.sender_session;
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(msg.payload.as_slice()) else {
            return;
        };
        let Some(channel_id) = v
            .get("channelId")
            .and_then(serde_json::Value::as_u64)
            .and_then(|c| u32::try_from(c).ok())
        else {
            return;
        };
        let uid = {
            let st = lock(&self.shared.state);
            let uid = st.sessions.get(&(server_id, sender)).copied().unwrap_or(-1);
            let owned = st
                .events
                .values()
                .any(|ev| ev.server_id == server_id && ev.channel_id == Some(channel_id));
            if !owned {
                return;
            }
            uid
        };
        // Guests (-1) never held access; nothing to revoke.
        if uid < 0 {
            return;
        }
        if !ctx.revoke_channel_access(server_id, channel_id, uid as u32) {
            tracing::warn!(
                channel_id,
                uid,
                "calendar: leave failed to revoke room access"
            );
        }
    }

    /// Handle `calendar.inviteLink`: the organiser requests a shareable link.
    fn handle_invite_link(&self, ctx: &PluginContext_TO<RArc<()>>, msg: &PluginMessageIn) {
        let server_id = msg.server_id;
        let sender = msg.sender_session;
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(msg.payload.as_slice()) else {
            return;
        };
        let Some(event_id) = event_id_of(&v) else {
            return;
        };
        // Only the organiser may mint a link.
        let authorized = {
            let st = lock(&self.shared.state);
            let uid = st.sessions.get(&(server_id, sender)).copied().unwrap_or(-1);
            st.events
                .get(&event_id)
                .is_some_and(|ev| ev.organizer_uid == uid && uid >= 0)
        };
        if !authorized {
            return;
        }
        let token = make_token(&self.shared.token_secret, &event_id);
        let url = format!("fancy://meeting/{event_id}?t={token}");
        let payload = serde_json::json!({ "eventId": event_id, "url": url });
        send_to(
            ctx,
            server_id,
            vec![sender],
            MSG_INVITE_LINK,
            &serde_json::to_vec(&payload).unwrap_or_default(),
        );
    }

    fn handle_upsert(
        &self,
        ctx: &PluginContext_TO<RArc<()>>,
        server_id: ServerId,
        sender: SessionId,
        bytes: &[u8],
    ) {
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            return;
        };
        let Some((id, organizer, participants)) = routing_of(&v) else {
            return;
        };
        let (start_ms, end_ms, title) = times_of(&v);
        let mut uids = participants.clone();
        uids.push(organizer);
        let targets = {
            let mut st = lock(&self.shared.state);
            let prev_cid = st.events.get(&id).and_then(|e| e.channel_id);
            let _ = st.events.insert(
                id,
                StoredEvent {
                    server_id,
                    organizer_uid: organizer,
                    participant_uids: participants,
                    start_ms,
                    end_ms,
                    title,
                    channel_id: prev_cid,
                    payload: bytes.to_vec(),
                },
            );
            sessions_for_uids(&st, server_id, &uids, sender)
        };
        self.shared.sched_cv.notify_all();
        send_to(ctx, server_id, targets, MSG_UPSERT, bytes);
    }

    fn handle_delete(
        &self,
        ctx: &PluginContext_TO<RArc<()>>,
        server_id: ServerId,
        sender: SessionId,
        bytes: &[u8],
    ) {
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            return;
        };
        let Some(id) = v.get("id").and_then(serde_json::Value::as_str) else {
            return;
        };
        let targets = {
            let mut st = lock(&self.shared.state);
            match st.events.remove(id) {
                Some(ev) => {
                    let mut uids = ev.participant_uids;
                    uids.push(ev.organizer_uid);
                    sessions_for_uids(&st, server_id, &uids, sender)
                }
                None => Vec::new(),
            }
        };
        self.shared.sched_cv.notify_all();
        send_to(ctx, server_id, targets, MSG_DELETE, bytes);
    }

    fn handle_publish(
        &self,
        ctx: &PluginContext_TO<RArc<()>>,
        server_id: ServerId,
        sender: SessionId,
        bytes: &[u8],
    ) {
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            return;
        };
        let Some(events) = v.get("events").and_then(serde_json::Value::as_array) else {
            return;
        };
        for ev in events {
            let Some((id, organizer, participants)) = routing_of(ev) else {
                continue;
            };
            let (start_ms, end_ms, title) = times_of(ev);
            let payload = serde_json::to_vec(ev).unwrap_or_default();
            let mut uids = participants.clone();
            uids.push(organizer);
            let targets = {
                let mut st = lock(&self.shared.state);
                let prev_cid = st.events.get(&id).and_then(|e| e.channel_id);
                let _ = st.events.insert(
                    id,
                    StoredEvent {
                        server_id,
                        organizer_uid: organizer,
                        participant_uids: participants,
                        start_ms,
                        end_ms,
                        title,
                        channel_id: prev_cid,
                        payload: payload.clone(),
                    },
                );
                sessions_for_uids(&st, server_id, &uids, sender)
            };
            send_to(ctx, server_id, targets, MSG_UPSERT, &payload);
        }
        self.shared.sched_cv.notify_all();
    }

    fn handle_availability(
        &self,
        ctx: &PluginContext_TO<RArc<()>>,
        server_id: ServerId,
        sender: SessionId,
        bytes: &[u8],
    ) {
        let targets = {
            let mut st = lock(&self.shared.state);
            let uid = st.sessions.get(&(server_id, sender)).copied().unwrap_or(-1);
            // Store free/busy for any registered user (incl. SuperUser,
            // uid 0) for connect catch-up; skip guests (-1).
            if uid >= 0 {
                let _ = st.availability.insert(uid, (server_id, bytes.to_vec()));
            }
            all_sessions(&st, server_id, sender)
        };
        send_to(ctx, server_id, targets, MSG_AVAILABILITY, bytes);
    }
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
                          participants and provisions hidden end-to-end-encrypted \
                          meeting rooms; calendars are stored per-user in the file-server."
                .to_owned(),
            author: Some("Fancy Mumble Developers".to_owned()),
            homepage: None,
            tags: vec!["calendar".to_owned(), "scheduling".to_owned()],
            debug_rows: Vec::new(),
            client_manifest: None,
        }
        .to_rstring()
    }

    fn on_load(&self, ctx: PluginContext_TO<RArc<()>>) -> PluginResult<()> {
        init_tracing();
        tracing::info!("calendar plugin loaded");
        // Retain the host handle for the scheduler thread (set-once).
        let _ = self.shared.ctx.set(ctx);
        if !self.shared.started.swap(true, Ordering::SeqCst) {
            let shared = Arc::clone(&self.shared);
            if let Err(e) = thread::Builder::new()
                .name("calendar-sched".to_owned())
                .spawn(move || run_scheduler(&shared))
            {
                tracing::warn!(error = %e, "calendar: failed to spawn scheduler thread");
            }
        }
        ROk(())
    }

    fn on_unload(&self, _ctx: &PluginContext_TO<RArc<()>>) -> PluginResult<()> {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.shared.sched_cv.notify_all();
        *lock(&self.shared.state) = State::default();
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
            let mut st = lock(&self.shared.state);
            let _ = st.sessions.insert((server_id, session), uid);
            // Registered users (incl. SuperUser, uid 0) get their meetings
            // replayed on connect; guests (-1) are never participants.
            if uid >= 0 {
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
        let _ = lock(&self.shared.state)
            .sessions
            .remove(&(server_id, session));
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
            MSG_UPSERT => self.handle_upsert(ctx, server_id, sender, bytes),
            MSG_DELETE => self.handle_delete(ctx, server_id, sender, bytes),
            MSG_PUBLISH => self.handle_publish(ctx, server_id, sender, bytes),
            MSG_AVAILABILITY => self.handle_availability(ctx, server_id, sender, bytes),
            MSG_JOIN => self.handle_join(ctx, &msg),
            MSG_LEAVE => self.handle_leave(ctx, &msg),
            MSG_INVITE_LINK => self.handle_invite_link(ctx, &msg),
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
    use super::{
        all_sessions, make_token, room_name, routing_of, sessions_for_uids, times_of, verify_token,
        ServerId, State, StoredEvent,
    };

    fn state_with(sessions: &[(ServerId, u32, i64)]) -> State {
        let mut st = State::default();
        for &(srv, sess, uid) in sessions {
            let _ = st.sessions.insert((srv, sess), uid);
        }
        st
    }

    fn stored(server_id: ServerId, organizer: i64, participants: Vec<i64>) -> StoredEvent {
        StoredEvent {
            server_id,
            organizer_uid: organizer,
            participant_uids: participants,
            start_ms: 0,
            end_ms: 0,
            title: String::new(),
            channel_id: None,
            payload: Vec::new(),
        }
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
    fn times_of_reads_start_end_title() {
        let v = serde_json::json!({ "start": 1000, "end": 2000.0, "title": "Standup" });
        let (start, end, title) = times_of(&v);
        assert_eq!(start, 1000);
        assert_eq!(end, 2000);
        assert_eq!(title, "Standup");
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

    #[test]
    fn invitee_uids_merges_organizer_and_drops_guests() {
        let ev = stored(1, 7, vec![8, 9, -1, 8]);
        let got = super::invitee_uids(&ev);
        assert_eq!(got, vec![7, 8, 9]);
    }

    #[test]
    fn room_name_is_titled_and_disambiguated() {
        assert_eq!(
            room_name("Sprint Review", "abcdef123456"),
            "Sprint Review [abcdef12]"
        );
        assert_eq!(room_name("   ", "id123456"), "Meeting [id123456]");
    }

    #[test]
    fn token_roundtrips_and_rejects_tampering() {
        let secret = [3u8; 32];
        let token = make_token(&secret, "ev-1");
        assert!(verify_token(&secret, "ev-1", &token));
        assert!(!verify_token(&secret, "ev-2", &token));
        assert!(!verify_token(&secret, "ev-1", "not-a-token"));
        assert!(!verify_token(&[4u8; 32], "ev-1", &token));
    }
}
