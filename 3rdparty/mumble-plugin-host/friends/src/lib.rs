//! `mumble-friends` - provisions per-friend-pair direct-message rooms.
//!
//! A friend chat between two *registered* users (or a user with themselves - a
//! personal notepad) is backed by a **detached, Signal-E2E (`signal_v1`)
//! channel**: parentless, never shown in the channel tree, only delivered to
//! Fancy clients, with both users as invitees. This gives end-to-end encryption
//! plus server-side persistence for free (the pchat subsystem), keyed per pair.
//!
//! The client asks to open a chat (`friends.open` with the peer's registered
//! `user_id`, or none for a self-notepad); this plugin find-or-creates the
//! deterministic `__dm:<lo>-<hi>` channel, grants both access, and replies
//! `friends.room` with the channel id to the requester (and the peer if online).
//! Guests / unregistered targets get no channel - the client then falls back to
//! a classic (non-persisted) direct message. The host and server ascribe no
//! meaning to "friends"; only this plugin does.
#![allow(
    unreachable_pub,
    reason = "internal cdylib: modules are private; cross-module items use `pub` for ergonomics, not as a library API"
)]

use std::collections::HashMap;
use std::sync::Mutex;

use abi_stable::std_types::ROption::RNone;
use abi_stable::std_types::RResult::{RErr, ROk};
use abi_stable::std_types::{RArc, RSlice, RStr, RString, RVec};
use mumble_plugin_api::{
    ClientInfo, MumblePlugin, PluginContext_TO, PluginInfo, PluginMessageIn, PluginMessageOut,
    PluginResult, ServerId, SessionId,
};

const PLUGIN_NAME: &str = "fancy-friends";
const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Client -> plugin: open (create-or-find) the DM room for a friend pair.
/// Payload `{ "targetUserId": <i64> }`; omit (or send self) for a self-notepad.
const MSG_OPEN: &str = "friends.open";
/// Plugin -> client: the channel hosting a friend chat.
/// Payload `{ "peerUserId": <i64>, "channelId": <u32> }`.
const MSG_ROOM: &str = "friends.room";

/// `signal_v1` persistent-chat protocol selector (Signal sender-key group E2E).
const PCHAT_SIGNAL_V1: u32 = 4;
/// No expiry: friend chats persist until explicitly removed.
const EXPIRY_NONE: u32 = 0;
/// Nominal parent passed to `create_channel`; ignored for detached channels.
const ROOT_CHANNEL_ID: u32 = 0;

#[derive(Default)]
struct State {
    /// (server, session) -> registered `user_id` (-1 for guests).
    sessions: HashMap<(ServerId, SessionId), i64>,
}

struct FriendsPlugin {
    state: Mutex<State>,
}

impl FriendsPlugin {
    fn new() -> Self {
        Self {
            state: Mutex::new(State::default()),
        }
    }
}

fn lock(m: &Mutex<State>) -> std::sync::MutexGuard<'_, State> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Deterministic channel name for a friend pair (or self-notepad), so both ends
/// resolve to the same channel and the host's create-or-reuse is idempotent.
fn dm_channel_name(a: i64, b: i64) -> String {
    if a == b {
        format!("__dm:{a}")
    } else {
        let (lo, hi) = if a < b { (a, b) } else { (b, a) };
        format!("__dm:{lo}-{hi}")
    }
}

/// Online sessions of any registered user in `uids` on `server_id`.
fn sessions_for_uids(state: &State, server_id: ServerId, uids: &[i64]) -> Vec<SessionId> {
    state
        .sessions
        .iter()
        .filter(|((srv, _), uid)| *srv == server_id && **uid >= 0 && uids.contains(uid))
        .map(|((_, sess), _)| *sess)
        .collect()
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
        tracing::warn!(error = %e, "friends: send_plugin_message failed");
    }
}

impl FriendsPlugin {
    /// Find-or-create the detached `signal_v1` DM channel for `(a, b)` (or self
    /// when `a == b`). Returns the channel id, or `None` if the host could not
    /// create it (older server without the detached/create callbacks).
    fn ensure_dm_channel(
        &self,
        ctx: &PluginContext_TO<RArc<()>>,
        server_id: ServerId,
        a: i64,
        b: i64,
    ) -> Option<u32> {
        let name = dm_channel_name(a, b);
        let invitees: Vec<u32> = if a == b {
            vec![a as u32]
        } else {
            vec![a as u32, b as u32]
        };
        ctx.create_channel(
            server_id,
            ROOT_CHANNEL_ID,
            RStr::from_str(&name),
            false, // hidden (detached is already tree-invisible; invitee ACLs gate access)
            false, // registered_can_manage
            true,  // detached
            PCHAT_SIGNAL_V1,
            EXPIRY_NONE,
            0,
            RSlice::from_slice(&invitees),
        )
        .into_option()
    }

    /// Handle `friends.open`: registered-only. Resolve the (sender, peer) pair,
    /// provision the channel, grant both, and reply with the channel id.
    fn handle_open(&self, ctx: &PluginContext_TO<RArc<()>>, msg: &PluginMessageIn) {
        let server_id = msg.server_id;
        let sender = msg.sender_session;
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(msg.payload.as_slice()) else {
            return;
        };
        let target = v.get("targetUserId").and_then(serde_json::Value::as_i64);

        let sender_uid = {
            lock(&self.state)
                .sessions
                .get(&(server_id, sender))
                .copied()
                .unwrap_or(-1)
        };
        // Friend chats are registered-only. A guest sender (or an explicitly
        // unregistered target) gets no channel; the client falls back to a
        // classic DM.
        if sender_uid < 0 {
            return;
        }
        let peer_uid = match target {
            Some(t) if t >= 0 => t,
            Some(_) => return,  // explicit unregistered target -> no channel
            None => sender_uid, // self-notepad
        };

        let Some(cid) = self.ensure_dm_channel(ctx, server_id, sender_uid, peer_uid) else {
            return;
        };
        // Belt-and-braces: the invitee ACLs already admit both at creation, but
        // re-granting is idempotent and covers reuse of an older channel.
        let _ = ctx.grant_channel_access(server_id, cid, sender_uid as u32);
        if peer_uid != sender_uid {
            let _ = ctx.grant_channel_access(server_id, cid, peer_uid as u32);
        }

        // Tell the requester which channel hosts the chat (peer = the other side).
        let to_sender = serde_json::json!({ "peerUserId": peer_uid, "channelId": cid });
        send_to(
            ctx,
            server_id,
            vec![sender],
            MSG_ROOM,
            &serde_json::to_vec(&to_sender).unwrap_or_default(),
        );
        // ...and the peer's online sessions, so their client learns the channel
        // for this pair without having to ask (peer = the requester, from their POV).
        if peer_uid != sender_uid {
            let peer_sessions = sessions_for_uids(&lock(&self.state), server_id, &[peer_uid]);
            let to_peer = serde_json::json!({ "peerUserId": sender_uid, "channelId": cid });
            send_to(
                ctx,
                server_id,
                peer_sessions,
                MSG_ROOM,
                &serde_json::to_vec(&to_peer).unwrap_or_default(),
            );
        }
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

impl MumblePlugin for FriendsPlugin {
    fn name(&self) -> RStr<'_> {
        RStr::from_str(PLUGIN_NAME)
    }

    fn version(&self) -> RStr<'_> {
        RStr::from_str(PLUGIN_VERSION)
    }

    fn info_json(&self) -> RString {
        PluginInfo {
            description: "Backs friend direct messages (and a self-notepad) with detached, \
                          end-to-end-encrypted, persisted signal channels between registered users."
                .to_owned(),
            author: Some("Fancy Mumble Developers".to_owned()),
            homepage: None,
            tags: vec!["friends".to_owned(), "dm".to_owned(), "e2ee".to_owned()],
            debug_rows: Vec::new(),
            client_manifest: None,
        }
        .to_rstring()
    }

    fn on_load(&self, _ctx: PluginContext_TO<RArc<()>>) -> PluginResult<()> {
        init_tracing();
        tracing::info!("friends plugin loaded");
        ROk(())
    }

    fn on_unload(&self, _ctx: &PluginContext_TO<RArc<()>>) -> PluginResult<()> {
        *lock(&self.state) = State::default();
        ROk(())
    }

    fn on_client_connected(
        &self,
        _ctx: &PluginContext_TO<RArc<()>>,
        info: ClientInfo,
    ) -> PluginResult<()> {
        let _ = lock(&self.state)
            .sessions
            .insert((info.server_id, info.session_id), info.user_id);
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
        if msg.payload_type.as_str() == MSG_OPEN {
            self.handle_open(ctx, &msg);
        }
        ROk(())
    }
}

mumble_plugin_api::fancy_export_plugin!(FriendsPlugin::new);

#[cfg(test)]
mod tests {
    use super::dm_channel_name;

    #[test]
    fn dm_name_is_order_independent_for_a_pair() {
        assert_eq!(dm_channel_name(7, 3), "__dm:3-7");
        assert_eq!(dm_channel_name(3, 7), "__dm:3-7");
    }

    #[test]
    fn self_notepad_uses_single_id() {
        assert_eq!(dm_channel_name(5, 5), "__dm:5");
    }
}
