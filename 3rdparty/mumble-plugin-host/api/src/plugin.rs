//! ABI-stable plugin and host context traits.
// `#[sabi_trait]` generates a trait-object forwarder for `PluginContext` that
// calls the now-deprecated `send_plugin_data`, producing an unavoidable
// in-crate deprecation warning. Allow it here so the deprecation remains a
// signal for external callers without dirtying our own build. The same
// forwarder also aggregates every trait method into one dispatch function,
// which trips `too_many_arguments`; that's macro output, not our API shape.
#![allow(
    deprecated,
    reason = "sabi_trait's generated PluginContext forwarder calls the deprecated send_plugin_data; deprecation targets external callers"
)]
#![allow(
    clippy::too_many_arguments,
    reason = "sabi_trait's generated PluginContext forwarder aggregates every trait method's parameters into one function"
)]

use abi_stable::{
    sabi_trait,
    std_types::{RArc, ROk, ROption, RSlice, RStr, RString, RVec},
    StableAbi,
};

use crate::{ChannelId, ClientInfo, PluginResult, ServerId, SessionId};

/// Inbound generic `PluginMessage` (wire ID 200) routed to the plugin
/// whose [`MumblePlugin::name`] equals `plugin_name`.  The payload bytes
/// are opaque to the host; each plugin decides its own encoding
/// (typically JSON or protobuf).
#[repr(C)]
#[derive(Debug, Clone, StableAbi)]
pub struct PluginMessageIn {
    /// Virtual server the message arrived on.
    pub server_id: ServerId,
    /// Session that sent the message.
    pub sender_session: SessionId,
    /// Display name of the sender at the time the message was received.
    pub sender_name: RString,
    /// Stable plugin identifier the envelope is addressed to.
    pub plugin_name: RString,
    /// Plugin-defined inner message type (e.g. `"OpenRequest"`).
    pub payload_type: RString,
    /// Opaque payload bytes encoded by the sending client.
    pub payload: abi_stable::std_types::RVec<u8>,
    /// Channel hint chosen by the client (when relevant).
    pub channel_id: ROption<ChannelId>,
}

/// Outbound generic `PluginMessage` produced by a plugin and dispatched
/// by the host via [`PluginContext::send_plugin_message`].  Routing is
/// either to an explicit set of sessions (`target_sessions` non-empty)
/// or to every member of `channel_id` (when set and `target_sessions`
/// is empty).  If both are empty the host drops the message.
#[repr(C)]
#[derive(Debug, Clone, StableAbi)]
pub struct PluginMessageOut {
    /// Virtual server the message is bound for.
    pub server_id: ServerId,
    /// Plugin identifier (used by the host to stamp `plugin_slot`).
    pub plugin_name: RString,
    /// Plugin-defined inner message type (e.g. `"Invite"`).
    pub payload_type: RString,
    /// Opaque payload bytes.
    pub payload: abi_stable::std_types::RVec<u8>,
    /// Explicit recipient sessions.
    pub target_sessions: abi_stable::std_types::RVec<SessionId>,
    /// Channel-scoped fan-out hint.
    pub channel_id: ROption<ChannelId>,
}

/// One write in a KV batch. A `None` value is a delete.
///
/// Batches are applied atomically, which is what lets a plugin keep its own
/// secondary indexes consistent with its records - the one thing key/value
/// genuinely costs it over SQL (`docs/STORAGE.md` §5.6).
#[repr(C)]
#[derive(Debug, Clone, StableAbi)]
pub struct KvOp {
    /// The key, within this plugin's own namespace.
    pub key: RVec<u8>,
    /// The value to store, or `RNone` to remove the key.
    pub value: ROption<RVec<u8>>,
}

/// One key/value pair a scan returned.
#[repr(C)]
#[derive(Debug, Clone, StableAbi)]
pub struct KvPair {
    /// The key.
    pub key: RVec<u8>,
    /// Its value.
    pub value: RVec<u8>,
}

/// A writable slot for one object, and where to send the bytes.
///
/// The bytes never cross this boundary: the host hands back a short-lived
/// signed URL and the plugin `PUT`s to it. That is the same split the control
/// connection makes for a client's uploads, and for the same reason - a
/// megabyte moved through the host is a megabyte blocking everything else.
#[repr(C)]
#[derive(Debug, Clone, StableAbi)]
pub struct ObjectSlot {
    /// The key the object will be stored under, for [`PluginContext::name_put`].
    pub key: RString,
    /// Where to send the bytes.
    pub url: RString,
    /// Which HTTP method to use.
    pub method: RString,
    /// When the URL stops working.
    pub expires_at_ms: u64,
}

/// One revision of a name.
#[repr(C)]
#[derive(Debug, Clone, StableAbi)]
pub struct NameRev {
    /// False when the name has never been written, which is the ordinary
    /// answer for a document being opened for the first time.
    pub found: bool,
    /// Which revision, from 1.
    pub rev: u64,
    /// The object this revision answers with.
    pub key: RString,
    /// When it was made.
    pub created_at_ms: u64,
}

/// One name in a namespace, at the revision it currently answers with.
#[repr(C)]
#[derive(Debug, Clone, StableAbi)]
pub struct NamedObject {
    /// The name.
    pub name: RString,
    /// Its latest revision.
    pub latest: NameRev,
}

/// Server-side handle plugins use to call back into the host.
///
/// Cloneable across threads.  The host wraps its internal state in an
/// `RArc<Self>` and passes the trait object to every plugin's
/// [`MumblePlugin::on_load`].
#[sabi_trait]
pub trait PluginContext: Send + Sync + 'static {
    /// Send a `PluginDataTransmission` message to a single connected
    /// client session.  `data` is opaque application bytes.
    ///
    /// # Deprecated
    ///
    /// `PluginDataTransmission` (Mumble wire ID 26) is deprecated in favour of
    /// the generic `PluginMessage` envelope (wire ID 200). Use
    /// [`send_plugin_message`](Self::send_plugin_message) instead.
    #[deprecated(
        since = "0.2.0",
        note = "PluginDataTransmission is deprecated; use `send_plugin_message` (PluginMessage) instead"
    )]
    fn send_plugin_data(
        &self,
        server_id: ServerId,
        target_session: SessionId,
        data_id: RStr<'_>,
        data: RSlice<'_, u8>,
    ) -> PluginResult<()>;

    /// Returns `true` if the given session is currently connected.
    fn is_session_active(&self, server_id: ServerId, session: SessionId) -> bool;

    /// Returns `true` if the given session may enter the given channel
    /// according to the server's ACLs.
    fn user_has_channel_access(
        &self,
        server_id: ServerId,
        session: SessionId,
        channel: ChannelId,
    ) -> bool;

    /// Returns `true` if the session has every permission in
    /// `permission_flags` on `channel`.
    ///
    /// The parameter is a raw `u32` because the `#[sabi_trait]` ABI
    /// surface must stay primitive; build the bitmask with
    /// [`crate::Permissions`] and pass `.bits()` (or use a higher-level
    /// facade such as `HostFacade` that accepts `Permissions` directly).
    fn has_permission(
        &self,
        server_id: ServerId,
        session: SessionId,
        channel: ChannelId,
        permission_flags: u32,
    ) -> bool;

    /// Returns the channel the session is currently in, or `RNone` if
    /// the session is unknown.
    fn current_channel(&self, server_id: ServerId, session: SessionId) -> ROption<ChannelId>;

    /// Look up a configuration value scoped to the calling plugin.
    fn get_config(&self, key: RStr<'_>) -> ROption<RString>;

    /// Dispatch a generic `PluginMessage` envelope (wire ID 200).  The
    /// host forwards to every recipient listed in `msg.target_sessions`
    /// or, when empty, every member of `msg.channel_id`.
    fn send_plugin_message(&self, msg: PluginMessageOut) -> PluginResult<()>;

    /// Returns the session IDs of every user currently joined to
    /// `channel`.  Returns an empty vector if the channel is unknown
    /// or the host does not implement enumeration.
    fn sessions_in_channel(&self, server_id: ServerId, channel: ChannelId) -> RVec<SessionId> {
        let _ = (server_id, channel);
        RVec::new()
    }

    /// Returns the session IDs of every connected user on `server_id`.
    /// Returns an empty vector if the host does not implement
    /// enumeration.
    fn all_sessions(&self, server_id: ServerId) -> RVec<SessionId> {
        let _ = server_id;
        RVec::new()
    }

    /// Resolve a username (exact match) to its current session ID.
    /// Returns `RNone` when no connected user carries that name or
    /// when the host does not implement name lookup.
    fn find_session_by_name(&self, server_id: ServerId, name: RStr<'_>) -> ROption<SessionId> {
        let _ = (server_id, name);
        abi_stable::std_types::RNone
    }

    /// Deliver a typed response for an in-flight, server-originated request
    /// back to the **host** (not to a client).
    ///
    /// This is the return leg of a generalized request/response bridge: the
    /// server hands a unit of work to a plugin (today via an `on_plugin_message`
    /// envelope) and the plugin, once its async work completes, calls this to
    /// hand the result back. The host routes by `response_type` to the
    /// server-side handler that owns that request kind (e.g. `"link-preview"`,
    /// which packs the JSON `payload` into a `FancyLinkPreviewResponse`),
    /// correlating via `request_id` and addressing `target_session`.
    ///
    /// `payload` is opaque bytes; each `response_type` defines its own encoding
    /// (the link-preview handler expects JSON `{ "embeds": [...] }`).
    ///
    /// The default returns `ROk(())` (no-op); the real host always overrides it.
    fn send_request_response(
        &self,
        server_id: ServerId,
        response_type: RStr<'_>,
        request_id: RStr<'_>,
        target_session: SessionId,
        payload: RSlice<'_, u8>,
    ) -> PluginResult<()> {
        let _ = (
            server_id,
            response_type,
            request_id,
            target_session,
            payload,
        );
        ROk(())
    }

    /// Create a sub-channel under `parent`, or return the id of an existing
    /// child of `parent` that already has this `name` (idempotent "ensure").
    ///
    /// All arguments are standard, content-agnostic channel properties that the
    /// host forwards verbatim to the server's channel machinery; the host
    /// ascribes no meaning to them:
    /// * `hidden` - only users with `SeeChannel` are told the channel exists;
    /// * `registered_can_manage` - make it a shared container the authenticated
    ///   (`auth`) group may see, traverse and create sub-channels in, while
    ///   `@all` is denied `SeeChannel` (i.e. hidden from guests but a workspace
    ///   for registered users);
    /// * `pchat_protocol` - persistent-chat protocol selector (0 = none);
    /// * `expiry_mode` / `expiry_duration_secs` - auto-expiry config (0 = none);
    /// * `invitee_uids` - when non-empty, makes it a private channel only those
    ///   registered users may see/enter (the server denies `@all` and grants the
    ///   invitees).
    ///
    /// Returns the channel id, or `RNone` on failure.  The default returns
    /// `RNone`; the real host overrides it.
    #[allow(
        clippy::too_many_arguments,
        reason = "mirrors the server's channel-property surface"
    )]
    fn create_channel(
        &self,
        server_id: ServerId,
        parent: ChannelId,
        name: RStr<'_>,
        hidden: bool,
        registered_can_manage: bool,
        detached: bool,
        pchat_protocol: u32,
        expiry_mode: u32,
        expiry_duration_secs: u32,
        invitee_uids: RSlice<'_, u32>,
    ) -> ROption<ChannelId> {
        let _ = (
            server_id,
            parent,
            name,
            hidden,
            registered_can_manage,
            detached,
            pchat_protocol,
            expiry_mode,
            expiry_duration_secs,
            invitee_uids,
        );
        abi_stable::std_types::RNone
    }

    /// Grant a registered `user_id` access (`SeeChannel|Enter|Traverse`) to an
    /// existing private `channel` (the inverse of the deny-`@all` baseline a
    /// private channel carries).  Returns `true` on success.
    ///
    /// The default returns `false`; the real host overrides it.
    fn grant_channel_access(&self, server_id: ServerId, channel: ChannelId, user_id: u32) -> bool {
        let _ = (server_id, channel, user_id);
        false
    }

    /// Revoke a registered `user_id`'s access to private `channel` (the
    /// inverse of [`Self::grant_channel_access`]).  The host removes the
    /// user's per-user allow ACLs, moves their sessions out of the channel and
    /// tells their clients the channel no longer exists once they cannot see
    /// it.  Idempotent; returns `true` on success.
    ///
    /// The default returns `false`; the real host overrides it.
    fn revoke_channel_access(&self, server_id: ServerId, channel: ChannelId, user_id: u32) -> bool {
        let _ = (server_id, channel, user_id);
        false
    }

    /// Read one key from this plugin's own storage.
    ///
    /// The namespace is implicit: the host knows which plugin is calling and
    /// scopes every operation to it, so a plugin cannot name - or reach -
    /// another's data (`docs/STORAGE.md` L6).
    ///
    /// The default returns nothing, for a host that offers no storage.
    fn kv_get(&self, server_id: ServerId, key: RSlice<'_, u8>) -> ROption<RVec<u8>> {
        let _ = (server_id, key);
        abi_stable::std_types::RNone
    }

    /// Every pair in `[start, end)`, in key order, at most `limit` of them.
    ///
    /// `reverse` walks the range backwards, which is what makes "the newest
    /// N" a range scan rather than a sort: a key of `channel ‖ uuidv7` is
    /// physically ordered by time, so the end of the range is the present.
    fn kv_scan(
        &self,
        server_id: ServerId,
        start: RSlice<'_, u8>,
        end: RSlice<'_, u8>,
        limit: u32,
        reverse: bool,
    ) -> RVec<KvPair> {
        let _ = (server_id, start, end, limit, reverse);
        RVec::new()
    }

    /// Apply a batch of writes atomically: all of them, or none.
    fn kv_write(&self, server_id: ServerId, ops: RSlice<'_, KvOp>) -> PluginResult<()> {
        let _ = (server_id, ops);
        PluginResult::RErr(crate::PluginError::Other(
            "this host offers no plugin storage".into(),
        ))
    }

    /// Open a writable slot for one object in this plugin's namespace.
    ///
    /// `size` is the ceiling the slot is signed for; an upload past it is cut
    /// off. `public` decides whether the object can be fetched by link with no
    /// signature - which an emote must be, because an `<img>` cannot sign a
    /// request, and a document must not.
    fn object_reserve(
        &self,
        server_id: ServerId,
        filename: RStr<'_>,
        content_type: RStr<'_>,
        size: u64,
        public: bool,
    ) -> ROption<ObjectSlot> {
        let _ = (server_id, filename, content_type, size, public);
        abi_stable::std_types::RNone
    }

    /// A short-lived signed URL to read one object back.
    ///
    /// Refused for a key outside this plugin's own namespace.
    fn object_url(&self, server_id: ServerId, key: RStr<'_>) -> ROption<RString> {
        let _ = (server_id, key);
        abi_stable::std_types::RNone
    }

    /// Point `name` at `key`, as a new revision. Returns the revision number.
    ///
    /// `keep` bounds the history afterwards: `0` keeps every revision, `1` is
    /// what something with no history wants. Objects left pointed at by
    /// nothing are removed with the revisions that held them.
    fn name_put(
        &self,
        server_id: ServerId,
        name: RStr<'_>,
        key: RStr<'_>,
        keep: u64,
    ) -> PluginResult<u64> {
        let _ = (server_id, name, key, keep);
        PluginResult::RErr(crate::PluginError::Other(
            "this host offers no plugin storage".into(),
        ))
    }

    /// What `name` currently answers with.
    fn name_latest(&self, server_id: ServerId, name: RStr<'_>) -> ROption<NameRev> {
        let _ = (server_id, name);
        abi_stable::std_types::RNone
    }

    /// A name's revisions, newest first.
    fn name_revisions(&self, server_id: ServerId, name: RStr<'_>, limit: u32) -> RVec<NameRev> {
        let _ = (server_id, name, limit);
        RVec::new()
    }

    /// Every name this plugin has stored, each at its latest revision.
    fn name_list(&self, server_id: ServerId) -> RVec<NamedObject> {
        let _ = server_id;
        RVec::new()
    }

    /// Forget a name and every revision of it, removing the objects that
    /// nothing else points at.
    fn name_forget(&self, server_id: ServerId, name: RStr<'_>) -> PluginResult<()> {
        let _ = (server_id, name);
        PluginResult::RErr(crate::PluginError::Other(
            "this host offers no plugin storage".into(),
        ))
    }
}

/// FFI-safe shape of every loadable plugin.
///
/// All hooks have default no-op implementations so authors only override
/// what they care about.  Hooks are **synchronous**: each plugin runs
/// its own internal `tokio` runtime and `block_on`s where needed.
#[sabi_trait]
pub trait MumblePlugin: Send + Sync + 'static {
    /// Stable plugin identifier.
    fn name(&self) -> RStr<'_>;

    /// `SemVer` of the plugin release.
    fn version(&self) -> RStr<'_>;

    /// JSON-encoded `PluginInfo`.  Plugins build a `PluginInfo` struct,
    /// call `to_validated_json` and return the bytes via
    /// `RString::from(String::from_utf8(...))`.
    ///
    /// Default returns an empty JSON object.
    fn info_json(&self) -> RString {
        RString::from("{}")
    }

    /// Called once when the plugin is loaded.
    ///
    /// `ctx` is given to the plugin by value so it may be retained
    /// (e.g. cloned via `RArc` into background tasks).  The host
    /// keeps its own independent handle to the same underlying
    /// context, so every later callback receives an equivalent
    /// reference - plugins that don't need long-lived access can
    /// simply drop the owned handle at the end of `on_load`.
    fn on_load(&self, ctx: PluginContext_TO<RArc<()>>) -> PluginResult<()> {
        let _ = ctx;
        ROk(())
    }

    /// Called once when the plugin is unloaded (server shutdown).
    fn on_unload(&self, ctx: &PluginContext_TO<RArc<()>>) -> PluginResult<()> {
        let _ = ctx;
        ROk(())
    }

    /// Fires when a client successfully authenticates and joins the
    /// server's user table.
    fn on_client_connected(
        &self,
        ctx: &PluginContext_TO<RArc<()>>,
        info: ClientInfo,
    ) -> PluginResult<()> {
        let _ = (ctx, info);
        ROk(())
    }

    /// Fires when a client disconnects.
    fn on_client_disconnected(
        &self,
        ctx: &PluginContext_TO<RArc<()>>,
        server_id: ServerId,
        session: SessionId,
    ) -> PluginResult<()> {
        let _ = (ctx, server_id, session);
        ROk(())
    }

    /// Fires for every `PluginDataTransmission` the server receives.
    fn on_plugin_data(
        &self,
        ctx: &PluginContext_TO<RArc<()>>,
        server_id: ServerId,
        sender: SessionId,
        data_id: RStr<'_>,
        data: RSlice<'_, u8>,
    ) -> PluginResult<()> {
        let _ = (ctx, server_id, sender, data_id, data);
        ROk(())
    }

    /// Receives a generic `PluginMessage` envelope (wire ID 200) whose
    /// `plugin_name` matches this plugin.  Only one plugin handles
    /// each inbound envelope; there is no fan-out.
    fn on_plugin_message(
        &self,
        ctx: &PluginContext_TO<RArc<()>>,
        msg: PluginMessageIn,
    ) -> PluginResult<()> {
        let _ = (ctx, msg);
        ROk(())
    }
}
