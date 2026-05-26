//! ABI-stable plugin and host context traits.

use abi_stable::{
    sabi_trait,
    std_types::{RArc, ROk, ROption, RSlice, RStr, RString},
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

/// Server-side handle plugins use to call back into the host.
///
/// Cloneable across threads.  The host wraps its internal state in an
/// `RArc<Self>` and passes the trait object to every plugin's
/// [`MumblePlugin::on_load`].
#[sabi_trait]
pub trait PluginContext: Send + Sync + 'static {
    /// Send a `PluginDataTransmission` message to a single connected
    /// client session.  `data` is opaque application bytes.
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
    fn on_load(&self, ctx: PluginContext_TO<RArc<()>>) -> PluginResult<()> {
        let _ = ctx;
        ROk(())
    }

    /// Called once when the plugin is unloaded (server shutdown).
    fn on_unload(&self) -> PluginResult<()> {
        ROk(())
    }

    /// Fires when a client successfully authenticates and joins the
    /// server's user table.
    fn on_client_connected(&self, info: ClientInfo) -> PluginResult<()> {
        let _ = info;
        ROk(())
    }

    /// Fires when a client disconnects.
    fn on_client_disconnected(&self, server_id: ServerId, session: SessionId) -> PluginResult<()> {
        let _ = (server_id, session);
        ROk(())
    }

    /// Fires for every `PluginDataTransmission` the server receives.
    fn on_plugin_data(
        &self,
        server_id: ServerId,
        sender: SessionId,
        data_id: RStr<'_>,
        data: RSlice<'_, u8>,
    ) -> PluginResult<()> {
        let _ = (server_id, sender, data_id, data);
        ROk(())
    }

    /// Receives a generic `PluginMessage` envelope (wire ID 200) whose
    /// `plugin_name` matches this plugin.  Only one plugin handles
    /// each inbound envelope; there is no fan-out.
    fn on_plugin_message(&self, msg: PluginMessageIn) -> PluginResult<()> {
        let _ = msg;
        ROk(())
    }
}
