//! Ergonomic, idiomatic wrapper around [`PluginContext_TO`].
//!
//! The raw FFI surface exposes free functions like
//! [`send_interaction_response_to_sessions`] that require the plugin
//! to thread `ctx` and `plugin_name` through every call site.  That
//! reads like C and clutters plugin code.
//!
//! [`Host`] is a zero-cost borrowed wrapper that stores the context
//! and the plugin name once, then exposes the same operations as
//! methods.  Plugins typically construct it once in their dispatcher
//! (or `on_plugin_message`) and pass it down to handlers in place of
//! the raw `&PluginContext_TO<...>`.
//!
//! ```ignore
//! let host = Host::new(ctx, PLUGIN_NAME);
//! let sessions = host.sessions_in_channel(server_id, channel_id);
//! host.respond_to_sessions(server_id, &sessions, response);
//! ```
//!
//! The raw free functions remain available for macro-generated code
//! and for plugins that prefer them.

use abi_stable::std_types::{RArc, ROption, RSlice, RStr, RString, RVec};

use crate::client_manifest::InteractionResponse;
use crate::commands::{
    send_interaction_response, send_interaction_response_to_channel,
    send_interaction_response_to_sessions,
};
use crate::permissions::Permissions;
use crate::plugin::{PluginContext_TO, PluginMessageIn, PluginMessageOut};
use crate::{ChannelId, PluginError, PluginResult, ServerId, SessionId};

/// Lightweight description of the user / channel / server that
/// triggered the current handler invocation.
///
/// Populated by the `#[fancy_plugin]`-generated dispatcher before it
/// hands a [`Host`] to a `#[command]` / `#[component]` / `#[modal]`
/// handler.  Lifecycle wrappers (`on_load`, `on_client_connected`,
/// etc.) leave the caller blank because they aren't tied to a
/// specific interaction; see [`Host::caller`].
#[derive(Copy, Clone, Debug)]
pub struct Caller {
    /// Virtual server the interaction came from.
    pub server_id: ServerId,
    /// Session of the user who triggered the interaction.
    pub session_id: SessionId,
    /// Channel the user was in when triggering the interaction, if
    /// the client included one in the envelope.
    pub channel_id: Option<ChannelId>,
}

impl Caller {
    /// Build a caller record by hand (mostly useful in tests and in
    /// manual `MumblePlugin` implementations).
    #[must_use]
    pub fn new(server_id: ServerId, session_id: SessionId, channel_id: Option<ChannelId>) -> Self {
        Self {
            server_id,
            session_id,
            channel_id,
        }
    }
}

/// Borrowed, idiomatic facade over [`PluginContext_TO`].
///
/// Constructed cheaply per dispatch from the FFI context plus the
/// plugin's own [`MumblePlugin::name`](crate::MumblePlugin::name).
/// All methods delegate to the underlying ABI-stable trait object;
/// nothing is allocated by the wrapper itself.
#[derive(Clone, Copy)]
pub struct Host<'a> {
    ctx: &'a PluginContext_TO<RArc<()>>,
    plugin_name: &'a str,
    caller: Option<Caller>,
}

impl std::fmt::Debug for Host<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Host")
            .field("plugin_name", &self.plugin_name)
            .field("caller", &self.caller)
            .finish_non_exhaustive()
    }
}

impl<'a> Host<'a> {
    /// Wrap a borrowed FFI context.  `plugin_name` should be the
    /// plugin's stable identifier so outbound envelopes are stamped
    /// correctly.
    #[must_use]
    pub fn new(ctx: &'a PluginContext_TO<RArc<()>>, plugin_name: &'a str) -> Self {
        Self {
            ctx,
            plugin_name,
            caller: None,
        }
    }

    /// Wrap a borrowed FFI context with a known [`Caller`].  Used by
    /// the `#[fancy_plugin]`-generated dispatcher before invoking a
    /// command / component / modal handler so the handler can ask
    /// `host.caller()` who triggered it.
    #[must_use]
    pub fn with_caller(
        ctx: &'a PluginContext_TO<RArc<()>>,
        plugin_name: &'a str,
        caller: Caller,
    ) -> Self {
        Self {
            ctx,
            plugin_name,
            caller: Some(caller),
        }
    }

    /// Caller record attached by the dispatcher, if any.  Returns
    /// `None` from lifecycle hooks (`on_load`, `on_client_connected`,
    /// `on_plugin_message`'s fallthrough path) where no single
    /// interaction is in scope.
    #[must_use]
    pub fn caller(&self) -> Option<Caller> {
        self.caller
    }

    /// Access the raw FFI context for callers that still need it
    /// (e.g. interop with the free functions in [`crate::commands`]
    /// or with proc-macro-generated dispatchers).
    #[must_use]
    pub fn raw(&self) -> &'a PluginContext_TO<RArc<()>> {
        self.ctx
    }

    /// Plugin name this facade was constructed with.
    #[must_use]
    pub fn plugin_name(&self) -> &'a str {
        self.plugin_name
    }

    // ---- Membership / lookup --------------------------------------

    /// Session IDs of every user currently joined to `channel`.
    /// Returns an empty `Vec` if the channel is unknown or the host
    /// does not implement enumeration.
    #[must_use]
    pub fn sessions_in_channel(&self, server_id: ServerId, channel: ChannelId) -> Vec<SessionId> {
        self.ctx
            .sessions_in_channel(server_id, channel)
            .into_iter()
            .collect()
    }

    /// Session IDs of every connected user on `server_id`.
    #[must_use]
    pub fn all_sessions(&self, server_id: ServerId) -> Vec<SessionId> {
        self.ctx.all_sessions(server_id).into_iter().collect()
    }

    /// Resolve a username (exact match) to its current session ID.
    #[must_use]
    pub fn find_session_by_name(&self, server_id: ServerId, name: &str) -> Option<SessionId> {
        self.ctx
            .find_session_by_name(server_id, RStr::from_str(name))
            .into_option()
    }

    /// Channel the session is currently in, or `None` if unknown.
    #[must_use]
    pub fn current_channel(&self, server_id: ServerId, session: SessionId) -> Option<ChannelId> {
        self.ctx.current_channel(server_id, session).into_option()
    }

    // ---- Channel management ---------------------------------------

    /// Create a sub-channel under `parent` (or return an existing same-named
    /// child) with the given standard, content-agnostic channel properties.
    /// See [`PluginContext::create_channel`] for the parameter meaning.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "mirrors the server's channel-property surface"
    )]
    pub fn create_channel(
        &self,
        server_id: ServerId,
        parent: ChannelId,
        name: &str,
        hidden: bool,
        registered_can_manage: bool,
        detached: bool,
        pchat_protocol: u32,
        expiry_mode: u32,
        expiry_duration_secs: u32,
        invitee_uids: &[u32],
    ) -> Option<ChannelId> {
        self.ctx
            .create_channel(
                server_id,
                parent,
                RStr::from_str(name),
                hidden,
                registered_can_manage,
                detached,
                pchat_protocol,
                expiry_mode,
                expiry_duration_secs,
                RSlice::from_slice(invitee_uids),
            )
            .into_option()
    }

    /// Grant a registered `user_id` access to an existing private `channel`.
    pub fn grant_channel_access(
        &self,
        server_id: ServerId,
        channel: ChannelId,
        user_id: u32,
    ) -> bool {
        self.ctx.grant_channel_access(server_id, channel, user_id)
    }

    /// Revoke a registered `user_id`'s access to an existing private
    /// `channel` (the inverse of [`Self::grant_channel_access`]).
    pub fn revoke_channel_access(
        &self,
        server_id: ServerId,
        channel: ChannelId,
        user_id: u32,
    ) -> bool {
        self.ctx.revoke_channel_access(server_id, channel, user_id)
    }

    /// Returns `true` if the session is currently connected.
    #[must_use]
    pub fn is_session_active(&self, server_id: ServerId, session: SessionId) -> bool {
        self.ctx.is_session_active(server_id, session)
    }

    /// Returns `true` if the session may enter `channel` per ACLs.
    #[must_use]
    pub fn user_has_channel_access(
        &self,
        server_id: ServerId,
        session: SessionId,
        channel: ChannelId,
    ) -> bool {
        self.ctx
            .user_has_channel_access(server_id, session, channel)
    }

    /// Returns `true` if the session has every permission in `perms`
    /// on `channel`.  Accepts a typed [`Permissions`] bitmask so
    /// plugin code does not have to call `.bits()` manually.
    #[must_use]
    pub fn has_permission(
        &self,
        server_id: ServerId,
        session: SessionId,
        channel: ChannelId,
        perms: Permissions,
    ) -> bool {
        self.ctx
            .has_permission(server_id, session, channel, perms.bits())
    }

    // ---- Configuration --------------------------------------------

    /// Look up a configuration value scoped to the calling plugin.
    #[must_use]
    pub fn get_config(&self, key: &str) -> Option<String> {
        self.ctx
            .get_config(RStr::from_str(key))
            .into_option()
            .map(|s| s.into_string())
    }

    // ---- Raw plugin data / message --------------------------------

    /// Send a `PluginDataTransmission` to a single connected session.
    ///
    /// # Deprecated
    ///
    /// `PluginDataTransmission` (Mumble wire ID 26) is deprecated in favour of
    /// the generic `PluginMessage` envelope (wire ID 200). Use
    /// [`send_plugin_message`](Self::send_plugin_message) or
    /// [`send_to_sessions`](Self::send_to_sessions) instead.
    #[deprecated(
        since = "0.2.0",
        note = "PluginDataTransmission is deprecated; use `send_plugin_message`/`send_to_sessions` (PluginMessage) instead"
    )]
    #[allow(
        deprecated,
        reason = "this wrapper is itself deprecated and must delegate to the deprecated primitive"
    )]
    pub fn send_plugin_data(
        &self,
        server_id: ServerId,
        target_session: SessionId,
        data_id: &str,
        data: &[u8],
    ) -> Result<(), PluginError> {
        result_to_std(self.ctx.send_plugin_data(
            server_id,
            target_session,
            RStr::from_str(data_id),
            RSlice::from_slice(data),
        ))
    }

    /// Dispatch a generic `PluginMessage` envelope.  The
    /// `plugin_name` field is overwritten with the value this facade
    /// was constructed with, so callers do not have to set it.
    pub fn send_plugin_message(&self, mut msg: PluginMessageOut) -> Result<(), PluginError> {
        msg.plugin_name = RString::from(self.plugin_name);
        result_to_std(self.ctx.send_plugin_message(msg))
    }

    // ---- Raw typed plugin messages -----------------------------------

    /// Send a serialised payload to an explicit list of sessions.
    ///
    /// This is a convenience wrapper that builds the [`PluginMessageOut`]
    /// envelope internally, so callers never touch `RString`, `RVec`, or
    /// `ROption` directly.
    pub fn send_to_sessions(
        &self,
        server_id: ServerId,
        sessions: &[SessionId],
        payload_type: &str,
        payload: &[u8],
    ) -> Result<(), PluginError> {
        let mut target_sessions: RVec<SessionId> = RVec::new();
        target_sessions.extend(sessions.iter().copied());
        let msg = PluginMessageOut {
            server_id,
            plugin_name: RString::new(), // overwritten by send_plugin_message
            payload_type: RString::from(payload_type),
            payload: payload.iter().copied().collect(),
            target_sessions,
            channel_id: ROption::RNone,
        };
        self.send_plugin_message(msg)
    }

    /// Send a serialised payload back to the sender of `msg`.
    ///
    /// Equivalent to `send_to_sessions(msg.server_id, &[msg.sender_session], ...).
    pub fn reply_to(
        &self,
        msg: &PluginMessageIn,
        payload_type: &str,
        payload: &[u8],
    ) -> Result<(), PluginError> {
        self.send_to_sessions(msg.server_id, &[msg.sender_session], payload_type, payload)
    }

    // ---- Server-originated request/response bridge --------------------

    /// Deliver a typed response for a server-originated request back to the
    /// host (the return leg of [`PluginContext::send_request_response`]).
    ///
    /// Unlike [`send_to_sessions`](Self::send_to_sessions), this does **not**
    /// reach the client directly: the host routes the `payload` by
    /// `response_type` to the server-side handler that issued the request
    /// (e.g. `"link-preview"`, which packs the JSON into a
    /// `FancyLinkPreviewResponse`), correlating by `request_id` and addressing
    /// `target_session`.
    pub fn send_request_response(
        &self,
        server_id: ServerId,
        response_type: &str,
        request_id: &str,
        target_session: SessionId,
        payload: &[u8],
    ) -> Result<(), PluginError> {
        result_to_std(self.ctx.send_request_response(
            server_id,
            RStr::from_str(response_type),
            RStr::from_str(request_id),
            target_session,
            RSlice::from_slice(payload),
        ))
    }

    // ---- Interaction responses ------------------------------------

    /// Ship an [`InteractionResponse`] back to the originating
    /// session of `msg`.  Mirrors
    /// [`crate::commands::send_interaction_response`].
    pub fn respond(&self, msg: &PluginMessageIn, response: InteractionResponse) {
        send_interaction_response(self.ctx, msg, response);
    }

    /// Fan an [`InteractionResponse`] out to an explicit set of
    /// recipient sessions.  Mirrors
    /// [`crate::commands::send_interaction_response_to_sessions`].
    pub fn respond_to_sessions(
        &self,
        server_id: ServerId,
        sessions: &[SessionId],
        response: InteractionResponse,
    ) {
        send_interaction_response_to_sessions(
            self.ctx,
            server_id,
            self.plugin_name,
            sessions,
            response,
        );
    }

    /// Fan an [`InteractionResponse`] out to every current member of
    /// `channel_id`.  Mirrors
    /// [`crate::commands::send_interaction_response_to_channel`].
    pub fn respond_to_channel(
        &self,
        server_id: ServerId,
        channel_id: ChannelId,
        response: InteractionResponse,
    ) {
        send_interaction_response_to_channel(
            self.ctx,
            server_id,
            self.plugin_name,
            channel_id,
            response,
        );
    }
}

fn result_to_std(r: PluginResult<()>) -> Result<(), PluginError> {
    match r {
        abi_stable::std_types::RResult::ROk(()) => Ok(()),
        abi_stable::std_types::RResult::RErr(e) => Err(e),
    }
}
