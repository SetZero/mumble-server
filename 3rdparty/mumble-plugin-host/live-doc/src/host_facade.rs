//! Internal sync facade over the ABI-stable [`mumble_plugin_api::PluginContext`].
//!
//! The rest of the live-doc crate is written against this trait so it
//! can keep using ordinary `&str` / `&[u8]` / `Option<String>` types
//! without sprinkling `abi_stable` conversions through every call site.
//! Production code uses [`SabiHostCtx`], which wraps a
//! `PluginContext_TO<RArc<()>>`; tests can supply their own
//! implementations.

use std::fmt::Debug;

use abi_stable::std_types::{RArc, RNone, ROption, RSlice, RSome, RStr, RString, RVec};
use mumble_plugin_api::{
    Permissions, PluginContext_TO, PluginError, PluginMessageOut, PluginResult,
};

/// Convenience alias used in plugin code.
pub type FacadeResult<T> = Result<T, PluginError>;

/// Sync, owned-string facade used throughout live-doc.
pub trait HostFacade: Debug + Send + Sync + 'static {
    /// Send a `PluginDataTransmission` to a connected session.
    fn send_plugin_data(
        &self,
        server_id: u32,
        target_session: u32,
        data_id: &str,
        data: &[u8],
    ) -> FacadeResult<()>;

    /// `true` while the session is connected.
    fn is_session_active(&self, server_id: u32, session: u32) -> bool;

    /// `true` if the session may enter the channel under server ACLs.
    fn user_has_channel_access(&self, server_id: u32, session: u32, channel: u32) -> bool;

    /// `true` if the session holds every flag in `perm` on `channel`.
    fn has_permission(&self, server_id: u32, session: u32, channel: u32, perm: Permissions)
        -> bool;

    /// Channel the session is currently in, if known to the host.
    fn current_channel(&self, _server_id: u32, _session: u32) -> Option<u32> {
        None
    }

    /// Look up a plugin-scoped configuration value.
    fn get_config(&self, key: &str) -> Option<String>;

    /// Dispatch a generic `PluginMessage` envelope (wire ID 200)
    /// addressed to the given plugin name with the supplied payload.
    /// Routing follows host rules: `target_sessions` first, then
    /// `channel_id` fan-out.
    fn send_plugin_message(&self, args: PluginMessageArgs<'_>) -> FacadeResult<()>;
}

/// Borrow-friendly outbound envelope used by [`HostFacade::send_plugin_message`].
#[derive(Debug, Clone, Copy)]
pub struct PluginMessageArgs<'a> {
    /// Virtual server.
    pub server_id: u32,
    /// Plugin identifier the envelope is addressed to.
    pub plugin_name: &'a str,
    /// Plugin-defined inner message type.
    pub payload_type: &'a str,
    /// Opaque payload bytes.
    pub payload: &'a [u8],
    /// Explicit recipients; empty means "fan-out via `channel_id`".
    pub target_sessions: &'a [u32],
    /// Channel fan-out hint.
    pub channel_id: Option<u32>,
}

/// Production adapter: wraps the ABI-stable trait object handed in by
/// the host loader.
pub struct SabiHostCtx {
    inner: PluginContext_TO<RArc<()>>,
}

impl SabiHostCtx {
    /// Wrap an ABI-stable plugin context handed in by the host loader.
    #[must_use]
    pub fn new(inner: PluginContext_TO<RArc<()>>) -> Self {
        Self { inner }
    }
}

impl Debug for SabiHostCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SabiHostCtx").finish_non_exhaustive()
    }
}

impl HostFacade for SabiHostCtx {
    fn send_plugin_data(
        &self,
        server_id: u32,
        target_session: u32,
        data_id: &str,
        data: &[u8],
    ) -> FacadeResult<()> {
        match self.inner.send_plugin_data(
            server_id,
            target_session,
            RStr::from(data_id),
            RSlice::from(data),
        ) {
            PluginResult::ROk(()) => Ok(()),
            PluginResult::RErr(e) => Err(e),
        }
    }

    fn is_session_active(&self, server_id: u32, session: u32) -> bool {
        self.inner.is_session_active(server_id, session)
    }

    fn user_has_channel_access(&self, server_id: u32, session: u32, channel: u32) -> bool {
        self.inner
            .user_has_channel_access(server_id, session, channel)
    }

    fn has_permission(
        &self,
        server_id: u32,
        session: u32,
        channel: u32,
        perm: Permissions,
    ) -> bool {
        self.inner
            .has_permission(server_id, session, channel, perm.bits())
    }

    fn current_channel(&self, server_id: u32, session: u32) -> Option<u32> {
        self.inner.current_channel(server_id, session).into_option()
    }

    fn get_config(&self, key: &str) -> Option<String> {
        self.inner
            .get_config(RStr::from(key))
            .into_option()
            .map(RString::into_string)
    }

    fn send_plugin_message(&self, args: PluginMessageArgs<'_>) -> FacadeResult<()> {
        let channel_id: ROption<u32> = args.channel_id.map_or(RNone, RSome);
        let msg = PluginMessageOut {
            server_id: args.server_id,
            plugin_name: RString::from(args.plugin_name),
            payload_type: RString::from(args.payload_type),
            payload: RVec::from(args.payload.to_vec()),
            target_sessions: RVec::from(args.target_sessions.to_vec()),
            channel_id,
        };
        match self.inner.send_plugin_message(msg) {
            PluginResult::ROk(()) => Ok(()),
            PluginResult::RErr(e) => Err(e),
        }
    }
}
