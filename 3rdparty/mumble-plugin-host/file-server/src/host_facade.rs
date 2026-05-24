//! Internal sync facade over the ABI-stable [`mumble_plugin_api::PluginContext`].
//!
//! The rest of the file-server crate is written against this trait so it
//! can keep using ordinary `&str` / `&[u8]` / `Option<String>` types
//! without sprinkling `abi_stable` conversions through every call site.
//! Production code uses [`SabiHostCtx`], which wraps a
//! `PluginContext_TO<RArc<()>>`; tests can supply their own
//! implementations.

use std::fmt::Debug;

use abi_stable::std_types::{RArc, RSlice, RStr, RString};
use mumble_plugin_api::{PluginContext_TO, PluginError, PluginResult};

/// Convenience alias used in plugin code.
pub type FacadeResult<T> = Result<T, PluginError>;

/// Sync, owned-string facade used throughout file-server.
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

    /// `true` if the session holds the given permission flags in the channel.
    fn has_permission(&self, server_id: u32, session: u32, channel: u32, perm: u32) -> bool;

    /// Channel the session is currently in, if known to the host.
    fn current_channel(&self, _server_id: u32, _session: u32) -> Option<u32> {
        None
    }

    /// Look up a plugin-scoped configuration value.
    fn get_config(&self, key: &str) -> Option<String>;
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

    fn has_permission(&self, server_id: u32, session: u32, channel: u32, perm: u32) -> bool {
        self.inner.has_permission(server_id, session, channel, perm)
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
}
