//! Public trait definitions for Mumble server plugins.
//!
//! This crate defines the contract between the C++ Mumble server (via the
//! `mumble-plugin-host` cdylib) and individual plugin implementations.
//! Plugins implement [`MumblePlugin`] and use the [`PluginContext`] handle
//! passed to them on load to call back into the server (deliver plugin
//! data, query session state, look up channel ACLs, read config values).
//!
//! Keep this crate dependency-free apart from `thiserror`/`async-trait` so
//! it remains cheap to depend on.

use std::fmt::Debug;
use std::sync::Arc;

use thiserror::Error;

/// Result alias used throughout the plugin API.
pub type Result<T> = std::result::Result<T, PluginError>;

/// Errors that may be returned from plugin lifecycle and event hooks.
#[derive(Debug, Error)]
pub enum PluginError {
    /// Plugin configuration was invalid or required keys were missing.
    #[error("invalid plugin configuration: {0}")]
    Config(String),

    /// I/O error during plugin operation (e.g. file system, network).
    #[error("plugin i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// Plugin attempted to use the context after it was disposed.
    #[error("plugin context has been disposed")]
    ContextDisposed,

    /// Catch-all for plugin-specific errors that don't map cleanly above.
    #[error("plugin error: {0}")]
    Other(String),
}

/// Identifier for a Mumble virtual server within a single murmur process.
pub type ServerId = u32;

/// Identifier for a connected client session within a virtual server.
pub type SessionId = u32;

/// Identifier for a channel within a virtual server.
pub type ChannelId = u32;

/// Snapshot of information about a newly connected client.
#[derive(Debug, Clone)]
pub struct ClientInfo {
    /// Virtual server the client connected to.
    pub server_id: ServerId,
    /// Session id assigned to this client by the server.
    pub session_id: SessionId,
    /// Username the client authenticated as.
    pub username: String,
    /// Hex-encoded SHA-1 hash of the client's TLS certificate, or empty
    /// string if the client did not present one.
    pub cert_hash: String,
}

/// Server-side handle that plugins use to call back into the host.
///
/// Implementations are provided by `mumble-plugin-host`; plugins receive
/// an `Arc<dyn PluginContext>` in [`MumblePlugin::on_load`] and may keep
/// it for the lifetime of the plugin.
pub trait PluginContext: Send + Sync + Debug {
    /// Send a `PluginDataTransmission` message to a single connected
    /// client session. The data is opaque bytes; consumers usually
    /// JSON-serialize a payload identified by `data_id`.
    fn send_plugin_data(
        &self,
        server_id: ServerId,
        target_session: SessionId,
        data_id: &str,
        data: &[u8],
    ) -> Result<()>;

    /// Returns `true` if the given session is currently connected to the
    /// virtual server.
    fn is_session_active(&self, server_id: ServerId, session: SessionId) -> bool;

    /// Returns `true` if the given session is allowed to enter the given
    /// channel according to the server's ACLs.
    fn user_has_channel_access(
        &self,
        server_id: ServerId,
        session: SessionId,
        channel: ChannelId,
    ) -> bool;

    /// Returns `true` if the given session has all the permissions in
    /// `permission_flags` on `channel` according to the server's ACL
    /// system. `permission_flags` is a bitmask using the constants in
    /// the [`permissions`] module (mirroring Mumble's `ChanACL::Perm`).
    ///
    /// Use channel id `0` (the root channel) to check server-wide
    /// administrative permissions: e.g. `Write` on the root channel is
    /// the canonical "is admin" check that the `SuperUser` and the
    /// `admin` group inherit.
    fn has_permission(
        &self,
        server_id: ServerId,
        session: SessionId,
        channel: ChannelId,
        permission_flags: u32,
    ) -> bool;

    /// Returns the channel the session is currently in, or `None` if the
    /// session is unknown.  Plugins use this to enforce that an action
    /// referencing a channel really came from a user inside that channel
    /// (defence against client-side spoofing).
    ///
    /// Default implementation returns `None` so existing test impls keep
    /// compiling; the production host implementation overrides it.
    fn current_channel(&self, server_id: ServerId, session: SessionId) -> Option<ChannelId> {
        let _ = (server_id, session);
        None
    }

    /// Look up a configuration value for the calling plugin. Keys are
    /// scoped to the plugin (the host strips any `plugin.<name>.` prefix
    /// before storing them).
    fn get_config(&self, key: &str) -> Option<String>;
}

/// Bit values for [`PluginContext::has_permission`].
///
/// These mirror the Mumble C++ `ChanACL::Perm` enum; only the subset
/// useful to plugins is exposed here. Combine flags with `|`.
pub mod permissions {
    /// Write access on a channel; on the root channel this is the
    /// canonical "is server admin" permission.
    pub const WRITE: u32 = 0x1;
    /// May traverse the channel tree through this channel.
    pub const TRAVERSE: u32 = 0x2;
    /// May enter (join) the channel.
    pub const ENTER: u32 = 0x4;
    /// May speak (transmit audio) in the channel.
    pub const SPEAK: u32 = 0x8;
    /// May mute or deafen other users in the channel.
    pub const MUTE_DEAFEN: u32 = 0x10;
    /// May move users into or out of the channel.
    pub const MOVE: u32 = 0x20;
    /// May create sub-channels.
    pub const MAKE_CHANNEL: u32 = 0x40;
    /// May link channels together.
    pub const LINK_CHANNEL: u32 = 0x80;
    /// May whisper into the channel.
    pub const WHISPER: u32 = 0x100;
    /// May post text messages in the channel.
    pub const TEXT_MESSAGE: u32 = 0x200;
    /// May create temporary channels.
    pub const MAKE_TEMP_CHANNEL: u32 = 0x400;
    /// May listen to (subscribe to) the channel.
    pub const LISTEN: u32 = 0x800;
    /// May delete messages in the channel.
    pub const DELETE_MESSAGE: u32 = 0x1000;
    /// May subscribe to push notifications for the channel.
    pub const SUBSCRIBE_PUSH: u32 = 0x2000;
    /// May upload and share files in the channel (any access mode).
    /// Denying this prevents the user from uploading files at all.
    pub const SHARE_FILES: u32 = 0x4000;
    /// May share files via publicly accessible links
    /// (modes `public` and `password`).  When denied, the user may
    /// still upload `session`-scoped files (downloadable only by
    /// currently-connected users) but cannot create links that work
    /// outside the server.
    pub const SHARE_FILES_PUBLIC: u32 = 0x8000;
    /// Root-channel only: may kick users.
    pub const KICK: u32 = 0x10000;
    /// Root-channel only: may ban users.
    pub const BAN: u32 = 0x20000;
    /// Root-channel only: may register users.
    pub const REGISTER: u32 = 0x40000;
    /// Root-channel only: may self-register.
    pub const SELF_REGISTER: u32 = 0x80000;
    /// Root-channel only: may reset other users' customisation content.
    pub const RESET_USER_CONTENT: u32 = 0x100000;
    /// Root-channel only: may own/manage cryptographic keys.
    pub const KEY_OWNER: u32 = 0x200000;
    /// Root-channel only: may add and remove custom server emotes.
    pub const MANAGE_EMOTES: u32 = 0x400000;
}

/// Lifecycle and event hooks implemented by every plugin.
///
/// All hook methods have default no-op implementations so plugins only
/// need to override what they actually care about.
#[async_trait::async_trait]
pub trait MumblePlugin: Send + Sync + Debug {
    /// Stable identifier for this plugin. Used in config sections
    /// (`[plugin.<name>]`) and in log messages.
    fn name(&self) -> &str;

    /// Called once when the plugin is loaded. The plugin should start any
    /// background tasks here and store the context handle for later use.
    async fn on_load(&self, ctx: Arc<dyn PluginContext>) -> Result<()> {
        let _ = ctx;
        Ok(())
    }

    /// Called once when the plugin is unloaded (e.g. server shutdown).
    /// Implementations should perform graceful shutdown of background
    /// tasks and flush any pending state.
    async fn on_unload(&self) -> Result<()> {
        Ok(())
    }

    /// Called whenever a client successfully authenticates and is added
    /// to the server's user table.
    async fn on_client_connected(&self, info: ClientInfo) -> Result<()> {
        let _ = info;
        Ok(())
    }

    /// Called whenever a client disconnects.
    async fn on_client_disconnected(
        &self,
        server_id: ServerId,
        session: SessionId,
    ) -> Result<()> {
        let _ = (server_id, session);
        Ok(())
    }

    /// Called when the server receives a `PluginDataTransmission` from a
    /// client. The plugin may inspect the payload and respond by sending
    /// further plugin data via the context.
    async fn on_plugin_data(
        &self,
        server_id: ServerId,
        sender: SessionId,
        data_id: &str,
        data: &[u8],
    ) -> Result<()> {
        let _ = (server_id, sender, data_id, data);
        Ok(())
    }
}
