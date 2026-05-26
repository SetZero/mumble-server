//! Permission flags accepted by [`crate::PluginContext::has_permission`].
//!
//! Mirrors the Mumble C++ `ChanACL::Perm` enum.  Only the subset useful
//! to plugins is exposed; combine with `|`.
//!
//! # ABI note
//!
//! The `#[sabi_trait]`-decorated [`crate::PluginContext::has_permission`]
//! still takes a raw `u32` so the abi_stable trait object remains
//! ABI-stable across plugin versions.  Plugins should construct the
//! permission set with [`Permissions`] and pass `.bits()` at the call:
//!
//! ```ignore
//! ctx.has_permission(srv, sid, 0, (Permissions::SHARE_FILES | Permissions::SHARE_FILES_PUBLIC).bits());
//! ```
//!
//! Higher-level facades inside this workspace (e.g. `HostFacade` in the
//! `mumble-file-server` and `mumble-live-doc` crates) accept
//! [`Permissions`] directly and perform the conversion themselves.

bitflags::bitflags! {
    /// Bitset of channel ACL permissions a session may hold.
    ///
    /// `#[repr(transparent)]` keeps the in-memory layout byte-identical
    /// to `u32`, so `.bits()` is a zero-cost conversion at the FFI line.
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Permissions: u32 {
        /// Write access on a channel; on the root channel this is the
        /// canonical "is server admin" permission.
        const WRITE = 0x1;
        /// May traverse the channel tree through this channel.
        const TRAVERSE = 0x2;
        /// May enter (join) the channel.
        const ENTER = 0x4;
        /// May speak (transmit audio) in the channel.
        const SPEAK = 0x8;
        /// May mute or deafen other users in the channel.
        const MUTE_DEAFEN = 0x10;
        /// May move users into or out of the channel.
        const MOVE = 0x20;
        /// May create sub-channels.
        const MAKE_CHANNEL = 0x40;
        /// May link channels together.
        const LINK_CHANNEL = 0x80;
        /// May whisper into the channel.
        const WHISPER = 0x100;
        /// May post text messages in the channel.
        const TEXT_MESSAGE = 0x200;
        /// May create temporary channels.
        const MAKE_TEMP_CHANNEL = 0x400;
        /// May listen to (subscribe to) the channel.
        const LISTEN = 0x800;
        /// May delete messages in the channel.
        const DELETE_MESSAGE = 0x1000;
        /// May subscribe to push notifications for the channel.
        const SUBSCRIBE_PUSH = 0x2000;
        /// May upload and share files in the channel (any access mode).
        const SHARE_FILES = 0x4000;
        /// May share files via publicly accessible links.
        const SHARE_FILES_PUBLIC = 0x8000;
        /// Root-channel only: may kick users.
        const KICK = 0x10000;
        /// Root-channel only: may ban users.
        const BAN = 0x20000;
        /// Root-channel only: may register users.
        const REGISTER = 0x40000;
        /// Root-channel only: may self-register.
        const SELF_REGISTER = 0x80000;
        /// Root-channel only: may reset other users' customisation content.
        const RESET_USER_CONTENT = 0x100000;
        /// Root-channel only: may own/manage cryptographic keys.
        const KEY_OWNER = 0x200000;
        /// Root-channel only: may add and remove custom server emotes.
        const MANAGE_EMOTES = 0x400000;
    }
}
