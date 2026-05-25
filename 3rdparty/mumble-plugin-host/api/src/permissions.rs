//! Bit values for [`crate::PluginContext::has_permission`].
//!
//! Mirrors the Mumble C++ `ChanACL::Perm` enum.  Only the subset useful
//! to plugins is exposed; combine with `|`.

/// Write access on a channel; on the root channel this is the canonical
/// "is server admin" permission.
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
pub const SHARE_FILES: u32 = 0x4000;
/// May share files via publicly accessible links.
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
