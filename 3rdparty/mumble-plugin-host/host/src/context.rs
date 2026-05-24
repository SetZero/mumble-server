//! C-callable callback table provided by the Mumble server, plus the
//! [`HostContext`] adapter that implements [`mumble_plugin_api::PluginContext`].

use std::ffi::{c_char, c_int, CStr, CString};
use std::os::raw::c_void;
use std::ptr;
use std::sync::Arc;

use mumble_plugin_api::{ChannelId, LiveDocInviteParams, PluginContext, PluginError, ServerId, SessionId};

/// C-callable callback table the server fills in and passes to
/// [`crate::ffi::plugin_host_create`].
///
/// All function pointers must be valid for the lifetime of the host
/// handle and safe to call from multiple threads concurrently.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PluginHostCallbacks {
    /// Opaque user-data pointer passed back to every callback.
    pub user_data: *mut c_void,

    /// Send a `PluginDataTransmission` to a single connected session.
    /// Returns 0 on success, non-zero on error.
    pub send_plugin_data: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            server_id: u32,
            target_session: u32,
            data_id: *const c_char,
            data: *const u8,
            data_len: usize,
        ) -> c_int,
    >,

    /// Returns true if `session` is connected to `server_id`.
    pub is_session_active:
        Option<unsafe extern "C" fn(user_data: *mut c_void, server_id: u32, session: u32) -> bool>,

    /// Returns true if `session` is allowed in `channel`.
    pub user_has_channel_access: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            server_id: u32,
            session: u32,
            channel: u32,
        ) -> bool,
    >,

    /// Returns true if `session` has all the permissions in
    /// `permission_flags` on `channel`. `permission_flags` is a bitmask
    /// of `ChanACL::Perm` values; channel `0` is the root channel.
    pub has_permission: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            server_id: u32,
            session: u32,
            channel: u32,
            permission_flags: u32,
        ) -> bool,
    >,

    /// Returns the channel id `session` is currently in, written through
    /// `out_channel`.  Returns `true` on success, `false` if the session
    /// is unknown (in which case `out_channel` is unmodified).  Used by
    /// plugins to defend against client-supplied channel id spoofing.
    pub current_channel: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            server_id: u32,
            session: u32,
            out_channel: *mut u32,
        ) -> bool,
    >,

    /// Look up a configuration value by key. Returns a NUL-terminated
    /// UTF-8 string allocated by the host (must be freed with
    /// [`PluginHostCallbacks::free_string`]) or NULL if absent.
    pub get_config:
        Option<unsafe extern "C" fn(user_data: *mut c_void, key: *const c_char) -> *mut c_char>,

    /// Free a string previously returned by [`Self::get_config`].
    pub free_string: Option<unsafe extern "C" fn(user_data: *mut c_void, ptr: *mut c_char)>,

    /// Deliver a `FancyLiveDocInvite` (wire ID 142) to a single session.
    /// Returns 0 on success, non-zero on error.
    pub send_fancy_live_doc_invite: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            server_id: u32,
            target_session: u32,
            channel_id: u32,
            slug: *const c_char,
            title: *const c_char,
            ws_url: *const c_char,
            token: *const c_char,
        ) -> c_int,
    >,
}

// SAFETY: The callbacks are required by API contract to be thread-safe.
// The user_data pointer is owned by the C++ host which guarantees it
// outlives every plugin call.
unsafe impl Send for PluginHostCallbacks {}
unsafe impl Sync for PluginHostCallbacks {}

/// Adapter wired to the C callbacks; handed to plugins as
/// `Arc<dyn PluginContext>`.
#[derive(Debug)]
pub(crate) struct HostContext {
    pub(crate) callbacks: PluginHostCallbacks,
}

impl HostContext {
    pub(crate) fn new(callbacks: PluginHostCallbacks) -> Self {
        Self { callbacks }
    }
}

impl PluginContext for HostContext {
    fn send_plugin_data(
        &self,
        server_id: ServerId,
        target_session: SessionId,
        data_id: &str,
        data: &[u8],
    ) -> mumble_plugin_api::Result<()> {
        let func = self
            .callbacks
            .send_plugin_data
            .ok_or_else(|| PluginError::Other("send_plugin_data callback missing".into()))?;
        let id_c = CString::new(data_id)
            .map_err(|_| PluginError::Other("data_id contains NUL".into()))?;
        let data_ptr = if data.is_empty() { ptr::null() } else { data.as_ptr() };
        // SAFETY: callback is non-null, id_c lives until function returns,
        // data slice is valid for `data.len()` bytes.
        let rc = unsafe {
            func(
                self.callbacks.user_data,
                server_id,
                target_session,
                id_c.as_ptr(),
                data_ptr,
                data.len(),
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(PluginError::Other(format!("send_plugin_data returned {rc}")))
        }
    }

    fn is_session_active(&self, server_id: ServerId, session: SessionId) -> bool {
        let Some(func) = self.callbacks.is_session_active else { return false };
        // SAFETY: callback is non-null and primitives are passed by value.
        unsafe { func(self.callbacks.user_data, server_id, session) }
    }

    fn user_has_channel_access(
        &self,
        server_id: ServerId,
        session: SessionId,
        channel: ChannelId,
    ) -> bool {
        let Some(func) = self.callbacks.user_has_channel_access else { return false };
        // SAFETY: callback is non-null and primitives are passed by value.
        unsafe { func(self.callbacks.user_data, server_id, session, channel) }
    }

    fn has_permission(
        &self,
        server_id: ServerId,
        session: SessionId,
        channel: ChannelId,
        permission_flags: u32,
    ) -> bool {
        let Some(func) = self.callbacks.has_permission else { return false };
        // SAFETY: callback is non-null and primitives are passed by value.
        unsafe {
            func(
                self.callbacks.user_data,
                server_id,
                session,
                channel,
                permission_flags,
            )
        }
    }

    fn current_channel(&self, server_id: ServerId, session: SessionId) -> Option<ChannelId> {
        let func = self.callbacks.current_channel?;
        let mut out: u32 = 0;
        // SAFETY: callback is non-null; `out` is a valid stack slot.
        let ok = unsafe { func(self.callbacks.user_data, server_id, session, &mut out) };
        if ok { Some(out) } else { None }
    }

    fn get_config(&self, key: &str) -> Option<String> {
        let func = self.callbacks.get_config?;
        let free = self.callbacks.free_string?;
        let key_c = CString::new(key).ok()?;
        // SAFETY: both callbacks are non-null; key_c outlives the call;
        // the returned pointer (if non-null) is owned by us until we hand
        // it back to `free`.
        let raw = unsafe { func(self.callbacks.user_data, key_c.as_ptr()) };
        if raw.is_null() {
            return None;
        }
        // SAFETY: the host promises a NUL-terminated UTF-8 string.
        let value = unsafe { CStr::from_ptr(raw) }.to_str().ok().map(str::to_owned);
        // SAFETY: pointer was returned by `get_config` and we only free it once.
        unsafe { free(self.callbacks.user_data, raw) };
        value
    }

    fn send_fancy_live_doc_invite(
        &self,
        server_id: ServerId,
        target_session: SessionId,
        channel_id: ChannelId,
        invite: &LiveDocInviteParams<'_>,
    ) -> mumble_plugin_api::Result<()> {
        let func = self
            .callbacks
            .send_fancy_live_doc_invite
            .ok_or_else(|| PluginError::Other("send_fancy_live_doc_invite not wired".into()))?;
        let slug_c = CString::new(invite.slug)
            .map_err(|_| PluginError::Other("slug contains NUL".into()))?;
        let title_c = CString::new(invite.title)
            .map_err(|_| PluginError::Other("title contains NUL".into()))?;
        let ws_url_c = CString::new(invite.ws_url)
            .map_err(|_| PluginError::Other("ws_url contains NUL".into()))?;
        let token_c = CString::new(invite.token)
            .map_err(|_| PluginError::Other("token contains NUL".into()))?;
        // SAFETY: callback is non-null; all CString values outlive the call.
        let rc = unsafe {
            func(
                self.callbacks.user_data,
                server_id,
                target_session,
                channel_id,
                slug_c.as_ptr(),
                title_c.as_ptr(),
                ws_url_c.as_ptr(),
                token_c.as_ptr(),
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(PluginError::Other(format!(
                "send_fancy_live_doc_invite returned {rc}"
            )))
        }
    }
}

/// Wraps a shared [`HostContext`] and prefixes every
/// [`PluginContext::get_config`] key with a plugin-specific namespace
/// (e.g. `"plugin.live-doc"`).  All other calls delegate directly to the
/// inner context, so no callback logic is duplicated here.
#[derive(Debug)]
pub(crate) struct ScopedContext {
    inner: Arc<HostContext>,
    prefix: String,
}

impl ScopedContext {
    /// Create a new scoped context. `prefix` should be the dot-separated
    /// plugin section name, e.g. `"plugin.live-doc"`.
    pub(crate) fn new(inner: Arc<HostContext>, prefix: impl Into<String>) -> Self {
        Self {
            inner,
            prefix: prefix.into(),
        }
    }
}

impl PluginContext for ScopedContext {
    fn send_plugin_data(
        &self,
        server_id: ServerId,
        target_session: SessionId,
        data_id: &str,
        data: &[u8],
    ) -> mumble_plugin_api::Result<()> {
        self.inner.send_plugin_data(server_id, target_session, data_id, data)
    }

    fn is_session_active(&self, server_id: ServerId, session: SessionId) -> bool {
        self.inner.is_session_active(server_id, session)
    }

    fn user_has_channel_access(
        &self,
        server_id: ServerId,
        session: SessionId,
        channel: ChannelId,
    ) -> bool {
        self.inner.user_has_channel_access(server_id, session, channel)
    }

    fn has_permission(
        &self,
        server_id: ServerId,
        session: SessionId,
        channel: ChannelId,
        permission_flags: u32,
    ) -> bool {
        self.inner.has_permission(server_id, session, channel, permission_flags)
    }

    fn current_channel(&self, server_id: ServerId, session: SessionId) -> Option<ChannelId> {
        self.inner.current_channel(server_id, session)
    }

    fn get_config(&self, key: &str) -> Option<String> {
        self.inner.get_config(&format!("{}.{}", self.prefix, key))
    }

    fn send_fancy_live_doc_invite(
        &self,
        server_id: ServerId,
        target_session: SessionId,
        channel_id: ChannelId,
        invite: &LiveDocInviteParams<'_>,
    ) -> mumble_plugin_api::Result<()> {
        self.inner.send_fancy_live_doc_invite(server_id, target_session, channel_id, invite)
    }
}
