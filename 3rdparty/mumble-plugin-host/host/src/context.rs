//! C-callable callback table provided by the Mumble server, plus a
//! [`PluginContext`] implementation that bridges plugins back to the
//! server through those callbacks.

use std::ffi::{c_char, c_int, CStr, CString};
use std::os::raw::c_void;
use std::ptr;
use std::sync::Arc;

use abi_stable::std_types::{RNone, ROption, RSlice, RSome, RStr, RString};
use mumble_plugin_api::{
    ChannelId, PluginContext, PluginError, PluginMessageOut, PluginResult, ServerId, SessionId,
};

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
    /// `permission_flags` on `channel` (a bitmask of `ChanACL::Perm`).
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
    /// is unknown.
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

    /// Dispatch a generic `PluginMessage` envelope (wire ID 200).  The
    /// host C++ side decides routing: every session in `target_sessions`
    /// receives the envelope; if that slice is empty and `channel_id`
    /// is set (non-zero `channel_id_present`), every member of the
    /// channel receives it instead.  Returns 0 on success.
    pub send_plugin_message: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            server_id: u32,
            plugin_name: *const c_char,
            payload_type: *const c_char,
            payload: *const u8,
            payload_len: usize,
            target_sessions: *const u32,
            target_len: usize,
            channel_id_present: bool,
            channel_id: u32,
        ) -> c_int,
    >,
}

// SAFETY: callbacks are documented as thread-safe; user_data is owned
// by the C++ host which guarantees it outlives every plugin call.
unsafe impl Send for PluginHostCallbacks {}
unsafe impl Sync for PluginHostCallbacks {}

/// Concrete adapter that holds the C callback table.
#[derive(Debug)]
pub(crate) struct HostContext {
    pub(crate) callbacks: PluginHostCallbacks,
}

impl HostContext {
    pub(crate) fn new(callbacks: PluginHostCallbacks) -> Self {
        Self { callbacks }
    }

    /// Direct C-callback bridge for `send_plugin_data`.  Used by the
    /// host itself (not just plugins) to ship `fancy-plugin-info`
    /// envelopes to newly connected clients.
    pub(crate) fn send_plugin_data_raw(
        &self,
        server_id: ServerId,
        target_session: SessionId,
        data_id: &str,
        data: &[u8],
    ) -> PluginResult<()> {
        let func = match self.callbacks.send_plugin_data {
            Some(f) => f,
            None => {
                return PluginResult::RErr(PluginError::Other(
                    "send_plugin_data callback missing".into(),
                ))
            }
        };
        let id_c = match CString::new(data_id) {
            Ok(c) => c,
            Err(_) => {
                return PluginResult::RErr(PluginError::Other("data_id contains NUL".into()))
            }
        };
        let data_ptr = if data.is_empty() { ptr::null() } else { data.as_ptr() };
        // SAFETY: callback non-null; id_c lives until return; data slice
        // is valid for `data.len()` bytes.
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
            PluginResult::ROk(())
        } else {
            PluginResult::RErr(PluginError::Other(
                format!("send_plugin_data returned {rc}").into(),
            ))
        }
    }
}

/// Plugin-facing context: namespaces config lookups under a per-plugin
/// prefix (e.g. `"plugin.live-doc"`) and forwards everything else to
/// the shared [`HostContext`].
#[derive(Debug)]
pub(crate) struct ScopedContext {
    inner: Arc<HostContext>,
    config_prefix: String,
}

impl ScopedContext {
    pub(crate) fn new(inner: Arc<HostContext>, config_prefix: impl Into<String>) -> Self {
        Self {
            inner,
            config_prefix: config_prefix.into(),
        }
    }
}

impl PluginContext for ScopedContext {
    fn send_plugin_data(
        &self,
        server_id: ServerId,
        target_session: SessionId,
        data_id: RStr<'_>,
        data: RSlice<'_, u8>,
    ) -> PluginResult<()> {
        self.inner
            .send_plugin_data_raw(server_id, target_session, data_id.as_str(), data.as_slice())
    }

    fn is_session_active(&self, server_id: ServerId, session: SessionId) -> bool {
        let Some(func) = self.inner.callbacks.is_session_active else {
            return false;
        };
        // SAFETY: callback non-null; primitive args passed by value.
        unsafe { func(self.inner.callbacks.user_data, server_id, session) }
    }

    fn user_has_channel_access(
        &self,
        server_id: ServerId,
        session: SessionId,
        channel: ChannelId,
    ) -> bool {
        let Some(func) = self.inner.callbacks.user_has_channel_access else {
            return false;
        };
        // SAFETY: callback non-null; primitive args passed by value.
        unsafe { func(self.inner.callbacks.user_data, server_id, session, channel) }
    }

    fn has_permission(
        &self,
        server_id: ServerId,
        session: SessionId,
        channel: ChannelId,
        permission_flags: u32,
    ) -> bool {
        let Some(func) = self.inner.callbacks.has_permission else {
            return false;
        };
        // SAFETY: callback non-null; primitive args passed by value.
        unsafe {
            func(
                self.inner.callbacks.user_data,
                server_id,
                session,
                channel,
                permission_flags,
            )
        }
    }

    fn current_channel(
        &self,
        server_id: ServerId,
        session: SessionId,
    ) -> ROption<ChannelId> {
        let Some(func) = self.inner.callbacks.current_channel else {
            return RNone;
        };
        let mut out: u32 = 0;
        // SAFETY: callback non-null; `out` is a valid stack slot.
        let ok = unsafe { func(self.inner.callbacks.user_data, server_id, session, &mut out) };
        if ok {
            RSome(out)
        } else {
            RNone
        }
    }

    fn get_config(&self, key: RStr<'_>) -> ROption<RString> {
        let Some(func) = self.inner.callbacks.get_config else {
            return RNone;
        };
        let Some(free) = self.inner.callbacks.free_string else {
            return RNone;
        };
        let prefixed = format!("{}.{}", self.config_prefix, key.as_str());
        let Ok(key_c) = CString::new(prefixed) else {
            return RNone;
        };
        // SAFETY: both callbacks non-null; key_c outlives the call; the
        // returned pointer (if non-null) is owned by us until we free it.
        let raw = unsafe { func(self.inner.callbacks.user_data, key_c.as_ptr()) };
        if raw.is_null() {
            return RNone;
        }
        // SAFETY: host promises NUL-terminated UTF-8.
        let value = unsafe { CStr::from_ptr(raw) }
            .to_str()
            .ok()
            .map(str::to_owned);
        // SAFETY: pointer was returned by `get_config`; freed exactly once.
        unsafe { free(self.inner.callbacks.user_data, raw) };
        match value {
            Some(v) => RSome(RString::from(v)),
            None => RNone,
        }
    }

    fn send_plugin_message(&self, msg: PluginMessageOut) -> PluginResult<()> {
        let func = match self.inner.callbacks.send_plugin_message {
            Some(f) => f,
            None => {
                return PluginResult::RErr(PluginError::Other(
                    "send_plugin_message callback missing".into(),
                ))
            }
        };
        let plugin_name_c = match CString::new(msg.plugin_name.as_str()) {
            Ok(c) => c,
            Err(_) => {
                return PluginResult::RErr(PluginError::Other(
                    "plugin_name contains NUL".into(),
                ))
            }
        };
        let payload_type_c = match CString::new(msg.payload_type.as_str()) {
            Ok(c) => c,
            Err(_) => {
                return PluginResult::RErr(PluginError::Other(
                    "payload_type contains NUL".into(),
                ))
            }
        };
        let payload_slice = msg.payload.as_slice();
        let payload_ptr =
            if payload_slice.is_empty() { ptr::null() } else { payload_slice.as_ptr() };
        let targets = msg.target_sessions.as_slice();
        let targets_ptr = if targets.is_empty() { ptr::null() } else { targets.as_ptr() };
        let (channel_present, channel_id) = match msg.channel_id {
            RSome(c) => (true, c),
            RNone => (false, 0),
        };
        // SAFETY: callback non-null; all pointers either NULL or backed
        // by RVec/CString that live until the call returns.
        let rc = unsafe {
            func(
                self.inner.callbacks.user_data,
                msg.server_id,
                plugin_name_c.as_ptr(),
                payload_type_c.as_ptr(),
                payload_ptr,
                payload_slice.len(),
                targets_ptr,
                targets.len(),
                channel_present,
                channel_id,
            )
        };
        if rc == 0 {
            PluginResult::ROk(())
        } else {
            PluginResult::RErr(PluginError::Other(
                format!("send_plugin_message returned {rc}").into(),
            ))
        }
    }
}
