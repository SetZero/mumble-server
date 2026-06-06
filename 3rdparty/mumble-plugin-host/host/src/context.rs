//! C-callable callback table provided by the Mumble server, plus a
//! [`PluginContext`] implementation that bridges plugins back to the
//! server through those callbacks.

use std::ffi::{c_char, c_int, CStr, CString};
use std::os::raw::c_void;
use std::ptr;
use std::sync::Arc;

use abi_stable::std_types::{RNone, ROption, RSlice, RSome, RStr, RString, RVec};
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
    ///
    /// **Deprecated:** `PluginDataTransmission` (Mumble wire ID 26) is
    /// superseded by the generic `PluginMessage` envelope (wire ID 200).
    /// New integrations should provide and use `send_plugin_message` instead;
    /// this callback is retained only for backward compatibility.
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

    /// Persist a configuration value through the host's settings
    /// layer (typically `mumble-server.ini`).  Returns 0 on success.
    /// Used by the plugin-admin FFI to toggle plugin enable/disable
    /// flags so they survive a server restart.
    pub set_config: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            key: *const c_char,
            value: *const c_char,
        ) -> c_int,
    >,

    /// Delete every configuration key sharing the given prefix.
    /// Returns 0 on success.  Used when uninstalling a plugin to
    /// strip its `plugin.<name>.*` keys from the server settings.
    pub delete_config_prefix:
        Option<unsafe extern "C" fn(user_data: *mut c_void, prefix: *const c_char) -> c_int>,

    /// Enumerate every session currently joined to `channel_id` on
    /// `server_id`.  On success the host allocates an array of
    /// `*out_count` `u32` session IDs (via the host's allocator) and
    /// returns the pointer; the caller releases it via
    /// [`Self::free_sessions`].  Returns NULL on failure (including
    /// when the channel is unknown).
    pub sessions_in_channel: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            server_id: u32,
            channel_id: u32,
            out_count: *mut usize,
        ) -> *mut u32,
    >,

    /// Enumerate every connected session on `server_id`.  Same
    /// allocation contract as [`Self::sessions_in_channel`].
    pub all_sessions: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            server_id: u32,
            out_count: *mut usize,
        ) -> *mut u32,
    >,

    /// Resolve a username (exact match) to a session ID, writing the
    /// result through `out_session`.  Returns `true` on success and
    /// `false` when no connected user carries that name.
    pub find_session_by_name: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            server_id: u32,
            name: *const c_char,
            out_session: *mut u32,
        ) -> bool,
    >,

    /// Release a session-ID array previously returned by
    /// [`Self::sessions_in_channel`] or [`Self::all_sessions`].
    pub free_sessions:
        Option<unsafe extern "C" fn(user_data: *mut c_void, ptr: *mut u32, count: usize)>,

    /// Deliver a typed response for a server-originated request back to the
    /// host (the return leg of the generalized request/response bridge).  The
    /// host routes by `response_type` (e.g. `"link-preview"`) to the C++
    /// handler that issued the request, correlating via `request_id` and
    /// addressing `target_session`.  `payload` is opaque bytes whose encoding
    /// is defined per `response_type` (JSON for link preview).  Returns 0 on
    /// success, non-zero on error.
    pub send_request_response: Option<
        unsafe extern "C" fn(
            user_data: *mut c_void,
            server_id: u32,
            response_type: *const c_char,
            request_id: *const c_char,
            target_session: u32,
            payload: *const u8,
            payload_len: usize,
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
            Err(_) => return PluginResult::RErr(PluginError::Other("data_id contains NUL".into())),
        };
        let data_ptr = if data.is_empty() {
            ptr::null()
        } else {
            data.as_ptr()
        };
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

    /// Direct C-callback bridge for `send_plugin_message` (wire ID 200).
    /// Used by the host itself (not a plugin context) to broadcast
    /// plugin-lifecycle status (enable/disable) to connected clients.
    /// `target_sessions` are the explicit recipients; channel routing is
    /// not used (`channel_id_present = false`).
    pub(crate) fn send_plugin_message_raw(
        &self,
        server_id: ServerId,
        plugin_name: &str,
        payload_type: &str,
        payload: &[u8],
        target_sessions: &[SessionId],
    ) -> PluginResult<()> {
        let func = match self.callbacks.send_plugin_message {
            Some(f) => f,
            None => {
                return PluginResult::RErr(PluginError::Other(
                    "send_plugin_message callback missing".into(),
                ))
            }
        };
        let name_c = match CString::new(plugin_name) {
            Ok(c) => c,
            Err(_) => {
                return PluginResult::RErr(PluginError::Other("plugin_name contains NUL".into()))
            }
        };
        let type_c = match CString::new(payload_type) {
            Ok(c) => c,
            Err(_) => {
                return PluginResult::RErr(PluginError::Other("payload_type contains NUL".into()))
            }
        };
        let payload_ptr = if payload.is_empty() {
            ptr::null()
        } else {
            payload.as_ptr()
        };
        let targets_ptr = if target_sessions.is_empty() {
            ptr::null()
        } else {
            target_sessions.as_ptr()
        };
        // SAFETY: callback non-null; CStrings + slices live until the call
        // returns; pointers are either NULL or backed by valid memory.
        let rc = unsafe {
            func(
                self.callbacks.user_data,
                server_id,
                name_c.as_ptr(),
                type_c.as_ptr(),
                payload_ptr,
                payload.len(),
                targets_ptr,
                target_sessions.len(),
                false,
                0,
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

    /// Persist a configuration value through the host's `set_config`
    /// callback.  Returns `Err` if the callback is missing, the key or
    /// value contain interior NULs, or the callback itself reported a
    /// non-zero status.
    pub(crate) fn set_config(&self, key: &str, value: &str) -> Result<(), String> {
        let func = self
            .callbacks
            .set_config
            .ok_or_else(|| "set_config callback missing".to_owned())?;
        let key_c = CString::new(key).map_err(|_| "key contains NUL".to_owned())?;
        let val_c = CString::new(value).map_err(|_| "value contains NUL".to_owned())?;
        // SAFETY: callback non-null; key_c / val_c live until return.
        let rc = unsafe { func(self.callbacks.user_data, key_c.as_ptr(), val_c.as_ptr()) };
        if rc == 0 {
            Ok(())
        } else {
            Err(format!("set_config returned {rc}"))
        }
    }

    /// Delete every configuration key sharing `prefix` via the host's
    /// `delete_config_prefix` callback.
    pub(crate) fn delete_config_prefix(&self, prefix: &str) -> Result<(), String> {
        let func = self
            .callbacks
            .delete_config_prefix
            .ok_or_else(|| "delete_config_prefix callback missing".to_owned())?;
        let prefix_c = CString::new(prefix).map_err(|_| "prefix contains NUL".to_owned())?;
        // SAFETY: callback non-null; prefix_c lives until return.
        let rc = unsafe { func(self.callbacks.user_data, prefix_c.as_ptr()) };
        if rc == 0 {
            Ok(())
        } else {
            Err(format!("delete_config_prefix returned {rc}"))
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
        self.inner.send_plugin_data_raw(
            server_id,
            target_session,
            data_id.as_str(),
            data.as_slice(),
        )
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

    fn current_channel(&self, server_id: ServerId, session: SessionId) -> ROption<ChannelId> {
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
                return PluginResult::RErr(PluginError::Other("plugin_name contains NUL".into()))
            }
        };
        let payload_type_c = match CString::new(msg.payload_type.as_str()) {
            Ok(c) => c,
            Err(_) => {
                return PluginResult::RErr(PluginError::Other("payload_type contains NUL".into()))
            }
        };
        let payload_slice = msg.payload.as_slice();
        let payload_ptr = if payload_slice.is_empty() {
            ptr::null()
        } else {
            payload_slice.as_ptr()
        };
        let targets = msg.target_sessions.as_slice();
        let targets_ptr = if targets.is_empty() {
            ptr::null()
        } else {
            targets.as_ptr()
        };
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

    fn sessions_in_channel(&self, server_id: ServerId, channel: ChannelId) -> RVec<SessionId> {
        let Some(func) = self.inner.callbacks.sessions_in_channel else {
            return RVec::new();
        };
        let mut count: usize = 0;
        // SAFETY: callback non-null; `count` is a valid stack slot.
        let ptr = unsafe {
            func(
                self.inner.callbacks.user_data,
                server_id,
                channel,
                &mut count,
            )
        };
        copy_and_free_sessions(self, ptr, count)
    }

    fn all_sessions(&self, server_id: ServerId) -> RVec<SessionId> {
        let Some(func) = self.inner.callbacks.all_sessions else {
            return RVec::new();
        };
        let mut count: usize = 0;
        // SAFETY: callback non-null; `count` is a valid stack slot.
        let ptr = unsafe { func(self.inner.callbacks.user_data, server_id, &mut count) };
        copy_and_free_sessions(self, ptr, count)
    }

    fn find_session_by_name(&self, server_id: ServerId, name: RStr<'_>) -> ROption<SessionId> {
        let Some(func) = self.inner.callbacks.find_session_by_name else {
            return RNone;
        };
        let Ok(name_c) = CString::new(name.as_str()) else {
            return RNone;
        };
        let mut out: u32 = 0;
        // SAFETY: callback non-null; name_c outlives the call; `out`
        // is a valid stack slot.
        let ok = unsafe {
            func(
                self.inner.callbacks.user_data,
                server_id,
                name_c.as_ptr(),
                &mut out,
            )
        };
        if ok {
            RSome(out)
        } else {
            RNone
        }
    }

    fn send_request_response(
        &self,
        server_id: ServerId,
        response_type: RStr<'_>,
        request_id: RStr<'_>,
        target_session: SessionId,
        payload: RSlice<'_, u8>,
    ) -> PluginResult<()> {
        let func = match self.inner.callbacks.send_request_response {
            Some(f) => f,
            None => {
                return PluginResult::RErr(PluginError::Other(
                    "send_request_response callback missing".into(),
                ))
            }
        };
        let type_c = match CString::new(response_type.as_str()) {
            Ok(c) => c,
            Err(_) => {
                return PluginResult::RErr(PluginError::Other("response_type contains NUL".into()))
            }
        };
        let id_c = match CString::new(request_id.as_str()) {
            Ok(c) => c,
            Err(_) => {
                return PluginResult::RErr(PluginError::Other("request_id contains NUL".into()))
            }
        };
        let payload_slice = payload.as_slice();
        let payload_ptr = if payload_slice.is_empty() {
            ptr::null()
        } else {
            payload_slice.as_ptr()
        };
        // SAFETY: callback non-null; CStrings + slice live until the call
        // returns; payload pointer is NULL or backed by `payload_slice`.
        let rc = unsafe {
            func(
                self.inner.callbacks.user_data,
                server_id,
                type_c.as_ptr(),
                id_c.as_ptr(),
                target_session,
                payload_ptr,
                payload_slice.len(),
            )
        };
        if rc == 0 {
            PluginResult::ROk(())
        } else {
            PluginResult::RErr(PluginError::Other(
                format!("send_request_response returned {rc}").into(),
            ))
        }
    }
}

/// Copy a host-allocated session-ID array into an `RVec` and release
/// the original buffer via the host's `free_sessions` callback.  When
/// the buffer is empty or the free callback is missing the data is
/// left untouched (leaking is preferable to a double-free in the
/// missing-callback case).
fn copy_and_free_sessions(ctx: &ScopedContext, ptr: *mut u32, count: usize) -> RVec<SessionId> {
    if ptr.is_null() || count == 0 {
        if !ptr.is_null() {
            if let Some(free) = ctx.inner.callbacks.free_sessions {
                // SAFETY: `ptr` came from the host's allocator and
                // `count` matches the host-reported length.
                unsafe { free(ctx.inner.callbacks.user_data, ptr, count) };
            }
        }
        return RVec::new();
    }
    // SAFETY: host promises `ptr` points to `count` readable `u32`s.
    let slice = unsafe { std::slice::from_raw_parts(ptr, count) };
    let mut out: RVec<SessionId> = RVec::with_capacity(count);
    for s in slice {
        out.push(*s);
    }
    if let Some(free) = ctx.inner.callbacks.free_sessions {
        // SAFETY: `ptr` came from the host allocator; freed exactly once.
        unsafe { free(ctx.inner.callbacks.user_data, ptr, count) };
    }
    out
}
