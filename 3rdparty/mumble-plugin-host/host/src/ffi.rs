//! C ABI entry points exposed from the cdylib.
//!
//! All functions in this module are `unsafe extern "C"` because they
//! cross the FFI boundary; their safety contracts are documented above
//! each declaration.
//!
//! Every entry point wraps its body in [`std::panic::catch_unwind`] so a
//! Rust-side panic cannot unwind into the C++ caller (which would be
//! undefined behaviour).  On panic we log and return a safe default.

use std::ffi::{c_char, CStr};
use std::panic::{catch_unwind, AssertUnwindSafe};

use mumble_plugin_api::ClientInfo;

use crate::context::{HostContext, PluginHostCallbacks};
use crate::host::Host;

/// Opaque handle returned by [`plugin_host_create`].
// cbindgen:opaque
#[repr(C)]
#[derive(Debug)]
pub struct PluginHostHandle {
    _private: [u8; 0],
}

/// Run an FFI body, swallowing panics and returning `default` on panic.
fn ffi_guard<R>(name: &'static str, default: R, f: impl FnOnce() -> R) -> R {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(_) => {
            tracing::error!(entry = %name, "panic caught at FFI boundary");
            default
        }
    }
}

/// Initialise tracing and create a new plugin host.
///
/// Returns `NULL` on failure. The returned pointer must be freed with
/// [`plugin_host_destroy`].
///
/// # Safety
/// `callbacks` must point to a fully initialised [`PluginHostCallbacks`]
/// struct that remains valid for the lifetime of the returned handle.
#[no_mangle]
pub unsafe extern "C" fn plugin_host_create(
    callbacks: *const PluginHostCallbacks,
) -> *mut PluginHostHandle {
    ffi_guard("plugin_host_create", std::ptr::null_mut(), || {
        init_tracing();
        if callbacks.is_null() {
            tracing::error!("plugin_host_create called with NULL callbacks");
            return std::ptr::null_mut();
        }
        // SAFETY: caller guarantees `callbacks` points to a valid struct.
        let cb = unsafe { *callbacks };
        let context = HostContext::new(cb);
        match Host::new(context) {
            Ok(host) => Box::into_raw(Box::new(host)).cast::<PluginHostHandle>(),
            Err(e) => {
                tracing::error!(error = %e, "failed to construct plugin host");
                std::ptr::null_mut()
            }
        }
    })
}

/// Destroy a host previously returned by [`plugin_host_create`].
///
/// # Safety
/// `handle` must be a pointer returned by [`plugin_host_create`] and not
/// previously destroyed. After this call the pointer is invalid.
#[no_mangle]
pub unsafe extern "C" fn plugin_host_destroy(handle: *mut PluginHostHandle) {
    ffi_guard("plugin_host_destroy", (), || {
        if handle.is_null() {
            return;
        }
        // SAFETY: handle was produced by `Box::into_raw` in `plugin_host_create`.
        drop(unsafe { Box::from_raw(handle.cast::<Host>()) });
    })
}

/// Notify the host of a newly connected client.
///
/// # Safety
/// `handle` must be valid; `username` and `cert_hash` must be NUL-terminated
/// UTF-8 strings (or NULL, which is treated as the empty string).
#[no_mangle]
pub unsafe extern "C" fn plugin_host_on_client_connected(
    handle: *mut PluginHostHandle,
    server_id: u32,
    session: u32,
    username: *const c_char,
    cert_hash: *const c_char,
) {
    ffi_guard("plugin_host_on_client_connected", (), || {
        let Some(host) = (unsafe { handle_ref(handle) }) else {
            return;
        };
        let info = ClientInfo {
            server_id,
            session_id: session,
            // SAFETY: caller promises NUL-terminated UTF-8 or NULL.
            username: abi_stable::std_types::RString::from(unsafe { cstr_to_string(username) }),
            // SAFETY: same contract.
            cert_hash: abi_stable::std_types::RString::from(unsafe { cstr_to_string(cert_hash) }),
        };
        host.on_client_connected(info);
    })
}

/// Notify the host of a disconnected client.
///
/// # Safety
/// `handle` must be valid.
#[no_mangle]
pub unsafe extern "C" fn plugin_host_on_client_disconnected(
    handle: *mut PluginHostHandle,
    server_id: u32,
    session: u32,
) {
    ffi_guard("plugin_host_on_client_disconnected", (), || {
        let Some(host) = (unsafe { handle_ref(handle) }) else {
            return;
        };
        host.on_client_disconnected(server_id, session);
    })
}

/// Notify the host of an inbound `PluginDataTransmission` message.
///
/// # Safety
/// `handle` must be valid; `data_id` must be NUL-terminated UTF-8 (or NULL);
/// `data` must point to at least `data_len` readable bytes (or NULL when
/// `data_len` is 0).
#[no_mangle]
pub unsafe extern "C" fn plugin_host_on_plugin_data(
    handle: *mut PluginHostHandle,
    server_id: u32,
    sender_session: u32,
    data_id: *const c_char,
    data: *const u8,
    data_len: usize,
) {
    ffi_guard("plugin_host_on_plugin_data", (), || {
        let Some(host) = (unsafe { handle_ref(handle) }) else {
            return;
        };
        // SAFETY: caller promises NUL-terminated UTF-8 or NULL.
        let id = unsafe { cstr_to_string(data_id) };
        let bytes: Vec<u8> = if data.is_null() || data_len == 0 {
            Vec::new()
        } else {
            // SAFETY: caller guarantees `data` is valid for `data_len` bytes.
            unsafe { std::slice::from_raw_parts(data, data_len) }.to_vec()
        };
        host.on_plugin_data(server_id, sender_session, id, bytes);
    })
}

/// Notify the host of an inbound generic `PluginMessage` (wire ID 200).
/// The host routes the envelope to the single plugin whose name matches
/// `plugin_name`; unknown names are dropped with a debug log.
///
/// # Safety
/// `handle` must be valid; every `*const c_char` argument must be either
/// NUL-terminated UTF-8 or NULL (treated as empty).  `payload` must
/// point to at least `payload_len` readable bytes (or NULL when
/// `payload_len` is 0); same contract for `target_sessions` as a
/// `*const u32` of length `target_len`.
#[no_mangle]
pub unsafe extern "C" fn plugin_host_on_plugin_message(
    handle: *mut PluginHostHandle,
    server_id: u32,
    sender_session: u32,
    sender_name: *const c_char,
    plugin_name: *const c_char,
    payload_type: *const c_char,
    payload: *const u8,
    payload_len: usize,
    target_sessions: *const u32,
    target_len: usize,
    channel_id_present: bool,
    channel_id: u32,
) {
    ffi_guard("plugin_host_on_plugin_message", (), || {
        let Some(host) = (unsafe { handle_ref(handle) }) else {
            return;
        };
        // SAFETY: caller contract above.
        let sender_name_s = unsafe { cstr_to_string(sender_name) };
        let plugin_name_s = unsafe { cstr_to_string(plugin_name) };
        let payload_type_s = unsafe { cstr_to_string(payload_type) };
        let payload_vec: Vec<u8> = if payload.is_null() || payload_len == 0 {
            Vec::new()
        } else {
            // SAFETY: caller guarantees `payload` valid for `payload_len`.
            unsafe { std::slice::from_raw_parts(payload, payload_len) }.to_vec()
        };
        let targets: Vec<u32> = if target_sessions.is_null() || target_len == 0 {
            Vec::new()
        } else {
            // SAFETY: caller guarantees `target_sessions` valid for `target_len` u32s.
            unsafe { std::slice::from_raw_parts(target_sessions, target_len) }.to_vec()
        };
        host.on_plugin_message(crate::host::PluginMessageInArgs {
            server_id,
            sender: sender_session,
            sender_name: sender_name_s,
            plugin_name: plugin_name_s,
            payload_type: payload_type_s,
            payload: payload_vec,
            target_sessions: targets,
            channel_id: if channel_id_present {
                Some(channel_id)
            } else {
                None
            },
        });
    })
}

/// Return the JSON-encoded plugin registry payload that the C++ server
/// embeds in a `PluginRegistry` message right after `ServerSync`.  The
/// returned pointer is heap-allocated by Rust (`CString::into_raw`) and
/// must be freed via [`plugin_host_free_string`].  Returns NULL only on
/// catastrophic allocation failure.
///
/// # Safety
/// `handle` must come from [`plugin_host_create`].
#[no_mangle]
pub unsafe extern "C" fn plugin_host_get_registry_json(
    handle: *mut PluginHostHandle,
) -> *mut c_char {
    ffi_guard(
        "plugin_host_get_registry_json",
        std::ptr::null_mut(),
        || {
            let Some(host) = (unsafe { handle_ref(handle) }) else {
                return std::ptr::null_mut();
            };
            let json = host.registry_json();
            match std::ffi::CString::new(json) {
                Ok(c) => c.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        },
    )
}

/// Free a string previously returned by [`plugin_host_get_registry_json`].
///
/// # Safety
/// `ptr` must be either NULL or a pointer obtained from
/// [`plugin_host_get_registry_json`]; calling it on anything else is UB.
#[no_mangle]
pub unsafe extern "C" fn plugin_host_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: caller promises pointer came from CString::into_raw.
    drop(unsafe { std::ffi::CString::from_raw(ptr) });
}

// -- helpers --------------------------------------------------------------

/// SAFETY: Caller must ensure `handle` came from [`plugin_host_create`].
unsafe fn handle_ref<'a>(handle: *mut PluginHostHandle) -> Option<&'a Host> {
    if handle.is_null() {
        return None;
    }
    // SAFETY: caller guarantees the pointer is valid and outlives the borrow.
    Some(unsafe { &*handle.cast::<Host>() })
}

/// SAFETY: `ptr` must be NUL-terminated UTF-8 or NULL. Returns the empty
/// string on NULL or invalid UTF-8.
unsafe fn cstr_to_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // SAFETY: caller promises NUL-termination.
    let cstr = unsafe { CStr::from_ptr(ptr) };
    cstr.to_str().unwrap_or("").to_owned()
}

fn init_tracing() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_env("MUMBLE_PLUGIN_LOG")
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .try_init();
    });
}
