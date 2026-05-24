//! End-to-end test of the FFI surface using a fake C-style callback table.
//!
//! With the new dynamic plugin model the host loads zero plugins when no
//! plugin directory is configured, so this test exercises the create →
//! dispatch → destroy cycle without any plugins being present.

#![allow(clippy::expect_used, clippy::unwrap_used, reason = "tests panic on failure")]

// These crates are dependencies of the cdylib but not used directly here.
use abi_stable as _;
use mumble_plugin_api as _;
use serde as _;
use serde_json as _;
use thiserror as _;
use tracing as _;
use tracing_subscriber as _;
use zstd as _;

use std::ffi::{c_char, c_int, CStr, CString};
use std::os::raw::c_void;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use mumble_plugin_host::{
    plugin_host_create, plugin_host_destroy, plugin_host_on_client_connected,
    plugin_host_on_client_disconnected, PluginHostCallbacks,
};

#[derive(Default)]
struct FakeServer {
    sends: AtomicUsize,
    last_data_id: Mutex<Option<String>>,
}

unsafe extern "C" fn cb_send(
    user_data: *mut c_void,
    _server: u32,
    _target: u32,
    data_id: *const c_char,
    _data: *const u8,
    _len: usize,
) -> c_int {
    let server = unsafe { &*(user_data as *const FakeServer) };
    let _ = server.sends.fetch_add(1, Ordering::SeqCst);
    let id = unsafe { CStr::from_ptr(data_id) }
        .to_str()
        .unwrap_or("")
        .to_owned();
    *server.last_data_id.lock().expect("lock") = Some(id);
    0
}

unsafe extern "C" fn cb_active(_user: *mut c_void, _server: u32, _session: u32) -> bool {
    true
}

unsafe extern "C" fn cb_access(_user: *mut c_void, _server: u32, _session: u32, _channel: u32) -> bool {
    true
}

unsafe extern "C" fn cb_perm(_user: *mut c_void, _server: u32, _session: u32, _channel: u32, _perm: u32) -> bool {
    false
}

unsafe extern "C" fn cb_get_config(_user: *mut c_void, _key: *const c_char) -> *mut c_char {
    ptr::null_mut()
}

unsafe extern "C" fn cb_free_string(_user: *mut c_void, ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(unsafe { CString::from_raw(ptr) });
    }
}

#[test]
fn create_dispatch_destroy_roundtrip() {
    let server = Box::new(FakeServer::default());
    let user_data = (&*server as *const FakeServer) as *mut c_void;

    let cb = PluginHostCallbacks {
        user_data,
        send_plugin_data: Some(cb_send),
        is_session_active: Some(cb_active),
        user_has_channel_access: Some(cb_access),
        has_permission: Some(cb_perm),
        current_channel: None,
        get_config: Some(cb_get_config),
        free_string: Some(cb_free_string),
        send_plugin_message: None,
    };

    let handle = unsafe { plugin_host_create(&cb) };
    assert!(!handle.is_null(), "plugin_host_create should succeed");

    let user = CString::new("alice").expect("c-string");
    let cert = CString::new("deadbeef").expect("c-string");
    unsafe {
        plugin_host_on_client_connected(handle, 0, 42, user.as_ptr(), cert.as_ptr());
        plugin_host_on_client_disconnected(handle, 0, 42);
        plugin_host_destroy(handle);
    }

    // No plugins loaded -> no plugin-data sends.
    assert_eq!(server.sends.load(Ordering::SeqCst), 0);
}
