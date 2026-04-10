//! C FFI interface for the WebRTC SFU.
//!
//! All functions in this module are `extern "C"` and use raw pointers / C
//! strings so the Mumble C++ server can call them via dynamic linking.
//!
//! # Lifecycle
//!
//! 1. `sfu_init(config)` -> `SfuHandle*`
//! 2. `sfu_create_session(handle, broadcaster_session)`
//! 3. `sfu_broadcaster_offer(handle, broadcaster_session, sdp)`
//! 4. `sfu_viewer_offer(handle, broadcaster_session, viewer_session, sdp)`
//! 5. `sfu_add_ice_candidate(handle, broadcaster_session, client_session, json)`
//! 6. `sfu_poll_event(handle)` -> `SfuFfiEvent*` (call periodically)
//! 7. `sfu_destroy_session(handle, broadcaster_session)`
//! 8. `sfu_shutdown(handle)` (frees the handle)

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use crate::session::{SfuConfig, SfuEvent, SfuHandle};

// ---------------------------------------------------------------------------
// FFI config
// ---------------------------------------------------------------------------

/// Configuration passed from C++ to initialise the SFU.
#[repr(C)]
pub struct SfuFfiConfig {
    /// UDP port for WebRTC media (0 = OS-assigned).
    pub udp_port: u16,
    /// Public IP address as a null-terminated C string (e.g. "203.0.113.1").
    pub public_ip: *const c_char,
}

// ---------------------------------------------------------------------------
// FFI event
// ---------------------------------------------------------------------------

/// Event types returned by `sfu_poll_event`.
#[repr(C)]
pub enum SfuFfiEventType {
    /// SDP answer ready for a client.
    SdpAnswer = 0,
    /// A broadcast session ended.
    SessionEnded = 1,
}

/// Event struct returned by `sfu_poll_event`.  Must be freed with
/// `sfu_free_event`.
#[repr(C)]
pub struct SfuFfiEvent {
    /// The type of event.
    pub event_type: SfuFfiEventType,
    /// Mumble session ID of the target client (for SDP answers) or
    /// broadcaster (for session-ended events).
    pub session_id: u32,
    /// For SDP answers: the broadcaster whose stream this answer is for.
    /// For session-ended events: same as `session_id`.
    pub broadcaster_session: u32,
    /// Null-terminated payload string (SDP answer text, etc.).
    /// NULL for events without a payload.
    pub payload: *mut c_char,
}

// ---------------------------------------------------------------------------
// FFI functions
// ---------------------------------------------------------------------------

/// Initialise the SFU runtime.  Returns an opaque handle.
/// Returns NULL on failure.
///
/// # Safety
///
/// `config` must point to a valid `SfuFfiConfig`.  `config.public_ip`
/// must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn sfu_init(config: *const SfuFfiConfig) -> *mut SfuHandle {
    // Install a tracing subscriber so SFU log output is visible on stderr.
    // If the subscriber is already set (e.g. called twice), ignore the error.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("webrtc_sfu=debug")),
        )
        .with_target(true)
        .with_writer(std::io::stderr)
        .try_init();

    let Some(config) = (unsafe { config.as_ref() }) else {
        return ptr::null_mut();
    };

    let public_ip_str = if config.public_ip.is_null() {
        "0.0.0.0"
    } else {
        match unsafe { CStr::from_ptr(config.public_ip) }.to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        }
    };

    let public_ip = match public_ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return ptr::null_mut(),
    };

    let handle = SfuHandle::start(SfuConfig {
        udp_port: config.udp_port,
        public_ip,
    });

    Box::into_raw(Box::new(handle))
}

/// Create a new broadcast session for the given broadcaster.
///
/// # Safety
///
/// `handle` must be a valid pointer returned by `sfu_init`.
#[no_mangle]
pub unsafe extern "C" fn sfu_create_session(handle: *mut SfuHandle, broadcaster_session: u32) {
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        return;
    };
    handle.create_session(broadcaster_session);
}

/// Submit a broadcaster's SDP offer to the SFU.  The SDP answer will be
/// available via `sfu_poll_event`.
///
/// # Safety
///
/// `handle` must be valid.  `sdp` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn sfu_broadcaster_offer(
    handle: *mut SfuHandle,
    broadcaster_session: u32,
    sdp: *const c_char,
) {
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        return;
    };
    let sdp = match c_str_to_string(sdp) {
        Some(s) => s,
        None => return,
    };
    handle.broadcaster_offer(broadcaster_session, sdp);
}

/// Submit a viewer's SDP offer.  The SDP answer will be available via
/// `sfu_poll_event`.
///
/// # Safety
///
/// `handle` must be valid.  `sdp` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn sfu_viewer_offer(
    handle: *mut SfuHandle,
    broadcaster_session: u32,
    viewer_session: u32,
    sdp: *const c_char,
) {
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        return;
    };
    let sdp = match c_str_to_string(sdp) {
        Some(s) => s,
        None => return,
    };
    handle.viewer_offer(broadcaster_session, viewer_session, sdp);
}

/// Add an ICE candidate from a client.
///
/// # Safety
///
/// `handle` must be valid.  `candidate_json` must be a valid
/// null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn sfu_add_ice_candidate(
    handle: *mut SfuHandle,
    broadcaster_session: u32,
    client_session: u32,
    candidate_json: *const c_char,
) {
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        return;
    };
    let json = match c_str_to_string(candidate_json) {
        Some(s) => s,
        None => return,
    };
    handle.add_ice_candidate(broadcaster_session, client_session, json);
}

/// Poll for the next event from the SFU.  Returns NULL if no events are
/// queued.  The returned pointer must be freed with `sfu_free_event`.
///
/// # Safety
///
/// `handle` must be valid.
#[no_mangle]
pub unsafe extern "C" fn sfu_poll_event(handle: *mut SfuHandle) -> *mut SfuFfiEvent {
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        return ptr::null_mut();
    };

    let event = match handle.poll_event() {
        Some(e) => e,
        None => return ptr::null_mut(),
    };

    match event {
        SfuEvent::SdpAnswer { target_session, broadcaster_session, sdp } => {
            let payload = CString::new(sdp).unwrap_or_default();
            Box::into_raw(Box::new(SfuFfiEvent {
                event_type: SfuFfiEventType::SdpAnswer,
                session_id: target_session,
                broadcaster_session,
                payload: payload.into_raw(),
            }))
        }
        SfuEvent::SessionEnded { broadcaster_session } => {
            Box::into_raw(Box::new(SfuFfiEvent {
                event_type: SfuFfiEventType::SessionEnded,
                session_id: broadcaster_session,
                broadcaster_session,
                payload: ptr::null_mut(),
            }))
        }
    }
}

/// Free an event returned by `sfu_poll_event`.
///
/// # Safety
///
/// `event` must be a pointer returned by `sfu_poll_event`, or NULL.
#[no_mangle]
pub unsafe extern "C" fn sfu_free_event(event: *mut SfuFfiEvent) {
    if event.is_null() {
        return;
    }
    let event = unsafe { Box::from_raw(event) };
    if !event.payload.is_null() {
        drop(unsafe { CString::from_raw(event.payload) });
    }
}

/// Destroy a broadcast session, closing all associated WebRTC connections.
///
/// # Safety
///
/// `handle` must be valid.
#[no_mangle]
pub unsafe extern "C" fn sfu_destroy_session(handle: *mut SfuHandle, broadcaster_session: u32) {
    let Some(handle) = (unsafe { handle.as_ref() }) else {
        return;
    };
    handle.destroy_session(broadcaster_session);
}

/// Shut down the SFU runtime and free the handle.
///
/// # Safety
///
/// `handle` must be a pointer returned by `sfu_init`.  After this call
/// the pointer is invalid.
#[no_mangle]
pub unsafe extern "C" fn sfu_shutdown(handle: *mut SfuHandle) {
    if handle.is_null() {
        return;
    }
    let handle = unsafe { Box::from_raw(handle) };
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a C string pointer to an owned Rust `String`.
/// Returns `None` if the pointer is null or not valid UTF-8.
fn c_str_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: caller guarantees ptr is a valid null-terminated C string.
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .ok()
        .map(String::from)
}
