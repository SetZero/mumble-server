//! WebRTC Selective Forwarding Unit for Mumble screen sharing.
//!
//! This crate provides a server-side SFU that receives a single WebRTC
//! stream from a broadcaster and re-broadcasts it to N viewers.  Each
//! viewer gets its own WebRTC connection to the server.
//!
//! # Architecture
//!
//! - Uses [`str0m`] in Sans-IO mode: the crate manages its own UDP
//!   sockets via a [`tokio`] runtime running on a background thread.
//! - Exposes a C FFI for integration with the C++ Mumble server.
//! - Uses ICE-lite on the server side (no candidate gathering).
//!
//! # Signal flow
//!
//! ```text
//! Broadcaster                 Server SFU              Viewer
//!    |-- START (broadcast) -->| relay to ch |<------ |
//!    |-- SDP_OFFER --------->| create recv |         |
//!    |<-- SDP_ANSWER --------| peer        |         |
//!    |-- ICE_CANDIDATE ----->|             |         |
//!    |===== media (UDP) ====>|             |         |
//!    |                       |<-- SDP_OFFER ---------|
//!    |                       | create send |         |
//!    |                       |-- SDP_ANSWER -------->|
//!    |                       |===== media (UDP) ===>|
//! ```

mod session;
pub mod ffi;

pub use session::{BroadcastSession, SfuConfig, SfuEvent, SfuHandle};
