//! Broadcast session management for the SFU.
//!
//! Each [`BroadcastSession`] represents one active screen share: a single
//! inbound WebRTC connection from the broadcaster and zero or more outbound
//! connections to viewers.  The SFU forwards RTP packets from the inbound
//! peer to all outbound peers without re-encoding.

mod broadcast;
mod forward;
mod helpers;
mod runtime;

pub use broadcast::BroadcastSession;

use std::sync::Mutex;

use tokio::sync::mpsc;
use tokio::time::Duration;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SOCKET_BUF_SIZE: usize = 2 * 1024 * 1024;
const UDP_BUF_SIZE: usize = 2000;
const TICK_INTERVAL: Duration = Duration::from_millis(5);
const STATS_INTERVAL: Duration = Duration::from_secs(5);
const STATS_LOG_INTERVAL: Duration = Duration::from_secs(2);
const REMB_INTERVAL: Duration = Duration::from_secs(1);
const REMB_BITRATE_BPS: u64 = 50_000_000;
const PLI_MIN_INTERVAL: Duration = Duration::from_secs(1);
const MAX_BATCH_DRAIN: usize = 200;
const ICE_UFRAG_LEN: usize = 8;
const ICE_PASS_LEN: usize = 24;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Opaque handle to the SFU runtime.
#[derive(Debug)]
pub struct SfuHandle {
    cmd_tx: mpsc::UnboundedSender<SfuCommand>,
    event_rx: Mutex<mpsc::UnboundedReceiver<SfuEvent>>,
    _runtime_thread: std::thread::JoinHandle<()>,
}

/// Events produced by the SFU that the server should act on.
#[derive(Debug)]
pub enum SfuEvent {
    SdpAnswer {
        target_session: u32,
        sdp: String,
    },
    SessionEnded {
        broadcaster_session: u32,
    },
}

/// Configuration for the SFU.
#[derive(Debug, Clone)]
pub struct SfuConfig {
    /// UDP port for WebRTC media (0 = OS-assigned).
    pub udp_port: u16,
    /// Public IP address for ICE candidates in SDP answers.
    pub public_ip: std::net::IpAddr,
}

// ---------------------------------------------------------------------------
// Internal command type
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum SfuCommand {
    CreateSession { broadcaster_session: u32 },
    BroadcasterOffer { broadcaster_session: u32, sdp: String },
    ViewerOffer { broadcaster_session: u32, viewer_session: u32, sdp: String },
    AddIceCandidate { client_session: u32 },
    DestroySession { broadcaster_session: u32 },
    Shutdown,
}

// ---------------------------------------------------------------------------
// SfuHandle - public command interface
// ---------------------------------------------------------------------------

impl SfuHandle {
    pub fn start(config: SfuConfig) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let thread = std::thread::Builder::new()
            .name("sfu-runtime".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .expect("failed to create SFU tokio runtime");

                rt.block_on(async {
                    let mut runtime = match runtime::SfuRuntime::new(config) {
                        Some(rt) => rt,
                        None => return,
                    };
                    runtime.run(cmd_rx, event_tx).await;
                });
            })
            .expect("failed to spawn SFU runtime thread");

        Self {
            cmd_tx,
            event_rx: Mutex::new(event_rx),
            _runtime_thread: thread,
        }
    }

    pub fn create_session(&self, broadcaster_session: u32) {
        let _r = self.cmd_tx.send(SfuCommand::CreateSession { broadcaster_session });
    }

    pub fn broadcaster_offer(&self, broadcaster_session: u32, sdp: String) {
        let _r = self.cmd_tx.send(SfuCommand::BroadcasterOffer { broadcaster_session, sdp });
    }

    pub fn viewer_offer(&self, broadcaster_session: u32, viewer_session: u32, sdp: String) {
        let _r = self.cmd_tx.send(SfuCommand::ViewerOffer { broadcaster_session, viewer_session, sdp });
    }

    pub fn add_ice_candidate(&self, _broadcaster_session: u32, client_session: u32, _candidate_json: String) {
        let _r = self.cmd_tx.send(SfuCommand::AddIceCandidate { client_session });
    }

    pub fn destroy_session(&self, broadcaster_session: u32) {
        let _r = self.cmd_tx.send(SfuCommand::DestroySession { broadcaster_session });
    }

    pub fn poll_event(&self) -> Option<SfuEvent> {
        self.event_rx
            .lock()
            .ok()
            .and_then(|mut rx| rx.try_recv().ok())
    }

    pub fn shutdown(&self) {
        let _r = self.cmd_tx.send(SfuCommand::Shutdown);
    }
}
