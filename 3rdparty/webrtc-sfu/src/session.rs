//! Broadcast session management for the SFU.
//!
//! Each [`BroadcastSession`] represents one active screen share: a single
//! inbound WebRTC connection from the broadcaster and zero or more outbound
//! connections to viewers.  The SFU forwards RTP packets from the inbound
//! peer to all outbound peers without re-encoding.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use str0m::change::SdpOffer;
use str0m::net::{Protocol, Receive};
use str0m::{Event, Input, Output, Rtc, RtcConfig};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tracing::{debug, error, trace, warn};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Opaque handle to the SFU runtime.
#[derive(Debug)]
pub struct SfuHandle {
    /// Channel to send commands to the SFU runtime.
    cmd_tx: mpsc::UnboundedSender<SfuCommand>,
    /// Channel to receive events from the SFU runtime.
    event_rx: Mutex<mpsc::UnboundedReceiver<SfuEvent>>,
    /// Join handle for the background runtime thread.
    _runtime_thread: std::thread::JoinHandle<()>,
}

/// Events produced by the SFU that the server should act on.
#[derive(Debug)]
pub enum SfuEvent {
    /// SDP answer ready for a client.
    SdpAnswer {
        /// Mumble session ID of the client to send this answer to.
        target_session: u32,
        /// SDP answer string.
        sdp: String,
    },
    /// A broadcast session ended (broadcaster disconnected or stopped).
    SessionEnded {
        /// Mumble session ID of the broadcaster.
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
    /// Create a new broadcast session.
    CreateSession {
        broadcaster_session: u32,
    },
    /// Handle a broadcaster's SDP offer.
    BroadcasterOffer {
        broadcaster_session: u32,
        sdp: String,
    },
    /// Handle a viewer's SDP offer.
    ViewerOffer {
        broadcaster_session: u32,
        viewer_session: u32,
        sdp: String,
    },
    /// Add an ICE candidate from a client.
    AddIceCandidate {
        broadcaster_session: u32,
        client_session: u32,
        candidate_json: String,
    },
    /// Destroy a broadcast session.
    DestroySession {
        broadcaster_session: u32,
    },
    /// Shut down the SFU.
    Shutdown,
}

// ---------------------------------------------------------------------------
// Broadcast session
// ---------------------------------------------------------------------------

/// A single broadcast session: one inbound (broadcaster) + N outbound (viewers).
#[derive(Debug)]
pub struct BroadcastSession {
    /// Mumble session ID of the broadcaster.
    broadcaster_session: u32,
    /// The inbound WebRTC peer (receives media from broadcaster).
    inbound: Option<PeerState>,
    /// Outbound WebRTC peers, keyed by viewer Mumble session ID.
    outbound: HashMap<u32, PeerState>,
}

/// State for a single WebRTC peer managed by str0m.
#[derive(Debug)]
struct PeerState {
    /// The str0m RTC instance.
    rtc: Rtc,
}

// ---------------------------------------------------------------------------
// SFU runtime
// ---------------------------------------------------------------------------

impl SfuHandle {
    /// Start the SFU runtime on a background thread.
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

                rt.block_on(sfu_event_loop(config, cmd_rx, event_tx));
            })
            .expect("failed to spawn SFU runtime thread");

        Self {
            cmd_tx,
            event_rx: Mutex::new(event_rx),
            _runtime_thread: thread,
        }
    }

    /// Send a command to create a new broadcast session.
    pub fn create_session(&self, broadcaster_session: u32) {
        let _r = self.cmd_tx.send(SfuCommand::CreateSession { broadcaster_session });
    }

    /// Handle a broadcaster's SDP offer.
    pub fn broadcaster_offer(&self, broadcaster_session: u32, sdp: String) {
        let _r = self.cmd_tx.send(SfuCommand::BroadcasterOffer {
            broadcaster_session,
            sdp,
        });
    }

    /// Handle a viewer's SDP offer.
    pub fn viewer_offer(&self, broadcaster_session: u32, viewer_session: u32, sdp: String) {
        let _r = self.cmd_tx.send(SfuCommand::ViewerOffer {
            broadcaster_session,
            viewer_session,
            sdp,
        });
    }

    /// Add an ICE candidate from a client.
    pub fn add_ice_candidate(
        &self,
        broadcaster_session: u32,
        client_session: u32,
        candidate_json: String,
    ) {
        let _r = self.cmd_tx.send(SfuCommand::AddIceCandidate {
            broadcaster_session,
            client_session,
            candidate_json,
        });
    }

    /// Destroy a broadcast session.
    pub fn destroy_session(&self, broadcaster_session: u32) {
        let _r = self.cmd_tx.send(SfuCommand::DestroySession { broadcaster_session });
    }

    /// Poll for the next event (non-blocking).
    pub fn poll_event(&self) -> Option<SfuEvent> {
        self.event_rx
            .lock()
            .ok()
            .and_then(|mut rx| rx.try_recv().ok())
    }

    /// Shut down the SFU.
    pub fn shutdown(&self) {
        let _r = self.cmd_tx.send(SfuCommand::Shutdown);
    }
}

// ---------------------------------------------------------------------------
// Async event loop
// ---------------------------------------------------------------------------

/// Main SFU event loop running on the tokio runtime.
async fn sfu_event_loop(
    config: SfuConfig,
    mut cmd_rx: mpsc::UnboundedReceiver<SfuCommand>,
    event_tx: mpsc::UnboundedSender<SfuEvent>,
) {
    let mut sessions: HashMap<u32, BroadcastSession> = HashMap::new();

    // Shared UDP socket for all peers (demuxed by source address).
    let bind_addr = SocketAddr::from(([0, 0, 0, 0], config.udp_port));
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!("SFU failed to bind UDP socket on {bind_addr}: {e}");
            return;
        }
    };
    let local_addr = socket
        .local_addr()
        .expect("bound socket should have local address");
    // The public address used in ICE candidates: config.public_ip + actual port.
    let public_addr = SocketAddr::new(config.public_ip, local_addr.port());
    debug!("SFU listening on UDP {local_addr} (public {public_addr})");

    let mut udp_buf = vec![0u8; 2000];

    // Periodic tick to drive str0m timeouts (DTLS handshake, ICE keepalive).
    let mut tick_interval = tokio::time::interval(Duration::from_millis(5));
    tick_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            // Process commands from the C++ server.
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(SfuCommand::Shutdown) | None => {
                        debug!("SFU shutting down");
                        break;
                    }
                    Some(cmd) => {
                        handle_command(
                            cmd,
                            &mut sessions,
                            &config,
                            &socket,
                            local_addr,
                            &event_tx,
                        ).await;
                    }
                }
            }
            // Process incoming UDP packets.
            result = socket.recv_from(&mut udp_buf) => {
                match result {
                    Ok((len, source)) => {
                        let data = &udp_buf[..len];
                        handle_udp_packet(
                            source,
                            public_addr,
                            data,
                            &mut sessions,
                            &socket,
                            &event_tx,
                        ).await;
                    }
                    Err(e) => {
                        warn!("SFU UDP recv error: {e}");
                    }
                }
            }
            // Periodic tick to drive str0m timeouts.
            _ = tick_interval.tick() => {
                let now = Instant::now();
                for session in sessions.values_mut() {
                    if let Some(inbound) = &mut session.inbound {
                        let _ = inbound.rtc.handle_input(Input::Timeout(now));
                    }
                    for peer in session.outbound.values_mut() {
                        let _ = peer.rtc.handle_input(Input::Timeout(now));
                    }
                }
            }
        }

        // Drive all str0m instances (poll outputs, send packets).
        drive_all_sessions(&mut sessions, &socket, &event_tx).await;
    }
}

/// Handle a command from the C++ server.
async fn handle_command(
    cmd: SfuCommand,
    sessions: &mut HashMap<u32, BroadcastSession>,
    config: &SfuConfig,
    socket: &Arc<UdpSocket>,
    local_addr: SocketAddr,
    event_tx: &mpsc::UnboundedSender<SfuEvent>,
) {
    match cmd {
        SfuCommand::CreateSession { broadcaster_session } => {
            debug!("SFU: creating session for broadcaster {broadcaster_session}");
            let _prev = sessions.insert(
                broadcaster_session,
                BroadcastSession {
                    broadcaster_session,
                    inbound: None,
                    outbound: HashMap::new(),
                },
            );
        }
        SfuCommand::BroadcasterOffer {
            broadcaster_session,
            sdp,
        } => {
            let Some(session) = sessions.get_mut(&broadcaster_session) else {
                warn!("SFU: no session for broadcaster {broadcaster_session}");
                return;
            };

            match create_receiving_peer(config, socket, local_addr, &sdp) {
                Ok((rtc, answer_sdp)) => {
                    debug!("SFU: broadcaster {broadcaster_session} offer accepted, sending SDP answer ({} bytes)", answer_sdp.len());
                    session.inbound = Some(PeerState {
                        rtc,
                    });
                    let _r = event_tx.send(SfuEvent::SdpAnswer {
                        target_session: broadcaster_session,
                        sdp: answer_sdp,
                    });
                }
                Err(e) => {
                    error!("SFU: failed to create receiving peer: {e}");
                }
            }
        }
        SfuCommand::ViewerOffer {
            broadcaster_session,
            viewer_session,
            sdp,
        } => {
            let Some(session) = sessions.get_mut(&broadcaster_session) else {
                warn!("SFU: no session for broadcaster {broadcaster_session}");
                return;
            };

            match create_sending_peer(config, socket, local_addr, &sdp) {
                Ok((rtc, answer_sdp)) => {
                    debug!("SFU: viewer {viewer_session} offer accepted for broadcaster {broadcaster_session}, sending SDP answer ({} bytes)", answer_sdp.len());
                    let _prev = session.outbound.insert(
                        viewer_session,
                        PeerState {
                            rtc,
                        },
                    );
                    let _r = event_tx.send(SfuEvent::SdpAnswer {
                        target_session: viewer_session,
                        sdp: answer_sdp,
                    });
                }
                Err(e) => {
                    error!("SFU: failed to create sending peer for viewer {viewer_session}: {e}");
                }
            }
        }
        SfuCommand::AddIceCandidate {
            broadcaster_session,
            client_session,
            candidate_json: _candidate_json,
        } => {
            let Some(session) = sessions.get_mut(&broadcaster_session) else {
                return;
            };

            // Route to the correct peer.
            let _peer = if client_session == broadcaster_session {
                session.inbound.as_mut()
            } else {
                session.outbound.get_mut(&client_session)
            };

            // str0m with ICE-lite receives remote candidates via the UDP
            // socket directly (STUN binding requests).  Explicit candidate
            // addition is not needed in ICE-lite mode - the remote peer's
            // candidates are discovered from incoming STUN packets.
            debug!(
                "SFU: ICE candidate from session {client_session} (handled via UDP)"
            );
        }
        SfuCommand::DestroySession { broadcaster_session } => {
            debug!("SFU: destroying session for broadcaster {broadcaster_session}");
            let _removed = sessions.remove(&broadcaster_session);
            let _r = event_tx.send(SfuEvent::SessionEnded { broadcaster_session });
        }
        SfuCommand::Shutdown => {
            // Handled in the main loop.
        }
    }
}

// ---------------------------------------------------------------------------
// Peer creation helpers
// ---------------------------------------------------------------------------

/// Create a receiving peer (for the broadcaster's inbound stream).
fn create_receiving_peer(
    config: &SfuConfig,
    _socket: &Arc<UdpSocket>,
    local_addr: SocketAddr,
    sdp: &str,
) -> Result<(Rtc, String), Box<dyn std::error::Error>> {
    let mut rtc = RtcConfig::new()
        .set_ice_lite(true)
        .set_local_ice_credentials(str0m::IceCreds {
            ufrag: generate_ice_ufrag(),
            pass: generate_ice_pass(),
        })
        .build(Instant::now());

    // Add our public address as a local ICE candidate.
    let public_addr = SocketAddr::new(config.public_ip, local_addr.port());
    rtc.add_local_candidate(str0m::Candidate::host(public_addr, Protocol::Udp)?);

    // Accept the remote SDP offer.
    let offer = SdpOffer::from_sdp_string(sdp)?;
    let answer = rtc.sdp_api().accept_offer(offer)?;
    let answer_sdp = answer.to_sdp_string();

    Ok((rtc, answer_sdp))
}

/// Create a sending peer (for a viewer's outbound stream).
fn create_sending_peer(
    config: &SfuConfig,
    _socket: &Arc<UdpSocket>,
    local_addr: SocketAddr,
    sdp: &str,
) -> Result<(Rtc, String), Box<dyn std::error::Error>> {
    let mut rtc = RtcConfig::new()
        .set_ice_lite(true)
        .set_local_ice_credentials(str0m::IceCreds {
            ufrag: generate_ice_ufrag(),
            pass: generate_ice_pass(),
        })
        .build(Instant::now());

    // Add our public address as a local ICE candidate.
    let public_addr = SocketAddr::new(config.public_ip, local_addr.port());
    rtc.add_local_candidate(str0m::Candidate::host(public_addr, Protocol::Udp)?);

    // Accept the viewer's offer (they want recvonly, we provide sendonly).
    let offer = SdpOffer::from_sdp_string(sdp)?;
    let answer = rtc.sdp_api().accept_offer(offer)?;
    let answer_sdp = answer.to_sdp_string();

    Ok((rtc, answer_sdp))
}

/// Generate a random ICE username fragment.
fn generate_ice_ufrag() -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(8);
    for _ in 0..8 {
        let c = (b'a' + (rand_byte() % 26)) as char;
        let _r = write!(s, "{c}");
    }
    s
}

/// Generate a random ICE password.
fn generate_ice_pass() -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(24);
    for _ in 0..24 {
        let c = (b'a' + (rand_byte() % 26)) as char;
        let _r = write!(s, "{c}");
    }
    s
}

/// Simple random byte using an atomic counter mixed with time.
fn rand_byte() -> u8 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);

    let c = CTR.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    // Mix counter with nanoseconds for better distribution.
    let mixed = (t.subsec_nanos() as u64).wrapping_mul(6364136223846793005).wrapping_add(c);
    (mixed >> 16) as u8
}

/// Classify a UDP packet by its first byte for debugging.
fn classify_packet(data: &[u8]) -> &'static str {
    match data.first().copied() {
        Some(0..=3) => "STUN",
        Some(20..=63) => "DTLS",
        Some(128..=191) => "RTP/RTCP",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// UDP packet handling
// ---------------------------------------------------------------------------

/// Route an incoming UDP packet to the correct str0m peer.
async fn handle_udp_packet(
    source: SocketAddr,
    public_addr: SocketAddr,
    data: &[u8],
    sessions: &mut HashMap<u32, BroadcastSession>,
    _socket: &Arc<UdpSocket>,
    _event_tx: &mpsc::UnboundedSender<SfuEvent>,
) {
    let now = Instant::now();

    // Try to route to a matching peer by checking all sessions.
    // In production, maintain a SocketAddr -> peer lookup table.
    for session in sessions.values_mut() {
        // Try inbound peer first.
        if let Some(inbound) = &mut session.inbound {
            let input = Input::Receive(
                now,
                Receive {
                    proto: Protocol::Udp,
                    source,
                    destination: public_addr,
                    contents: data.try_into().expect("valid UDP data"),
                },
            );
            if inbound.rtc.accepts(&input) {
                trace!("SFU: UDP packet from {source} matched broadcaster {}", session.broadcaster_session);
                let _r = inbound.rtc.handle_input(input);
                return;
            }
        }

        // Try outbound peers.
        for (viewer_id, viewer_peer) in session.outbound.iter_mut() {
            let input = Input::Receive(
                now,
                Receive {
                    proto: Protocol::Udp,
                    source,
                    destination: public_addr,
                    contents: data.try_into().expect("valid UDP data"),
                },
            );
            if viewer_peer.rtc.accepts(&input) {
                trace!("SFU: UDP packet from {source} matched viewer {viewer_id}");
                let _r = viewer_peer.rtc.handle_input(input);
                return;
            }
        }
    }

    debug!("SFU: UDP packet from {source} ({} bytes, type={}) matched no peer", data.len(), classify_packet(data));
}

// ---------------------------------------------------------------------------
// Driving str0m instances
// ---------------------------------------------------------------------------

/// Poll all str0m instances for output and handle events.
async fn drive_all_sessions(
    sessions: &mut HashMap<u32, BroadcastSession>,
    socket: &Arc<UdpSocket>,
    _event_tx: &mpsc::UnboundedSender<SfuEvent>,
) {
    for session in sessions.values_mut() {
        // Collect media from the inbound peer.
        let mut forwarded_media = Vec::new();

        if let Some(inbound) = &mut session.inbound {
            loop {
                match inbound.rtc.poll_output() {
                    Ok(Output::Transmit(t)) => {
                        trace!("SFU: broadcaster {} TX {} bytes to {}", session.broadcaster_session, t.contents.len(), t.destination);
                        let _r = socket.send_to(&t.contents, t.destination).await;
                    }
                    Ok(Output::Event(Event::MediaData(data))) => {
                        trace!(
                            "SFU: broadcaster {} media: mid={} pt={} len={}",
                            session.broadcaster_session,
                            data.mid,
                            data.pt,
                            data.data.len()
                        );
                        // Collect for forwarding to viewers.
                        forwarded_media.push(data);
                    }
                    Ok(Output::Event(ev)) => {
                        debug!("SFU: broadcaster {} event: {ev:?}", session.broadcaster_session);
                    }
                    Ok(Output::Timeout(_)) => break,
                    Err(e) => {
                        warn!("SFU: inbound poll error: {e}");
                        break;
                    }
                }
            }
        }

        // Forward collected media to all outbound peers.
        for (viewer_id, viewer_peer) in session.outbound.iter_mut() {
            // Write forwarded media.
            for media in &forwarded_media {
                // Find a matching writer on the outbound peer.
                // The mid/pt mapping depends on SDP negotiation.
                if let Some(writer) = viewer_peer.rtc.writer(media.mid) {
                    let _r = writer.write(media.pt, media.network_time, media.time, media.data.clone());
                } else {
                    debug!(
                        "SFU: no writer for mid={} on viewer {viewer_id}",
                        media.mid,
                    );
                }
            }

            // Drive the outbound peer's output.
            loop {
                match viewer_peer.rtc.poll_output() {
                    Ok(Output::Transmit(t)) => {
                        trace!("SFU: viewer {viewer_id} TX {} bytes to {}", t.contents.len(), t.destination);
                        let _r = socket.send_to(&t.contents, t.destination).await;
                    }
                    Ok(Output::Event(Event::IceConnectionStateChange(state))) => {
                        debug!("SFU: viewer {viewer_id} ICE state: {state:?}");
                    }
                    Ok(Output::Event(ev)) => {
                        debug!("SFU: viewer {viewer_id} event: {ev:?}");
                    }
                    Ok(Output::Timeout(_)) => break,
                    Err(e) => {
                        warn!("SFU: outbound poll error: {e}");
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ice_ufrag_is_8_chars() {
        let ufrag = generate_ice_ufrag();
        assert_eq!(ufrag.len(), 8);
        assert!(ufrag.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn ice_pass_is_24_chars() {
        let pass = generate_ice_pass();
        assert_eq!(pass.len(), 24);
        assert!(pass.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn sfu_config_is_debug() {
        let config = SfuConfig {
            udp_port: 0,
            public_ip: "127.0.0.1".parse().expect("valid IP"),
        };
        let _ = format!("{config:?}");
    }
}
