use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, trace, warn};

use super::broadcast::BroadcastSession;
use super::helpers::classify_packet;
use super::{
    SfuCommand, SfuConfig, SfuEvent,
    MAX_BATCH_DRAIN, SOCKET_BUF_SIZE, TICK_INTERVAL, UDP_BUF_SIZE,
};

// ---------------------------------------------------------------------------
// SfuRuntime - owns socket, sessions, and the event loop
// ---------------------------------------------------------------------------

pub(super) struct SfuRuntime {
    sessions: HashMap<u32, BroadcastSession>,
    socket: UdpSocket,
    public_addr: SocketAddr,
    config: SfuConfig,
}

impl SfuRuntime {
    pub(super) fn new(config: SfuConfig) -> Option<Self> {
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], config.udp_port));
        let socket = Self::bind_socket(bind_addr)?;
        let local_addr = socket
            .local_addr()
            .expect("bound socket should have local address");
        let public_addr = SocketAddr::new(config.public_ip, local_addr.port());
        debug!("SFU listening on UDP {local_addr} (public {public_addr})");

        Some(Self {
            sessions: HashMap::new(),
            socket,
            public_addr,
            config,
        })
    }

    fn bind_socket(addr: SocketAddr) -> Option<UdpSocket> {
        let std_socket = match std::net::UdpSocket::bind(addr) {
            Ok(s) => s,
            Err(e) => {
                error!("SFU failed to bind UDP socket on {addr}: {e}");
                return None;
            }
        };
        let sock2 = socket2::Socket::from(std_socket);
        if let Err(e) = sock2.set_recv_buffer_size(SOCKET_BUF_SIZE) {
            warn!("SFU: failed to set UDP recv buffer to 2 MiB: {e}");
        }
        if let Err(e) = sock2.set_send_buffer_size(SOCKET_BUF_SIZE) {
            warn!("SFU: failed to set UDP send buffer to 2 MiB: {e}");
        }
        let std_socket: std::net::UdpSocket = sock2.into();
        std_socket
            .set_nonblocking(true)
            .expect("non-blocking UDP socket");
        match UdpSocket::from_std(std_socket) {
            Ok(s) => Some(s),
            Err(e) => {
                error!("SFU failed to create async UDP socket: {e}");
                None
            }
        }
    }

    pub(super) async fn run(
        &mut self,
        mut cmd_rx: mpsc::UnboundedReceiver<SfuCommand>,
        event_tx: mpsc::UnboundedSender<SfuEvent>,
    ) {
        let mut udp_buf = vec![0u8; UDP_BUF_SIZE];
        let mut tick_interval = tokio::time::interval(TICK_INTERVAL);
        tick_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;

                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(SfuCommand::Shutdown) | None => {
                            debug!("SFU shutting down");
                            break;
                        }
                        Some(cmd) => self.handle_command(cmd, &event_tx),
                    }
                }
                result = self.socket.recv_from(&mut udp_buf) => {
                    match result {
                        Ok((len, source)) => {
                            self.route_udp_packet(source, &udp_buf[..len]);
                            self.batch_drain_udp(&mut udp_buf);
                        }
                        Err(e) => warn!("SFU UDP recv error: {e}"),
                    }
                }
                _ = tick_interval.tick() => {}
            }

            self.advance_timers();
            self.drive_all_sessions().await;
        }
    }

    fn route_udp_packet(&mut self, source: SocketAddr, data: &[u8]) {
        let now = Instant::now();
        let public_addr = self.public_addr;

        for session in self.sessions.values_mut() {
            if session.try_route_inbound(now, source, public_addr, data) {
                return;
            }
            if session.try_route_outbound(now, source, public_addr, data) {
                return;
            }
        }

        trace!(
            "SFU: UDP packet from {source} ({} bytes, type={}) matched no peer",
            data.len(),
            classify_packet(data),
        );
    }

    fn batch_drain_udp(&mut self, udp_buf: &mut [u8]) {
        for _ in 0..MAX_BATCH_DRAIN {
            match self.socket.try_recv_from(udp_buf) {
                Ok((len, source)) => self.route_udp_packet(source, &udp_buf[..len]),
                Err(_) => break,
            }
        }
    }

    fn advance_timers(&mut self) {
        let now = Instant::now();
        for session in self.sessions.values_mut() {
            session.advance_timers(now);
        }
    }

    async fn drive_all_sessions(&mut self) {
        for session in self.sessions.values_mut() {
            session.drive(&self.socket).await;
        }
    }

    fn handle_command(&mut self, cmd: SfuCommand, event_tx: &mpsc::UnboundedSender<SfuEvent>) {
        match cmd {
            SfuCommand::CreateSession { broadcaster_session } => {
                if self.sessions.contains_key(&broadcaster_session) {
                    debug!("SFU: session for broadcaster {broadcaster_session} already exists");
                    return;
                }
                debug!("SFU: creating session for broadcaster {broadcaster_session}");
                self.sessions.insert(
                    broadcaster_session,
                    BroadcastSession::new(broadcaster_session),
                );
            }
            SfuCommand::BroadcasterOffer { broadcaster_session, sdp } => {
                let Some(session) = self.sessions.get_mut(&broadcaster_session) else {
                    warn!("SFU: no session for broadcaster {broadcaster_session}");
                    return;
                };
                match session.accept_broadcaster_offer(&self.config, &self.socket, &sdp) {
                    Ok(answer_sdp) => {
                        debug!(
                            "SFU: broadcaster {broadcaster_session} offer accepted\n\
                             --- OFFER ---\n{sdp}\n--- ANSWER ---\n{answer_sdp}\n---",
                        );
                        let _r = event_tx.send(SfuEvent::SdpAnswer {
                            target_session: broadcaster_session,
                            broadcaster_session,
                            sdp: answer_sdp,
                        });
                    }
                    Err(e) => error!("SFU: failed to create receiving peer: {e}"),
                }
            }
            SfuCommand::ViewerOffer { broadcaster_session, viewer_session, sdp } => {
                let Some(session) = self.sessions.get_mut(&broadcaster_session) else {
                    warn!("SFU: no session for broadcaster {broadcaster_session}");
                    return;
                };
                match session.accept_viewer_offer(&self.config, &self.socket, viewer_session, &sdp) {
                    Ok(answer_sdp) => {
                        debug!(
                            "SFU: viewer {viewer_session} offer accepted for broadcaster \
                             {broadcaster_session} ({} bytes)",
                            answer_sdp.len(),
                        );
                        let _r = event_tx.send(SfuEvent::SdpAnswer {
                            target_session: viewer_session,
                            broadcaster_session,
                            sdp: answer_sdp,
                        });
                    }
                    Err(e) => error!("SFU: failed to create sending peer for viewer {viewer_session}: {e}"),
                }
            }
            SfuCommand::AddIceCandidate { client_session, .. } => {
                debug!("SFU: ICE candidate from session {client_session} (handled via UDP)");
            }
            SfuCommand::DestroySession { broadcaster_session } => {
                debug!("SFU: destroying session for broadcaster {broadcaster_session}");
                self.sessions.remove(&broadcaster_session);
                let _r = event_tx.send(SfuEvent::SessionEnded { broadcaster_session });
            }
            SfuCommand::Shutdown => {}
        }
    }
}
