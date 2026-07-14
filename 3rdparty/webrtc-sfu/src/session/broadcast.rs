use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use str0m::bwe::Bitrate;
use str0m::change::SdpOffer;
use str0m::media::Mid;
use str0m::net::{Protocol, Receive};
use str0m::rtp::Extension;
use str0m::{Event, Input, Output, Rtc, RtcConfig};
use tokio::net::UdpSocket;
use tracing::{debug, trace, warn};

use super::helpers::{generate_ice_creds, SessionStats};
use super::{SfuConfig, REMB_BITRATE_BPS, REMB_INTERVAL, STATS_INTERVAL};

// ---------------------------------------------------------------------------
// BroadcastSession
// ---------------------------------------------------------------------------

/// A single broadcast session: one inbound (broadcaster) + N outbound (viewers).
/// The inbound peer may carry several video tracks (screen + camera), each on
/// its own mid; all of them are forwarded to every viewer.
#[derive(Debug)]
pub struct BroadcastSession {
    pub(super) broadcaster_session: u32,
    pub(super) inbound: Option<Rtc>,
    pub(super) outbound: HashMap<u32, Rtc>,
    pub(super) stats: SessionStats,
    pub(super) last_pli_forwarded: HashMap<Mid, Instant>,
    pub(super) needs_initial_keyframe: bool,
    pub(super) last_remb_sent: Option<Instant>,
    pub(super) inbound_mids: Vec<Mid>,
}

impl BroadcastSession {
    pub(super) fn new(broadcaster_session: u32) -> Self {
        Self {
            broadcaster_session,
            inbound: None,
            outbound: HashMap::new(),
            stats: SessionStats::default(),
            last_pli_forwarded: HashMap::new(),
            needs_initial_keyframe: false,
            last_remb_sent: None,
            inbound_mids: Vec::new(),
        }
    }

    pub(super) fn accept_broadcaster_offer(
        &mut self,
        config: &SfuConfig,
        socket: &UdpSocket,
        sdp: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let (rtc, answer_sdp) = Self::create_receiving_peer(config, socket, sdp)?;
        self.inbound = Some(rtc);
        // A re-offer (broadcaster replaced its capture set) starts a fresh
        // peer whose track set/mids may differ; re-discover them.
        self.inbound_mids.clear();
        self.last_pli_forwarded.clear();
        Ok(answer_sdp)
    }

    pub(super) fn accept_viewer_offer(
        &mut self,
        config: &SfuConfig,
        socket: &UdpSocket,
        viewer_session: u32,
        sdp: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let (rtc, answer_sdp) = Self::create_sending_peer(config, socket, sdp)?;
        self.outbound.insert(viewer_session, rtc);
        self.needs_initial_keyframe = true;
        Ok(answer_sdp)
    }

    pub(super) fn try_route_inbound(
        &mut self,
        now: Instant,
        source: SocketAddr,
        destination: SocketAddr,
        data: &[u8],
    ) -> bool {
        let Some(rtc) = &mut self.inbound else { return false };
        let input = Input::Receive(now, Receive {
            proto: Protocol::Udp,
            source,
            destination,
            contents: data.try_into().expect("valid UDP data"),
        });
        if !rtc.accepts(&input) {
            return false;
        }
        self.stats.raw_udp_rx += 1;
        if let Err(e) = rtc.handle_input(input) {
            warn!("SFU: inbound handle_input error for broadcaster {}: {e}", self.broadcaster_session);
        }
        true
    }

    pub(super) fn try_route_outbound(
        &mut self,
        now: Instant,
        source: SocketAddr,
        destination: SocketAddr,
        data: &[u8],
    ) -> bool {
        for (viewer_id, rtc) in &mut self.outbound {
            let input = Input::Receive(now, Receive {
                proto: Protocol::Udp,
                source,
                destination,
                contents: data.try_into().expect("valid UDP data"),
            });
            if rtc.accepts(&input) {
                if let Err(e) = rtc.handle_input(input) {
                    warn!("SFU: outbound handle_input error for viewer {viewer_id}: {e}");
                }
                return true;
            }
        }
        false
    }

    pub(super) fn advance_timers(&mut self, now: Instant) {
        if let Some(rtc) = &mut self.inbound {
            let _ = rtc.handle_input(Input::Timeout(now));
        }
        for rtc in self.outbound.values_mut() {
            let _ = rtc.handle_input(Input::Timeout(now));
        }
    }

    pub(super) async fn drive(&mut self, socket: &UdpSocket) {
        let forwarded_media = self.poll_inbound(socket).await;
        self.stats.frames_forwarded += forwarded_media.len() as u32;
        self.discover_inbound_mids(&forwarded_media);
        self.send_remb();
        let keyframe_requests = self.forward_to_viewers(&forwarded_media, socket).await;
        self.request_initial_keyframe(&keyframe_requests, &forwarded_media);
        self.forward_rate_limited_pli(&keyframe_requests);
        self.log_stats();
    }

    async fn poll_inbound(&mut self, socket: &UdpSocket) -> Vec<str0m::media::MediaData> {
        let mut media = Vec::new();
        let Some(rtc) = &mut self.inbound else { return media };

        loop {
            match rtc.poll_output() {
                Ok(Output::Transmit(t)) => {
                    self.stats.inbound_tx += 1;
                    let _r = socket.send_to(&t.contents, t.destination).await;
                }
                Ok(Output::Event(Event::MediaData(data))) => {
                    self.stats.inbound_rtp_rx += 1;
                    trace!(
                        "SFU: broadcaster {} media: mid={} pt={} len={}",
                        self.broadcaster_session, data.mid, data.pt, data.data.len(),
                    );
                    media.push(data);
                }
                Ok(Output::Event(ev)) => {
                    trace!("SFU: broadcaster {} event: {ev:?}", self.broadcaster_session);
                }
                Ok(Output::Timeout(_)) => break,
                Err(e) => {
                    warn!("SFU: inbound poll error: {e}");
                    break;
                }
            }
        }
        media
    }

    /// Learn the broadcaster's video mids from the media actually flowing.
    /// A multi-track broadcast (screen + camera) surfaces one mid per track.
    fn discover_inbound_mids(&mut self, media: &[str0m::media::MediaData]) {
        for frame in media {
            if !self.inbound_mids.contains(&frame.mid) {
                self.inbound_mids.push(frame.mid);
                debug!(
                    "SFU: discovered inbound mid={} for broadcaster {} ({} total)",
                    frame.mid, self.broadcaster_session, self.inbound_mids.len(),
                );
            }
        }
    }

    /// Periodically send REMB to tell the broadcaster we can handle a generous
    /// bitrate.  This replaces TWCC-based congestion control (see
    /// [`Self::create_receiving_peer`] for rationale).  Sent per inbound mid;
    /// the allowance is per-track, matching the per-track encoders client-side.
    fn send_remb(&mut self) {
        if self.inbound_mids.is_empty() {
            return;
        }
        let Some(rtc) = &mut self.inbound else { return };

        let due = self.last_remb_sent
            .map(|t| Instant::now().duration_since(t) >= REMB_INTERVAL)
            .unwrap_or(true);
        if !due {
            return;
        }

        for mid in &self.inbound_mids {
            if let Some(stream) = rtc.direct_api().stream_rx_by_mid(*mid, None) {
                stream.request_remb(Bitrate::from(REMB_BITRATE_BPS as f64));
                trace!(
                    "SFU: sent REMB {REMB_BITRATE_BPS} bps to broadcaster {} (mid {mid})",
                    self.broadcaster_session,
                );
            }
        }
        self.last_remb_sent = Some(Instant::now());
    }

    // -- Peer creation (associated functions) --------------------------------

    /// Create a receiving peer (for the broadcaster's inbound stream).
    ///
    /// Builds a custom extension map WITHOUT `TransportSequenceNumber`.
    ///
    /// When the SFU reads packets from the kernel's UDP socket buffer, it
    /// processes them in a burst: all RTP packets belonging to a single video
    /// frame receive nearly identical `Instant::now()` timestamps (microseconds
    /// apart), even though Chrome's pacer sent them spread over tens of
    /// milliseconds.  TWCC feedback built from these compressed timestamps
    /// makes Chrome's delay-based congestion controller (GCC) detect false
    /// "overuse" at every frame boundary and progressively throttle the send
    /// rate to <1 fps within 3 seconds.
    ///
    /// Removing the transport-cc header extension from the SDP answer tells
    /// Chrome not to use send-side TWCC-based bandwidth estimation.  Instead,
    /// the SFU periodically sends REMB (goog-remb, still negotiated in the
    /// codec feedback lines) with a generous bitrate allowance so Chrome
    /// maintains full send rate.
    fn create_receiving_peer(
        config: &SfuConfig,
        socket: &UdpSocket,
        sdp: &str,
    ) -> Result<(Rtc, String), Box<dyn std::error::Error>> {
        let rtc_config = RtcConfig::new()
            .clear_extension_map()
            .set_extension(1, Extension::AudioLevel)
            .set_extension(2, Extension::AbsoluteSendTime)
            .set_extension(4, Extension::RtpMid)
            .set_extension(10, Extension::RtpStreamId)
            .set_extension(11, Extension::RepairedRtpStreamId)
            .set_extension(13, Extension::VideoOrientation)
            .set_ice_lite(true)
            .set_local_ice_credentials(generate_ice_creds())
            .set_stats_interval(Some(STATS_INTERVAL));
        Self::negotiate_peer(rtc_config, config, socket, sdp)
    }

    fn create_sending_peer(
        config: &SfuConfig,
        socket: &UdpSocket,
        sdp: &str,
    ) -> Result<(Rtc, String), Box<dyn std::error::Error>> {
        let rtc_config = RtcConfig::new()
            .set_ice_lite(true)
            .set_local_ice_credentials(generate_ice_creds())
            .set_stats_interval(Some(STATS_INTERVAL));
        Self::negotiate_peer(rtc_config, config, socket, sdp)
    }

    fn negotiate_peer(
        rtc_config: RtcConfig,
        config: &SfuConfig,
        socket: &UdpSocket,
        sdp: &str,
    ) -> Result<(Rtc, String), Box<dyn std::error::Error>> {
        let mut rtc = rtc_config.build(Instant::now());
        let public_addr = SocketAddr::new(
            config.public_ip,
            socket.local_addr()?.port(),
        );
        rtc.add_local_candidate(str0m::Candidate::host(public_addr, Protocol::Udp)?);
        let offer = SdpOffer::from_sdp_string(sdp)?;
        let answer = rtc.sdp_api().accept_offer(offer)?;
        Ok((rtc, answer.to_sdp_string()))
    }
}
