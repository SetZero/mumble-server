use std::time::Instant;

use str0m::media::KeyframeRequestKind;
use str0m::{Event, Output, Rtc};
use tokio::net::UdpSocket;
use tracing::{debug, trace, warn};

use super::broadcast::BroadcastSession;
use super::helpers::SessionStats;
use super::PLI_MIN_INTERVAL;

impl BroadcastSession {
    pub(super) async fn forward_to_viewers(
        &mut self,
        media: &[str0m::media::MediaData],
        socket: &UdpSocket,
    ) -> Vec<str0m::media::KeyframeRequest> {
        if !media.is_empty() && !self.outbound.is_empty() {
            trace!(
                "SFU: forwarding {} frames from broadcaster {} to {} viewer(s)",
                media.len(), self.broadcaster_session, self.outbound.len(),
            );
        }

        let mut keyframe_requests = Vec::new();

        for (viewer_id, rtc) in &mut self.outbound {
            Self::write_media_to_viewer(*viewer_id, rtc, media);
            Self::poll_viewer_output(
                *viewer_id,
                rtc,
                socket,
                &mut self.stats,
                &mut keyframe_requests,
            ).await;
        }

        keyframe_requests
    }

    fn write_media_to_viewer(
        viewer_id: u32,
        rtc: &mut Rtc,
        media: &[str0m::media::MediaData],
    ) {
        let mut write_err = 0u32;
        let mut no_writer = 0u32;
        let mut no_pt_match = 0u32;

        for frame in media {
            let Some(writer) = rtc.writer(frame.mid) else {
                no_writer += 1;
                continue;
            };
            let Some(pt) = writer.match_params(frame.params) else {
                no_pt_match += 1;
                continue;
            };
            if let Err(e) = writer.write(pt, frame.network_time, frame.time, frame.data.clone()) {
                if write_err == 0 {
                    warn!("SFU: write to viewer {viewer_id} failed: {e}");
                }
                write_err += 1;
            }
        }

        if write_err > 0 || no_writer > 0 || no_pt_match > 0 {
            debug!("SFU: viewer {viewer_id} write issues: err={write_err} no_writer={no_writer} no_pt={no_pt_match}");
        }
    }

    async fn poll_viewer_output(
        viewer_id: u32,
        rtc: &mut Rtc,
        socket: &UdpSocket,
        stats: &mut SessionStats,
        keyframe_requests: &mut Vec<str0m::media::KeyframeRequest>,
    ) {
        loop {
            match rtc.poll_output() {
                Ok(Output::Transmit(t)) => {
                    stats.outbound_tx += 1;
                    let _r = socket.send_to(&t.contents, t.destination).await;
                }
                Ok(Output::Event(Event::IceConnectionStateChange(state))) => {
                    trace!("SFU: viewer {viewer_id} ICE state: {state:?}");
                }
                Ok(Output::Event(Event::KeyframeRequest(req))) => {
                    trace!("SFU: viewer {viewer_id} requests keyframe: mid={} kind={:?}", req.mid, req.kind);
                    keyframe_requests.push(req);
                }
                Ok(Output::Event(ev)) => {
                    trace!("SFU: viewer {viewer_id} event: {ev:?}");
                }
                Ok(Output::Timeout(_)) => break,
                Err(e) => {
                    warn!("SFU: outbound poll error for viewer {viewer_id}: {e}");
                    break;
                }
            }
        }
    }

    /// When a viewer just joined, ask the broadcaster for an IDR on EVERY
    /// video track it sends - a screen+camera share must deliver both
    /// pictures immediately, not whenever the periodic keyframe lands.
    pub(super) fn request_initial_keyframe(
        &mut self,
        keyframe_requests: &[str0m::media::KeyframeRequest],
        media: &[str0m::media::MediaData],
    ) {
        if !self.needs_initial_keyframe {
            return;
        }
        // All known track mids; before any media flowed, fall back to the
        // mids named by the viewers' own keyframe requests.
        let mut mids: Vec<_> = self.inbound_mids.clone();
        for source in media.iter().map(|m| m.mid).chain(keyframe_requests.iter().map(|r| r.mid)) {
            if !mids.contains(&source) {
                mids.push(source);
            }
        }
        if mids.is_empty() {
            return;
        }
        let Some(rtc) = &mut self.inbound else { return };

        let mut requested = false;
        for mid in mids {
            let Some(mut writer) = rtc.writer(mid) else { continue };
            match writer.request_keyframe(None, KeyframeRequestKind::Pli) {
                Ok(()) => {
                    debug!(
                        "SFU: requested initial keyframe from broadcaster {} (mid {mid}) for new viewer(s)",
                        self.broadcaster_session,
                    );
                    self.last_pli_forwarded.insert(mid, Instant::now());
                    requested = true;
                }
                Err(e) => warn!(
                    "SFU: failed to request initial keyframe from broadcaster {} (mid {mid}): {e}",
                    self.broadcaster_session,
                ),
            }
        }
        if requested {
            self.needs_initial_keyframe = false;
        }
    }

    /// Forward viewer PLIs to the broadcaster, rate-limited PER TRACK so a
    /// lossy camera track cannot starve the screen track of keyframes (and
    /// vice versa).
    pub(super) fn forward_rate_limited_pli(&mut self, keyframe_requests: &[str0m::media::KeyframeRequest]) {
        if keyframe_requests.is_empty() {
            return;
        }
        let now = Instant::now();
        let Some(rtc) = &mut self.inbound else { return };

        let mut handled: Vec<str0m::media::Mid> = Vec::new();
        for req in keyframe_requests {
            if handled.contains(&req.mid) {
                continue; // one forward per mid per drive tick
            }
            handled.push(req.mid);

            let allowed = self.last_pli_forwarded
                .get(&req.mid)
                .map(|t| now.duration_since(*t) >= PLI_MIN_INTERVAL)
                .unwrap_or(true);
            if !allowed {
                trace!(
                    "SFU: suppressed PLI for broadcaster {} (mid {}, rate limited)",
                    self.broadcaster_session, req.mid,
                );
                continue;
            }

            if let Some(mut writer) = rtc.writer(req.mid) {
                match writer.request_keyframe(req.rid, req.kind) {
                    Ok(()) => {
                        debug!(
                            "SFU: forwarded PLI to broadcaster {} (mid {})",
                            self.broadcaster_session, req.mid,
                        );
                        self.last_pli_forwarded.insert(req.mid, now);
                    }
                    Err(e) => warn!(
                        "SFU: failed to forward PLI to broadcaster {} (mid {}): {e}",
                        self.broadcaster_session, req.mid,
                    ),
                }
            }
        }
    }

    pub(super) fn log_stats(&mut self) {
        let now = Instant::now();
        if !self.stats.is_due(now) || !self.stats.has_activity() {
            return;
        }

        trace!(
            "SFU stats [broadcaster {}]: raw_rx={} media_in={} rtcp_out={} fwd={} viewer_tx={}",
            self.broadcaster_session,
            self.stats.raw_udp_rx, self.stats.inbound_rtp_rx,
            self.stats.inbound_tx, self.stats.frames_forwarded,
            self.stats.outbound_tx,
        );
        self.stats.reset();
        self.stats.last_log = Some(now);
    }
}
