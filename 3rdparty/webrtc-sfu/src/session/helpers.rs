use std::time::Instant;

use super::{ICE_UFRAG_LEN, ICE_PASS_LEN, STATS_LOG_INTERVAL};

// ---------------------------------------------------------------------------
// SessionStats
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub(super) struct SessionStats {
    pub(super) last_log: Option<Instant>,
    pub(super) raw_udp_rx: u32,
    pub(super) inbound_rtp_rx: u32,
    pub(super) inbound_tx: u32,
    pub(super) frames_forwarded: u32,
    pub(super) outbound_tx: u32,
}

impl SessionStats {
    pub(super) fn has_activity(&self) -> bool {
        self.inbound_rtp_rx > 0 || self.inbound_tx > 0 || self.raw_udp_rx > 0
    }

    pub(super) fn is_due(&self, now: Instant) -> bool {
        self.last_log
            .map(|t| now.duration_since(t) >= STATS_LOG_INTERVAL)
            .unwrap_or(true)
    }

    pub(super) fn reset(&mut self) {
        self.raw_udp_rx = 0;
        self.inbound_rtp_rx = 0;
        self.inbound_tx = 0;
        self.frames_forwarded = 0;
        self.outbound_tx = 0;
    }
}

// ---------------------------------------------------------------------------
// ICE credential generation
// ---------------------------------------------------------------------------

pub(super) fn generate_ice_creds() -> str0m::IceCreds {
    str0m::IceCreds {
        ufrag: random_alpha_string(ICE_UFRAG_LEN),
        pass: random_alpha_string(ICE_PASS_LEN),
    }
}

fn random_alpha_string(len: usize) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        let c = (b'a' + (rand_byte() % 26)) as char;
        let _r = write!(s, "{c}");
    }
    s
}

fn rand_byte() -> u8 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);

    let c = CTR.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let mixed = (t.subsec_nanos() as u64)
        .wrapping_mul(6364136223846793005)
        .wrapping_add(c);
    (mixed >> 16) as u8
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(super) fn classify_packet(data: &[u8]) -> &'static str {
    match data.first().copied() {
        Some(0..=3) => "STUN",
        Some(20..=63) => "DTLS",
        Some(128..=191) => "RTP/RTCP",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ice_credentials_have_correct_lengths() {
        let creds = generate_ice_creds();
        assert_eq!(creds.ufrag.len(), super::super::ICE_UFRAG_LEN);
        assert!(creds.ufrag.chars().all(|c| c.is_ascii_lowercase()));
        assert_eq!(creds.pass.len(), super::super::ICE_PASS_LEN);
        assert!(creds.pass.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn sfu_config_is_debug() {
        let config = super::super::SfuConfig {
            udp_port: 0,
            public_ip: "127.0.0.1".parse().expect("valid IP"),
        };
        let _ = format!("{config:?}");
    }

    #[test]
    fn classify_packet_variants() {
        assert_eq!(classify_packet(&[0]), "STUN");
        assert_eq!(classify_packet(&[3]), "STUN");
        assert_eq!(classify_packet(&[20]), "DTLS");
        assert_eq!(classify_packet(&[63]), "DTLS");
        assert_eq!(classify_packet(&[128]), "RTP/RTCP");
        assert_eq!(classify_packet(&[191]), "RTP/RTCP");
        assert_eq!(classify_packet(&[200]), "unknown");
        assert_eq!(classify_packet(&[]), "unknown");
    }

    #[test]
    fn session_stats_tracks_activity() {
        let mut stats = SessionStats::default();
        assert!(!stats.has_activity());

        stats.raw_udp_rx = 1;
        assert!(stats.has_activity());

        stats.reset();
        assert!(!stats.has_activity());
    }

    #[test]
    fn broadcast_session_starts_empty() {
        let session = super::super::broadcast::BroadcastSession::new(42);
        assert_eq!(session.broadcaster_session, 42);
        assert!(session.inbound.is_none());
        assert!(session.outbound.is_empty());
        assert!(session.inbound_mid.is_none());
        assert!(!session.needs_initial_keyframe);
    }
}
