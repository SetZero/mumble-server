//! Per-part toggle matrix (§9.2).
//!
//! There is no single on/off. Every collectable/exportable part is an
//! independent switch owned by `ConfigureAudit`, so two operators can run very
//! different policies on the same software. This module owns the set of parts,
//! their defaults, and the toggle semantics: **stop the future, never rewrite
//! the past** - flipping a switch changes what is recorded from now on, deletes
//! nothing, and the flip is itself an audit entry.

use std::collections::BTreeMap;

use crate::model::{AuditRecord, Identity, Severity, Source};

/// One switchable part of the audit/signal/telemetry surface (§9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Part {
    /// Bans.
    AuditBan,
    /// Kicks.
    AuditKick,
    /// Server-imposed mute/deafen/suppress/priority-speaker.
    AuditMuteDeafenSuppress,
    /// Forced channel moves.
    AuditMove,
    /// ACL/group edits.
    AuditAcl,
    /// Channel create/remove/rename.
    AuditChannel,
    /// User (de)registration.
    AuditRegister,
    /// Server-settings changes (secrets redacted).
    AuditConfig,
    /// Plugin install/enable/disable.
    AuditPluginAdmin,
    /// Plugin-initiated privileged calls (§7.10).
    AuditPluginAction,
    /// Persistent-chat delete/pin/rate-limit.
    AuditPchatModeration,
    /// Audit-the-auditors: viewing/searching/exporting/clearing (§7.2).
    AuditAccess,
    /// Explicit user reports (recommended).
    SignalReport,
    /// Passive mute telemetry.
    SignalMute,
    /// Block telemetry.
    SignalBlock,
    /// Hide telemetry.
    SignalHide,
    /// Stopped-listening telemetry.
    SignalDeafenFrom,
    /// Raw who→whom edges (separate from aggregate counts).
    SignalRawEdges,
    /// Aggregate metrics over OTLP.
    TelemetryOtlpMetrics,
    /// Per-entry logs over OTLP (carry identity).
    TelemetryOtlpLogs,
    /// Show the client "records moderation signals" indicator (§6.4).
    DiscloseToUsers,
}

/// Every part, in a stable order (used for defaults and UI rendering).
pub const ALL_PARTS: [Part; 21] = [
    Part::AuditBan,
    Part::AuditKick,
    Part::AuditMuteDeafenSuppress,
    Part::AuditMove,
    Part::AuditAcl,
    Part::AuditChannel,
    Part::AuditRegister,
    Part::AuditConfig,
    Part::AuditPluginAdmin,
    Part::AuditPluginAction,
    Part::AuditPchatModeration,
    Part::AuditAccess,
    Part::SignalReport,
    Part::SignalMute,
    Part::SignalBlock,
    Part::SignalHide,
    Part::SignalDeafenFrom,
    Part::SignalRawEdges,
    Part::TelemetryOtlpMetrics,
    Part::TelemetryOtlpLogs,
    Part::DiscloseToUsers,
];

impl Part {
    /// The stable wire/config string for this part (also its audit category
    /// for `audit.*` parts).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuditBan => "audit.ban",
            Self::AuditKick => "audit.kick",
            Self::AuditMuteDeafenSuppress => "audit.mute_deafen_suppress",
            Self::AuditMove => "audit.move",
            Self::AuditAcl => "audit.acl",
            Self::AuditChannel => "audit.channel",
            Self::AuditRegister => "audit.register",
            Self::AuditConfig => "audit.config",
            Self::AuditPluginAdmin => "audit.plugin_admin",
            Self::AuditPluginAction => "audit.plugin_action",
            Self::AuditPchatModeration => "audit.pchat_moderation",
            Self::AuditAccess => "audit.access",
            Self::SignalReport => "signal.report",
            Self::SignalMute => "signal.mute",
            Self::SignalBlock => "signal.block",
            Self::SignalHide => "signal.hide",
            Self::SignalDeafenFrom => "signal.deafen_from",
            Self::SignalRawEdges => "signal.raw_edges",
            Self::TelemetryOtlpMetrics => "telemetry.otlp.metrics",
            Self::TelemetryOtlpLogs => "telemetry.otlp.logs",
            Self::DiscloseToUsers => "disclose_to_users",
        }
    }

    /// Parse a part from its wire/config string.
    #[must_use]
    #[allow(
        clippy::should_implement_trait,
        reason = "fallible parse returning Option, not the infallible-error FromStr contract"
    )]
    pub fn from_str(value: &str) -> Option<Self> {
        ALL_PARTS.into_iter().find(|part| part.as_str() == value)
    }

    /// Default collection state (§9.2). `audit.*` accountability parts default
    /// on; passive signal telemetry and OTLP export default off.
    #[must_use]
    pub const fn default_collect(self) -> bool {
        matches!(
            self,
            Self::AuditBan
                | Self::AuditKick
                | Self::AuditMuteDeafenSuppress
                | Self::AuditMove
                | Self::AuditAcl
                | Self::AuditChannel
                | Self::AuditRegister
                | Self::AuditConfig
                | Self::AuditPluginAdmin
                | Self::AuditPluginAction
                | Self::AuditPchatModeration
                | Self::AuditAccess
                | Self::SignalReport
        )
    }

    /// Whether this is an `audit.*` accountability part, which carries the hard
    /// 30-day retention floor (§7.9). Signal and telemetry parts do not.
    #[must_use]
    pub const fn is_accountability(self) -> bool {
        matches!(
            self,
            Self::AuditBan
                | Self::AuditKick
                | Self::AuditMuteDeafenSuppress
                | Self::AuditMove
                | Self::AuditAcl
                | Self::AuditChannel
                | Self::AuditRegister
                | Self::AuditConfig
                | Self::AuditPluginAdmin
                | Self::AuditPluginAction
                | Self::AuditPchatModeration
                | Self::AuditAccess
        )
    }

    /// Map a bridge event `kind` (§7.10) to the audit part that governs whether
    /// it is recorded. Returns `None` for kinds the audit plugin does not model.
    #[must_use]
    pub fn from_event_kind(kind: &str) -> Option<Self> {
        let mapped = match kind {
            "ban" => Self::AuditBan,
            "kick" => Self::AuditKick,
            "mute" | "deafen" | "suppress" | "priority_speaker" | "recording" | "listen" => {
                Self::AuditMuteDeafenSuppress
            }
            "move" => Self::AuditMove,
            "acl" => Self::AuditAcl,
            "register" | "deregister" => Self::AuditRegister,
            "config" => Self::AuditConfig,
            "plugin.action" => Self::AuditPluginAction,
            "audit.access" => Self::AuditAccess,
            other => return Self::from_prefixed_kind(other),
        };
        Some(mapped)
    }

    /// Handle event kinds addressed by prefix rather than exact match.
    fn from_prefixed_kind(kind: &str) -> Option<Self> {
        if kind.starts_with("channel.") {
            Some(Self::AuditChannel)
        } else if kind.starts_with("plugin.") {
            // plugin.install / plugin.enable / plugin.disable / plugin.uninstall
            Some(Self::AuditPluginAdmin)
        } else if kind.starts_with("pchat.") {
            Some(Self::AuditPchatModeration)
        } else if let Some(signal) = kind.strip_prefix("signal.") {
            Self::from_signal(signal)
        } else {
            None
        }
    }

    fn from_signal(signal: &str) -> Option<Self> {
        let mapped = match signal {
            "report" => Self::SignalReport,
            "mute" => Self::SignalMute,
            "block" => Self::SignalBlock,
            "hide" => Self::SignalHide,
            "deafen_from" => Self::SignalDeafenFrom,
            _ => return None,
        };
        Some(mapped)
    }
}

/// The live toggle state: which parts are currently collecting/exporting.
///
/// Constructed from defaults; an admin holding `ConfigureAudit` flips
/// individual parts. Flipping produces an [`AuditRecord`] so the change lands
/// in the log (§9.2 rule 3).
#[derive(Debug, Clone)]
pub struct Toggles {
    enabled: BTreeMap<Part, bool>,
}

impl Default for Toggles {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl Toggles {
    /// Build the toggle state from the §9.2 defaults.
    #[must_use]
    pub fn with_defaults() -> Self {
        let enabled = ALL_PARTS
            .into_iter()
            .map(|part| (part, part.default_collect()))
            .collect();
        Self { enabled }
    }

    /// Whether `part` is currently enabled.
    #[must_use]
    pub fn is_enabled(&self, part: Part) -> bool {
        self.enabled
            .get(&part)
            .copied()
            .unwrap_or_else(|| part.default_collect())
    }

    /// Whether a bridge event of `kind` should be recorded right now: its
    /// governing part must exist and be enabled.
    #[must_use]
    pub fn records_kind(&self, kind: &str) -> bool {
        Part::from_event_kind(kind).is_some_and(|part| self.is_enabled(part))
    }

    /// Flip `part` to `enable`, returning the audit entry that records the
    /// change (§9.2 rule 3), or `None` if the state was already `enable`
    /// (an idempotent no-op writes nothing).
    ///
    /// `actor` is the operator making the change; `ts_ms`/`server_id` stamp the
    /// resulting `audit.config` record. Disabling the watcher is therefore the
    /// first thing the log shows.
    pub fn set(
        &mut self,
        part: Part,
        enable: bool,
        server_id: i32,
        ts_ms: i64,
        actor: Identity,
    ) -> Option<AuditRecord> {
        let previous = self.is_enabled(part);
        if previous == enable {
            return None;
        }
        let _ = self.enabled.insert(part, enable);
        let detail = format!(
            r#"{{"part":"{}","from":{previous},"to":{enable}}}"#,
            part.as_str()
        );
        Some(
            AuditRecord::new(server_id, ts_ms, Source::Server, Part::AuditConfig.as_str())
                .with_severity(Severity::Notice)
                .with_actor(actor)
                .with_reason(if enable {
                    "enable audit part"
                } else {
                    "disable audit part"
                })
                .with_detail_json(detail),
        )
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "unwrap is the standard, readable idiom in unit tests"
)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_spec_matrix() {
        let toggles = Toggles::with_defaults();
        // Accountability parts default on.
        assert!(toggles.is_enabled(Part::AuditBan));
        assert!(toggles.is_enabled(Part::AuditPluginAction));
        assert!(toggles.is_enabled(Part::AuditAccess));
        // Explicit reports on; passive signal telemetry off.
        assert!(toggles.is_enabled(Part::SignalReport));
        assert!(!toggles.is_enabled(Part::SignalMute));
        assert!(!toggles.is_enabled(Part::SignalRawEdges));
        // Telemetry + disclosure off.
        assert!(!toggles.is_enabled(Part::TelemetryOtlpMetrics));
        assert!(!toggles.is_enabled(Part::DiscloseToUsers));
    }

    #[test]
    fn part_roundtrips_through_its_string() {
        for part in ALL_PARTS {
            assert_eq!(Part::from_str(part.as_str()), Some(part));
        }
    }

    #[test]
    fn event_kinds_map_to_parts() {
        assert_eq!(Part::from_event_kind("ban"), Some(Part::AuditBan));
        assert_eq!(
            Part::from_event_kind("channel.remove"),
            Some(Part::AuditChannel)
        );
        assert_eq!(
            Part::from_event_kind("plugin.install"),
            Some(Part::AuditPluginAdmin)
        );
        assert_eq!(
            Part::from_event_kind("plugin.action"),
            Some(Part::AuditPluginAction)
        );
        assert_eq!(
            Part::from_event_kind("pchat.delete"),
            Some(Part::AuditPchatModeration)
        );
        assert_eq!(
            Part::from_event_kind("signal.report"),
            Some(Part::SignalReport)
        );
        assert_eq!(Part::from_event_kind("nonsense"), None);
    }

    #[test]
    fn accountability_parts_are_classified_for_the_floor() {
        assert!(Part::AuditBan.is_accountability());
        assert!(Part::AuditConfig.is_accountability());
        assert!(!Part::SignalMute.is_accountability());
        assert!(!Part::TelemetryOtlpLogs.is_accountability());
    }

    #[test]
    fn disabling_a_part_stops_recording_and_emits_an_entry() {
        let mut toggles = Toggles::with_defaults();
        assert!(toggles.records_kind("plugin.action"));
        let entry = toggles
            .set(
                Part::AuditPluginAction,
                false,
                1,
                123,
                Identity {
                    user_id: Some(5),
                    ..Identity::default()
                },
            )
            .unwrap();
        assert_eq!(entry.category, "audit.config");
        assert_eq!(entry.actor.user_id, Some(5));
        assert!(entry.detail_json.unwrap().contains("audit.plugin_action"));
        // The future is stopped...
        assert!(!toggles.records_kind("plugin.action"));
    }

    #[test]
    fn idempotent_toggle_writes_nothing() {
        let mut toggles = Toggles::with_defaults();
        // Already on by default; enabling again is a no-op.
        assert!(toggles
            .set(Part::AuditBan, true, 1, 0, Identity::system())
            .is_none());
    }
}
