//! Retention policy (§7.9): the one *legitimate* deletion path, deliberately
//! constrained so it can't be used to launder tampering.
//!
//! Three rules from the design hold here:
//!
//! 1. **Hard 30-day floor on `audit.*`.** Accountability categories cannot be
//!    configured below it - a request to go lower is refused *and* recorded.
//! 2. **Lowering is never retroactive.** Each row's `expires_at` is stamped at
//!    write time from the policy then in force ([`RetentionPolicy::stamp_expiry`]),
//!    so reducing a setting only affects records written afterwards.
//! 3. **Every retention change is an audit entry** (`audit.config`) recording
//!    actor, part, old and new value.

use std::collections::BTreeMap;

use crate::model::{AuditRecord, Identity, Severity, Source};
use crate::toggles::Part;

const MS_PER_DAY: i64 = 86_400_000;

/// Hard floor for `audit.*` accountability parts (§7.9): 30 days.
pub const AUDIT_FLOOR_MS: i64 = 30 * MS_PER_DAY;

const DAYS_180: i64 = 180 * MS_PER_DAY;
const YEAR: i64 = 365 * MS_PER_DAY;
const TWO_YEARS: i64 = 730 * MS_PER_DAY;

/// A per-part retention duration in milliseconds; `None` means "keep forever".
pub type Retention = Option<i64>;

/// The live retention configuration: a duration per part, seeded from the
/// reference policy and adjustable (within the floor) by `ConfigureAudit`.
#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    windows: BTreeMap<Part, Retention>,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self::reference()
    }
}

impl RetentionPolicy {
    /// The shipped reference policy (§7.9): privacy-sensitive data stays short,
    /// the accountability record lives long.
    #[must_use]
    pub fn reference() -> Self {
        let mut windows = BTreeMap::new();
        for part in crate::toggles::ALL_PARTS {
            let _ = windows.insert(part, Self::reference_window(part));
        }
        Self { windows }
    }

    /// The reference retention window for a single part.
    #[must_use]
    pub const fn reference_window(part: Part) -> Retention {
        match part {
            // The record most needed later - ban evasion, appeals.
            Part::AuditBan | Part::AuditKick => None,
            // Who changed permissions / disabled logging; account lifecycle.
            Part::AuditAcl
            | Part::AuditConfig
            | Part::AuditPluginAdmin
            | Part::AuditAccess
            | Part::AuditRegister => Some(TWO_YEARS),
            // Routine and high-volume; useful for patterns, not forever.
            Part::AuditMuteDeafenSuppress
            | Part::AuditMove
            | Part::AuditChannel
            | Part::AuditPchatModeration
            | Part::AuditPluginAction => Some(DAYS_180),
            // The most privacy-sensitive data in the system.
            Part::SignalRawEdges => Some(30 * MS_PER_DAY),
            // Pseudonymous counts, low risk.
            Part::SignalReport
            | Part::SignalMute
            | Part::SignalBlock
            | Part::SignalHide
            | Part::SignalDeafenFrom => Some(YEAR),
            // Telemetry lives in the OTLP backend; disclosure is not stored data.
            Part::TelemetryOtlpMetrics | Part::TelemetryOtlpLogs | Part::DiscloseToUsers => None,
        }
    }

    /// The configured retention window for `part`.
    #[must_use]
    pub fn window(&self, part: Part) -> Retention {
        self.windows
            .get(&part)
            .copied()
            .unwrap_or_else(|| Self::reference_window(part))
    }

    /// Stamp the `expires_at` for a row of `part` written at `write_ts_ms`
    /// (§7.9 rule 2). `None` means the row never expires.
    #[must_use]
    pub fn stamp_expiry(&self, part: Part, write_ts_ms: i64) -> Option<i64> {
        self.window(part)
            .map(|window| write_ts_ms.saturating_add(window))
    }

    /// Attempt to change the retention window for `part`.
    ///
    /// Enforces the 30-day floor on accountability parts (§7.9 rule 1): a
    /// request below the floor is refused. Either way the attempt is recorded
    /// (§7.9 rule 3) - the returned [`RetentionChange`] always carries the
    /// `audit.config` entry to write, and `applied` says whether the value
    /// actually changed.
    pub fn set_window(
        &mut self,
        part: Part,
        requested: Retention,
        server_id: i32,
        ts_ms: i64,
        actor: Identity,
    ) -> RetentionChange {
        let previous = self.window(part);
        let below_floor =
            part.is_accountability() && matches!(requested, Some(value) if value < AUDIT_FLOOR_MS);
        let applied = !below_floor && requested != previous;
        if applied {
            let _ = self.windows.insert(part, requested);
        }
        let audit = Self::change_record(
            part,
            previous,
            requested,
            applied,
            below_floor,
            server_id,
            ts_ms,
            actor,
        );
        RetentionChange {
            applied,
            below_floor,
            audit,
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "a retention-change record needs the full before/after context in one atomic construction"
    )]
    fn change_record(
        part: Part,
        previous: Retention,
        requested: Retention,
        applied: bool,
        below_floor: bool,
        server_id: i32,
        ts_ms: i64,
        actor: Identity,
    ) -> AuditRecord {
        let reason = if below_floor {
            "retention change refused: below 30-day accountability floor"
        } else if applied {
            "retention window changed"
        } else {
            "retention change was a no-op"
        };
        let detail = format!(
            r#"{{"part":"{}","from":{},"to":{},"applied":{applied},"below_floor":{below_floor}}}"#,
            part.as_str(),
            render_window(previous),
            render_window(requested),
        );
        AuditRecord::new(server_id, ts_ms, Source::Server, Part::AuditConfig.as_str())
            .with_severity(if below_floor {
                Severity::Warning
            } else {
                Severity::Notice
            })
            .with_actor(actor)
            .with_reason(reason)
            .with_detail_json(detail)
    }
}

/// Render a retention window for the `detail_json` payload: a number of
/// milliseconds, or JSON `null` for "keep forever".
fn render_window(window: Retention) -> String {
    window.map_or_else(|| "null".to_owned(), |ms| ms.to_string())
}

/// The outcome of a retention change: what to record and whether it took.
#[derive(Debug, Clone)]
pub struct RetentionChange {
    /// Whether the window was actually changed (false if refused or a no-op).
    pub applied: bool,
    /// Whether the change was refused for breaching the accountability floor.
    pub below_floor: bool,
    /// The `audit.config` entry that records this attempt (always written).
    pub audit: AuditRecord,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "unwrap is the standard, readable idiom in unit tests"
)]
mod tests {
    use super::*;

    #[test]
    fn reference_policy_matches_the_spec_table() {
        let policy = RetentionPolicy::reference();
        assert_eq!(
            policy.window(Part::AuditBan),
            None,
            "bans kept indefinitely"
        );
        assert_eq!(policy.window(Part::AuditConfig), Some(TWO_YEARS));
        assert_eq!(policy.window(Part::AuditMove), Some(DAYS_180));
        assert_eq!(policy.window(Part::SignalRawEdges), Some(30 * MS_PER_DAY));
        assert_eq!(policy.window(Part::SignalReport), Some(YEAR));
    }

    #[test]
    fn expiry_is_stamped_from_write_time() {
        let policy = RetentionPolicy::reference();
        // A 180-day part written at t gets expiry t + 180d.
        assert_eq!(
            policy.stamp_expiry(Part::AuditMove, 1_000),
            Some(1_000 + DAYS_180)
        );
        // An indefinite part never expires.
        assert_eq!(policy.stamp_expiry(Part::AuditBan, 1_000), None);
    }

    #[test]
    fn lowering_below_the_floor_is_refused_and_recorded() {
        let mut policy = RetentionPolicy::reference();
        let outcome = policy.set_window(
            Part::AuditConfig,
            Some(MS_PER_DAY), // 1 day - well under the 30-day floor
            1,
            42,
            Identity {
                user_id: Some(3),
                ..Identity::default()
            },
        );
        assert!(!outcome.applied, "must be refused");
        assert!(outcome.below_floor);
        // The window is unchanged...
        assert_eq!(policy.window(Part::AuditConfig), Some(TWO_YEARS));
        // ...and the refusal is itself an audit.config entry.
        assert_eq!(outcome.audit.category, "audit.config");
        assert!(outcome
            .audit
            .detail_json
            .unwrap()
            .contains("below_floor\":true"));
    }

    #[test]
    fn signal_parts_have_no_floor() {
        let mut policy = RetentionPolicy::reference();
        // Shortening privacy-sensitive raw edges is a *privacy improvement*.
        let outcome = policy.set_window(
            Part::SignalRawEdges,
            Some(MS_PER_DAY),
            1,
            0,
            Identity::system(),
        );
        assert!(outcome.applied);
        assert_eq!(policy.window(Part::SignalRawEdges), Some(MS_PER_DAY));
    }

    #[test]
    fn raising_retention_is_allowed() {
        let mut policy = RetentionPolicy::reference();
        let outcome = policy.set_window(Part::AuditMove, Some(TWO_YEARS), 1, 0, Identity::system());
        assert!(outcome.applied);
        assert_eq!(policy.window(Part::AuditMove), Some(TWO_YEARS));
    }

    #[test]
    fn setting_the_same_value_is_a_noop_but_still_recorded() {
        let mut policy = RetentionPolicy::reference();
        let outcome =
            policy.set_window(Part::AuditConfig, Some(TWO_YEARS), 1, 0, Identity::system());
        assert!(!outcome.applied);
        assert!(!outcome.below_floor);
        assert_eq!(outcome.audit.category, "audit.config");
    }
}
