//! Ingestion: turn a bridge [`ServerEvent`] into a chained audit entry (§7.10).
//!
//! This is the seam between the durable event log ([`crate::event_log`]) and
//! the store ([`crate::store`]). It enforces three design rules at once:
//!
//! - **toggles gate recording** (§9.2): a disabled part is skipped, not chained;
//! - **at-least-once is made idempotent** (§7.10): a redelivered offset that is
//!   already in the chain is skipped, so no event is double-recorded;
//! - **retention is stamped at write time** (§7.9): `expires_at` comes from the
//!   policy in force *now*, never retroactively.

use crate::event_log::ServerEvent;
use crate::model::{AuditRecord, Severity, Source};
use crate::retention::RetentionPolicy;
use crate::store::{AuditStore, StoreError};
use crate::toggles::{Part, Toggles};

/// What happened when an event was offered to the audit store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestOutcome {
    /// The event was recorded; carries the new entry's row id.
    Recorded(i64),
    /// The governing part is disabled (§9.2), or the kind is unmodelled.
    SkippedDisabled,
    /// The event offset was already chained (idempotent redelivery, §7.10).
    SkippedDuplicate,
}

/// Record `event` (delivered at `offset`) into `store`, honouring `toggles`
/// and `retention`.
///
/// # Errors
/// Fails on a store/database error.
pub fn record_event(
    store: &AuditStore,
    toggles: &Toggles,
    retention: &RetentionPolicy,
    event: &ServerEvent,
    offset: u64,
) -> Result<IngestOutcome, StoreError> {
    let Some(part) = Part::from_event_kind(&event.kind) else {
        return Ok(IngestOutcome::SkippedDisabled);
    };
    if !toggles.is_enabled(part) {
        return Ok(IngestOutcome::SkippedDisabled);
    }
    if store.has_offset(event.server_id, offset)? {
        return Ok(IngestOutcome::SkippedDuplicate);
    }
    let record = build_record(part, event, offset, retention);
    let entry = store.append(record)?;
    Ok(IngestOutcome::Recorded(entry.id))
}

/// Map an event + its governing part into a fully-populated [`AuditRecord`].
fn build_record(
    part: Part,
    event: &ServerEvent,
    offset: u64,
    retention: &RetentionPolicy,
) -> AuditRecord {
    let mut record = AuditRecord::new(
        event.server_id,
        event.ts_ms,
        source_for(part),
        part.as_str(),
    )
    .with_severity(severity_for(part))
    .with_actor(event.actor.clone())
    .with_target(event.target.clone())
    .with_event_offset(offset);
    if let Some(channel_id) = event.channel_id {
        record = record.with_channel(channel_id);
    }
    if let Some(detail) = &event.detail_json {
        record = record.with_detail_json(detail.clone());
    }
    record.expires_at_ms = retention.stamp_expiry(part, event.ts_ms);
    record
}

/// The event source implied by a part: signals are client claims, plugin
/// actions come from a plugin, everything else is server-authoritative.
const fn source_for(part: Part) -> Source {
    match part {
        Part::SignalReport
        | Part::SignalMute
        | Part::SignalBlock
        | Part::SignalHide
        | Part::SignalDeafenFrom
        | Part::SignalRawEdges => Source::Client,
        Part::AuditPluginAction => Source::Plugin,
        _ => Source::Server,
    }
}

/// A default severity per part; the design uses these for filtering and
/// notifications (§7.7). Destructive accountability actions rank highest.
const fn severity_for(part: Part) -> Severity {
    match part {
        Part::AuditBan | Part::AuditKick => Severity::Critical,
        Part::AuditAcl
        | Part::AuditConfig
        | Part::AuditPluginAdmin
        | Part::AuditPluginAction
        | Part::SignalReport => Severity::Warning,
        Part::AuditRegister | Part::AuditPchatModeration | Part::AuditAccess => Severity::Notice,
        _ => Severity::Info,
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "unwrap is the standard, readable idiom in unit tests"
)]
mod tests {
    use super::*;
    use crate::model::Identity;

    fn ban_event(server: i32) -> ServerEvent {
        ServerEvent::new(server, 1_000, "ban")
            .with_actor(Identity {
                user_id: Some(1),
                hash: None,
                name: Some("mod".into()),
            })
            .with_target(Identity {
                user_id: Some(2),
                hash: None,
                name: Some("troll".into()),
            })
            .with_reason_in_detail("spam")
    }

    // Small test helper: events carry reason inside detail_json.
    trait WithReasonDetail {
        fn with_reason_in_detail(self, reason: &str) -> Self;
    }
    impl WithReasonDetail for ServerEvent {
        fn with_reason_in_detail(self, reason: &str) -> Self {
            self.with_detail_json(format!(r#"{{"reason":"{reason}"}}"#))
        }
    }

    #[test]
    fn a_ban_is_recorded_with_the_right_shape() {
        let store = AuditStore::open_in_memory().unwrap();
        let toggles = Toggles::with_defaults();
        let retention = RetentionPolicy::reference();
        let outcome = record_event(&store, &toggles, &retention, &ban_event(1), 0).unwrap();
        assert!(matches!(outcome, IngestOutcome::Recorded(_)));

        let chain = store.load_chain(1).unwrap();
        assert_eq!(chain.len(), 1);
        let rec = &chain[0].record;
        assert_eq!(rec.category, "audit.ban");
        assert_eq!(rec.source, Source::Server);
        assert_eq!(rec.severity, Severity::Critical);
        assert_eq!(rec.target.name.as_deref(), Some("troll"));
        // Bans are kept indefinitely -> no expiry stamped.
        assert_eq!(rec.expires_at_ms, None);
    }

    #[test]
    fn a_disabled_part_is_not_recorded() {
        let store = AuditStore::open_in_memory().unwrap();
        let mut toggles = Toggles::with_defaults();
        let _ = toggles.set(Part::AuditBan, false, 1, 0, Identity::system());
        let retention = RetentionPolicy::reference();
        let outcome = record_event(&store, &toggles, &retention, &ban_event(1), 0).unwrap();
        assert_eq!(outcome, IngestOutcome::SkippedDisabled);
        assert!(store.load_chain(1).unwrap().is_empty());
    }

    #[test]
    fn redelivery_of_the_same_offset_is_idempotent() {
        let store = AuditStore::open_in_memory().unwrap();
        let toggles = Toggles::with_defaults();
        let retention = RetentionPolicy::reference();
        let first = record_event(&store, &toggles, &retention, &ban_event(1), 5).unwrap();
        assert!(matches!(first, IngestOutcome::Recorded(_)));
        // Same offset delivered again (at-least-once) must not double-chain.
        let second = record_event(&store, &toggles, &retention, &ban_event(1), 5).unwrap();
        assert_eq!(second, IngestOutcome::SkippedDuplicate);
        assert_eq!(store.load_chain(1).unwrap().len(), 1);
        assert!(store.verify(1).unwrap().is_intact());
    }

    #[test]
    fn a_high_volume_part_gets_an_expiry_stamp() {
        let store = AuditStore::open_in_memory().unwrap();
        let toggles = Toggles::with_defaults();
        let retention = RetentionPolicy::reference();
        let event = ServerEvent::new(1, 1_000, "plugin.action").with_actor(Identity::system());
        let _ = record_event(&store, &toggles, &retention, &event, 0).unwrap();
        let rec = &store.load_chain(1).unwrap()[0].record;
        // 180-day part -> expiry stamped from write time.
        assert!(rec.expires_at_ms.is_some());
        assert!(rec.expires_at_ms.unwrap() > rec.ts_ms);
    }

    #[test]
    fn an_unmodelled_kind_is_skipped() {
        let store = AuditStore::open_in_memory().unwrap();
        let toggles = Toggles::with_defaults();
        let retention = RetentionPolicy::reference();
        let event = ServerEvent::new(1, 0, "totally.unknown");
        assert_eq!(
            record_event(&store, &toggles, &retention, &event, 0).unwrap(),
            IngestOutcome::SkippedDisabled
        );
    }
}
