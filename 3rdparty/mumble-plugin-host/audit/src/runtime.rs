//! The plugin's live audit runtime: the store plus the mutable toggle and
//! retention state, wired together behind one interface.
//!
//! Every mutation that the design says must be audited (§9.2 rule 3, §7.9
//! rule 3) writes its own chained `audit.config` entry here, so the runtime is
//! the single place those invariants are enforced.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use crate::chain::VerifyOutcome;
use crate::event_log::ServerEvent;
use crate::ingest::{self, IngestOutcome};
use crate::model::{AuditEntry, AuditRecord, Identity};
use crate::retention::{Retention, RetentionPolicy};
use crate::store::{AuditStore, Query, StoreError};
use crate::toggles::{Part, Toggles};

/// The live audit subsystem for one plugin instance (all virtual servers share
/// one store; chains are keyed per `server_id`).
#[derive(Debug)]
pub struct AuditRuntime {
    store: AuditStore,
    toggles: Mutex<Toggles>,
    retention: Mutex<RetentionPolicy>,
}

impl AuditRuntime {
    /// Open the runtime against a database at `path`.
    ///
    /// # Errors
    /// Fails if the store cannot be opened/migrated.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        Ok(Self::from_store(AuditStore::open(path)?))
    }

    /// Open an in-memory runtime (tests, and the advanced-SQL self-check).
    ///
    /// # Errors
    /// Fails if the store cannot be created.
    pub fn in_memory() -> Result<Self, StoreError> {
        Ok(Self::from_store(AuditStore::open_in_memory()?))
    }

    fn from_store(store: AuditStore) -> Self {
        Self {
            store,
            toggles: Mutex::new(Toggles::with_defaults()),
            retention: Mutex::new(RetentionPolicy::reference()),
        }
    }

    fn toggles(&self) -> MutexGuard<'_, Toggles> {
        self.toggles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn retention(&self) -> MutexGuard<'_, RetentionPolicy> {
        self.retention
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Ingest one bridge event delivered at `offset` (§7.10). Idempotent,
    /// toggle-gated, retention-stamped - see [`ingest::record_event`].
    ///
    /// # Errors
    /// Fails on a store error.
    pub fn ingest(&self, event: &ServerEvent, offset: u64) -> Result<IngestOutcome, StoreError> {
        let toggles = self.toggles();
        let retention = self.retention();
        ingest::record_event(&self.store, &toggles, &retention, event, offset)
    }

    /// Run a filtered query (§5). Newest-first, keyset-paginated.
    ///
    /// # Errors
    /// Fails on a store error.
    pub fn query(&self, server_id: i32, query: &Query) -> Result<Vec<AuditEntry>, StoreError> {
        self.store.query(server_id, query)
    }

    /// Verify a server's chain (§7.1).
    ///
    /// # Errors
    /// Fails on a store error.
    pub fn verify(&self, server_id: i32) -> Result<VerifyOutcome, StoreError> {
        self.store.verify(server_id)
    }

    /// Whether `part` is currently collecting.
    #[must_use]
    pub fn is_enabled(&self, part: Part) -> bool {
        self.toggles().is_enabled(part)
    }

    /// A snapshot of every part's current on/off state, for the config UI (§10.1).
    #[must_use]
    pub fn toggle_snapshot(&self) -> Vec<(Part, bool)> {
        let toggles = self.toggles();
        crate::toggles::ALL_PARTS
            .into_iter()
            .map(|part| (part, toggles.is_enabled(part)))
            .collect()
    }

    /// Flip a toggle (§9.2). If the state changes, the change is chained as an
    /// `audit.config` entry and its row id returned.
    ///
    /// # Errors
    /// Fails on a store error.
    pub fn set_toggle(
        &self,
        part: Part,
        enable: bool,
        server_id: i32,
        ts_ms: i64,
        actor: Identity,
    ) -> Result<Option<i64>, StoreError> {
        let change = self.toggles().set(part, enable, server_id, ts_ms, actor);
        match change {
            Some(record) => Ok(Some(self.record_config(record, ts_ms)?)),
            None => Ok(None),
        }
    }

    /// Change a retention window (§7.9). The attempt is always chained (applied
    /// or refused); returns whether it took effect.
    ///
    /// # Errors
    /// Fails on a store error.
    pub fn set_retention(
        &self,
        part: Part,
        requested: Retention,
        server_id: i32,
        ts_ms: i64,
        actor: Identity,
    ) -> Result<bool, StoreError> {
        let change = self
            .retention()
            .set_window(part, requested, server_id, ts_ms, actor);
        let _ = self.record_config(change.audit, ts_ms)?;
        Ok(change.applied)
    }

    /// Run the retention expiry sweep for a server (§7.9).
    ///
    /// # Errors
    /// Fails on a store error.
    pub fn sweep_expired(&self, server_id: i32, now_ms: i64) -> Result<u64, StoreError> {
        self.store.sweep_expired(server_id, now_ms)
    }

    /// Append a config record, stamping its expiry from the live policy so the
    /// `audit.config` trail obeys the same retention rules as everything else.
    fn record_config(&self, mut record: AuditRecord, ts_ms: i64) -> Result<i64, StoreError> {
        record.expires_at_ms = self.retention().stamp_expiry(Part::AuditConfig, ts_ms);
        Ok(self.store.append(record)?.id)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "unwrap is the standard, readable idiom in unit tests"
)]
mod tests {
    use super::*;

    fn ban(server: i32, ts: i64) -> ServerEvent {
        ServerEvent::new(server, ts, "ban")
            .with_actor(Identity {
                user_id: Some(1),
                hash: None,
                name: Some("mod".into()),
            })
            .with_target(Identity {
                user_id: Some(2),
                hash: None,
                name: Some("t".into()),
            })
    }

    #[test]
    fn end_to_end_record_toggle_and_verify() {
        let rt = AuditRuntime::in_memory().unwrap();
        // Record two bans.
        assert!(matches!(
            rt.ingest(&ban(1, 10), 0).unwrap(),
            IngestOutcome::Recorded(_)
        ));
        assert!(matches!(
            rt.ingest(&ban(1, 20), 1).unwrap(),
            IngestOutcome::Recorded(_)
        ));

        // Disable bans; the toggle change is itself chained.
        let config_id = rt
            .set_toggle(
                Part::AuditBan,
                false,
                1,
                25,
                Identity {
                    user_id: Some(9),
                    ..Identity::default()
                },
            )
            .unwrap();
        assert!(config_id.is_some());

        // A further ban is now skipped (stop the future).
        assert_eq!(
            rt.ingest(&ban(1, 30), 2).unwrap(),
            IngestOutcome::SkippedDisabled
        );

        // The chain - two bans + the config entry - still verifies end to end.
        assert!(rt.verify(1).unwrap().is_intact());

        // The disabling is visible in the log.
        let configs = rt
            .query(
                1,
                &Query {
                    categories: vec!["audit.config".into()],
                    ..Query::default()
                },
            )
            .unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].record.actor.user_id, Some(9));
    }

    #[test]
    fn retention_change_is_recorded_and_chained() {
        let rt = AuditRuntime::in_memory().unwrap();
        // Refused (below floor) but still chained.
        let applied = rt
            .set_retention(Part::AuditConfig, Some(1), 1, 5, Identity::system())
            .unwrap();
        assert!(!applied);
        assert!(rt.verify(1).unwrap().is_intact());
        let configs = rt.query(1, &Query::default()).unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].record.category, "audit.config");
    }

    #[test]
    fn toggle_snapshot_reflects_changes() {
        let rt = AuditRuntime::in_memory().unwrap();
        assert!(rt.is_enabled(Part::SignalReport));
        let _ = rt
            .set_toggle(Part::SignalMute, true, 1, 0, Identity::system())
            .unwrap();
        let snap = rt.toggle_snapshot();
        let mute = snap.iter().find(|(p, _)| *p == Part::SignalMute).unwrap();
        assert!(mute.1, "signal.mute should now be enabled");
    }
}
