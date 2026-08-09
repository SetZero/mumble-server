//! Persistent storage for the audit log (§4), backed by the plugin's own
//! `SQLite` database via `rusqlite` - the `file-server` storage pattern.
//!
//! The store owns three responsibilities that must stay together for the hash
//! chain (§7.1) to be sound:
//!
//! - **append** computes each entry's hashes from the current per-server head
//!   and inserts atomically, so the chain never forks under concurrent writers;
//! - **idempotency** keys on the originating event offset (a partial unique
//!   index), so an at-least-once redelivery (§7.10) never double-chains;
//! - **verify** replays the stored chain through [`crate::chain::verify_chain`].

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::chain::{self, VerifyOutcome, GENESIS_PARENT};
use crate::model::{AuditEntry, AuditRecord, Identity, Severity, Source};

/// Errors the store can raise.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A database error from the underlying `SQLite` engine.
    #[error("audit store database error: {0}")]
    Database(#[from] rusqlite::Error),
    /// A persisted hash column was not exactly 32 bytes - a corrupt row.
    #[error("audit store: malformed {column} hash (expected 32 bytes, got {len})")]
    MalformedHash {
        /// Which column was malformed.
        column: &'static str,
        /// The unexpected byte length found.
        len: usize,
    },
}

/// A filter for [`AuditStore::query`] (a subset of `FancyAuditQuery`, §5).
#[derive(Debug, Clone, Default)]
pub struct Query {
    /// Restrict to these categories (empty = all).
    pub categories: Vec<String>,
    /// Restrict to a single source.
    pub source: Option<Source>,
    /// Restrict to an actor user id.
    pub actor_user_id: Option<i64>,
    /// Restrict to a target user id.
    pub target_user_id: Option<i64>,
    /// Restrict to a channel.
    pub channel_id: Option<i64>,
    /// Substring match over `reason`/`detail_json` (fallback `LIKE`, §4).
    pub text: Option<String>,
    /// Lower time bound (inclusive), unix millis.
    pub since_ms: Option<i64>,
    /// Upper time bound (inclusive), unix millis.
    pub until_ms: Option<i64>,
    /// Keyset pagination cursor: only rows with `id < before_id`.
    pub before_id: Option<i64>,
    /// Maximum rows returned (capped by [`MAX_LIMIT`]).
    pub limit: Option<u32>,
}

/// Server-side cap on a single query's row count (§5).
pub const MAX_LIMIT: u32 = 200;

/// The audit database handle.
#[derive(Debug)]
pub struct AuditStore {
    conn: Mutex<Connection>,
}

impl AuditStore {
    /// Open (creating if needed) the audit database at `path` and run
    /// migrations.
    ///
    /// # Errors
    /// Fails if the database cannot be opened or migrated.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        Self::from_connection(conn)
    }

    /// Open an in-memory database (used by tests and the advanced-SQL sandbox
    /// self-check).
    ///
    /// # Errors
    /// Fails if the database cannot be created or migrated.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(conn: Connection) -> Result<Self, StoreError> {
        migrate(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        // Poison-tolerant: a panic mid-write must not wedge the audit log.
        self.conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The current chain head hash for `server_id` ([`GENESIS_PARENT`] if the
    /// chain is empty).
    ///
    /// # Errors
    /// Fails on a database error or a malformed stored hash.
    pub fn head_hash(&self, server_id: i32) -> Result<[u8; 32], StoreError> {
        let conn = self.lock();
        head_hash(&conn, server_id)
    }

    /// Append `record` to `server_id`'s chain and return the persisted entry.
    ///
    /// The chain hashes are computed from the current head under the store lock,
    /// so concurrent appends serialize rather than fork.
    ///
    /// # Errors
    /// Fails on a database error or a malformed stored head hash.
    pub fn append(&self, record: AuditRecord) -> Result<AuditEntry, StoreError> {
        let conn = self.lock();
        let prev_hash = head_hash(&conn, record.server_id)?;
        let entry_hash = chain::hash_entry(&prev_hash, &record);
        let id = insert_row(&conn, &record, &prev_hash, &entry_hash)?;
        Ok(AuditEntry {
            id,
            record,
            prev_hash,
            entry_hash,
        })
    }

    /// Whether an event `offset` has already been recorded for `server_id`
    /// (idempotency check for at-least-once ingestion, §7.10).
    ///
    /// # Errors
    /// Fails on a database error.
    pub fn has_offset(&self, server_id: i32, offset: u64) -> Result<bool, StoreError> {
        let conn = self.lock();
        let found: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM server_audit WHERE server_id = ?1 AND event_offset = ?2 LIMIT 1",
                params![server_id, offset_to_i64(offset)],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// Load the full chain for `server_id` in ascending id order.
    ///
    /// # Errors
    /// Fails on a database error or a malformed stored hash.
    pub fn load_chain(&self, server_id: i32) -> Result<Vec<AuditEntry>, StoreError> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, server_id, ts_ms, source, category, severity, \
             actor_user_id, actor_hash, actor_name, target_user_id, target_hash, target_name, \
             channel_id, reason, detail_json, relates_to, event_offset, expires_at_ms, \
             prev_hash, entry_hash \
             FROM server_audit WHERE server_id = ?1 ORDER BY id ASC",
        )?;
        let rows = stmt.query_map(params![server_id], row_to_entry)?;
        collect_entries(rows)
    }

    /// Verify `server_id`'s chain end to end (§7.1).
    ///
    /// # Errors
    /// Fails on a database error or a malformed stored hash.
    pub fn verify(&self, server_id: i32) -> Result<VerifyOutcome, StoreError> {
        Ok(chain::verify_chain(&self.load_chain(server_id)?))
    }

    /// Run a filtered, keyset-paginated query (§5). Results are newest-first.
    ///
    /// # Errors
    /// Fails on a database error or a malformed stored hash.
    pub fn query(&self, server_id: i32, query: &Query) -> Result<Vec<AuditEntry>, StoreError> {
        let (sql, binds) = build_query_sql(server_id, query);
        let conn = self.lock();
        let mut stmt = conn.prepare(&sql)?;
        let params = rusqlite::params_from_iter(binds.iter());
        let rows = stmt.query_map(params, row_to_entry)?;
        collect_entries(rows)
    }

    /// Delete rows whose stamped `expires_at_ms` is at or before `now_ms`, then
    /// append one audited summary entry recording the sweep (§7.9). Deleting a
    /// chained entry intentionally leaves a verifiable gap (§7.1) - the visible
    /// hole is the point.
    ///
    /// Returns the number of rows removed.
    ///
    /// # Errors
    /// Fails on a database error or a malformed stored hash.
    pub fn sweep_expired(&self, server_id: i32, now_ms: i64) -> Result<u64, StoreError> {
        let removed = {
            let conn = self.lock();
            conn.execute(
                "DELETE FROM server_audit \
                 WHERE server_id = ?1 AND expires_at_ms IS NOT NULL AND expires_at_ms <= ?2",
                params![server_id, now_ms],
            )?
        };
        if removed > 0 {
            let detail = format!(r#"{{"removed":{removed},"as_of_ms":{now_ms}}}"#);
            let summary = AuditRecord::new(server_id, now_ms, Source::Server, "audit.access")
                .with_severity(Severity::Notice)
                .with_actor(Identity::system())
                .with_reason("retention expiry sweep")
                .with_detail_json(detail);
            let _ = self.append(summary)?;
        }
        Ok(removed as u64)
    }
}

/// Create the `server_audit` table, its indexes and the idempotency index.
fn migrate(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS server_audit (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id      INTEGER NOT NULL,
            ts_ms          INTEGER NOT NULL,
            source         TEXT    NOT NULL,
            category       TEXT    NOT NULL,
            severity       TEXT    NOT NULL,
            actor_user_id  INTEGER,
            actor_hash     TEXT,
            actor_name     TEXT,
            target_user_id INTEGER,
            target_hash    TEXT,
            target_name    TEXT,
            channel_id     INTEGER,
            reason         TEXT,
            detail_json    TEXT,
            relates_to     INTEGER,
            event_offset   INTEGER,
            expires_at_ms  INTEGER,
            prev_hash      BLOB    NOT NULL,
            entry_hash     BLOB    NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_audit_server_ts ON server_audit(server_id, ts_ms);
         CREATE INDEX IF NOT EXISTS idx_audit_server_target ON server_audit(server_id, target_user_id, ts_ms);
         CREATE INDEX IF NOT EXISTS idx_audit_server_actor ON server_audit(server_id, actor_user_id, ts_ms);
         CREATE INDEX IF NOT EXISTS idx_audit_server_category ON server_audit(server_id, category, ts_ms);
         CREATE INDEX IF NOT EXISTS idx_audit_server_expiry ON server_audit(server_id, expires_at_ms);
         CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_offset
             ON server_audit(server_id, event_offset) WHERE event_offset IS NOT NULL;",
    )
}

fn head_hash(conn: &Connection, server_id: i32) -> Result<[u8; 32], StoreError> {
    let head: Option<Vec<u8>> = conn
        .query_row(
            "SELECT entry_hash FROM server_audit WHERE server_id = ?1 ORDER BY id DESC LIMIT 1",
            params![server_id],
            |row| row.get(0),
        )
        .optional()?;
    match head {
        Some(bytes) => to_hash(&bytes, "entry_hash"),
        None => Ok(GENESIS_PARENT),
    }
}

fn insert_row(
    conn: &Connection,
    record: &AuditRecord,
    prev_hash: &[u8; 32],
    entry_hash: &[u8; 32],
) -> Result<i64, StoreError> {
    let _rows = conn.execute(
        "INSERT INTO server_audit (
            server_id, ts_ms, source, category, severity,
            actor_user_id, actor_hash, actor_name,
            target_user_id, target_hash, target_name,
            channel_id, reason, detail_json, relates_to, event_offset, expires_at_ms,
            prev_hash, entry_hash
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
        params![
            record.server_id,
            record.ts_ms,
            record.source.as_str(),
            record.category,
            record.severity.as_str(),
            record.actor.user_id,
            record.actor.hash,
            record.actor.name,
            record.target.user_id,
            record.target.hash,
            record.target.name,
            record.channel_id,
            record.reason,
            record.detail_json,
            record.relates_to,
            record.event_offset.map(offset_to_i64),
            record.expires_at_ms,
            prev_hash.as_slice(),
            entry_hash.as_slice(),
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

fn row_to_entry(row: &Row<'_>) -> rusqlite::Result<AuditEntry> {
    let source_str: String = row.get("source")?;
    let severity_str: String = row.get("severity")?;
    let prev: Vec<u8> = row.get("prev_hash")?;
    let entry: Vec<u8> = row.get("entry_hash")?;
    let event_offset: Option<i64> = row.get("event_offset")?;
    let record = AuditRecord {
        server_id: row.get("server_id")?,
        ts_ms: row.get("ts_ms")?,
        source: Source::from_wire(&source_str).unwrap_or(Source::Server),
        category: row.get("category")?,
        severity: Severity::from_wire(&severity_str),
        actor: Identity {
            user_id: row.get("actor_user_id")?,
            hash: row.get("actor_hash")?,
            name: row.get("actor_name")?,
        },
        target: Identity {
            user_id: row.get("target_user_id")?,
            hash: row.get("target_hash")?,
            name: row.get("target_name")?,
        },
        channel_id: row.get("channel_id")?,
        reason: row.get("reason")?,
        detail_json: row.get("detail_json")?,
        relates_to: row.get("relates_to")?,
        event_offset: event_offset.map(i64_to_offset),
        expires_at_ms: row.get("expires_at_ms")?,
    };
    Ok(AuditEntry {
        id: row.get("id")?,
        record,
        prev_hash: vec_to_hash(&prev),
        entry_hash: vec_to_hash(&entry),
    })
}

/// Collect a `query_map` iterator into entries, promoting a malformed stored
/// hash into a typed [`StoreError`].
fn collect_entries<I>(rows: I) -> Result<Vec<AuditEntry>, StoreError>
where
    I: Iterator<Item = rusqlite::Result<AuditEntry>>,
{
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Build the `SELECT` and its bound parameters for a [`Query`].
fn build_query_sql(
    server_id: i32,
    query: &Query,
) -> (String, Vec<Box<dyn rusqlite::types::ToSql>>) {
    let mut sql = String::from(
        "SELECT id, server_id, ts_ms, source, category, severity, \
         actor_user_id, actor_hash, actor_name, target_user_id, target_hash, target_name, \
         channel_id, reason, detail_json, relates_to, event_offset, expires_at_ms, \
         prev_hash, entry_hash FROM server_audit WHERE server_id = ?",
    );
    let mut binds: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(server_id)];
    push_filters(&mut sql, &mut binds, query);
    sql.push_str(" ORDER BY id DESC LIMIT ?");
    let limit = query.limit.unwrap_or(MAX_LIMIT).min(MAX_LIMIT);
    binds.push(Box::new(i64::from(limit)));
    (sql, binds)
}

fn push_filters(sql: &mut String, binds: &mut Vec<Box<dyn rusqlite::types::ToSql>>, query: &Query) {
    if !query.categories.is_empty() {
        let placeholders = vec!["?"; query.categories.len()].join(",");
        sql.push_str(&format!(" AND category IN ({placeholders})"));
        for category in &query.categories {
            binds.push(Box::new(category.clone()));
        }
    }
    push_eq(
        sql,
        binds,
        " AND source = ?",
        query.source.map(|s| s.as_str().to_owned()),
    );
    push_eq(sql, binds, " AND actor_user_id = ?", query.actor_user_id);
    push_eq(sql, binds, " AND target_user_id = ?", query.target_user_id);
    push_eq(sql, binds, " AND channel_id = ?", query.channel_id);
    push_eq(sql, binds, " AND ts_ms >= ?", query.since_ms);
    push_eq(sql, binds, " AND ts_ms <= ?", query.until_ms);
    push_eq(sql, binds, " AND id < ?", query.before_id);
    if let Some(text) = &query.text {
        sql.push_str(" AND (reason LIKE ? OR detail_json LIKE ?)");
        let like = format!("%{text}%");
        binds.push(Box::new(like.clone()));
        binds.push(Box::new(like));
    }
}

fn push_eq<T: rusqlite::types::ToSql + 'static>(
    sql: &mut String,
    binds: &mut Vec<Box<dyn rusqlite::types::ToSql>>,
    clause: &str,
    value: Option<T>,
) {
    if let Some(value) = value {
        sql.push_str(clause);
        binds.push(Box::new(value));
    }
}

fn to_hash(bytes: &[u8], column: &'static str) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(bytes).map_err(|_| StoreError::MalformedHash {
        column,
        len: bytes.len(),
    })
}

/// Convert a stored blob to a 32-byte hash, tolerating corruption by falling
/// back to the genesis parent so `verify` reports the break rather than the
/// loader panicking.
fn vec_to_hash(bytes: &[u8]) -> [u8; 32] {
    to_hash(bytes, "hash").unwrap_or(GENESIS_PARENT)
}

/// Encode a `u64` offset as `i64` for `SQLite` storage (round-trips exactly).
#[allow(
    clippy::cast_possible_wrap,
    reason = "offset is stored and read back through the same reinterpretation"
)]
const fn offset_to_i64(offset: u64) -> i64 {
    offset as i64
}

#[allow(
    clippy::cast_sign_loss,
    reason = "offset is stored and read back through the same reinterpretation"
)]
const fn i64_to_offset(value: i64) -> u64 {
    value as u64
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "unwrap is the standard, readable idiom in unit tests"
)]
mod tests {
    use super::*;

    fn record(server: i32, ts: i64, category: &str) -> AuditRecord {
        AuditRecord::new(server, ts, Source::Server, category).with_actor(Identity {
            user_id: Some(1),
            hash: None,
            name: Some("mod".into()),
        })
    }

    #[test]
    fn append_builds_a_verifiable_chain() {
        let store = AuditStore::open_in_memory().unwrap();
        let _ = store.append(record(1, 10, "audit.ban")).unwrap();
        let _ = store.append(record(1, 20, "audit.kick")).unwrap();
        let _ = store
            .append(record(1, 30, "audit.mute_deafen_suppress"))
            .unwrap();
        assert!(store.verify(1).unwrap().is_intact());
    }

    #[test]
    fn genesis_entry_chains_from_zero() {
        let store = AuditStore::open_in_memory().unwrap();
        let entry = store.append(record(1, 10, "audit.ban")).unwrap();
        assert_eq!(entry.prev_hash, GENESIS_PARENT);
    }

    #[test]
    fn chains_are_independent_per_server() {
        let store = AuditStore::open_in_memory().unwrap();
        let _ = store.append(record(1, 10, "audit.ban")).unwrap();
        let _ = store.append(record(2, 10, "audit.ban")).unwrap();
        let _ = store.append(record(1, 20, "audit.kick")).unwrap();
        assert!(store.verify(1).unwrap().is_intact());
        assert!(store.verify(2).unwrap().is_intact());
    }

    #[test]
    fn tampering_with_a_row_is_detected_by_verify() {
        let store = AuditStore::open_in_memory().unwrap();
        let _ = store.append(record(1, 10, "audit.ban")).unwrap();
        let second = store.append(record(1, 20, "audit.kick")).unwrap();
        let _ = store.append(record(1, 30, "audit.acl")).unwrap();
        // Rogue admin edits the middle row's reason directly in the DB.
        {
            let conn = store.lock();
            let _ = conn
                .execute(
                    "UPDATE server_audit SET reason = 'forged' WHERE id = ?1",
                    params![second.id],
                )
                .unwrap();
        }
        assert!(
            !store.verify(1).unwrap().is_intact(),
            "edit must break verify"
        );
    }

    #[test]
    fn offsets_are_idempotent() {
        let store = AuditStore::open_in_memory().unwrap();
        let rec = record(1, 10, "audit.ban").with_event_offset(7);
        let _ = store.append(rec).unwrap();
        assert!(store.has_offset(1, 7).unwrap());
        assert!(!store.has_offset(1, 8).unwrap());
    }

    #[test]
    fn query_filters_and_paginates() {
        let store = AuditStore::open_in_memory().unwrap();
        let _ = store.append(record(1, 10, "audit.ban")).unwrap();
        let _ = store.append(record(1, 20, "audit.kick")).unwrap();
        let _ = store.append(record(1, 30, "audit.ban")).unwrap();

        let bans = store
            .query(
                1,
                &Query {
                    categories: vec!["audit.ban".into()],
                    ..Query::default()
                },
            )
            .unwrap();
        assert_eq!(bans.len(), 2);
        // Newest-first.
        assert!(bans[0].id > bans[1].id);

        // Keyset pagination: everything before the newest.
        let page = store
            .query(
                1,
                &Query {
                    before_id: Some(bans[0].id),
                    ..Query::default()
                },
            )
            .unwrap();
        assert!(page.iter().all(|e| e.id < bans[0].id));
    }

    #[test]
    fn text_search_matches_reason() {
        let store = AuditStore::open_in_memory().unwrap();
        let _ = store
            .append(record(1, 10, "audit.ban").with_reason("ban evasion"))
            .unwrap();
        let _ = store
            .append(record(1, 20, "audit.kick").with_reason("spam"))
            .unwrap();
        let hits = store
            .query(
                1,
                &Query {
                    text: Some("evasion".into()),
                    ..Query::default()
                },
            )
            .unwrap();
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn sweep_removes_expired_and_writes_an_audited_summary() {
        let store = AuditStore::open_in_memory().unwrap();
        // One row already expired, one far in the future.
        let mut expired = record(1, 10, "audit.plugin_action");
        expired.expires_at_ms = Some(100);
        let _ = store.append(expired).unwrap();
        let mut kept = record(1, 20, "audit.ban");
        kept.expires_at_ms = None;
        let _ = store.append(kept).unwrap();

        let removed = store.sweep_expired(1, 1_000).unwrap();
        assert_eq!(removed, 1);
        // The sweep itself is recorded as an audit.access entry.
        let summary = store
            .query(
                1,
                &Query {
                    categories: vec!["audit.access".into()],
                    ..Query::default()
                },
            )
            .unwrap();
        assert_eq!(summary.len(), 1);
        assert!(summary[0]
            .record
            .detail_json
            .as_deref()
            .unwrap()
            .contains("\"removed\":1"));
    }
}
