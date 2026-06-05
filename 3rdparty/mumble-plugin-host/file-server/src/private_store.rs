//! Per-user opaque key/value storage (the "private storage" namespace).
//!
//! Scoped by the caller's registered identity (the session JWT `scope` claim,
//! `"<server_id>:<user_id>"`).  Unregistered guests have no scope and are
//! rejected, so only registered accounts get storage.  The file server treats
//! values as opaque blobs: the
//! live-doc sidebar uses it to persist each user's document index under a fixed
//! key, but this store has no knowledge of that.  Backed by an independent
//! connection to the same `SQLite` DB used by [`crate::storage::Storage`].

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};

use crate::storage::{StorageError, METADATA_DB_FILE};

/// Per-user key/value store keyed by `(cert_hash, key)`.
#[derive(Debug)]
pub struct PrivateStore {
    db: Mutex<Connection>,
}

impl PrivateStore {
    /// Open (or create) the store and run schema migrations.  The directory
    /// must already exist - `Storage::open` creates it first.
    pub fn open(storage_path: &Path) -> Result<Self, StorageError> {
        let conn = Connection::open(storage_path.join(METADATA_DB_FILE))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS private_storage (
                cert_hash TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (cert_hash, key)
            );",
        )?;
        Ok(Self {
            db: Mutex::new(conn),
        })
    }

    /// Fetch the value stored under `(cert_hash, key)`, or `None`.
    pub fn get(&self, cert_hash: &str, key: &str) -> Result<Option<String>, StorageError> {
        let conn = self.db.lock().map_err(|_| poisoned_mutex_err())?;
        let value: Option<String> = conn
            .prepare("SELECT value FROM private_storage WHERE cert_hash = ?1 AND key = ?2")?
            .query_row(params![cert_hash, key], |row| row.get(0))
            .optional()?;
        Ok(value)
    }

    /// Insert or overwrite the value under `(cert_hash, key)`.
    pub fn put(&self, cert_hash: &str, key: &str, value: &str) -> Result<(), StorageError> {
        let now = unix_millis_now();
        let conn = self.db.lock().map_err(|_| poisoned_mutex_err())?;
        let _ = conn.execute(
            "INSERT INTO private_storage(cert_hash, key, value, updated_at) VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(cert_hash, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![cert_hash, key, value, now],
        )?;
        Ok(())
    }
}

fn unix_millis_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn poisoned_mutex_err() -> StorageError {
    StorageError::Io(std::io::Error::other("private-storage db mutex poisoned"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test code - panics are acceptable")]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn open_store() -> (TempDir, PrivateStore) {
        let dir = TempDir::new().unwrap();
        let store = PrivateStore::open(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn put_get_round_trip() {
        let (_dir, store) = open_store();
        assert_eq!(store.get("certA", "k").unwrap(), None);
        store.put("certA", "k", "value-1").unwrap();
        assert_eq!(store.get("certA", "k").unwrap().as_deref(), Some("value-1"));
    }

    #[test]
    fn put_overwrites() {
        let (_dir, store) = open_store();
        store.put("certA", "k", "v1").unwrap();
        store.put("certA", "k", "v2").unwrap();
        assert_eq!(store.get("certA", "k").unwrap().as_deref(), Some("v2"));
    }

    #[test]
    fn scoped_per_cert_hash() {
        let (_dir, store) = open_store();
        store.put("certA", "k", "a").unwrap();
        store.put("certB", "k", "b").unwrap();
        assert_eq!(store.get("certA", "k").unwrap().as_deref(), Some("a"));
        assert_eq!(store.get("certB", "k").unwrap().as_deref(), Some("b"));
    }
}
