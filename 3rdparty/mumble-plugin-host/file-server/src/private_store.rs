//! Per-user private key/value storage.
//!
//! A generic, caller-agnostic store: each registered user (identified by
//! their stable TLS `cert_hash`) gets a private namespace of small blobs
//! addressed by an opaque `key`.  The file-server attaches no meaning to
//! the keys or values - sibling features (e.g. a client's live-doc
//! sidebar) use it as a transparent backing store.
//!
//! Blobs are stored directly in the same `SQLite` DB used by the rest of
//! the plugin (separate table, independent connection - `SQLite`
//! serialises writes at the file level so the stores coexist safely).

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};

use crate::storage::{StorageError, METADATA_DB_FILE};

/// Per-user private key/value store backed by an independent connection
/// to the shared metadata DB.
#[derive(Debug)]
pub struct PrivateStore {
    db: Mutex<Connection>,
}

impl PrivateStore {
    /// Open (or create) the store at `storage_path` and run migrations.
    /// The directory must already exist (`Storage::open` creates it).
    pub fn open(storage_path: &Path) -> Result<Self, StorageError> {
        let conn = Connection::open(storage_path.join(METADATA_DB_FILE))?;
        run_migrations(&conn)?;
        Ok(Self {
            db: Mutex::new(conn),
        })
    }

    /// Fetch the blob stored under `(cert_hash, key)`, or `None`.
    pub fn get(&self, cert_hash: &str, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let conn = self.db.lock().map_err(|_| poisoned_mutex_err())?;
        let blob: Option<Vec<u8>> = conn
            .prepare("SELECT blob FROM private_storage WHERE cert_hash = ?1 AND key = ?2")?
            .query_row(params![cert_hash, key], |row| row.get::<_, Vec<u8>>(0))
            .optional()?;
        Ok(blob)
    }

    /// Insert or replace the blob under `(cert_hash, key)`.
    pub fn put(&self, cert_hash: &str, key: &str, blob: &[u8]) -> Result<(), StorageError> {
        let now = unix_millis_now();
        let conn = self.db.lock().map_err(|_| poisoned_mutex_err())?;
        let _ = conn.execute(
            "INSERT INTO private_storage(cert_hash, key, blob, updated_at) VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(cert_hash, key) DO UPDATE SET blob = excluded.blob, updated_at = excluded.updated_at",
            params![cert_hash, key, blob, now],
        )?;
        Ok(())
    }

    /// Delete the blob under `(cert_hash, key)`.  Returns `true` if a row
    /// was removed.
    pub fn delete(&self, cert_hash: &str, key: &str) -> Result<bool, StorageError> {
        let conn = self.db.lock().map_err(|_| poisoned_mutex_err())?;
        let n = conn.execute(
            "DELETE FROM private_storage WHERE cert_hash = ?1 AND key = ?2",
            params![cert_hash, key],
        )?;
        Ok(n > 0)
    }

    /// List every key in a user's namespace (sorted).
    pub fn list_keys(&self, cert_hash: &str) -> Result<Vec<String>, StorageError> {
        let conn = self.db.lock().map_err(|_| poisoned_mutex_err())?;
        let mut stmt =
            conn.prepare("SELECT key FROM private_storage WHERE cert_hash = ?1 ORDER BY key ASC")?;
        let rows = stmt.query_map(params![cert_hash], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}

fn run_migrations(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS private_storage (
            cert_hash TEXT NOT NULL,
            key TEXT NOT NULL,
            blob BLOB NOT NULL,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (cert_hash, key)
        );",
    )
}

fn unix_millis_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn poisoned_mutex_err() -> StorageError {
    StorageError::Io(std::io::Error::other("private-store db mutex poisoned"))
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
        assert_eq!(store.get("user-a", "sidebar").unwrap(), None);
        store.put("user-a", "sidebar", b"{\"v\":1}").unwrap();
        assert_eq!(
            store.get("user-a", "sidebar").unwrap().unwrap(),
            b"{\"v\":1}"
        );
    }

    #[test]
    fn put_overwrites() {
        let (_dir, store) = open_store();
        store.put("u", "k", b"first").unwrap();
        store.put("u", "k", b"second").unwrap();
        assert_eq!(store.get("u", "k").unwrap().unwrap(), b"second");
    }

    #[test]
    fn namespaces_are_isolated() {
        let (_dir, store) = open_store();
        store.put("user-a", "k", b"a-data").unwrap();
        store.put("user-b", "k", b"b-data").unwrap();
        assert_eq!(store.get("user-a", "k").unwrap().unwrap(), b"a-data");
        assert_eq!(store.get("user-b", "k").unwrap().unwrap(), b"b-data");
    }

    #[test]
    fn delete_and_list() {
        let (_dir, store) = open_store();
        store.put("u", "a", b"1").unwrap();
        store.put("u", "b", b"2").unwrap();
        assert_eq!(store.list_keys("u").unwrap(), vec!["a", "b"]);
        assert!(store.delete("u", "a").unwrap());
        assert!(!store.delete("u", "a").unwrap());
        assert_eq!(store.list_keys("u").unwrap(), vec!["b"]);
    }
}
