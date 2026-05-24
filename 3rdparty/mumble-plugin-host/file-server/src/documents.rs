//! Stable-named documents with append-only revision history.
//!
//! Used by sibling plugins (live-doc) to persist collaborative
//! documents under a caller-chosen name and pull a specific
//! revision back later.  Lives in the same `SQLite` DB as the
//! per-upload `files` table but in separate tables so revisions
//! never collide with random-id uploads.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::storage::{StorageError, METADATA_DB_FILE};

/// Subdirectory under `storage_path` where document revision blobs live.
pub const DOCS_SUBDIR: &str = "doc-revisions";

/// One revision entry returned by `list_revisions`.
#[derive(Debug, Clone, Serialize)]
pub struct RevisionMeta {
    /// Monotonically increasing per-document sequence number.
    pub rev_seq: u32,
    /// Size of the revision blob in bytes.
    pub size_bytes: u64,
    /// Hex-encoded SHA-256 of the blob bytes.
    pub sha256: String,
    /// Unix-millis time the revision was written.
    pub created_at: i64,
}

/// Append-only document store backed by an independent connection
/// to the same `SQLite` DB used by `Storage` (SQLite serialises
/// writes at the file level so the two stores coexist safely).
/// Revision blobs live under `{storage_path}/doc-revisions/{id}`.
#[derive(Debug)]
pub struct DocumentsStore {
    db: Mutex<Connection>,
    revs_dir: PathBuf,
}

impl DocumentsStore {
    /// Open (or create) the store at `storage_path` and run schema
    /// migrations.  The directory must already exist - `Storage::open`
    /// creates it before this is called.
    pub fn open(storage_path: &Path) -> Result<Self, StorageError> {
        let revs_dir = storage_path.join(DOCS_SUBDIR);
        std::fs::create_dir_all(&revs_dir)?;
        let conn = Connection::open(storage_path.join(METADATA_DB_FILE))?;
        run_migrations(&conn)?;
        Ok(Self {
            db: Mutex::new(conn),
            revs_dir,
        })
    }

    /// Append a new revision under `name`.  Returns the assigned
    /// sequence number.  The blob is written before the row is
    /// inserted; on failure the row is not inserted.
    pub fn put(&self, name: &str, body: &[u8]) -> Result<u32, StorageError> {
        let id = random_id();
        let blob_path = self.revs_dir.join(&id);
        std::fs::write(&blob_path, body)?;

        let mut digest = Sha256::new();
        digest.update(body);
        let sha = hex::encode(digest.finalize());
        let size = body.len() as u64;
        let now = unix_millis_now();

        let conn = self.db.lock().expect("docs db mutex poisoned");
        let tx_rev: u32 = conn
            .prepare(
                "SELECT COALESCE(MAX(rev_seq), 0) + 1 FROM document_revisions WHERE doc_name = ?1",
            )?
            .query_row(params![name], |row| row.get::<_, u32>(0))?;
        let _ = conn.execute(
            "INSERT INTO document_revisions(id, doc_name, rev_seq, size_bytes, sha256, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, name, tx_rev, size as i64, sha, now],
        )?;
        let _ = conn.execute(
            "INSERT INTO documents(name, latest_rev, updated_at) VALUES (?1, ?2, ?3) \
             ON CONFLICT(name) DO UPDATE SET latest_rev = excluded.latest_rev, updated_at = excluded.updated_at",
            params![name, tx_rev, now],
        )?;
        Ok(tx_rev)
    }

    /// Fetch the body of the latest revision, or `None` when no
    /// revisions exist.
    pub fn get_latest(&self, name: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let conn = self.db.lock().expect("docs db mutex poisoned");
        let row: Option<(String,)> = conn
            .prepare(
                "SELECT r.id FROM documents d \
                 JOIN document_revisions r ON r.doc_name = d.name AND r.rev_seq = d.latest_rev \
                 WHERE d.name = ?1",
            )?
            .query_row(params![name], |row| Ok((row.get(0)?,)))
            .optional()?;
        drop(conn);
        match row {
            Some((id,)) => Ok(Some(std::fs::read(self.revs_dir.join(id))?)),
            None => Ok(None),
        }
    }

    /// Fetch the body of a specific revision, or `None` when no such
    /// revision exists.
    pub fn get_revision(&self, name: &str, rev_seq: u32) -> Result<Option<Vec<u8>>, StorageError> {
        let conn = self.db.lock().expect("docs db mutex poisoned");
        let row: Option<(String,)> = conn
            .prepare(
                "SELECT id FROM document_revisions WHERE doc_name = ?1 AND rev_seq = ?2",
            )?
            .query_row(params![name, rev_seq], |row| Ok((row.get(0)?,)))
            .optional()?;
        drop(conn);
        match row {
            Some((id,)) => Ok(Some(std::fs::read(self.revs_dir.join(id))?)),
            None => Ok(None),
        }
    }

    /// List all revisions for a document, newest first.
    pub fn list_revisions(&self, name: &str) -> Result<Vec<RevisionMeta>, StorageError> {
        let conn = self.db.lock().expect("docs db mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT rev_seq, size_bytes, sha256, created_at \
             FROM document_revisions WHERE doc_name = ?1 ORDER BY rev_seq DESC",
        )?;
        let rows = stmt.query_map(params![name], |row| {
            Ok(RevisionMeta {
                rev_seq: row.get(0)?,
                size_bytes: row.get::<_, i64>(1)? as u64,
                sha256: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}

fn run_migrations(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS documents (
            name TEXT PRIMARY KEY,
            latest_rev INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS document_revisions (
            id TEXT PRIMARY KEY,
            doc_name TEXT NOT NULL,
            rev_seq INTEGER NOT NULL,
            size_bytes INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            UNIQUE(doc_name, rev_seq)
        );
        CREATE INDEX IF NOT EXISTS idx_doc_revisions_name ON document_revisions(doc_name);",
    )
}

fn unix_millis_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn random_id() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn open_store() -> (TempDir, DocumentsStore) {
        let dir = TempDir::new().unwrap();
        let store = DocumentsStore::open(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn put_get_round_trip() {
        let (_dir, store) = open_store();
        let rev = store.put("notes.md", b"# Hello").unwrap();
        assert_eq!(rev, 1);
        let body = store.get_latest("notes.md").unwrap().unwrap();
        assert_eq!(body, b"# Hello");
    }

    #[test]
    fn revisions_monotonic() {
        let (_dir, store) = open_store();
        assert_eq!(store.put("a", b"v1").unwrap(), 1);
        assert_eq!(store.put("a", b"v2").unwrap(), 2);
        assert_eq!(store.put("a", b"v3").unwrap(), 3);
        assert_eq!(store.get_latest("a").unwrap().unwrap(), b"v3");
        assert_eq!(store.get_revision("a", 1).unwrap().unwrap(), b"v1");
        assert_eq!(store.get_revision("a", 4).unwrap(), None);

        let list = store.list_revisions("a").unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].rev_seq, 3);
        assert_eq!(list[2].rev_seq, 1);
    }
}
