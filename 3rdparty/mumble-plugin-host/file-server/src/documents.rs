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

/// One document as exposed to the admin dashboard by `list_documents`.
#[derive(Debug, Clone, Serialize)]
pub struct DocumentSummary {
    /// Stable document name (the live-doc `DocKey` filename).
    pub name: String,
    /// Sequence number of the most recent revision.
    pub latest_rev: u32,
    /// Total number of stored revisions.
    pub revision_count: u32,
    /// Size in bytes of the latest revision blob.
    pub size_bytes: u64,
    /// Unix-millis time the document was last written.
    pub updated_at: i64,
    /// Display name of the document's creator (the first session to persist
    /// it), or `null` for documents stored before owner tracking existed.
    pub owner_name: Option<String>,
    /// Stable cert hash of the creator, so the client can match a live user.
    pub owner_cert_hash: Option<String>,
}

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
/// to the same `SQLite` DB used by `Storage` (`SQLite` serialises
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
    ///
    /// `owner_name` / `owner_cert_hash` identify the creator and are recorded
    /// only on the document's **first** revision - subsequent revisions keep
    /// the original owner, so collaborative edits never reassign it.
    pub fn put(
        &self,
        name: &str,
        body: &[u8],
        owner_name: Option<&str>,
        owner_cert_hash: Option<&str>,
    ) -> Result<u32, StorageError> {
        let id = random_id();
        let blob_path = self.revs_dir.join(&id);
        std::fs::write(&blob_path, body)?;

        let mut digest = Sha256::new();
        digest.update(body);
        let sha = hex::encode(digest.finalize());
        let size = body.len() as u64;
        let now = unix_millis_now();

        let conn = self.db.lock().map_err(|_| poisoned_mutex_err())?;
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
        // Owner columns are written only on first insert; the ON CONFLICT path
        // deliberately leaves owner_name / owner_cert_hash untouched.
        let _ = conn.execute(
            "INSERT INTO documents(name, latest_rev, updated_at, owner_name, owner_cert_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT(name) DO UPDATE SET latest_rev = excluded.latest_rev, updated_at = excluded.updated_at",
            params![name, tx_rev, now, owner_name, owner_cert_hash],
        )?;
        Ok(tx_rev)
    }

    /// Fetch the body of the latest revision, or `None` when no
    /// revisions exist.
    pub fn get_latest(&self, name: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let conn = self.db.lock().map_err(|_| poisoned_mutex_err())?;
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
        let conn = self.db.lock().map_err(|_| poisoned_mutex_err())?;
        let row: Option<(String,)> = conn
            .prepare("SELECT id FROM document_revisions WHERE doc_name = ?1 AND rev_seq = ?2")?
            .query_row(params![name, rev_seq], |row| Ok((row.get(0)?,)))
            .optional()?;
        drop(conn);
        match row {
            Some((id,)) => Ok(Some(std::fs::read(self.revs_dir.join(id))?)),
            None => Ok(None),
        }
    }

    /// List every stored document with its latest-revision metadata,
    /// most-recently-updated first.  Powers the admin dashboard's
    /// "Documents" view.
    pub fn list_documents(&self) -> Result<Vec<DocumentSummary>, StorageError> {
        let conn = self.db.lock().map_err(|_| poisoned_mutex_err())?;
        let mut stmt = conn.prepare(
            "SELECT d.name, d.latest_rev, d.updated_at, \
                    COALESCE(r.size_bytes, 0), \
                    (SELECT COUNT(*) FROM document_revisions WHERE doc_name = d.name), \
                    d.owner_name, d.owner_cert_hash \
             FROM documents d \
             LEFT JOIN document_revisions r \
                 ON r.doc_name = d.name AND r.rev_seq = d.latest_rev \
             ORDER BY d.updated_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(DocumentSummary {
                name: row.get(0)?,
                latest_rev: row.get(1)?,
                updated_at: row.get(2)?,
                size_bytes: row.get::<_, i64>(3)? as u64,
                revision_count: row.get(4)?,
                owner_name: row.get(5)?,
                owner_cert_hash: row.get(6)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Delete a document and **all** its revisions - the `documents` row,
    /// the `document_revisions` rows, and every revision blob on disk.
    /// Returns `true` if the document existed.
    pub fn delete(&self, name: &str) -> Result<bool, StorageError> {
        let conn = self.db.lock().map_err(|_| poisoned_mutex_err())?;
        // Collect blob ids before removing the rows so the files can be cleaned
        // up afterwards (outside the transaction).
        let blob_ids: Vec<String> = {
            let mut stmt = conn.prepare("SELECT id FROM document_revisions WHERE doc_name = ?1")?;
            let rows = stmt.query_map(params![name], |row| row.get::<_, String>(0))?;
            let mut ids = Vec::new();
            for r in rows {
                ids.push(r?);
            }
            ids
        };
        let _ = conn.execute(
            "DELETE FROM document_revisions WHERE doc_name = ?1",
            params![name],
        )?;
        let removed = conn.execute("DELETE FROM documents WHERE name = ?1", params![name])?;
        drop(conn);
        for id in blob_ids {
            let blob = self.revs_dir.join(id);
            if blob.exists() {
                let _ = std::fs::remove_file(blob);
            }
        }
        Ok(removed > 0)
    }

    /// List all revisions for a document, newest first.
    pub fn list_revisions(&self, name: &str) -> Result<Vec<RevisionMeta>, StorageError> {
        let conn = self.db.lock().map_err(|_| poisoned_mutex_err())?;
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
            updated_at INTEGER NOT NULL,
            owner_name TEXT,
            owner_cert_hash TEXT
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
    )?;
    // Tolerant migration for DBs created before owner tracking: ADD COLUMN
    // errors with "duplicate column name" once the columns exist, which is the
    // expected steady state, so the result is intentionally ignored.
    let _ = conn.execute("ALTER TABLE documents ADD COLUMN owner_name TEXT", []);
    let _ = conn.execute("ALTER TABLE documents ADD COLUMN owner_cert_hash TEXT", []);
    Ok(())
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

fn poisoned_mutex_err() -> StorageError {
    StorageError::Io(std::io::Error::other("docs db mutex poisoned"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test code - panics are acceptable")]
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
        let rev = store.put("notes.md", b"# Hello", None, None).unwrap();
        assert_eq!(rev, 1);
        let body = store.get_latest("notes.md").unwrap().unwrap();
        assert_eq!(body, b"# Hello");
    }

    #[test]
    fn revisions_monotonic() {
        let (_dir, store) = open_store();
        assert_eq!(store.put("a", b"v1", None, None).unwrap(), 1);
        assert_eq!(store.put("a", b"v2", None, None).unwrap(), 2);
        assert_eq!(store.put("a", b"v3", None, None).unwrap(), 3);
        assert_eq!(store.get_latest("a").unwrap().unwrap(), b"v3");
        assert_eq!(store.get_revision("a", 1).unwrap().unwrap(), b"v1");
        assert_eq!(store.get_revision("a", 4).unwrap(), None);

        let list = store.list_revisions("a").unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].rev_seq, 3);
        assert_eq!(list[2].rev_seq, 1);
    }

    #[test]
    fn delete_removes_document_and_revisions() {
        let (_dir, store) = open_store();
        let _ = store
            .put("doc", b"v1", Some("Alice"), Some("certA"))
            .unwrap();
        let _ = store.put("doc", b"v2", None, None).unwrap();
        assert!(store.delete("doc").unwrap());
        assert_eq!(store.get_latest("doc").unwrap(), None);
        assert!(store.list_revisions("doc").unwrap().is_empty());
        assert!(store
            .list_documents()
            .unwrap()
            .iter()
            .all(|d| d.name != "doc"));
        // Deleting a non-existent document is a no-op that reports `false`.
        assert!(!store.delete("doc").unwrap());
    }

    #[test]
    fn owner_recorded_on_first_revision_only() {
        let (_dir, store) = open_store();
        let _ = store
            .put("doc", b"v1", Some("Alice"), Some("certA"))
            .unwrap();
        // A later revision by someone else must NOT reassign the owner.
        let _ = store.put("doc", b"v2", Some("Bob"), Some("certB")).unwrap();
        let docs = store.list_documents().unwrap();
        let d = docs.iter().find(|d| d.name == "doc").unwrap();
        assert_eq!(d.owner_name.as_deref(), Some("Alice"));
        assert_eq!(d.owner_cert_hash.as_deref(), Some("certA"));
        assert_eq!(d.revision_count, 2);
    }
}
