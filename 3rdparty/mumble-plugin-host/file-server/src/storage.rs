//! SQLite-backed metadata store + on-disk blob storage.
//!
//! Two persistent artifacts live under [`FileServerConfig::storage_path`]:
//!
//! * `signing.key`  - 32 random bytes generated on first start, used to
//!   sign download URLs and session JWTs.
//! * `metadata.db`  - `SQLite` database with the `files` table.
//!
//! Blob bytes are written to `{storage_path}/blobs/{file_id}`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rand::RngCore;
use rusqlite::{params, Connection};

/// Length of the auto-generated signing secret in bytes.
pub const SIGNING_SECRET_BYTES: usize = 32;

/// Subdirectory of `storage_path` where uploaded blobs live.
pub const BLOBS_SUBDIR: &str = "blobs";

/// Filename of the signing secret within `storage_path`.
pub const SIGNING_SECRET_FILE: &str = "signing.key";

/// Filename of the metadata `SQLite` database within `storage_path`.
pub const METADATA_DB_FILE: &str = "metadata.db";

/// Errors raised by the storage layer.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Disk I/O error.
    #[error("storage i/o: {0}")]
    Io(#[from] io::Error),
    /// `SQLite` error.
    #[error("storage db: {0}")]
    Db(#[from] rusqlite::Error),
    /// Storage cap would be exceeded by the requested operation.
    #[error("storage cap exceeded ({total_after} > {limit})")]
    CapExceeded {
        /// Total bytes that would be in use after the operation.
        total_after: u64,
        /// Configured cap.
        limit: u64,
    },
}

/// Per-file metadata persisted in the `files` table.
#[derive(Debug, Clone)]
pub struct FileRecord {
    /// 256-bit URL-safe random identifier.
    pub id: String,
    /// Mumble session id of the uploader (transient - cleared after disconnect).
    pub session_id: Option<u32>,
    /// Channel where the file was shared.
    pub channel_id: u32,
    /// Mumble virtual server id.
    pub server_id: u32,
    /// Original file name as provided by the uploader.
    pub filename: String,
    /// MIME type as provided by the uploader.
    pub mime_type: String,
    /// File size in bytes.
    pub size_bytes: u64,
    /// 16 hex chars = 8 raw bytes; the `is` URL parameter.
    pub url_nonce: String,
    /// Unix-seconds expiry; matches the `ex` URL parameter.
    pub url_expiry: u64,
    /// One of `public`, `password`, `session`.
    pub access_mode: AccessMode,
    /// Argon2id hash for password-protected files.
    pub password_hash: Option<String>,
    /// Unix-millis upload time.
    pub uploaded_at: i64,
    /// Unix-seconds expiry for TTL cleanup, or `None` to disable TTL.
    pub expires_at: Option<u64>,
    /// Unix-millis time of last successful download.
    pub downloaded_at: Option<i64>,
    /// Cert hash of the uploader at upload time.
    pub uploader_cert_hash: Option<String>,
}

/// Access mode chosen by the uploader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessMode {
    /// Anyone with the signed link may download.
    Public,
    /// Requires password verification at `POST /auth`.
    Password,
    /// Requires a valid session JWT and channel access.
    Session,
}

impl AccessMode {
    /// Render as the string stored in `SQLite`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Password => "password",
            Self::Session => "session",
        }
    }
    /// Parse from the `SQLite` string representation.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "public" => Some(Self::Public),
            "password" => Some(Self::Password),
            "session" => Some(Self::Session),
            _ => None,
        }
    }
}

/// Combined `SQLite` + filesystem storage.
#[derive(Debug)]
pub struct Storage {
    db: Mutex<Connection>,
    blobs_dir: PathBuf,
    cap_bytes: u64,
}

impl Storage {
    /// Open or create storage at `storage_path`. Creates the blobs
    /// subdirectory and runs schema migrations.
    pub fn open(storage_path: &Path, cap_bytes: u64) -> Result<Self, StorageError> {
        fs::create_dir_all(storage_path)?;
        let blobs_dir = storage_path.join(BLOBS_SUBDIR);
        fs::create_dir_all(&blobs_dir)?;
        let db_path = storage_path.join(METADATA_DB_FILE);
        let conn = Connection::open(&db_path)?;
        Self::run_migrations(&conn)?;
        crate::emotes::run_migrations(&conn)?;
        Ok(Self {
            db: Mutex::new(conn),
            blobs_dir,
            cap_bytes,
        })
    }

    fn run_migrations(conn: &Connection) -> Result<(), rusqlite::Error> {
        // The `CHECK` constraint enforces M-5: a `password` row may never
        // be inserted without a stored hash, eliminating the latent 500
        // error path in `verify_password_credential`.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                session_id INTEGER,
                channel_id INTEGER NOT NULL,
                server_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                mime_type TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                url_nonce TEXT NOT NULL,
                url_expiry INTEGER NOT NULL,
                access_mode TEXT NOT NULL,
                password_hash TEXT,
                uploaded_at INTEGER NOT NULL,
                expires_at INTEGER,
                downloaded_at INTEGER,
                uploader_cert_hash TEXT,
                CHECK (access_mode != 'password' OR password_hash IS NOT NULL)
            );
            CREATE INDEX IF NOT EXISTS idx_files_expires_at ON files(expires_at);
            CREATE INDEX IF NOT EXISTS idx_files_session_id ON files(session_id);",
        )
    }

    /// Path on disk where the blob for `file_id` should be written.
    pub fn blob_path(&self, file_id: &str) -> PathBuf {
        self.blobs_dir.join(file_id)
    }

    /// Borrow the underlying `SQLite` connection mutex. Used by the
    /// `emotes` module which manages its own table within the same DB.
    #[must_use]
    pub fn emote_db(&self) -> &Mutex<Connection> {
        &self.db
    }

    /// Total bytes currently in use (sum of `size_bytes`).
    pub fn total_bytes_used(&self) -> Result<u64, StorageError> {
        let conn = self.db.lock().map_err(|_| poisoned_db())?;
        let total: i64 = conn.query_row(
            "SELECT COALESCE(SUM(size_bytes), 0) FROM files",
            [],
            |row| row.get(0),
        )?;
        Ok(total as u64)
    }

    /// Insert a new file record. Caller has already written the blob.
    /// Fails if the storage cap would be exceeded.
    ///
    /// The cap check is performed inside the same locked section as the
    /// `INSERT`, so concurrent uploaders cannot both observe `used + N
    /// <= cap` and both insert (H-2: TOCTOU bypass).
    pub fn insert(&self, record: &FileRecord) -> Result<(), StorageError> {
        let conn = self.db.lock().map_err(|_| poisoned_db())?;
        let used: i64 = conn.query_row(
            "SELECT COALESCE(SUM(size_bytes), 0) FROM files",
            [],
            |row| row.get(0),
        )?;
        let total_after = (used as u64).saturating_add(record.size_bytes);
        if total_after > self.cap_bytes {
            return Err(StorageError::CapExceeded {
                total_after,
                limit: self.cap_bytes,
            });
        }
        let _ = conn.execute(
            "INSERT INTO files
              (id, session_id, channel_id, server_id, filename, mime_type, size_bytes,
               url_nonce, url_expiry, access_mode, password_hash, uploaded_at,
               expires_at, downloaded_at, uploader_cert_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                record.id,
                record.session_id,
                record.channel_id,
                record.server_id,
                record.filename,
                record.mime_type,
                record.size_bytes as i64,
                record.url_nonce,
                record.url_expiry as i64,
                record.access_mode.as_str(),
                record.password_hash,
                record.uploaded_at,
                record.expires_at.map(|v| v as i64),
                record.downloaded_at,
                record.uploader_cert_hash,
            ],
        )?;
        Ok(())
    }

    /// Fetch a single record by id.
    pub fn get(&self, file_id: &str) -> Result<Option<FileRecord>, StorageError> {
        let conn = self.db.lock().map_err(|_| poisoned_db())?;
        conn.query_row(
            "SELECT id, session_id, channel_id, server_id, filename, mime_type, size_bytes,
                    url_nonce, url_expiry, access_mode, password_hash, uploaded_at,
                    expires_at, downloaded_at, uploader_cert_hash
             FROM files WHERE id = ?1",
            params![file_id],
            row_to_record,
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(StorageError::from(other)),
        })
    }

    /// Mark a file as downloaded (sets `downloaded_at`).
    pub fn mark_downloaded(&self, file_id: &str, when_unix_ms: i64) -> Result<(), StorageError> {
        let conn = self.db.lock().map_err(|_| poisoned_db())?;
        let _ = conn.execute(
            "UPDATE files SET downloaded_at = ?1 WHERE id = ?2",
            params![when_unix_ms, file_id],
        )?;
        Ok(())
    }

    /// Delete a file record and its blob from disk.
    pub fn delete(&self, file_id: &str) -> Result<(), StorageError> {
        let conn = self.db.lock().map_err(|_| poisoned_db())?;
        let _ = conn.execute("DELETE FROM files WHERE id = ?1", params![file_id])?;
        drop(conn);
        let blob = self.blob_path(file_id);
        if blob.exists() {
            fs::remove_file(blob)?;
        }
        Ok(())
    }

    /// Return ids of records whose `expires_at < now`.
    pub fn list_expired(&self, now_unix_seconds: u64) -> Result<Vec<String>, StorageError> {
        let conn = self.db.lock().map_err(|_| poisoned_db())?;
        let mut stmt =
            conn.prepare("SELECT id FROM files WHERE expires_at IS NOT NULL AND expires_at < ?1")?;
        let rows = stmt.query_map(params![now_unix_seconds as i64], |row| {
            row.get::<_, String>(0)
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Return ids of records uploaded by the given session.
    pub fn list_for_session(&self, session_id: u32) -> Result<Vec<String>, StorageError> {
        let conn = self.db.lock().map_err(|_| poisoned_db())?;
        let mut stmt = conn.prepare("SELECT id FROM files WHERE session_id = ?1")?;
        let rows = stmt.query_map(params![session_id], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}

/// Load or create the signing secret stored under `storage_path/signing.key`.
///
/// On Unix the file is created with mode `0600` (owner read/write only).
/// On Windows the inherited ACL is used; operators are expected to keep
/// the storage directory off shared paths.
pub fn load_or_create_signing_secret(
    storage_path: &Path,
) -> Result<[u8; SIGNING_SECRET_BYTES], StorageError> {
    fs::create_dir_all(storage_path)?;
    let path = storage_path.join(SIGNING_SECRET_FILE);
    if path.exists() {
        let bytes = fs::read(&path)?;
        if bytes.len() == SIGNING_SECRET_BYTES {
            let mut out = [0u8; SIGNING_SECRET_BYTES];
            out.copy_from_slice(&bytes);
            return Ok(out);
        }
        // File present but wrong size: treat as corrupt and regenerate.
        tracing::warn!("signing secret file has unexpected size; regenerating");
        fs::remove_file(&path)?;
    }
    let mut secret = [0u8; SIGNING_SECRET_BYTES];
    rand::thread_rng().fill_bytes(&mut secret);
    write_secret_restricted(&path, &secret)?;
    Ok(secret)
}

#[cfg(unix)]
fn write_secret_restricted(path: &Path, secret: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(secret)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_restricted(path: &Path, secret: &[u8]) -> io::Result<()> {
    fs::write(path, secret)
}

fn poisoned_db() -> StorageError {
    StorageError::Io(io::Error::other("metadata db mutex poisoned"))
}

fn row_to_record(row: &rusqlite::Row<'_>) -> Result<FileRecord, rusqlite::Error> {
    let access_str: String = row.get(9)?;
    let access_mode = AccessMode::parse(&access_str).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            9,
            rusqlite::types::Type::Text,
            Box::new(io::Error::other(format!(
                "unknown access mode: {access_str}"
            ))),
        )
    })?;
    Ok(FileRecord {
        id: row.get(0)?,
        session_id: row.get(1)?,
        channel_id: row.get(2)?,
        server_id: row.get(3)?,
        filename: row.get(4)?,
        mime_type: row.get(5)?,
        size_bytes: row.get::<_, i64>(6)? as u64,
        url_nonce: row.get(7)?,
        url_expiry: row.get::<_, i64>(8)? as u64,
        access_mode,
        password_hash: row.get(10)?,
        uploaded_at: row.get(11)?,
        expires_at: row.get::<_, Option<i64>>(12)?.map(|v| v as u64),
        downloaded_at: row.get(13)?,
        uploader_cert_hash: row.get(14)?,
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        reason = "tests panic on failure"
    )]
    use super::*;

    fn sample_record(id: &str, size: u64) -> FileRecord {
        FileRecord {
            id: id.to_owned(),
            session_id: Some(1),
            channel_id: 0,
            server_id: 1,
            filename: "x.bin".into(),
            mime_type: "application/octet-stream".into(),
            size_bytes: size,
            url_nonce: "0011223344556677".into(),
            url_expiry: 9_999_999_999,
            access_mode: AccessMode::Public,
            password_hash: None,
            uploaded_at: 0,
            expires_at: None,
            downloaded_at: None,
            uploader_cert_hash: None,
        }
    }

    #[test]
    fn insert_get_delete_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Storage::open(dir.path(), 1024 * 1024).expect("open");
        let rec = sample_record("file-1", 100);
        store.insert(&rec).expect("insert");

        let loaded = store.get("file-1").expect("get").expect("present");
        assert_eq!(loaded.id, "file-1");
        assert_eq!(loaded.access_mode, AccessMode::Public);

        store.delete("file-1").expect("delete");
        assert!(store.get("file-1").expect("get").is_none());
    }

    #[test]
    fn cap_enforced_on_insert() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Storage::open(dir.path(), 50).expect("open");
        store.insert(&sample_record("a", 30)).expect("first ok");
        let err = store.insert(&sample_record("b", 30)).unwrap_err();
        assert!(matches!(err, StorageError::CapExceeded { .. }));
    }

    #[test]
    fn signing_secret_persists_across_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s1 = load_or_create_signing_secret(dir.path()).expect("ok");
        let s2 = load_or_create_signing_secret(dir.path()).expect("ok");
        assert_eq!(s1, s2);
    }

    #[test]
    fn list_expired_returns_only_expired_ids() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Storage::open(dir.path(), 1_000_000).expect("open");
        let mut a = sample_record("expired", 1);
        a.expires_at = Some(100);
        let mut b = sample_record("future", 1);
        b.expires_at = Some(9_999_999_999);
        let mut c = sample_record("noexpiry", 1);
        c.expires_at = None;
        store.insert(&a).expect("insert");
        store.insert(&b).expect("insert");
        store.insert(&c).expect("insert");

        let expired = store.list_expired(1_000).expect("query");
        assert_eq!(expired, vec!["expired".to_owned()]);
    }

    #[test]
    fn list_for_session_filters_correctly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Storage::open(dir.path(), 1_000_000).expect("open");
        let mut a = sample_record("a", 1);
        a.session_id = Some(7);
        let mut b = sample_record("b", 1);
        b.session_id = Some(8);
        store.insert(&a).expect("ok");
        store.insert(&b).expect("ok");

        let mut out = store.list_for_session(7).expect("ok");
        out.sort();
        assert_eq!(out, vec!["a".to_owned()]);
    }
}
