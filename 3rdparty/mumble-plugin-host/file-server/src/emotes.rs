//! Custom server emote storage and management.
//!
//! Emotes are admin-uploaded images/GIFs that all connected clients can
//! use as reactions or insert into messages. They live in the same
//! `SQLite` database as uploaded files (`metadata.db`), in a separate
//! `emotes` table.
//!
//! Each emote has:
//! * `shortcode` - unique short identifier used as the wire id
//!   (e.g. `myCustom`). Must be `[A-Za-z0-9_-]{1,64}`.
//! * `alias_emoji` - a fallback unicode emoji to display when the image
//!   cannot be loaded (e.g. `🤣`).
//! * `description` - optional human-readable description.
//! * `mime_type` + `bytes` - the actual image data (PNG/JPEG/GIF/WebP).
//!
//! Permission to add or remove emotes is gated by the Mumble ACL
//! system: the requesting session must hold `Write` on the root
//! channel (the canonical "is server admin" check that `SuperUser` and
//! the `admin` group inherit).

use std::io;
use std::sync::Mutex;

use rusqlite::{params, Connection};

/// Maximum length of a shortcode in characters.
pub const MAX_SHORTCODE_LEN: usize = 64;
/// Maximum length of the optional description field in characters.
pub const MAX_DESCRIPTION_LEN: usize = 256;
/// Hard cap on emote image size (bytes). Most useful emotes are well
/// under 100 KiB; we allow up to 2 MiB to support short GIFs.
pub const MAX_EMOTE_SIZE_BYTES: usize = 2 * 1024 * 1024;

/// Errors raised by the emote storage layer.
#[derive(Debug, thiserror::Error)]
pub enum EmoteError {
    /// Disk I/O error.
    #[error("emote i/o: {0}")]
    Io(#[from] io::Error),
    /// `SQLite` error.
    #[error("emote db: {0}")]
    Db(#[from] rusqlite::Error),
    /// Caller-supplied input failed validation.
    #[error("invalid emote: {0}")]
    Invalid(&'static str),
    /// Shortcode collides with an existing emote.
    #[error("emote with shortcode '{0}' already exists")]
    DuplicateShortcode(String),
    /// Emote not found.
    #[error("emote not found")]
    NotFound,
}

/// Persisted emote record.
#[derive(Debug, Clone)]
pub struct EmoteRecord {
    /// Unique shortcode identifier.
    pub shortcode: String,
    /// Fallback unicode emoji.
    pub alias_emoji: String,
    /// Optional description.
    pub description: Option<String>,
    /// MIME type (e.g. `image/png`).
    pub mime_type: String,
    /// Raw image bytes.
    pub bytes: Vec<u8>,
    /// Unix-millis when the emote was added.
    pub created_at: i64,
    /// Cert hash of the admin who added the emote.
    pub created_by_cert_hash: String,
}

/// Lightweight summary returned to clients in the broadcast list. Omits
/// the raw bytes; the bytes are encoded into a `data:` URL on the fly
/// when serializing the broadcast payload.
#[derive(Debug, Clone)]
pub struct EmoteSummary {
    /// Unique shortcode identifier.
    pub shortcode: String,
    /// Fallback unicode emoji.
    pub alias_emoji: String,
    /// Optional description.
    pub description: Option<String>,
    /// MIME type (e.g. `image/png`).
    pub mime_type: String,
    /// Raw image bytes (used to build the broadcast `data:` URL).
    pub bytes: Vec<u8>,
}

/// Validate a shortcode candidate.
///
/// Allowed: ASCII letters, digits, underscore, dash. 1..=`MAX_SHORTCODE_LEN`.
pub fn validate_shortcode(s: &str) -> Result<(), EmoteError> {
    if s.is_empty() || s.len() > MAX_SHORTCODE_LEN {
        return Err(EmoteError::Invalid(
            "shortcode must be 1-64 characters",
        ));
    }
    let valid = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !valid {
        return Err(EmoteError::Invalid(
            "shortcode may only contain letters, digits, underscore and dash",
        ));
    }
    Ok(())
}

/// Validate the alias emoji - must be non-empty and fit a small budget.
pub fn validate_alias_emoji(s: &str) -> Result<(), EmoteError> {
    if s.is_empty() {
        return Err(EmoteError::Invalid("alias_emoji must not be empty"));
    }
    // Allow up to ~32 bytes to comfortably fit ZWJ sequences and skin
    // tone modifiers without imposing a tight limit.
    if s.len() > 32 {
        return Err(EmoteError::Invalid("alias_emoji is too long"));
    }
    Ok(())
}

/// Validate the optional description.
pub fn validate_description(s: &str) -> Result<(), EmoteError> {
    if s.len() > MAX_DESCRIPTION_LEN {
        return Err(EmoteError::Invalid("description is too long"));
    }
    Ok(())
}

/// Validate the supplied MIME type. Only raster image types are allowed.
///
/// `image/svg+xml` is intentionally rejected: SVG can carry script that
/// executes when the image is loaded as a top-level document or via
/// `<object>`/`<iframe>`, which would let any client (including
/// non-Fancy-Mumble UIs) be `XSS`ed by an admin-uploaded emote.
pub fn validate_mime_type(s: &str) -> Result<(), EmoteError> {
    matches!(
        s,
        "image/png" | "image/jpeg" | "image/gif" | "image/webp"
    )
    .then_some(())
    .ok_or(EmoteError::Invalid(
        "mime_type must be image/png, image/jpeg, image/gif or image/webp",
    ))
}

/// Run the schema migration for the emotes table. Idempotent.
pub fn run_migrations(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS emotes (
            shortcode TEXT PRIMARY KEY,
            alias_emoji TEXT NOT NULL,
            description TEXT,
            mime_type TEXT NOT NULL,
            bytes BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            created_by_cert_hash TEXT NOT NULL
        );",
    )
}

/// Insert a new emote. Fails with [`EmoteError::DuplicateShortcode`] if
/// the shortcode already exists.
pub fn insert(db: &Mutex<Connection>, record: &EmoteRecord) -> Result<(), EmoteError> {
    validate_shortcode(&record.shortcode)?;
    validate_alias_emoji(&record.alias_emoji)?;
    if let Some(d) = record.description.as_deref() {
        validate_description(d)?;
    }
    validate_mime_type(&record.mime_type)?;
    if record.bytes.len() > MAX_EMOTE_SIZE_BYTES {
        return Err(EmoteError::Invalid("emote image exceeds size limit"));
    }
    if record.bytes.is_empty() {
        return Err(EmoteError::Invalid("emote image is empty"));
    }

    let conn = db.lock().map_err(|_| EmoteError::Invalid("db poisoned"))?;
    let result = conn.execute(
        "INSERT INTO emotes
            (shortcode, alias_emoji, description, mime_type, bytes,
             created_at, created_by_cert_hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            record.shortcode,
            record.alias_emoji,
            record.description,
            record.mime_type,
            record.bytes,
            record.created_at,
            record.created_by_cert_hash,
        ],
    );
    match result {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(err, _))
            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            Err(EmoteError::DuplicateShortcode(record.shortcode.clone()))
        }
        Err(e) => Err(EmoteError::Db(e)),
    }
}

/// Delete the emote with the given shortcode. Returns
/// [`EmoteError::NotFound`] if no row matched.
pub fn delete(db: &Mutex<Connection>, shortcode: &str) -> Result<(), EmoteError> {
    let conn = db.lock().map_err(|_| EmoteError::Invalid("db poisoned"))?;
    let affected = conn.execute("DELETE FROM emotes WHERE shortcode = ?1", params![shortcode])?;
    if affected == 0 {
        Err(EmoteError::NotFound)
    } else {
        Ok(())
    }
}

/// Load all emotes (without bytes if `include_bytes` is `false`).
pub fn list_all(db: &Mutex<Connection>) -> Result<Vec<EmoteSummary>, EmoteError> {
    let conn = db.lock().map_err(|_| EmoteError::Invalid("db poisoned"))?;
    let mut stmt = conn.prepare(
        "SELECT shortcode, alias_emoji, description, mime_type, bytes
         FROM emotes ORDER BY shortcode ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(EmoteSummary {
            shortcode: row.get(0)?,
            alias_emoji: row.get(1)?,
            description: row.get(2)?,
            mime_type: row.get(3)?,
            bytes: row.get(4)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers panic on failure"
)]
mod tests {
    use super::*;

    fn open_test_db() -> Mutex<Connection> {
        let conn = Connection::open_in_memory().expect("open in-memory");
        run_migrations(&conn).expect("migrate");
        Mutex::new(conn)
    }

    fn sample(shortcode: &str) -> EmoteRecord {
        EmoteRecord {
            shortcode: shortcode.into(),
            alias_emoji: "\u{1F600}".into(),
            description: Some("test".into()),
            mime_type: "image/png".into(),
            bytes: vec![0x89, 0x50, 0x4e, 0x47],
            created_at: 1,
            created_by_cert_hash: "deadbeef".into(),
        }
    }

    #[test]
    fn insert_then_list_returns_one() {
        let db = open_test_db();
        insert(&db, &sample("foo")).expect("insert");
        let listed = list_all(&db).expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].shortcode, "foo");
        assert_eq!(listed[0].alias_emoji, "\u{1F600}");
        assert_eq!(listed[0].mime_type, "image/png");
        assert_eq!(listed[0].bytes, vec![0x89, 0x50, 0x4e, 0x47]);
    }

    #[test]
    fn duplicate_shortcode_rejected() {
        let db = open_test_db();
        insert(&db, &sample("foo")).expect("insert first");
        let err = insert(&db, &sample("foo")).expect_err("dup rejected");
        assert!(matches!(err, EmoteError::DuplicateShortcode(_)));
    }

    #[test]
    fn delete_removes_row() {
        let db = open_test_db();
        insert(&db, &sample("foo")).expect("insert");
        delete(&db, "foo").expect("delete");
        assert!(list_all(&db).expect("list").is_empty());
    }

    #[test]
    fn delete_missing_returns_not_found() {
        let db = open_test_db();
        let err = delete(&db, "missing").expect_err("not found");
        assert!(matches!(err, EmoteError::NotFound));
    }

    #[test]
    fn invalid_shortcode_rejected() {
        let db = open_test_db();
        let mut bad = sample("ok");
        bad.shortcode = "has spaces".into();
        let err = insert(&db, &bad).expect_err("invalid");
        assert!(matches!(err, EmoteError::Invalid(_)));
    }

    #[test]
    fn empty_bytes_rejected() {
        let db = open_test_db();
        let mut bad = sample("foo");
        bad.bytes.clear();
        let err = insert(&db, &bad).expect_err("invalid");
        assert!(matches!(err, EmoteError::Invalid(_)));
    }

    #[test]
    fn oversize_bytes_rejected() {
        let db = open_test_db();
        let mut bad = sample("foo");
        bad.bytes = vec![0u8; MAX_EMOTE_SIZE_BYTES + 1];
        let err = insert(&db, &bad).expect_err("invalid");
        assert!(matches!(err, EmoteError::Invalid(_)));
    }

    #[test]
    fn shortcode_validation_accepts_alphanum_underscore_dash() {
        validate_shortcode("abc_123-XYZ").expect("valid");
        validate_shortcode("a").expect("min len");
        validate_shortcode(&"x".repeat(MAX_SHORTCODE_LEN)).expect("max len");
        assert!(validate_shortcode("").is_err(), "empty");
        assert!(validate_shortcode("with space").is_err(), "space");
        assert!(validate_shortcode("with:colon").is_err(), "colon");
    }
}
