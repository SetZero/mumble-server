//! Git-style hash chain for tamper evidence (§7.1).
//!
//! Every entry commits to its parent, exactly like a git commit references its
//! parent:
//!
//! ```text
//! entry_hash = SHA-256( parent_hash || canonical_encode(record) )
//! ```
//!
//! This matters precisely because the people with DB write access *are* the
//! people being audited: a rogue admin who deletes or edits a row breaks the
//! chain visibly. Deleting a row leaves a parent-hash gap; editing a row makes
//! its stored `entry_hash` fail to reproduce.
//!
//! `canonical_encode` is a deterministic, length-prefixed serialization with a
//! fixed field order and no map ambiguity, so the hash is reproducible on any
//! platform and in any backend.

use sha2::{Digest, Sha256};

use crate::model::{AuditEntry, AuditRecord, Identity};

/// Parent hash of the genesis entry: 32 zero bytes.
pub const GENESIS_PARENT: [u8; 32] = [0u8; 32];

/// Domain-separation tag mixed into every hash so an audit entry hash can never
/// collide with a hash computed for another purpose over the same bytes.
const DOMAIN: &[u8] = b"fancymumble.audit.v1";

/// Canonically encode a record into a deterministic byte string.
///
/// Every field is written in a fixed order. Variable-length and optional fields
/// are length-prefixed (with a distinct marker for "absent" vs "present but
/// empty") so that no two distinct records can encode to the same bytes.
#[must_use]
pub fn canonical_encode(record: &AuditRecord) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    put_bytes(&mut out, DOMAIN);
    put_i64(&mut out, i64::from(record.server_id));
    put_i64(&mut out, record.ts_ms);
    put_str(&mut out, record.source.as_str());
    put_str(&mut out, &record.category);
    put_str(&mut out, record.severity.as_str());
    put_identity(&mut out, &record.actor);
    put_identity(&mut out, &record.target);
    put_opt_i64(&mut out, record.channel_id);
    put_opt_str(&mut out, record.reason.as_deref());
    put_opt_str(&mut out, record.detail_json.as_deref());
    put_opt_i64(&mut out, record.relates_to);
    put_opt_i64(&mut out, record.event_offset.map(cast_u64));
    put_opt_i64(&mut out, record.expires_at_ms);
    out
}

/// Compute the chain hash for `record` given its `parent` hash.
#[must_use]
pub fn hash_entry(parent: &[u8; 32], record: &AuditRecord) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(parent);
    hasher.update(canonical_encode(record));
    hasher.finalize().into()
}

/// Where a chain verification stopped, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// The whole chain reproduces: no gaps, no edits. Carries the number of
    /// entries checked and the head hash (a cheap checkpoint value, §7.1).
    Intact {
        /// How many entries were walked.
        checked: usize,
        /// Hash of the last entry (the current chain head).
        head: [u8; 32],
    },
    /// The chain broke at `id`. Everything before it verified.
    Broken {
        /// Row id of the first entry that failed.
        id: i64,
        /// Zero-based position of that entry in the walked slice.
        index: usize,
        /// What specifically failed.
        kind: BreakKind,
    },
}

impl VerifyOutcome {
    /// Whether the chain verified end to end.
    #[must_use]
    pub const fn is_intact(&self) -> bool {
        matches!(self, Self::Intact { .. })
    }
}

/// The specific way a chain entry failed to verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakKind {
    /// The entry's stored `prev_hash` does not match the previous entry's
    /// `entry_hash` — the signature of a **deleted** (or reordered) row.
    ParentMismatch,
    /// The entry's stored `entry_hash` does not reproduce from its content —
    /// the signature of an **edited** row.
    ContentMismatch,
}

impl BreakKind {
    /// A short human explanation of the break.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::ParentMismatch => {
                "parent-hash gap: a previous entry was deleted, reordered or its hash altered"
            }
            Self::ContentMismatch => "content mismatch: this entry was edited after it was written",
        }
    }
}

/// Walk `entries` in order and report the first break, if any (§7.1).
///
/// `entries` must be in ascending chain order (as returned by the store). The
/// first entry is expected to chain from [`GENESIS_PARENT`]; each subsequent
/// entry from its predecessor's `entry_hash`.
#[must_use]
pub fn verify_chain(entries: &[AuditEntry]) -> VerifyOutcome {
    let mut parent = GENESIS_PARENT;
    for (index, entry) in entries.iter().enumerate() {
        if entry.prev_hash != parent {
            return VerifyOutcome::Broken {
                id: entry.id,
                index,
                kind: BreakKind::ParentMismatch,
            };
        }
        let recomputed = hash_entry(&parent, &entry.record);
        if recomputed != entry.entry_hash {
            return VerifyOutcome::Broken {
                id: entry.id,
                index,
                kind: BreakKind::ContentMismatch,
            };
        }
        parent = entry.entry_hash;
    }
    VerifyOutcome::Intact {
        checked: entries.len(),
        head: parent,
    }
}

// --- canonical encoding primitives ---------------------------------------
//
// Each primitive writes a self-delimiting encoding so the concatenation is
// unambiguous. Integers are fixed-width big-endian; byte strings are length-
// prefixed; optionals get a 1-byte present/absent tag.

fn put_i64(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_i64(out, cast_usize(bytes.len()));
    out.extend_from_slice(bytes);
}

fn put_str(out: &mut Vec<u8>, value: &str) {
    put_bytes(out, value.as_bytes());
}

fn put_opt_i64(out: &mut Vec<u8>, value: Option<i64>) {
    match value {
        Some(v) => {
            out.push(1);
            put_i64(out, v);
        }
        None => out.push(0),
    }
}

fn put_opt_str(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(v) => {
            out.push(1);
            put_str(out, v);
        }
        None => out.push(0),
    }
}

fn put_identity(out: &mut Vec<u8>, identity: &Identity) {
    put_opt_i64(out, identity.user_id);
    put_opt_str(out, identity.hash.as_deref());
    put_opt_str(out, identity.name.as_deref());
}

/// Cast a `usize` length to `i64` for encoding. Lengths in this system are far
/// below `i64::MAX`; saturating keeps the function total without a panic path.
fn cast_usize(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Reinterpret a `u64` offset as `i64` bit-for-bit for encoding. The value is
/// only ever decoded back through the same reinterpretation, so the round trip
/// is exact regardless of the high bit.
#[allow(
    clippy::cast_possible_wrap,
    reason = "offsets are encoded/decoded through the same bit reinterpretation; exactness is preserved"
)]
fn cast_u64(value: u64) -> i64 {
    value as i64
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "unwrap is the standard, readable idiom in unit tests"
)]
mod tests {
    use super::*;
    use crate::model::{Severity, Source};

    fn sample(offset: u64) -> AuditRecord {
        AuditRecord::new(
            1,
            1_700_000_000_000 + i64::from(u32::try_from(offset).unwrap()),
            Source::Server,
            "audit.ban",
        )
        .with_severity(Severity::Critical)
        .with_actor(Identity {
            user_id: Some(7),
            hash: Some("aa".into()),
            name: Some("mod".into()),
        })
        .with_target(Identity {
            user_id: Some(9),
            hash: Some("bb".into()),
            name: Some("troll".into()),
        })
        .with_channel(0)
        .with_reason("spam")
        .with_detail_json(r#"{"ban":true}"#)
        .with_event_offset(offset)
    }

    /// Build a valid chain from a set of records.
    fn build_chain(records: &[AuditRecord]) -> Vec<AuditEntry> {
        let mut parent = GENESIS_PARENT;
        let mut out = Vec::new();
        for (i, record) in records.iter().enumerate() {
            let entry_hash = hash_entry(&parent, record);
            out.push(AuditEntry {
                id: i64::try_from(i).unwrap() + 1,
                record: record.clone(),
                prev_hash: parent,
                entry_hash,
            });
            parent = entry_hash;
        }
        out
    }

    #[test]
    fn canonical_encoding_is_deterministic() {
        let record = sample(1);
        assert_eq!(canonical_encode(&record), canonical_encode(&record.clone()));
    }

    #[test]
    fn distinct_records_encode_differently() {
        assert_ne!(canonical_encode(&sample(1)), canonical_encode(&sample(2)));
    }

    #[test]
    fn absent_vs_empty_string_differ() {
        let base = AuditRecord::new(1, 0, Source::Server, "audit.config");
        let with_empty = base.clone().with_reason("");
        // "reason absent" must not encode the same as "reason present but empty".
        assert_ne!(canonical_encode(&base), canonical_encode(&with_empty));
    }

    #[test]
    fn genesis_and_growth_verify() {
        let chain = build_chain(&[sample(1), sample(2), sample(3)]);
        let outcome = verify_chain(&chain);
        assert!(outcome.is_intact(), "expected intact, got {outcome:?}");
        match outcome {
            VerifyOutcome::Intact { checked, .. } => assert_eq!(checked, 3),
            VerifyOutcome::Broken { .. } => unreachable!(),
        }
    }

    #[test]
    fn empty_chain_is_intact() {
        assert!(verify_chain(&[]).is_intact());
    }

    #[test]
    fn editing_a_row_is_detected_as_content_mismatch() {
        let mut chain = build_chain(&[sample(1), sample(2), sample(3)]);
        // Tamper with the middle entry's stored content but keep its hashes.
        chain[1].record.reason = Some("rewritten".into());
        match verify_chain(&chain) {
            VerifyOutcome::Broken { id, index, kind } => {
                assert_eq!(id, 2);
                assert_eq!(index, 1);
                assert_eq!(kind, BreakKind::ContentMismatch);
            }
            VerifyOutcome::Intact { .. } => panic!("edit went undetected"),
        }
    }

    #[test]
    fn deleting_a_row_is_detected_as_parent_mismatch() {
        let chain = build_chain(&[sample(1), sample(2), sample(3)]);
        // Drop the middle entry, as a rogue admin deleting a row would.
        let tampered = vec![chain[0].clone(), chain[2].clone()];
        match verify_chain(&tampered) {
            VerifyOutcome::Broken { id, index, kind } => {
                assert_eq!(id, 3);
                assert_eq!(index, 1);
                assert_eq!(kind, BreakKind::ParentMismatch);
            }
            VerifyOutcome::Intact { .. } => panic!("deletion went undetected"),
        }
    }

    #[test]
    fn head_hash_is_stable_for_the_same_chain() {
        let a = verify_chain(&build_chain(&[sample(1), sample(2)]));
        let b = verify_chain(&build_chain(&[sample(1), sample(2)]));
        assert_eq!(a, b);
    }
}
