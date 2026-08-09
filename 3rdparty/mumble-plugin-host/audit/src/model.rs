//! Core data model for the server audit log.
//!
//! These types mirror the `server_audit` table described in §4 of the design
//! doc (`docs/audit-log.md`) and the toggle matrix in §9.2. They are storage-
//! and transport-agnostic: the same [`AuditRecord`] is what the hash chain
//! ([`crate::chain`]) commits to and what the store persists.

use serde::{Deserialize, Serialize};

/// Origin of an audit event.
///
/// The distinction is a load-bearing design principle (§2): `server`-sourced
/// events are facts the server mediated, `client`-sourced events are *claims*,
/// and `plugin`-sourced events come from a host privileged callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// Authoritative action the server itself performed.
    Server,
    /// A subjective, client-reported signal (a *claim*).
    Client,
    /// A privileged action taken by a plugin via a host callback.
    Plugin,
}

impl Source {
    /// The stable wire string for this source (used in canonical encoding).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Client => "client",
            Self::Plugin => "plugin",
        }
    }

    /// Parse a source from its wire string.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "server" => Some(Self::Server),
            "client" => Some(Self::Client),
            "plugin" => Some(Self::Plugin),
            _ => None,
        }
    }
}

/// Relative importance of an event, used for filtering and notifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Routine, high-volume activity.
    Info,
    /// Noteworthy but not alarming.
    Notice,
    /// Something an operator likely wants to see.
    Warning,
    /// High-impact action (e.g. ban of a registered user).
    Critical,
}

impl Severity {
    /// The stable wire string for this severity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Notice => "notice",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }

    /// Parse a severity from its wire string, defaulting to `Info` for unknown
    /// values so a forward-compatible row never fails to load.
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value {
            "notice" => Self::Notice,
            "warning" => Self::Warning,
            "critical" => Self::Critical,
            _ => Self::Info,
        }
    }
}

/// A snapshot of an identity *at the time an event was recorded* (§4).
///
/// Names are stored as they were then; a later rename or deletion must never
/// rewrite history, so this is a point-in-time copy rather than a live join.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// Registered user id, or `None` for a guest/system actor.
    pub user_id: Option<i64>,
    /// Certificate-hash snapshot: the stable cross-session identity.
    pub hash: Option<String>,
    /// Display name at the time of the event.
    pub name: Option<String>,
}

impl Identity {
    /// A `system` identity: no user id, hash or name. Used for events the
    /// server originates without a human actor (e.g. an expiry sweep).
    #[must_use]
    pub const fn system() -> Self {
        Self {
            user_id: None,
            hash: None,
            name: None,
        }
    }

    /// Whether this identity carries no information at all.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.user_id.is_none() && self.hash.is_none() && self.name.is_none()
    }
}

/// The immutable, hashable content of one audit entry: every column of
/// `server_audit` (§4) *except* the chain plumbing (`id`, `prev_hash`,
/// `entry_hash`), which the store and [`crate::chain`] own.
///
/// This is what [`crate::chain::hash_entry`] canonically encodes, so its field
/// set and their meaning are part of the tamper-evidence contract: changing how
/// a field is encoded changes every downstream hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Virtual server this event belongs to.
    pub server_id: i32,
    /// Event time in unix milliseconds on the server clock.
    pub ts_ms: i64,
    /// Whether this is an authoritative action, a claim or a plugin action.
    pub source: Source,
    /// The event category (the toggle *part*, e.g. `audit.ban`); see
    /// [`crate::toggles::Part`].
    pub category: String,
    /// Relative importance.
    pub severity: Severity,
    /// Who performed the action (empty for system events).
    pub actor: Identity,
    /// Who the action was about, if any.
    pub target: Identity,
    /// Channel the action concerned, if any.
    pub channel_id: Option<i64>,
    /// Free-text reason (may be empty; the UI flags "no reason given").
    pub reason: Option<String>,
    /// Category-specific structured payload as a canonical JSON string
    /// (before/after, CIDR, duration, …). Kept as a string so the exact bytes
    /// that were hashed are the exact bytes stored.
    pub detail_json: Option<String>,
    /// Links a reversing action back to what it reverses (§7.4): an unban
    /// points at the ban, an unmute at the mute.
    pub relates_to: Option<i64>,
    /// Offset of the originating bridge event (§7.10). Recording it makes
    /// ingestion idempotent: a redelivered event is detected and skipped.
    pub event_offset: Option<u64>,
    /// Wall-clock expiry stamped **at write time** from the retention policy
    /// then in force (§7.9), in unix milliseconds. `None` means "never".
    pub expires_at_ms: Option<i64>,
}

impl AuditRecord {
    /// Construct a minimal record for `category` at `ts_ms` on `server_id`,
    /// with everything optional left unset. Builder-style setters fill the rest.
    #[must_use]
    pub fn new(server_id: i32, ts_ms: i64, source: Source, category: impl Into<String>) -> Self {
        Self {
            server_id,
            ts_ms,
            source,
            category: category.into(),
            severity: Severity::Info,
            actor: Identity::default(),
            target: Identity::default(),
            channel_id: None,
            reason: None,
            detail_json: None,
            relates_to: None,
            event_offset: None,
            expires_at_ms: None,
        }
    }

    /// Set the severity.
    #[must_use]
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Set the actor identity.
    #[must_use]
    pub fn with_actor(mut self, actor: Identity) -> Self {
        self.actor = actor;
        self
    }

    /// Set the target identity.
    #[must_use]
    pub fn with_target(mut self, target: Identity) -> Self {
        self.target = target;
        self
    }

    /// Set the channel id.
    #[must_use]
    pub const fn with_channel(mut self, channel_id: i64) -> Self {
        self.channel_id = Some(channel_id);
        self
    }

    /// Set the reason text.
    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Set the canonical `detail_json` payload.
    #[must_use]
    pub fn with_detail_json(mut self, detail_json: impl Into<String>) -> Self {
        self.detail_json = Some(detail_json.into());
        self
    }

    /// Set the originating bridge event offset (idempotency key).
    #[must_use]
    pub const fn with_event_offset(mut self, offset: u64) -> Self {
        self.event_offset = Some(offset);
        self
    }
}

/// A fully-formed, chained entry: a persisted [`AuditRecord`] plus its
/// monotonic `id` and the two chain hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// Monotonic per-server row id.
    pub id: i64,
    /// The immutable content that was hashed.
    pub record: AuditRecord,
    /// Hash of the previous entry (32 bytes); the genesis entry uses
    /// [`crate::chain::GENESIS_PARENT`].
    pub prev_hash: [u8; 32],
    /// `H(prev_hash || canonical(record))` - see [`crate::chain::hash_entry`].
    pub entry_hash: [u8; 32],
}
