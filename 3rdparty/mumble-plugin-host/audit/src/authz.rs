//! Permission seam (§9.1).
//!
//! The two audit permissions — `ViewAudit` and `ConfigureAudit` — ride on
//! Mumble ACL today, but ACL is channel-scoped and coarse, and a future model
//! (roles, per-scope grants, time-boxed audit access) may fit better. So the
//! audit plugin never calls the ACL API directly; it resolves permissions
//! through this narrow interface and one swappable implementation.
//!
//! `can_view_raw_signals` is deliberately separate: viewing raw who→whom edges
//! — the most privacy-sensitive data — requires `ViewAudit` **plus** the raw
//! part being enabled (§9.2), and is never implied by a plain audit view.

/// Virtual-server id, mirroring the host's `ServerId`.
pub type ServerId = u32;
/// Session id, mirroring the host's `SessionId`.
pub type SessionId = u32;

/// Resolves the three audit authorization questions for a session on a server.
///
/// Implementations must be cheap to call (they gate every query) and must never
/// leak: an unauthorized caller gets `false`, never a partial answer.
pub trait AuditAuthz: std::fmt::Debug + Send + Sync {
    /// May this session read/search the audit log, run `verify`, and see
    /// aggregate signal counts? (The `ViewAudit` grant.)
    fn can_view(&self, server: ServerId, session: SessionId) -> bool;

    /// May this session change what is collected and exported — toggles, OTLP,
    /// retention, rules, disclosure? (The `ConfigureAudit` grant; strictly
    /// higher than `ViewAudit`.)
    fn can_configure(&self, server: ServerId, session: SessionId) -> bool;

    /// May this session reach the raw who→whom signal edges? Requires the view
    /// grant *and* the raw-signal part being enabled; callers must pass whether
    /// that part is currently on.
    fn can_view_raw_signals(
        &self,
        server: ServerId,
        session: SessionId,
        raw_edges_enabled: bool,
    ) -> bool {
        raw_edges_enabled && self.can_view(server, session)
    }
}

/// Whether a session holds a given permission on the root channel — the exact
/// shape of the host's `PluginContext::has_permission` for channel 0. Kept as a
/// trait so the ACL-backed authz can be unit-tested without the FFI host.
pub trait RootPermissionOracle: std::fmt::Debug + Send + Sync {
    /// Does `session` hold `permission_flags` on the root channel of `server`?
    fn has_root_permission(
        &self,
        server: ServerId,
        session: SessionId,
        permission_flags: u32,
    ) -> bool;
}

/// Mumble ACL `Write` permission bit — the gate `msgFancyPluginAdminListRequest`
/// already uses for privileged admin surfaces (§5). `ConfigureAudit` maps to
/// `Write` on root; `ViewAudit` maps to `Write`-or-a-dedicated-bit. Until a
/// dedicated bit exists, both resolve through `Write` on root, which is the
/// conservative choice (no accidental widening).
pub const PERM_WRITE: u32 = 0x01;

/// ACL-backed [`AuditAuthz`]: today both grants resolve to `Write` on the root
/// channel via the host permission oracle. Swapping in a role model later is
/// one new implementation of [`AuditAuthz`], not a hunt through call sites.
#[derive(Debug)]
pub struct AclAuthz<O: RootPermissionOracle> {
    oracle: O,
}

impl<O: RootPermissionOracle> AclAuthz<O> {
    /// Wrap a root-permission oracle (in production, the host `PluginContext`).
    pub const fn new(oracle: O) -> Self {
        Self { oracle }
    }
}

impl<O: RootPermissionOracle> AuditAuthz for AclAuthz<O> {
    fn can_view(&self, server: ServerId, session: SessionId) -> bool {
        self.oracle.has_root_permission(server, session, PERM_WRITE)
    }

    fn can_configure(&self, server: ServerId, session: SessionId) -> bool {
        self.oracle.has_root_permission(server, session, PERM_WRITE)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "unwrap is the standard, readable idiom in unit tests"
)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct FakeOracle {
        /// Sessions granted Write on root.
        writers: Vec<SessionId>,
    }

    impl RootPermissionOracle for FakeOracle {
        fn has_root_permission(&self, _server: ServerId, session: SessionId, flags: u32) -> bool {
            flags == PERM_WRITE && self.writers.contains(&session)
        }
    }

    #[test]
    fn write_on_root_grants_view_and_configure() {
        let authz = AclAuthz::new(FakeOracle { writers: vec![10] });
        assert!(authz.can_view(1, 10));
        assert!(authz.can_configure(1, 10));
        assert!(!authz.can_view(1, 11));
        assert!(!authz.can_configure(1, 11));
    }

    #[test]
    fn raw_signals_need_both_the_grant_and_the_part_enabled() {
        let authz = AclAuthz::new(FakeOracle { writers: vec![10] });
        // Has the grant, but the raw part is off -> denied.
        assert!(!authz.can_view_raw_signals(1, 10, false));
        // Has the grant and the part is on -> allowed.
        assert!(authz.can_view_raw_signals(1, 10, true));
        // Lacks the grant even with the part on -> denied.
        assert!(!authz.can_view_raw_signals(1, 11, true));
    }
}
