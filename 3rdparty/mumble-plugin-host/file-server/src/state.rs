//! Shared state passed to every HTTP handler.

use std::sync::Arc;

use crate::config::FileServerConfig;
use crate::documents::DocumentsStore;
use crate::host_facade::HostFacade;
use crate::private_store::PrivateStore;
use crate::rate_limit::RateLimiter;
use crate::session::SessionMap;
use crate::storage::Storage;
use crate::tickets::TicketStore;

/// Bundle of shared state references handed to every axum handler.
#[derive(Debug, Clone)]
pub struct AppState {
    /// File metadata + blob storage.
    pub storage: Arc<Storage>,
    /// Stable-named documents with revision history.  Used by sibling
    /// plugins via the `/admin/documents/...` endpoints.
    pub documents: Arc<DocumentsStore>,
    /// Per-user opaque key/value storage exposed at `/me/storage/{key}`.
    pub private: Arc<PrivateStore>,
    /// In-memory single-use ticket map.
    pub tickets: Arc<TicketStore>,
    /// Active session table.
    pub sessions: Arc<SessionMap>,
    /// Per-peer credential-failure rate limiter (H-4).
    pub auth_rate_limiter: Arc<RateLimiter>,
    /// HMAC signing secret.
    pub signing_secret: Arc<[u8; crate::storage::SIGNING_SECRET_BYTES]>,
    /// Plugin configuration.
    pub config: Arc<FileServerConfig>,
    /// Handle back into the host (for `is_session_active` / channel ACL checks).
    pub plugin_ctx: Arc<dyn HostFacade>,
}
