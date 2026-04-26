//! `GET /capabilities` - public discovery endpoint.
//!
//! Returns the Mumble + Fancy Mumble server versions, the list of
//! features this Fancy Mumble file-server plugin advertises, and the
//! configured limits (max upload size, total storage cap, file TTL,
//! ...).
//!
//! The endpoint is intentionally unauthenticated so clients can probe a
//! server before connecting / before they have a session token. Only
//! information that is also visible to any connected user is exposed
//! (no admin lists, no secrets).
//!
//! Versions are read from the host via two synthetic config keys
//! (`__host_mumble_version`, `__host_fancy_version`) populated by the
//! C++ host directly from compile-time `MUMBLE_VERSION_*` and
//! `FANCY_VERSION_*` macros - there is no separate version channel
//! between the Rust plugin and its C++ host.

use axum::extract::State;
use axum::Json;
use serde::Serialize;

use crate::state::AppState;

/// Plugin's own crate version (the file-server itself), filled in at
/// compile time from `Cargo.toml`.
const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
const PLUGIN_NAME: &str = env!("CARGO_PKG_NAME");

/// Semantic version triple plus a pre-formatted "MAJOR.MINOR.PATCH"
/// string for convenience.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VersionInfo {
    /// Major component, or `null` if unknown.
    pub major: Option<u16>,
    /// Minor component, or `null` if unknown.
    pub minor: Option<u16>,
    /// Patch component, or `null` if unknown.
    pub patch: Option<u16>,
    /// Combined "MAJOR.MINOR.PATCH" string, or the literal "unknown"
    /// when the host did not report a value.
    pub display: String,
}

impl VersionInfo {
    /// Parse a "MAJOR.MINOR.PATCH" string. Missing/garbage values
    /// produce `unknown`.
    fn parse(raw: Option<String>) -> Self {
        let Some(raw) = raw else { return Self::unknown() };
        let parts: Vec<&str> = raw.trim().split('.').collect();
        if parts.len() != 3 {
            return Self::unknown_with(raw);
        }
        let parsed: Option<(u16, u16, u16)> = (|| {
            Some((
                parts[0].parse().ok()?,
                parts[1].parse().ok()?,
                parts[2].parse().ok()?,
            ))
        })();
        match parsed {
            Some((maj, min, patch)) => Self {
                major: Some(maj),
                minor: Some(min),
                patch: Some(patch),
                display: format!("{maj}.{min}.{patch}"),
            },
            None => Self::unknown_with(raw),
        }
    }

    fn unknown() -> Self {
        Self {
            major: None,
            minor: None,
            patch: None,
            display: "unknown".to_owned(),
        }
    }

    fn unknown_with(raw: String) -> Self {
        Self {
            major: None,
            minor: None,
            patch: None,
            display: raw,
        }
    }
}

/// Feature flags advertised by this server. Each flag is `true` when
/// the server supports the corresponding client feature.
#[derive(Debug, Clone, Serialize)]
pub struct Features {
    /// HTTP file uploads via this plugin.
    pub file_uploads: bool,
    /// Custom server-managed emotes (admin-uploaded image emojis
    /// pushed to all clients via plugin data).
    pub custom_emotes: bool,
    /// Files are deleted automatically after their TTL expires.
    pub file_ttl: bool,
    /// Files are deleted after the first successful download.
    pub delete_on_download: bool,
    /// Files uploaded by a user are deleted when that user disconnects.
    pub delete_on_disconnect: bool,
}

/// Configured upload / storage limits, mirroring the values
/// advertised to authenticated clients in the per-session
/// `file-server-config` plugin-data payload.
#[derive(Debug, Clone, Serialize)]
pub struct Limits {
    /// Maximum size in bytes of a single uploaded file.
    pub max_file_size_bytes: u64,
    /// Hard cap on the total bytes stored across all files.
    pub max_total_storage_bytes: u64,
    /// File TTL in seconds (only meaningful when `features.file_ttl`).
    pub ttl_seconds: u64,
}

/// Plugin self-identification.
#[derive(Debug, Clone, Serialize)]
pub struct PluginInfo {
    /// Cargo package name of the plugin crate.
    pub name: &'static str,
    /// Cargo package version of the plugin crate.
    pub version: &'static str,
}

/// `GET /capabilities` response body.
#[derive(Debug, Clone, Serialize)]
pub struct CapabilitiesResponse {
    /// Plugin self-identification.
    pub plugin: PluginInfo,
    /// Mumble protocol/server version of the host running this plugin.
    pub mumble_version: VersionInfo,
    /// Fancy Mumble extension version of the host running this plugin.
    pub fancy_version: VersionInfo,
    /// Server-level feature toggles.
    pub features: Features,
    /// Configured size / TTL limits.
    pub limits: Limits,
}

impl CapabilitiesResponse {
    /// Build the response from the live plugin state.
    pub fn build(state: &AppState) -> Self {
        let cfg = state.config.as_ref();
        Self {
            plugin: PluginInfo {
                name: PLUGIN_NAME,
                version: PLUGIN_VERSION,
            },
            mumble_version: VersionInfo::parse(state.plugin_ctx.get_config("__host_mumble_version")),
            fancy_version: VersionInfo::parse(state.plugin_ctx.get_config("__host_fancy_version")),
            features: Features {
                file_uploads: true,
                custom_emotes: true,
                file_ttl: cfg.delete_on_ttl,
                delete_on_download: cfg.delete_on_download,
                delete_on_disconnect: cfg.delete_on_disconnect,
            },
            limits: Limits {
                max_file_size_bytes: cfg.max_file_size_bytes,
                max_total_storage_bytes: cfg.max_total_storage_bytes,
                ttl_seconds: cfg.ttl.as_secs(),
            },
        }
    }
}

/// `GET /capabilities` handler. Always returns 200 with a JSON body.
pub async fn get(State(state): State<AppState>) -> Json<CapabilitiesResponse> {
    let response = CapabilitiesResponse::build(&state);
    tracing::debug!(
        mumble = %response.mumble_version.display,
        fancy = %response.fancy_version.display,
        "capabilities: served discovery response"
    );
    Json(response)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, reason = "tests panic on failure")]
    use super::*;

    #[test]
    fn parse_well_formed_version() {
        let v = VersionInfo::parse(Some("1.5.0".to_owned()));
        assert_eq!(v.major, Some(1));
        assert_eq!(v.minor, Some(5));
        assert_eq!(v.patch, Some(0));
        assert_eq!(v.display, "1.5.0");
    }

    #[test]
    fn parse_missing_yields_unknown() {
        let v = VersionInfo::parse(None);
        assert_eq!(v.major, None);
        assert_eq!(v.display, "unknown");
    }

    #[test]
    fn parse_garbage_keeps_raw_display() {
        let v = VersionInfo::parse(Some("not.a.version".to_owned()));
        assert_eq!(v.major, None);
        assert_eq!(v.display, "not.a.version");
    }

    #[test]
    fn parse_wrong_segment_count_is_unknown() {
        let v = VersionInfo::parse(Some("1.2".to_owned()));
        assert_eq!(v.major, None);
        assert_eq!(v.display, "1.2");
    }

    #[test]
    fn plugin_info_constants_are_populated() {
        assert!(!PLUGIN_NAME.is_empty());
        assert!(!PLUGIN_VERSION.is_empty());
    }
}
