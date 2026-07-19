//! Where the audit database lives.
//!
//! Mirrors the `file-server` convention: the host hands the plugin a config
//! value (`plugin.fancy-audit.storage_path`), with a platform default when it
//! is unset.

use std::path::PathBuf;

/// The plugin's stable name, used for config-key scoping and the plugin
/// registry entry.
pub const PLUGIN_NAME: &str = "fancy-audit";

/// Resolve the audit database path from the host-provided `configured` value,
/// falling back to `MUMBLE_AUDIT_DB` and then a per-plugin temp location.
#[must_use]
pub fn resolve_db_path(configured: Option<String>) -> PathBuf {
    if let Some(path) = configured.filter(|value| !value.is_empty()) {
        return PathBuf::from(path);
    }
    if let Ok(env) = std::env::var("MUMBLE_AUDIT_DB") {
        if !env.is_empty() {
            return PathBuf::from(env);
        }
    }
    std::env::temp_dir()
        .join("mumble")
        .join(PLUGIN_NAME)
        .join("audit.sqlite")
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "unwrap is the standard, readable idiom in unit tests"
)]
mod tests {
    use super::*;

    #[test]
    fn a_configured_path_wins() {
        assert_eq!(
            resolve_db_path(Some("/data/audit.db".into())),
            PathBuf::from("/data/audit.db")
        );
    }

    #[test]
    fn an_empty_configured_path_falls_through_to_a_default() {
        let path = resolve_db_path(Some(String::new()));
        assert!(path.ends_with("audit.sqlite"));
        assert!(path.to_string_lossy().contains(PLUGIN_NAME));
    }
}
