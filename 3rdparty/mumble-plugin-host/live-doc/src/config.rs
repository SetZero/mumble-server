//! Plugin configuration parsed from `plugin.fancy-live-doc.*` keys.
//!
//! Mirrors the `file-server` `FileServerConfig` shape so operators
//! configure both plugins with the same idioms.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use thiserror::Error;

use crate::host_facade::HostFacade;

/// Stable plugin identifier; used to derive the default `state_path`
/// (`<system data dir>/mumble/fancy-live-doc`).
const PLUGIN_NAME: &str = "fancy-live-doc";

/// Default WS port if `port` is not set in config.
pub const DEFAULT_PORT: u16 = 64740;
/// Default per-doc CRDT update cap (4 MiB).  Updates above this size
/// are rejected to bound memory growth from malicious clients.
pub const DEFAULT_MAX_UPDATE_BYTES: usize = 4 * 1024 * 1024;
/// Default snapshot persistence interval (60 seconds of idle).
pub const DEFAULT_SNAPSHOT_IDLE_SECS: u64 = 60;
/// Default grace window between last-viewer leaving and room teardown.
pub const DEFAULT_TEARDOWN_GRACE_SECS: u64 = 30;

/// Configuration errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Required key is missing.
    #[error("required config key missing: plugin.fancy-live-doc.{0}")]
    Missing(&'static str),
    /// Value could not be parsed in the expected format.
    #[error("invalid config value for plugin.fancy-live-doc.{key}: {value}")]
    Parse {
        /// Offending key name.
        key: &'static str,
        /// Raw value as supplied.
        value: String,
    },
    /// Value was parsed but failed a semantic validation rule.
    #[error("invalid config value for plugin.fancy-live-doc.{key}: {reason}")]
    Invalid {
        /// Offending key name.
        key: &'static str,
        /// Why the value was rejected.
        reason: &'static str,
    },
}

/// Parsed configuration for the live-doc plugin.
#[derive(Debug, Clone)]
pub struct LiveDocConfig {
    /// Socket address the WS server binds to.
    pub bind: SocketAddr,
    /// Public base URL clients should connect to (e.g. `wss://chat.example.com/live-doc`).
    /// When unset, the plugin reports the bind socket as the URL.
    pub public_url: Option<String>,
    /// Shared HMAC secret for JWT signing.  Auto-generated and stored
    /// on disk on first start if not provided.
    pub jwt_secret: Option<String>,
    /// Where to persist signing secret + transient state.
    pub state_path: PathBuf,
    /// Maximum size of a single CRDT update message in bytes.
    pub max_update_bytes: usize,
    /// Idle window before flushing a snapshot.
    pub snapshot_idle_secs: u64,
    /// Grace window between last viewer leaving and room teardown.
    pub teardown_grace_secs: u64,
    /// Base URL of the `file-server` plugin used for revision persistence.
    pub file_server_url: Option<String>,
    /// Shared secret used to authenticate against the file-server
    /// admin endpoint (TODO: revision-aware endpoint not yet implemented).
    pub file_server_admin_token: Option<String>,

    /// Internal: convenience field carrying the parsed port for logs.
    pub port: u16,
}

impl LiveDocConfig {
    /// Parse the configuration from a [`HostFacade`].
    pub fn from_context(ctx: &dyn HostFacade) -> Result<Self, ConfigError> {
        let port =
            parse_optional("port", ctx.get_config("port").as_deref())?.unwrap_or(DEFAULT_PORT);
        let host: IpAddr = match ctx.get_config("host").as_deref() {
            Some(v) => v.parse().map_err(|_| ConfigError::Parse {
                key: "host",
                value: v.to_string(),
            })?,
            None => IpAddr::from([0u8, 0, 0, 0]),
        };

        let state_path = ctx
            .get_config("state_path")
            .map_or_else(|| default_data_dir(PLUGIN_NAME), PathBuf::from);
        if !state_path.is_absolute() {
            return Err(ConfigError::Invalid {
                key: "state_path",
                reason: "must be an absolute path (leave unset to use the system default)",
            });
        }

        let max_update_bytes = parse_optional(
            "max_update_bytes",
            ctx.get_config("max_update_bytes").as_deref(),
        )?
        .unwrap_or(DEFAULT_MAX_UPDATE_BYTES);

        let snapshot_idle_secs = parse_optional(
            "snapshot_idle_secs",
            ctx.get_config("snapshot_idle_secs").as_deref(),
        )?
        .unwrap_or(DEFAULT_SNAPSHOT_IDLE_SECS);

        let teardown_grace_secs = parse_optional(
            "teardown_grace_secs",
            ctx.get_config("teardown_grace_secs").as_deref(),
        )?
        .unwrap_or(DEFAULT_TEARDOWN_GRACE_SECS);

        Ok(Self {
            bind: SocketAddr::new(host, port),
            public_url: ctx.get_config("public_url"),
            jwt_secret: ctx.get_config("jwt_secret"),
            state_path,
            max_update_bytes,
            snapshot_idle_secs,
            teardown_grace_secs,
            file_server_url: ctx.get_config("file_server_url"),
            file_server_admin_token: ctx.get_config("file_server_admin_token"),
            port,
        })
    }
}

fn parse_optional<T: std::str::FromStr>(
    key: &'static str,
    value: Option<&str>,
) -> Result<Option<T>, ConfigError> {
    let Some(value) = value else { return Ok(None) };
    value
        .parse::<T>()
        .map(Some)
        .map_err(|_| ConfigError::Parse {
            key,
            value: value.to_string(),
        })
}

/// Build a platform-appropriate absolute path under the system data
/// directory:
///
/// * Windows: `%PROGRAMDATA%\mumble\<plugin_name>` (fallback
///   `C:\ProgramData\mumble\<plugin_name>` if the env var is unset).
/// * Unix (Linux, macOS, BSD): `/var/lib/mumble/<plugin_name>`.
///
/// Operators who want a different location override
/// `plugin.fancy-live-doc.state_path` in the server INI.
pub(crate) fn default_data_dir(plugin_name: &str) -> PathBuf {
    #[cfg(windows)]
    {
        let base = std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        base.join("mumble").join(plugin_name)
    }
    #[cfg(unix)]
    {
        PathBuf::from(format!("/var/lib/mumble/{plugin_name}"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        reason = "tests panic on failure"
    )]

    use super::*;
    use std::collections::HashMap;

    #[derive(Debug, Default)]
    struct StubCtx(HashMap<&'static str, String>);

    impl HostFacade for StubCtx {
        fn send_plugin_data(
            &self,
            _: u32,
            _: u32,
            _: &str,
            _: &[u8],
        ) -> crate::host_facade::FacadeResult<()> {
            Ok(())
        }
        fn is_session_active(&self, _: u32, _: u32) -> bool {
            true
        }
        fn user_has_channel_access(&self, _: u32, _: u32, _: u32) -> bool {
            true
        }
        fn has_permission(
            &self,
            _: u32,
            _: u32,
            _: u32,
            _: mumble_plugin_api::Permissions,
        ) -> bool {
            true
        }
        fn get_config(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
        fn send_plugin_message(
            &self,
            _: crate::host_facade::PluginMessageArgs<'_>,
        ) -> crate::host_facade::FacadeResult<()> {
            Ok(())
        }
    }

    #[test]
    fn default_state_path_is_absolute() {
        let cfg = LiveDocConfig::from_context(&StubCtx::default()).expect("loads defaults");
        assert!(
            cfg.state_path.is_absolute(),
            "default state_path must be absolute, got {}",
            cfg.state_path.display()
        );
        assert!(cfg.state_path.ends_with("fancy-live-doc"));
        assert_eq!(cfg.port, DEFAULT_PORT);
    }

    #[test]
    fn explicit_relative_state_path_is_rejected() {
        let mut map = HashMap::new();
        let _ = map.insert("state_path", "./relative".to_owned());
        let err = LiveDocConfig::from_context(&StubCtx(map)).expect_err("must reject");
        assert!(err.to_string().contains("plugin.fancy-live-doc.state_path"));
    }

    #[test]
    fn explicit_state_path_wins() {
        let mut map = HashMap::new();
        #[cfg(windows)]
        let _ = map.insert("state_path", r"C:\custom\live-doc".to_owned());
        #[cfg(unix)]
        let _ = map.insert("state_path", "/srv/live-doc".to_owned());
        let cfg = LiveDocConfig::from_context(&StubCtx(map)).expect("loads");
        #[cfg(windows)]
        assert_eq!(cfg.state_path.to_string_lossy(), r"C:\custom\live-doc");
        #[cfg(unix)]
        assert_eq!(cfg.state_path.to_string_lossy(), "/srv/live-doc");
    }

    #[test]
    fn default_data_dir_is_platform_appropriate() {
        let p = default_data_dir("fancy-live-doc");
        assert!(p.is_absolute());
        let s = p.to_string_lossy();
        if cfg!(windows) {
            assert!(s.contains("mumble") && s.ends_with("fancy-live-doc"));
        } else {
            assert_eq!(s, "/var/lib/mumble/fancy-live-doc");
        }
    }
}
