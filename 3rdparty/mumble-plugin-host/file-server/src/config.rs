//! Configuration for the file-server plugin.
//!
//! All values are read from the host's [`PluginContext::get_config`] hook
//! at startup. Defaults match the values documented in the plan.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use mumble_plugin_api::PluginContext;

/// Hard upper bound on `max_total_storage_bytes`. The plugin refuses to
/// start with a configured value above this.
pub const MAX_TOTAL_STORAGE_LIMIT: u64 = 10 * 1024 * 1024 * 1024;

/// Configuration for the file-server plugin.
#[derive(Debug, Clone)]
pub struct FileServerConfig {
    /// Whether the plugin is enabled at all.
    pub enabled: bool,
    /// IP address the embedded HTTP server binds to.
    ///
    /// Defaults to `127.0.0.1` because the plugin only speaks plain HTTP
    /// and **must** be terminated by an external TLS-capable reverse
    /// proxy before being exposed to the public network. Operators who
    /// understand the implications can override this via
    /// `bind_address = 0.0.0.0` plus `tls_terminated_by_proxy = true`.
    pub bind_address: IpAddr,
    /// TCP port the embedded HTTP server binds to.
    pub port: u16,
    /// Acknowledge that a non-loopback `bind_address` is reachable only
    /// via a TLS-terminating proxy. Required when `bind_address` is not
    /// loopback to prevent accidental plaintext exposure.
    pub tls_terminated_by_proxy: bool,
    /// Public base URL embedded into shareable file links.
    pub base_url: String,
    /// Allowed CORS origins for credentialed (`Authorization`-bearing)
    /// endpoints. Empty means "no cross-origin browser access" -
    /// `GET /capabilities` and `GET /files/{id}` remain reachable.
    pub allowed_origins: Vec<String>,
    /// Maximum upload size in bytes per file.
    pub max_file_size_bytes: u64,
    /// Hard cap on total bytes stored across all files.
    pub max_total_storage_bytes: u64,
    /// Directory where uploaded blobs and metadata live. **Must** be
    /// absolute - relative paths produce non-deterministic storage
    /// locations depending on the murmur process's working directory.
    pub storage_path: PathBuf,
    /// If `true`, files are deleted after `ttl_seconds`.
    pub delete_on_ttl: bool,
    /// TTL applied to newly uploaded files (only when `delete_on_ttl`).
    pub ttl: Duration,
    /// If `true`, files are deleted after the first successful download.
    pub delete_on_download: bool,
    /// If `true`, files are deleted when the uploader disconnects.
    pub delete_on_disconnect: bool,
    /// Maximum failed `POST /files/{id}/auth` attempts allowed from a
    /// single peer IP within [`Self::auth_rate_limit_window`] before the
    /// endpoint returns `429 Too Many Requests`.
    pub auth_rate_limit_max_failures: u32,
    /// Sliding window for the auth-failure rate limiter.
    pub auth_rate_limit_window: Duration,
    /// Bearer token required on `/admin/*` endpoints used by sibling
    /// plugins (live-doc) to persist revisioned documents.  When
    /// unset the admin endpoints are disabled.
    pub admin_token: Option<String>,
}

impl FileServerConfig {
    /// Load configuration from the plugin context. Unknown keys are
    /// ignored; missing keys fall back to defaults.
    pub fn from_context(ctx: &dyn PluginContext) -> Result<Self, ConfigError> {
        let port = parse_or(ctx, "port", 64739_u16)?;
        let bind_address: IpAddr = parse_or(
            ctx,
            "bind_address",
            IpAddr::from([127, 0, 0, 1]),
        )?;
        let mut cfg = Self {
            enabled: parse_or(ctx, "enabled", true)?,
            bind_address,
            port,
            tls_terminated_by_proxy: parse_or(ctx, "tls_terminated_by_proxy", false)?,
            base_url: ctx
                .get_config("base_url")
                .unwrap_or_else(|| format!("http://127.0.0.1:{port}")),
            allowed_origins: parse_origins(ctx.get_config("allowed_origins")),
            max_file_size_bytes: parse_or(ctx, "max_file_size_bytes", 256_u64 * 1024 * 1024)?,
            max_total_storage_bytes: parse_or(
                ctx,
                "max_total_storage_bytes",
                MAX_TOTAL_STORAGE_LIMIT,
            )?,
            storage_path: ctx
                .get_config("storage_path")
                .map_or_else(|| PathBuf::from("./murmur-files"), PathBuf::from),
            delete_on_ttl: parse_or(ctx, "delete_on_ttl", true)?,
            ttl: Duration::from_secs(parse_or(ctx, "ttl_seconds", 86_400_u64)?),
            delete_on_download: parse_or(ctx, "delete_on_download", false)?,
            delete_on_disconnect: parse_or(ctx, "delete_on_disconnect", false)?,
            auth_rate_limit_max_failures: parse_or(ctx, "auth_rate_limit_max_failures", 5_u32)?,
            auth_rate_limit_window: Duration::from_secs(parse_or(
                ctx,
                "auth_rate_limit_window_seconds",
                600_u64,
            )?),
            admin_token: ctx.get_config("admin_token").filter(|s| !s.is_empty()),
        };

        cfg.base_url = cfg.base_url.trim_end_matches('/').to_owned();

        if cfg.max_total_storage_bytes > MAX_TOTAL_STORAGE_LIMIT {
            return Err(ConfigError::ExceedsHardLimit {
                requested: cfg.max_total_storage_bytes,
                limit: MAX_TOTAL_STORAGE_LIMIT,
            });
        }
        if cfg.max_file_size_bytes == 0 {
            return Err(ConfigError::Invalid("max_file_size_bytes must be > 0"));
        }
        if !cfg.storage_path.is_absolute() {
            return Err(ConfigError::Invalid(
                "storage_path must be an absolute path",
            ));
        }
        if !cfg.bind_address.is_loopback() && !cfg.tls_terminated_by_proxy {
            return Err(ConfigError::Invalid(
                "bind_address is non-loopback but tlsTerminatedByProxy is not set; \
                 the plugin only speaks plain HTTP and must be terminated by a TLS proxy",
            ));
        }

        Ok(cfg)
    }
}

fn parse_origins(raw: Option<String>) -> Vec<String> {
    raw.unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Errors raised while loading or validating configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A value could not be parsed as the expected type.
    #[error("invalid value for `{key}`: {value}")]
    ParseError {
        /// The configuration key whose value failed to parse.
        key: String,
        /// The raw value that could not be parsed.
        value: String,
    },

    /// Generic message for misconfiguration.
    #[error("invalid configuration: {0}")]
    Invalid(&'static str),

    /// `max_total_storage_bytes` was set above the compile-time hard
    /// limit. The plugin refuses to start in this case.
    #[error("max_total_storage_bytes ({requested}) exceeds hard limit ({limit})")]
    ExceedsHardLimit {
        /// The configured value.
        requested: u64,
        /// The compile-time hard limit.
        limit: u64,
    },
}

fn parse_or<T>(ctx: &dyn PluginContext, key: &str, default: T) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
{
    match ctx.get_config(key) {
        None => Ok(default),
        Some(raw) => raw.parse::<T>().map_err(|_| ConfigError::ParseError {
            key: key.to_owned(),
            value: raw,
        }),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, reason = "tests panic on failure")]
    use super::*;

    #[derive(Debug)]
    struct StubCtx(std::collections::HashMap<&'static str, String>);

    impl PluginContext for StubCtx {
        fn send_plugin_data(
            &self,
            _server_id: u32,
            _target_session: u32,
            _data_id: &str,
            _data: &[u8],
        ) -> mumble_plugin_api::Result<()> {
            Ok(())
        }
        fn is_session_active(&self, _server_id: u32, _session: u32) -> bool {
            false
        }
        fn user_has_channel_access(&self, _: u32, _: u32, _: u32) -> bool {
            false
        }
        fn has_permission(&self, _: u32, _: u32, _: u32, _: u32) -> bool {
            false
        }
        fn get_config(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
    }

    fn ctx_with(extra: &[(&'static str, &str)]) -> StubCtx {
        let mut map = std::collections::HashMap::new();
        // Defaults need an absolute storage path - the no-config default
        // is intentionally rejected by `from_context`.
        let _ = map.insert("storage_path", abs_storage_path());
        for (k, v) in extra {
            let _ = map.insert(k, (*v).to_owned());
        }
        StubCtx(map)
    }

    fn abs_storage_path() -> String {
        // Pick a platform-appropriate absolute path. The directory does
        // not need to exist for `from_context` to succeed; only `is_absolute`
        // is checked.
        if cfg!(windows) {
            "C:\\murmur-files".to_owned()
        } else {
            "/var/lib/murmur-files".to_owned()
        }
    }

    #[test]
    fn defaults_when_no_config() {
        let ctx = ctx_with(&[]);
        let cfg = FileServerConfig::from_context(&ctx).expect("loads defaults");
        assert!(cfg.enabled);
        assert_eq!(cfg.port, 64739);
        assert_eq!(cfg.base_url, "http://127.0.0.1:64739");
        assert!(cfg.delete_on_ttl);
        assert!(!cfg.delete_on_download);
        assert!(cfg.bind_address.is_loopback());
        assert!(cfg.allowed_origins.is_empty());
        assert_eq!(cfg.auth_rate_limit_max_failures, 5);
    }

    #[test]
    fn relative_storage_path_is_rejected() {
        let mut map = std::collections::HashMap::new();
        let _ = map.insert("storage_path", "./relative".to_owned());
        let ctx = StubCtx(map);
        assert!(matches!(
            FileServerConfig::from_context(&ctx),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn no_config_at_all_is_rejected_due_to_relative_default() {
        // The absent-storage_path default is `./murmur-files` which the
        // validator rejects as relative.  This keeps operators from
        // accidentally splitting their storage across cwds.
        let ctx = StubCtx(std::collections::HashMap::new());
        assert!(matches!(
            FileServerConfig::from_context(&ctx),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_oversized_total_storage() {
        let ctx = ctx_with(&[(
            "max_total_storage_bytes",
            &(MAX_TOTAL_STORAGE_LIMIT + 1).to_string(),
        )]);
        assert!(matches!(
            FileServerConfig::from_context(&ctx),
            Err(ConfigError::ExceedsHardLimit { .. })
        ));
    }

    #[test]
    fn non_loopback_bind_requires_proxy_ack() {
        let ctx = ctx_with(&[("bind_address", "0.0.0.0")]);
        assert!(matches!(
            FileServerConfig::from_context(&ctx),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn non_loopback_bind_with_proxy_ack_is_allowed() {
        let ctx = ctx_with(&[
            ("bind_address", "0.0.0.0"),
            ("tls_terminated_by_proxy", "true"),
        ]);
        let cfg = FileServerConfig::from_context(&ctx).expect("loads");
        assert!(!cfg.bind_address.is_loopback());
        assert!(cfg.tls_terminated_by_proxy);
    }

    #[test]
    fn allowed_origins_are_parsed_csv() {
        let ctx = ctx_with(&[(
            "allowed_origins",
            "https://chat.example.com, https://admin.example.com",
        )]);
        let cfg = FileServerConfig::from_context(&ctx).expect("loads");
        assert_eq!(
            cfg.allowed_origins,
            vec![
                "https://chat.example.com".to_owned(),
                "https://admin.example.com".to_owned(),
            ]
        );
    }

    #[test]
    fn trims_trailing_slash_from_base_url() {
        let ctx = ctx_with(&[("base_url", "https://files.example.com/")]);
        let cfg = FileServerConfig::from_context(&ctx).expect("loads");
        assert_eq!(cfg.base_url, "https://files.example.com");
    }
}
