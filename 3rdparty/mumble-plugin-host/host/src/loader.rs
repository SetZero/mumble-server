//! Discovery and ABI-stable loading of plugin cdylibs at runtime.

use std::path::{Path, PathBuf};

use abi_stable::library::lib_header_from_path;
use mumble_plugin_api::{
    FancyPluginModRef, MumblePlugin_TO, PLUGIN_ABI_VERSION,
};
use thiserror::Error;

/// Errors produced while loading a single plugin cdylib.
#[derive(Debug, Error)]
pub enum LoadError {
    /// `abi_stable::library` rejected the file (missing symbol, wrong
    /// version strings, etc.).
    #[error("plugin '{path}' is not a valid fancy-plugin cdylib: {message}")]
    Invalid {
        /// File that failed to load.
        path: PathBuf,
        /// Underlying loader error message.
        message: String,
    },

    /// Plugin declared an `abi_version` that disagrees with the host.
    #[error("plugin '{path}' has ABI version {found} but host expects {expected}")]
    AbiMismatch {
        /// File that was rejected.
        path: PathBuf,
        /// Version declared by the plugin.
        found: u32,
        /// [`PLUGIN_ABI_VERSION`] of the host build.
        expected: u32,
    },
}

/// One successfully loaded plugin: the trait object plus the path it
/// came from (kept for diagnostics).
pub struct LoadedPlugin {
    /// Source file the plugin was loaded from.
    pub path: PathBuf,
    /// Trait object owning the plugin instance.
    pub plugin: MumblePlugin_TO<abi_stable::std_types::RBox<()>>,
}

impl std::fmt::Debug for LoadedPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedPlugin").field("path", &self.path).finish()
    }
}

/// Compose the search list from an explicit configured directory plus
/// the `MUMBLE_PLUGIN_DIRS` env var (platform-specific separator).
pub fn discover_plugin_dirs(configured: Option<&str>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(c) = configured.map(str::trim).filter(|s| !s.is_empty()) {
        out.push(PathBuf::from(c));
    }
    if let Ok(env) = std::env::var("MUMBLE_PLUGIN_DIRS") {
        for entry in std::env::split_paths(&env) {
            if !entry.as_os_str().is_empty() {
                out.push(entry);
            }
        }
    }
    out
}

/// File-name suffix for cdylibs on the current platform.
pub fn cdylib_suffix() -> &'static str {
    if cfg!(target_os = "windows") {
        ".dll"
    } else if cfg!(target_os = "macos") {
        ".dylib"
    } else {
        ".so"
    }
}

/// Enumerate cdylib candidates in `dir`.  Missing or unreadable
/// directories yield an empty iterator; errors on individual entries
/// are logged and skipped.
pub fn scan_dir(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(dir = %dir.display(), error = %e, "plugin dir not readable");
            return out;
        }
    };
    let suffix = cdylib_suffix();
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(dir = %dir.display(), error = %e, "skipping unreadable dir entry");
                continue;
            }
        };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.ends_with(suffix) {
            out.push(path);
        }
    }
    out
}

/// Load a single plugin cdylib via `abi_stable`, verify its ABI
/// version, and return the constructed trait object.
pub fn load_plugin(path: &Path) -> Result<LoadedPlugin, LoadError> {
    // Load the LibHeader directly from this specific file rather than going
    // through `RootModule::load_from_file`, which uses a per-type static
    // cache in the host process: the cache returns the FIRST loaded module
    // for every subsequent call, regardless of the path - so the second
    // and later plugin cdylibs would silently dispatch into the first
    // plugin's code.
    let header = lib_header_from_path(path).map_err(|e| LoadError::Invalid {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    let module = header
        .init_root_module::<FancyPluginModRef>()
        .map_err(|e| LoadError::Invalid {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;
    let abi = module.abi_version();
    if abi != PLUGIN_ABI_VERSION {
        return Err(LoadError::AbiMismatch {
            path: path.to_path_buf(),
            found: abi,
            expected: PLUGIN_ABI_VERSION,
        });
    }
    let plugin = (module.create_plugin())();
    Ok(LoadedPlugin {
        path: path.to_path_buf(),
        plugin,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdylib_suffix_matches_platform() {
        let s = cdylib_suffix();
        assert!(s.starts_with('.'));
        assert!(s.len() >= 3);
    }

    #[test]
    fn scan_returns_empty_for_missing_dir() {
        let p = std::env::temp_dir().join("definitely-does-not-exist-xyz-123");
        assert!(scan_dir(&p).is_empty());
    }

    #[test]
    fn discover_collects_configured_and_env() {
        // SAFETY: we are only reading/writing our own env in a single-threaded test.
        std::env::set_var("MUMBLE_PLUGIN_DIRS", format!("/tmp/a{}/tmp/b", if cfg!(windows) { ";" } else { ":" }));
        let dirs = discover_plugin_dirs(Some("/tmp/configured"));
        assert!(dirs.len() >= 2);
        assert!(dirs.iter().any(|p| p.to_string_lossy().contains("configured")));
        std::env::remove_var("MUMBLE_PLUGIN_DIRS");
    }
}
