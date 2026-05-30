//! Discovery and ABI-stable loading of plugin cdylibs at runtime.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use abi_stable::library::{lib_header_from_path, RawLibrary};
use mumble_plugin_api::{
    FancyPluginModRef, MumblePlugin_TO, PLUGIN_ABI_VERSION, PLUGIN_ABI_VERSION_SYMBOL,
};
use thiserror::Error;

/// Condense a potentially multi-kilobyte `abi_stable` layout-diff error into a
/// single human-readable line.  When the error contains an `abi_stable` type
/// layout dump (identified by the characteristic `Type Layout` marker) we
/// replace the whole thing with a short summary; otherwise we pass it through.
fn summarize_load_error(raw: &str) -> String {
    if raw.contains("Type Layout") {
        "incompatible plugin API (vtable layout mismatch; recompile against the current mumble-plugin-api)".to_owned()
    } else {
        raw.to_owned()
    }
}

/// Errors produced while loading a single plugin cdylib.
#[derive(Debug, Error)]
pub enum LoadError {
    /// `abi_stable::library` rejected the file (missing symbol, wrong
    /// version strings, etc.).
    #[error("plugin '{path}' is not a valid fancy-plugin cdylib: {message}")]
    Invalid {
        /// File that failed to load.
        path: PathBuf,
        /// Short summary of the underlying loader error.
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

    /// Plugin cdylib lacks the layout-independent
    /// [`PLUGIN_ABI_VERSION_SYMBOL`] probe, so the host cannot safely
    /// determine its ABI version without risking a vtable-cast crash.
    #[error(
        "plugin '{path}' does not export {symbol}; rebuild against the current mumble-plugin-api"
    )]
    MissingAbiProbe {
        /// File that was rejected.
        path: PathBuf,
        /// Name of the missing symbol.
        symbol: &'static str,
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
        f.debug_struct("LoadedPlugin")
            .field("path", &self.path)
            .finish()
    }
}

/// Compose the search list from an explicit configured directory plus
/// the `MUMBLE_PLUGIN_DIRS` env var (platform-specific separator).
pub fn discover_plugin_dirs(configured: Option<&str>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut push = |p: PathBuf| {
        if seen.insert(p.clone()) {
            out.push(p);
        }
    };
    if let Some(c) = configured.map(str::trim).filter(|s| !s.is_empty()) {
        push(PathBuf::from(c));
    }
    if let Ok(env) = std::env::var("MUMBLE_PLUGIN_DIRS") {
        for entry in std::env::split_paths(&env) {
            if !entry.as_os_str().is_empty() {
                push(entry);
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
    // Pre-flight: read the plugin's ABI version through a plain
    // `extern "C" fn() -> u32` symbol BEFORE handing the binary to
    // `abi_stable`'s typed loader.  A cdylib built against an
    // incompatible `mumble-plugin-api` can have a vtable/type layout
    // different enough that `abi_stable`'s `init_root_module` cast (or
    // even its layout walk) dereferences bad pointers and SIGSEGVs
    // instead of returning a `LibraryError`.  Reading a bare integer
    // is layout-independent, so we can reject a mismatched plugin
    // cleanly here and never feed it to the typed cast.
    match read_plugin_abi_version(path) {
        Ok(found) if found == PLUGIN_ABI_VERSION => { /* compatible: fall through */ }
        Ok(found) => {
            return Err(LoadError::AbiMismatch {
                path: path.to_path_buf(),
                found,
                expected: PLUGIN_ABI_VERSION,
            });
        }
        Err(AbiProbeError::SymbolMissing) => {
            return Err(LoadError::MissingAbiProbe {
                path: path.to_path_buf(),
                symbol: PLUGIN_ABI_VERSION_SYMBOL,
            });
        }
        Err(AbiProbeError::LibraryError(message)) => {
            return Err(LoadError::Invalid {
                path: path.to_path_buf(),
                message: summarize_load_error(&message),
            });
        }
    }

    // Load the LibHeader directly from this specific file rather than going
    // through `RootModule::load_from_file`, which uses a per-type static
    // cache in the host process: the cache returns the FIRST loaded module
    // for every subsequent call, regardless of the path - so the second
    // and later plugin cdylibs would silently dispatch into the first
    // plugin's code.
    let header = lib_header_from_path(path).map_err(|e| LoadError::Invalid {
        path: path.to_path_buf(),
        message: summarize_load_error(&e.to_string()),
    })?;
    let module = header
        .init_root_module::<FancyPluginModRef>()
        .map_err(|e| LoadError::Invalid {
            path: path.to_path_buf(),
            message: summarize_load_error(&e.to_string()),
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

/// Failure modes of the plain-C ABI version probe.
enum AbiProbeError {
    /// The cdylib loaded but did not export [`PLUGIN_ABI_VERSION_SYMBOL`].
    SymbolMissing,
    /// The cdylib itself could not be opened (corrupt file, missing
    /// dependency, wrong architecture, ...).
    LibraryError(String),
}

/// Linux: parse `path` as an ELF binary *without* calling `dlopen` or
/// executing any code inside it, and verify:
///
/// 1. The file is a shared library (`ET_DYN`).
/// 2. It targets the same machine architecture as the running host.
/// 3. Its dynamic symbol table exports [`PLUGIN_ABI_VERSION_SYMBOL`].
///
/// Returning an error here prevents the subsequent `dlopen` call, so a
/// corrupt or wrong-arch binary can never run its `.init_array` entries
/// inside the server process.
#[cfg(target_os = "linux")]
fn elf_pre_validate(path: &Path) -> Result<(), AbiProbeError> {
    let bytes = std::fs::read(path)
        .map_err(|e| AbiProbeError::LibraryError(format!("cannot read plugin file: {e}")))?;
    let elf = goblin::elf::Elf::parse(&bytes)
        .map_err(|e| AbiProbeError::LibraryError(format!("not a valid ELF binary: {e}")))?;

    if elf.header.e_type != goblin::elf::header::ET_DYN {
        return Err(AbiProbeError::LibraryError(
            "not a shared library (ELF e_type != ET_DYN)".to_owned(),
        ));
    }

    let host_machine: u16 = if cfg!(target_arch = "x86_64") {
        goblin::elf::header::EM_X86_64
    } else if cfg!(target_arch = "aarch64") {
        goblin::elf::header::EM_AARCH64
    } else {
        0 // Unknown host arch — skip the machine-type check.
    };
    if host_machine != 0 && elf.header.e_machine != host_machine {
        return Err(AbiProbeError::LibraryError(format!(
            "binary targets machine type 0x{:04x} but host requires 0x{:04x}",
            elf.header.e_machine, host_machine
        )));
    }

    // The ABI probe symbol must be present in the dynamic symbol table.
    // If it is absent, `abi_stable`'s typed loader would segfault trying
    // to follow a null vtable pointer.
    let has_symbol = elf
        .dynsyms
        .iter()
        .any(|sym| elf.dynstrtab.get_at(sym.st_name) == Some(PLUGIN_ABI_VERSION_SYMBOL));
    if !has_symbol {
        return Err(AbiProbeError::SymbolMissing);
    }

    Ok(())
}

/// Non-Linux stub: no ELF pre-validation on platforms where the binary
/// format is different (PE on Windows, Mach-O on macOS).
#[cfg(not(target_os = "linux"))]
fn elf_pre_validate(_path: &Path) -> Result<(), AbiProbeError> {
    Ok(())
}

/// Open `path` as a raw shared object and call its
/// [`PLUGIN_ABI_VERSION_SYMBOL`] export to learn the ABI version it was
/// built against, without performing any `abi_stable` layout cast.
fn read_plugin_abi_version(path: &Path) -> Result<u32, AbiProbeError> {
    // Validate the ELF binary without `dlopen` first.  A corrupt or
    // wrong-arch cdylib can SIGSEGV the server process inside `dlopen`
    // when its `.init_array` runs — that happens *before* `dlopen`
    // returns any error.  Parsing the ELF headers statically lets us
    // reject such binaries before any code inside them ever executes.
    elf_pre_validate(path)?;

    let lib = RawLibrary::load_at(path).map_err(|e| AbiProbeError::LibraryError(e.to_string()))?;
    // The symbol must be NUL-terminated for the underlying loader.
    let mut symbol = PLUGIN_ABI_VERSION_SYMBOL.as_bytes().to_vec();
    symbol.push(0);
    // SAFETY: every plugin built with `fancy_export_plugin!` exports this
    // symbol as `extern "C" fn() -> u32`.  If the type is wrong the call
    // is UB, but the macro is the only supported way to export the symbol,
    // so a present symbol always has this signature.  A genuinely foreign
    // library is far more likely to omit the symbol entirely (handled as
    // `SymbolMissing`) than to export an incompatible one under this name.
    let probe = unsafe { lib.get::<extern "C" fn() -> u32>(&symbol) }
        .map_err(|_| AbiProbeError::SymbolMissing)?;
    Ok(probe())
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
        std::env::set_var(
            "MUMBLE_PLUGIN_DIRS",
            format!("/tmp/a{}/tmp/b", if cfg!(windows) { ";" } else { ":" }),
        );
        let dirs = discover_plugin_dirs(Some("/tmp/configured"));
        assert!(dirs.len() >= 2);
        assert!(dirs
            .iter()
            .any(|p| p.to_string_lossy().contains("configured")));
        std::env::remove_var("MUMBLE_PLUGIN_DIRS");
    }
}
