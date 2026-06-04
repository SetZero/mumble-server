//! Marketplace install support: download a plugin manifest, fetch the
//! matching artifact, verify its SHA-256 digest, and extract its
//! cdylib (and optional `plugin.example.ini`) into the host's plugin
//! directory.
//!
//! All I/O is synchronous: the plugin host is not built around a
//! Tokio runtime and we want to keep it that way.  The C++ server
//! invokes the install entry point on a worker thread so blocking is
//! acceptable.

use std::fs::File;
use std::io::{self, Cursor, Read, Write};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Maximum manifest body we will read.  Sized generously so even a
/// large `description` can fit, but bounded so a malicious endpoint
/// cannot fill memory.
const MAX_MANIFEST_BYTES: u64 = 1_048_576; // 1 MiB

/// Maximum artifact body we will download.  Plugin cdylibs are
/// typically a few hundred KiB; the cap mainly defends against
/// runaway downloads.
const MAX_ARTIFACT_BYTES: u64 = 32 * 1_048_576; // 32 MiB

/// Errors raised by the install flow.
#[derive(Debug, thiserror::Error)]
pub(crate) enum InstallError {
    /// Network or HTTP-level failure (DNS, TLS, non-2xx status, ...).
    #[error("http error: {0}")]
    Http(String),
    /// Response body exceeded the configured cap.
    #[error("response body exceeds {0} bytes")]
    TooLarge(u64),
    /// Manifest JSON could not be parsed or lacked a usable artifact.
    #[error("invalid manifest: {0}")]
    Manifest(String),
    /// SHA-256 mismatch between expected and observed digest.
    #[error("digest mismatch (expected {expected}, got {actual})")]
    DigestMismatch {
        /// Hex digest declared by the caller / manifest.
        expected: String,
        /// Hex digest of the bytes we received.
        actual: String,
    },
    /// Archive extraction failed (corrupt zip/tar, no cdylib member, ...).
    #[error("archive error: {0}")]
    Archive(String),
    /// Filesystem error while persisting the extracted files.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// One artifact entry in the marketplace manifest.
#[derive(Debug, Deserialize)]
pub(crate) struct ManifestArtifact {
    /// `linux`, `windows`, or `macos`.  Ignored for `wasm` artifacts,
    /// which are portable (conventionally `"any"`).
    pub os: String,
    /// `x86_64`, `aarch64`, ...  Ignored for `wasm` artifacts.
    pub arch: String,
    /// `zip` or `tar.gz`.
    pub format: String,
    /// Direct download URL.
    pub download_url: String,
    /// Hex-encoded SHA-256 of the archive body.
    pub sha256: String,
    /// File name of the plugin binary inside the archive (e.g.
    /// `libfancy_greeter.so` or, for wasm, `fancy_greeter.wasm`).
    pub cdylib_filename: String,
    /// Backend: `"native"` (default) or `"wasm"`.  A `wasm` artifact is
    /// portable and is selected on any host when no native artifact
    /// matches the current platform.
    #[serde(default = "default_artifact_kind")]
    pub kind: String,
}

/// Default value for [`ManifestArtifact::kind`] when the manifest omits
/// it, preserving backward compatibility with native-only manifests.
fn default_artifact_kind() -> String {
    "native".to_owned()
}

/// Top-level marketplace manifest schema (subset we actually use).
#[derive(Debug, Deserialize)]
pub(crate) struct Manifest {
    /// Stable marketplace ID echoed back so we can sanity-check.
    pub marketplace_id: String,
    /// Semver version string.
    pub version: String,
    /// [`mumble_plugin_api::PLUGIN_ABI_VERSION`] this artifact was compiled
    /// against.  When present the host rejects the install immediately if the
    /// value does not match, before any artifact is downloaded.
    #[serde(default)]
    pub required_abi_version: Option<u32>,
    /// Per-(os,arch,format) downloadable artifacts.
    pub artifacts: Vec<ManifestArtifact>,
}

/// Outcome of a successful install: where the cdylib was written, the
/// digest we observed, and the optional INI snippet bundled with the
/// archive (caller appends it to `mumble-server.ini`).
#[derive(Debug)]
pub(crate) struct InstalledFiles {
    /// Absolute path of the cdylib written to disk.
    pub cdylib_path: PathBuf,
    /// Hex digest of the downloaded archive body.
    pub sha256: String,
    /// Contents of the bundled `plugin.example.ini`, if present.
    pub ini_snippet: Option<String>,
}

/// Detect the current platform tuple `(os, arch)` used to pick a
/// matching manifest artifact.
pub(crate) fn current_platform() -> (&'static str, &'static str) {
    let os = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "unknown"
    };
    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "unknown"
    };
    (os, arch)
}

/// Download `url` into memory, enforcing `cap` bytes.
fn http_get(url: &str, cap: u64) -> Result<Vec<u8>, InstallError> {
    let resp = ureq::get(url)
        .timeout(std::time::Duration::from_secs(30))
        .call()
        .map_err(|e| InstallError::Http(e.to_string()))?;
    let mut reader = resp.into_reader().take(cap + 1);
    let mut body = Vec::new();
    let _ = reader
        .read_to_end(&mut body)
        .map_err(|e| InstallError::Http(e.to_string()))?;
    if body.len() as u64 > cap {
        return Err(InstallError::TooLarge(cap));
    }
    Ok(body)
}

/// Compute the lowercase hex SHA-256 digest of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut s = String::with_capacity(out.len() * 2);
    for b in out {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

/// Fetch the manifest at `manifest_url`, verify its digest (if the
/// caller provided one), and parse it.
pub(crate) fn fetch_manifest(
    manifest_url: &str,
    expected_sha256: Option<&str>,
) -> Result<Manifest, InstallError> {
    let body = http_get(manifest_url, MAX_MANIFEST_BYTES)?;
    if let Some(want) = expected_sha256.filter(|s| !s.is_empty()) {
        let got = sha256_hex(&body);
        if !got.eq_ignore_ascii_case(want) {
            return Err(InstallError::DigestMismatch {
                expected: want.to_owned(),
                actual: got,
            });
        }
    }
    parse_manifest_bytes(&body)
}

/// Pick the artifact in `manifest` matching the current `(os, arch)`.
///
/// Preference order: a `native` artifact for this exact platform, then
/// a portable `wasm` artifact (which runs on any host).
pub(crate) fn pick_artifact(manifest: &Manifest) -> Result<&ManifestArtifact, InstallError> {
    let (os, arch) = current_platform();
    if let Some(native) = manifest.artifacts.iter().find(|a| {
        a.kind.eq_ignore_ascii_case("native")
            && a.os.eq_ignore_ascii_case(os)
            && a.arch.eq_ignore_ascii_case(arch)
    }) {
        return Ok(native);
    }
    if let Some(wasm) = manifest
        .artifacts
        .iter()
        .find(|a| a.kind.eq_ignore_ascii_case("wasm"))
    {
        return Ok(wasm);
    }
    Err(InstallError::Manifest(format!(
        "no artifact for {os}/{arch} (and no portable wasm artifact); available: {avail:?}",
        avail = manifest
            .artifacts
            .iter()
            .map(|a| format!("{}/{}/{}", a.kind, a.os, a.arch))
            .collect::<Vec<_>>()
    )))
}

/// Parse a marketplace manifest from raw bytes.  Split out from
/// [`fetch_manifest`] so the fuzz harness can target the JSON parser in
/// isolation without performing any network I/O.
pub(crate) fn parse_manifest_bytes(data: &[u8]) -> Result<Manifest, InstallError> {
    serde_json::from_slice::<Manifest>(data).map_err(|e| InstallError::Manifest(e.to_string()))
}

/// Extract `cdylib_filename` (and optional `plugin.example.ini`) from
/// a zip archive.
pub(crate) fn extract_zip(
    archive: &[u8],
    cdylib_filename: &str,
) -> Result<(Vec<u8>, Option<String>), InstallError> {
    let mut z = zip::ZipArchive::new(Cursor::new(archive))
        .map_err(|e| InstallError::Archive(e.to_string()))?;
    let mut cdylib_bytes: Option<Vec<u8>> = None;
    let mut ini_snippet: Option<String> = None;
    for i in 0..z.len() {
        let mut entry = z
            .by_index(i)
            .map_err(|e| InstallError::Archive(e.to_string()))?;
        let name = entry.name().to_owned();
        let basename = Path::new(&name)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        if basename == cdylib_filename {
            let mut buf = Vec::with_capacity(entry.size() as usize);
            let _ = entry
                .read_to_end(&mut buf)
                .map_err(|e| InstallError::Archive(e.to_string()))?;
            cdylib_bytes = Some(buf);
        } else if basename == "plugin.example.ini" {
            let mut s = String::new();
            let _ = entry
                .read_to_string(&mut s)
                .map_err(|e| InstallError::Archive(e.to_string()))?;
            ini_snippet = Some(s);
        }
    }
    let bytes = cdylib_bytes.ok_or_else(|| {
        InstallError::Archive(format!("cdylib '{cdylib_filename}' not found in zip"))
    })?;
    Ok((bytes, ini_snippet))
}

/// Extract `cdylib_filename` (and optional `plugin.example.ini`) from
/// a gzip-compressed tar archive.
pub(crate) fn extract_tar_gz(
    archive: &[u8],
    cdylib_filename: &str,
) -> Result<(Vec<u8>, Option<String>), InstallError> {
    let dec = flate2::read::GzDecoder::new(Cursor::new(archive));
    let mut t = tar::Archive::new(dec);
    let mut cdylib_bytes: Option<Vec<u8>> = None;
    let mut ini_snippet: Option<String> = None;
    for entry in t
        .entries()
        .map_err(|e| InstallError::Archive(e.to_string()))?
    {
        let mut entry = entry.map_err(|e| InstallError::Archive(e.to_string()))?;
        let path = entry
            .path()
            .map_err(|e| InstallError::Archive(e.to_string()))?
            .into_owned();
        let basename = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_owned();
        if basename == cdylib_filename {
            let mut buf = Vec::new();
            let _ = entry
                .read_to_end(&mut buf)
                .map_err(|e| InstallError::Archive(e.to_string()))?;
            cdylib_bytes = Some(buf);
        } else if basename == "plugin.example.ini" {
            let mut s = String::new();
            let _ = entry
                .read_to_string(&mut s)
                .map_err(|e| InstallError::Archive(e.to_string()))?;
            ini_snippet = Some(s);
        }
    }
    let bytes = cdylib_bytes.ok_or_else(|| {
        InstallError::Archive(format!("cdylib '{cdylib_filename}' not found in tar.gz"))
    })?;
    Ok((bytes, ini_snippet))
}

/// Download the artifact pointed to by `artifact`, verify its digest,
/// extract the cdylib into `dest_dir`, and return what we wrote.
pub(crate) fn download_and_extract(
    artifact: &ManifestArtifact,
    dest_dir: &Path,
) -> Result<InstalledFiles, InstallError> {
    let body = http_get(&artifact.download_url, MAX_ARTIFACT_BYTES)?;
    let got = sha256_hex(&body);
    if !got.eq_ignore_ascii_case(&artifact.sha256) {
        return Err(InstallError::DigestMismatch {
            expected: artifact.sha256.clone(),
            actual: got,
        });
    }
    let (cdylib_bytes, ini_snippet) = match artifact.format.to_ascii_lowercase().as_str() {
        "zip" => extract_zip(&body, &artifact.cdylib_filename)?,
        "tar.gz" | "tgz" => extract_tar_gz(&body, &artifact.cdylib_filename)?,
        other => {
            return Err(InstallError::Archive(format!(
                "unsupported artifact format '{other}'"
            )))
        }
    };
    std::fs::create_dir_all(dest_dir)?;
    let cdylib_path = dest_dir.join(&artifact.cdylib_filename);
    let mut f = File::create(&cdylib_path)?;
    f.write_all(&cdylib_bytes)?;
    f.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&cdylib_path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&cdylib_path, perms)?;
    }
    Ok(InstalledFiles {
        cdylib_path,
        sha256: got,
        ini_snippet,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_matches_known_vector() {
        // "abc" -> ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let got = sha256_hex(b"abc");
        assert_eq!(
            got,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn current_platform_returns_known_tuple() {
        let (os, arch) = current_platform();
        assert!(matches!(os, "linux" | "windows" | "macos" | "unknown"));
        assert!(matches!(arch, "x86_64" | "aarch64" | "unknown"));
    }
}
