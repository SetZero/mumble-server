//! Wire envelope for the `fancy-plugin-info` plugin-data payload.
//!
//! ```text
//! +-------+-------+-----------------+--------------------------------+
//! | u8 ver| u8 fl | u32 LE raw_len  | payload (raw json or zstd)     |
//! +-------+-------+-----------------+--------------------------------+
//!     1       1            4                       N
//! ```
//!
//! * `ver` is currently `1`.
//! * `flags` bit 0 = payload is zstd-compressed.
//! * `raw_len` is the uncompressed JSON byte length (decoder validates
//!   against [`mumble_plugin_api::PLUGIN_INFO_MAX_BYTES`]).

use mumble_plugin_api::PLUGIN_INFO_MAX_BYTES;
use serde::Serialize;
use thiserror::Error;

/// Current envelope format version.
pub const ENVELOPE_VERSION: u8 = 1;

/// Bit flag: payload is zstd-compressed.
pub const FLAG_ZSTD: u8 = 0b0000_0001;

/// Compress with zstd only above this raw-JSON size (sub-256 B payloads
/// shrink negligibly and the framing overhead dominates).
const ZSTD_THRESHOLD: usize = 256;

/// Default zstd compression level.  Level 3 is a sensible trade-off
/// between speed and ratio for short, mostly-ASCII JSON payloads.
const ZSTD_LEVEL: i32 = 3;

/// Errors produced while encoding a plugin-info envelope.
#[derive(Debug, Error)]
pub enum EnvelopeError {
    /// JSON serialisation of the per-plugin record failed.
    #[error("plugin info json encode failed: {0}")]
    Encode(#[from] serde_json::Error),

    /// `zstd` reported a compression failure.
    #[error("zstd compression failed: {0}")]
    Compress(std::io::Error),

    /// Encoded JSON exceeds [`mumble_plugin_api::PLUGIN_INFO_MAX_BYTES`].
    #[error("plugin info payload {size} B exceeds limit of {limit} B")]
    TooLarge {
        /// Actual encoded JSON length in bytes.
        size: usize,
        /// Configured limit ([`mumble_plugin_api::PLUGIN_INFO_MAX_BYTES`]).
        limit: usize,
    },
}

/// JSON shape broadcast inside the envelope: name + version + the
/// plugin's typed `PluginInfo` object.
#[derive(Debug, Clone, Serialize)]
pub struct PluginInfoRecord<'a> {
    /// Stable plugin identifier (matches `MumblePlugin::name`).
    pub name: &'a str,
    /// `SemVer` of the plugin release (matches `MumblePlugin::version`).
    pub version: &'a str,
    /// Parsed `PluginInfo` (passed in as a borrowed JSON value).
    pub info: &'a serde_json::Value,
}

/// Encode a [`PluginInfoRecord`] into the on-wire envelope.
pub fn encode(record: &PluginInfoRecord<'_>) -> Result<Vec<u8>, EnvelopeError> {
    let raw = serde_json::to_vec(record)?;
    if raw.len() > PLUGIN_INFO_MAX_BYTES {
        return Err(EnvelopeError::TooLarge {
            size: raw.len(),
            limit: PLUGIN_INFO_MAX_BYTES,
        });
    }

    let (payload, flags) = if raw.len() >= ZSTD_THRESHOLD {
        let compressed = zstd::stream::encode_all(raw.as_slice(), ZSTD_LEVEL)
            .map_err(EnvelopeError::Compress)?;
        if compressed.len() < raw.len() {
            (compressed, FLAG_ZSTD)
        } else {
            (raw.clone(), 0)
        }
    } else {
        (raw.clone(), 0)
    };

    let raw_len_u32 = u32::try_from(raw.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(6 + payload.len());
    out.push(ENVELOPE_VERSION);
    out.push(flags);
    out.extend_from_slice(&raw_len_u32.to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests panic on failure")]

    use super::*;
    use serde_json::json;

    #[test]
    fn encodes_small_payload_uncompressed() {
        let v = json!({ "description": "x" });
        let env = encode(&PluginInfoRecord {
            name: "p",
            version: "0.1.0",
            info: &v,
        })
        .unwrap();
        assert_eq!(env[0], ENVELOPE_VERSION);
        assert_eq!(env[1] & FLAG_ZSTD, 0);
        let raw_len = u32::from_le_bytes([env[2], env[3], env[4], env[5]]) as usize;
        assert_eq!(raw_len, env.len() - 6);
    }

    #[test]
    fn encodes_large_payload_with_zstd() {
        let big = "lorem ipsum dolor sit amet ".repeat(64);
        let v = json!({ "description": big });
        let env = encode(&PluginInfoRecord {
            name: "p",
            version: "0.1.0",
            info: &v,
        })
        .unwrap();
        assert_eq!(env[0], ENVELOPE_VERSION);
        assert_eq!(env[1] & FLAG_ZSTD, FLAG_ZSTD);
    }

    #[test]
    fn rejects_oversized_payload() {
        let huge = "x".repeat(PLUGIN_INFO_MAX_BYTES + 1);
        let v = json!({ "description": huge });
        let err = encode(&PluginInfoRecord {
            name: "p",
            version: "0.1.0",
            info: &v,
        })
        .unwrap_err();
        assert!(matches!(err, EnvelopeError::TooLarge { .. }));
    }
}
