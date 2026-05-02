//! Wire-format contract test: build a `CapabilitiesResponse` from the
//! generated TypeSpec types, serialize it to JSON, and assert that the
//! resulting field shape matches what the existing clients expect.
//!
//! If the .tsp definition is changed in a way that breaks the JSON
//! contract (renamed/dropped/added required field, type change, ...),
//! this test will fail and the developer will know to regenerate /
//! version-bump the API rather than silently shipping the break.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "tests panic on failure"
)]

use mumble_file_server_types::{
    CapabilitiesResponse, Features, Limits, PluginInfo, VersionInfo,
};
use serde_json::{json, Value};

fn sample_response() -> CapabilitiesResponse {
    CapabilitiesResponse {
        plugin: PluginInfo {
            name: "mumble-file-server".to_owned(),
            version: "0.1.0".to_owned(),
        },
        mumble_version: VersionInfo {
            major: Some(1),
            minor: Some(5),
            patch: Some(0),
            display: "1.5.0".to_owned(),
        },
        fancy_version: VersionInfo {
            major: None,
            minor: None,
            patch: None,
            display: "unknown".to_owned(),
        },
        features: Features {
            file_uploads: true,
            custom_emotes: true,
            file_ttl: true,
            delete_on_download: false,
            delete_on_disconnect: false,
        },
        limits: Limits {
            max_file_size_bytes: 256 * 1024 * 1024,
            max_total_storage_bytes: 10 * 1024 * 1024 * 1024,
            ttl_seconds: 86_400,
        },
    }
}

#[test]
fn capabilities_response_matches_documented_shape() {
    let actual: Value = serde_json::to_value(sample_response()).unwrap();
    let expected = json!({
        "plugin": { "name": "mumble-file-server", "version": "0.1.0" },
        "mumble_version": {
            "major": 1, "minor": 5, "patch": 0, "display": "1.5.0"
        },
        "fancy_version": {
            "major": null, "minor": null, "patch": null, "display": "unknown"
        },
        "features": {
            "file_uploads": true,
            "custom_emotes": true,
            "file_ttl": true,
            "delete_on_download": false,
            "delete_on_disconnect": false
        },
        "limits": {
            "max_file_size_bytes": 268435456_u64,
            "max_total_storage_bytes": 10737418240_u64,
            "ttl_seconds": 86400_u64
        }
    });
    assert_eq!(
        actual, expected,
        "TypeSpec-generated CapabilitiesResponse JSON shape changed; \
         either update this test or version-bump the .tsp definition."
    );
}

#[test]
fn capabilities_response_roundtrips_through_json() {
    let original = sample_response();
    let bytes = serde_json::to_vec(&original).unwrap();
    let parsed: CapabilitiesResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed.plugin.name, original.plugin.name);
    assert_eq!(parsed.plugin.version, original.plugin.version);
    assert_eq!(parsed.mumble_version.display, original.mumble_version.display);
    assert_eq!(parsed.fancy_version.major, None);
    assert_eq!(parsed.limits.ttl_seconds, 86_400);
    assert!(parsed.features.file_uploads);
    assert!(!parsed.features.delete_on_download);
}
