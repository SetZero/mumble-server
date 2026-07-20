// Fuzzes the admin document-name validator and its percent-decoder. The
// `{name}` path segment is attacker-controlled and is turned into an on-disk
// document key, so this is the natural path-traversal target. The harness
// asserts the post-condition: a name that validate_name() accepts must never
// contain a traversal sequence or an absolute-path prefix.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mumble_file_server::http::admin::fuzz;

fuzz_target!(|data: &[u8]| {
    let raw = String::from_utf8_lossy(data);

    // Exercise the standalone percent-decoder.
    let _ = fuzz::urlencoding_decode(&raw);

    // Exercise the full validator and assert its safety contract holds for
    // every accepted input.
    if let Ok(name) = fuzz::validate_name(&raw) {
        assert!(
            !name.contains(".."),
            "validate_name accepted a traversal: {name:?}"
        );
        assert!(
            !name.starts_with('/'),
            "validate_name accepted an absolute path: {name:?}"
        );
        assert!(
            !name.ends_with('/'),
            "validate_name accepted a trailing slash: {name:?}"
        );
        assert!(!name.is_empty(), "validate_name accepted an empty name");
    }
});
