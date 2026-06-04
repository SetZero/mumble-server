// Fuzzes the marketplace-manifest JSON parser. The manifest body is fetched
// from a (potentially untrusted) URL before any artifact is downloaded.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = mumble_plugin_host::fuzz::parse_manifest(data);
});
