// Fuzzes gzip+tar extraction of a downloaded plugin archive. Targets the
// gzip inflate path and tar header parsing on malformed / truncated input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = mumble_plugin_host::fuzz::extract_tar_gz(data);
});
