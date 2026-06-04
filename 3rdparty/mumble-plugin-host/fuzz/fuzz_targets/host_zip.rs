// Fuzzes zip extraction of a downloaded plugin archive. Targets malformed
// central directories and, notably, the `Vec::with_capacity(entry.size())`
// allocation that trusts the archive's declared member size (zip-bomb /
// allocation-pressure surface).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = mumble_plugin_host::fuzz::extract_zip(data);
});
