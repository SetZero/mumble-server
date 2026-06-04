// Fuzzes the signed-download-URL verifier. `ex`, `is` and `hm` are all
// attacker-controlled query parameters; this exercises the hex decoding,
// `u64::from_str_radix`, length handling and constant-time compare without
// ever matching a real signature.
#![no_main]

use libfuzzer_sys::fuzz_target;

const SECRET: &[u8] = b"fuzz-secret-fixed-32-bytes-aaaaaa";

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    // Treat newline-separated chunks as the distinct URL fields so the fuzzer
    // can drive each parameter independently.
    let mut parts = s.split('\n');
    let file_id = parts.next().unwrap_or("");
    let ex = parts.next().unwrap_or("");
    let is = parts.next().unwrap_or("");
    let hm = parts.next().unwrap_or("");

    let _ = mumble_file_server::signing::verify(SECRET, file_id, ex, is, hm, 0);
    let _ = mumble_file_server::signing::verify(SECRET, file_id, ex, is, hm, u64::MAX);
});
