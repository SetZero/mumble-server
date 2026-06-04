// Fuzzes the session-JWT verifier. The token arrives in the `Authorization`
// header; this drives the base64url + JSON claims parsing and signature
// checking in jsonwebtoken with arbitrary bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;

const SECRET: &[u8] = b"fuzz-secret-fixed-32-bytes-aaaaaa";

fuzz_target!(|data: &[u8]| {
    let token = String::from_utf8_lossy(data);
    let _ = mumble_file_server::auth::verify_session_jwt(SECRET, &token);
});
