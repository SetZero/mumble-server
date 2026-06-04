// Fuzzes the access-mode parser used when reading the `access_mode` column
// back out of SQLite (and indirectly the upload `mode` form field).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let _ = mumble_file_server::storage::AccessMode::parse(&s);
});
