//! Build script: emit a C header for the cdylib's FFI surface.

use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let out_dir = env::var("OUT_DIR").unwrap_or_else(|_| format!("{crate_dir}/target/include"));
    let out_path = PathBuf::from(&out_dir).join("mumble_plugin_host.h");

    let config_path = PathBuf::from(&crate_dir).join("cbindgen.toml");
    let config = cbindgen::Config::from_file(&config_path).unwrap_or_default();

    match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(bindings) => {
            let _ = bindings.write_to_file(&out_path);
            println!("cargo:rerun-if-changed=src/lib.rs");
            println!("cargo:rerun-if-changed=src/ffi.rs");
            // context.rs defines PluginHostCallbacks (the C callback table), so
            // it must retrigger header regeneration too; otherwise an edit there
            // leaves a stale header and breaks the C++ build.
            println!("cargo:rerun-if-changed=src/context.rs");
            println!("cargo:rerun-if-changed=cbindgen.toml");
            // Also publish the header alongside the cdylib for the C++ build.
            let publish = PathBuf::from(&crate_dir)
                .join("include")
                .join("mumble_plugin_host.h");
            if let Some(parent) = publish.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = bindings.write_to_file(&publish);
            make_opaque_handle_forward_decl(&publish);
        }
        Err(e) => {
            println!("cargo:warning=cbindgen failed: {e}");
        }
    }
}

/// Replace cbindgen's zero-size-array struct body for `PluginHostHandle` with
/// an opaque forward declaration.  The zero-size array `uint8_t _private[0]`
/// is a GCC extension that triggers `-Wpedantic` when the header is compiled
/// as C++; a forward-declaration-only typedef is valid ISO C and ISO C++.
fn make_opaque_handle_forward_decl(header: &std::path::Path) {
    let Ok(src) = std::fs::read_to_string(header) else {
        return;
    };
    const BODY: &str =
        "typedef struct PluginHostHandle {\n  uint8_t _private[0];\n} PluginHostHandle;";
    const FORWARD: &str = "typedef struct PluginHostHandle PluginHostHandle;";
    if src.contains(BODY) {
        let _ = std::fs::write(header, src.replace(BODY, FORWARD));
    }
}
