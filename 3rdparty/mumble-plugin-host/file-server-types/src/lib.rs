//! Generated Rust bindings for the Fancy Mumble file-server REST API.
//!
//! Every type in this crate is produced at build time by `build.rs`
//! from the OpenAPI document emitted by the TypeSpec definition under
//! `../file-server/typespec-poc/`. **Do not edit the generated module
//! directly** - changes will be overwritten on the next build.
//!
//! Consumers should re-export the subset they need; for example the
//! `mumble-file-server` crate aliases [`generated::CapabilitiesResponse`]
//! into its `http::capabilities` module so the wire format is dictated
//! by the `.tsp` source rather than by hand-written Rust structs.
//!
//! This crate intentionally does **not** opt into `[lints] workspace =
//! true`. The generated module would otherwise trip the workspace's
//! strict lint set (deny `missing_docs`, `unused_results`, every
//! pedantic clippy, ...) on code we do not author. Default rustc lints
//! still apply, which is sufficient because typify always emits
//! syntactically clean, snake-cased, fully-public types.

/// Auto-generated request / response models for the file-server REST API.
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/typespec_types.rs"));
}

pub use generated::*;
