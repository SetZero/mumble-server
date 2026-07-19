//! Build script: compile the React/MUI password-entry frontend in `web/` into
//! the single self-contained `web/dist/password.html` that `http::download`
//! embeds with `include_str!`.
//!
//! Hybrid strategy so the crate builds in any environment:
//!   * When a Node/npm toolchain is available, the frontend is (re)built from
//!     `web/`, refreshing the committed artifact.
//!   * When npm is absent (offline / minimal CI image), the committed
//!     `web/dist/password.html` is used as-is.
//!   * Set `MUMBLE_FILESERVER_SKIP_WEB_BUILD=1` to skip the npm build entirely
//!     and always use the committed artifact.

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let web_dir = PathBuf::from(&crate_dir).join("web");
    let dist_file = web_dir.join("dist").join("password.html");

    // Rebuild the frontend only when its sources change.
    for rel in [
        "index.html",
        "package.json",
        "package-lock.json",
        "vite.config.ts",
        "tsconfig.json",
        "tsconfig.app.json",
        "tsconfig.node.json",
    ] {
        println!("cargo:rerun-if-changed={}", web_dir.join(rel).display());
    }
    rerun_if_tree_changed(&web_dir.join("src"));
    rerun_if_tree_changed(&web_dir.join("scripts"));
    println!("cargo:rerun-if-env-changed=MUMBLE_FILESERVER_SKIP_WEB_BUILD");

    if env::var_os("MUMBLE_FILESERVER_SKIP_WEB_BUILD").is_some() {
        ensure_artifact(&dist_file, "MUMBLE_FILESERVER_SKIP_WEB_BUILD is set");
        return;
    }

    if !npm_available(&web_dir) {
        ensure_artifact(&dist_file, "npm was not found on PATH");
        return;
    }

    build_frontend(&web_dir, &dist_file);
}

/// Emit a `rerun-if-changed` line for every file under `dir` (recursively).
fn rerun_if_tree_changed(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rerun_if_tree_changed(&path);
        } else {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

/// A `Command` that invokes `npm` portably (`cmd /C npm` on Windows where npm is
/// a `.cmd` shim) with the working directory set to the frontend project.
fn npm_command(web_dir: &Path) -> Command {
    let mut cmd = if cfg!(windows) {
        Command::new("cmd")
    } else {
        Command::new("npm")
    };
    if cfg!(windows) {
        let _ = cmd.arg("/C").arg("npm");
    }
    let _ = cmd.current_dir(web_dir);
    cmd
}

/// Whether an `npm` toolchain is callable.
fn npm_available(web_dir: &Path) -> bool {
    npm_command(web_dir)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run `npm <args...>` in the frontend project, returning whether it succeeded.
fn run_npm(web_dir: &Path, args: &[&str]) -> bool {
    match npm_command(web_dir).args(args).status() {
        Ok(status) if status.success() => true,
        Ok(status) => {
            println!(
                "cargo:warning=`npm {}` exited with {status}",
                args.join(" ")
            );
            false
        }
        Err(e) => {
            println!("cargo:warning=failed to run `npm {}`: {e}", args.join(" "));
            false
        }
    }
}

/// Install dependencies (if needed) and build the single-file page. On any
/// failure, fall back to the committed artifact rather than breaking the build.
fn build_frontend(web_dir: &Path, dist_file: &Path) {
    if !web_dir.join("node_modules").is_dir() {
        // `npm ci` is reproducible but requires a lockfile; fall back to install.
        let installed = if web_dir.join("package-lock.json").is_file() {
            run_npm(web_dir, &["ci"])
        } else {
            false
        };
        if !installed && !run_npm(web_dir, &["install"]) {
            ensure_artifact(dist_file, "`npm install` failed");
            return;
        }
    }

    if !run_npm(web_dir, &["run", "build"]) {
        ensure_artifact(dist_file, "`npm run build` failed");
    }
}

/// Require that the committed artifact exists when the npm build is skipped or
/// fails; panic with an actionable message otherwise (the crate cannot compile
/// without it because `download.rs` embeds it with `include_str!`).
fn ensure_artifact(dist_file: &Path, reason: &str) {
    if dist_file.is_file() {
        println!(
            "cargo:warning=using committed {} ({reason})",
            dist_file.display()
        );
    } else {
        panic!(
            "{reason} and the committed frontend artifact {} is missing. \
             Build it once with `npm --prefix web install && npm --prefix web run build`.",
            dist_file.display()
        );
    }
}
