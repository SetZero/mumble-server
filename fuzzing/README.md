# Fuzzing

Coverage-guided fuzzing for the server's untrusted-input parsers, across all
three languages in the tree.

This directory holds only the **harness source** that lives with the code it
fuzzes. The **Docker image and the runner** live in the sibling `mumble-docker`
repo and are driven by `python -m tools.dev_fuzz`, alongside `dev-build` /
`dev-debug` — so fuzzing matches the same Docker dev loop you already use.

```
fuzzing/                              # (this dir, in mumble-server)
  cpp/              # C++ libFuzzer harnesses + CMake
  corpus/           # seed inputs for the C++ targets
3rdparty/mumble-plugin-host/fuzz/     # Rust cargo-fuzz crate (targets + corpus)

mumble-docker/                        # (sibling repo)
  Dockerfile.fuzz          # toolchain image (clang+libFuzzer, Rust nightly+cargo-fuzz, Qt6, protobuf)
  scripts/fuzz_runner.py   # in-container driver
  tools/dev_fuzz.py        # `python -m tools.dev_fuzz` entry point
```

## Quick start

Run everything from the **`mumble-docker`** repo (it bind-mounts this
checkout via `MUMBLE_SRC` in its `.env`):

```bash
python -m tools.dev_fuzz list                       # see every target
python -m tools.dev_fuzz rust fileserver_path_validate
python -m tools.dev_fuzz cpp fuzz_opengraph -- -timeout=2 -rss_limit_mb=2048
python -m tools.dev_fuzz smoke                       # quick bounded pass over all targets (CI gate)
python -m tools.dev_fuzz all                         # every target, 300s each (--time to change)
python -m tools.dev_fuzz --rebuild list             # force a fresh toolchain image
```

`dev_fuzz` builds the `mumble-fuzz` image on first use (and caches it), then
runs the in-container driver with this source tree mounted at `/src`, with
`--cap-add SYS_PTRACE --security-opt seccomp=unconfined` set so AddressSanitizer
works. A crash drops a reproducer file into the mounted tree.

The same subcommands (`list` / `rust <t>` / `cpp <t>` / `smoke`, plus `--`
passthrough to libFuzzer) are implemented by `mumble-docker/scripts/fuzz_runner.py`
if you want to run inside the container directly.

## Targets

### Rust (`cargo-fuzz`, AddressSanitizer)

| Target | Exercises |
| --- | --- |
| `fileserver_signing` | signed-download-URL verifier (hex/radix parsing, constant-time compare) |
| `fileserver_jwt` | session-JWT base64url + claims parsing |
| `fileserver_access_mode` | `access_mode` string parser |
| `fileserver_path_validate` | admin document-name validator + percent-decoder; **asserts no accepted name contains a traversal** |
| `host_manifest` | marketplace manifest JSON parser |
| `host_zip` | zip extraction (incl. the `Vec::with_capacity(entry.size())` allocation that trusts the declared member size) |
| `host_targz` | gzip+tar extraction on malformed/truncated input |

Safe Rust has no UB, so for these the wins are panics (DoS) and pathological
allocations; ASan additionally covers the C code inside `zip`/`flate2`/`sqlite`.

### C++ (`libFuzzer`, ASan + UBSan)

| Target | Exercises |
| --- | --- |
| `fuzz_ssrf` | the link-preview URL classifier (`isSafeUrl` / `isBlockedIp` / `decodeHtmlEntities`); asserts no accepted literal-IP URL is an internal address |
| `fuzz_opengraph` | the `QRegularExpression`-heavy Open Graph / HTML meta parser — **the main ReDoS surface** |
| `fuzz_htmlfilter` | `HTMLFilter::filter()`, run over untrusted chat messages when HTML is stripped |
| `fuzz_protocol` | `ParseFromArray` round-trip across the TCP control messages, weighted to the custom `Fancy*`/`Pchat*` types |

Hunting ReDoS in `fuzz_opengraph`: run with a per-input timeout, e.g.
`cpp fuzz_opengraph -- -timeout=2 -rss_limit_mb=2048`. A 2 s timeout that
trips on a *small* input is a strong catastrophic-backtracking signal.

## What's intentionally out of scope

* **Stateful C++ message handlers** (`Server::msgXxx`). `fuzz_protocol` covers
  the parse/serialize layer only; driving the handlers needs a constructed
  `Server` + `ServerUser` (a heavier in-process harness) and is a good next
  step if the parse layer comes up clean.
* **`.wasm` component loading.** The wasmtime parser/validator is fuzzed
  upstream by the Bytecode Alliance; re-fuzzing it here is low ROI and very
  slow (JIT per input).
* **`resolveAndCheck` DNS path.** It performs real network resolution, so it is
  excluded from the in-process harness.

## Running on a Windows host

Use `python -m tools.dev_fuzz` (the container). Native-Windows runs are **not**
supported for the Rust targets: `mumble-file-server` / `mumble-plugin-host` are
`cdylib` crates, and
the MSVC linker requires every DLL symbol to be resolved at link time, but the
libFuzzer/ASan coverage runtime is only linked into the final fuzz binary
(`LNK1104: clang_rt.asan_*` with ASan, `LNK2001: __sanitizer_cov_*` without).
On Linux this is a non-issue (shared objects resolve those symbols at load),
so the container — or WSL2 — is the way to run. `cargo +nightly fuzz list`
and corpus management still work natively on Windows.

## Notes / caveats

* The fuzz crate under `3rdparty/mumble-plugin-host/fuzz/` is deliberately
  **not** a workspace member, so it doesn't inherit the strict workspace lints
  and `cargo-fuzz` controls the sanitizer build. Run it via
  `cargo +nightly fuzz` (the `+nightly` overrides the pinned stable toolchain).
* The fuzz-only surface is gated behind a `fuzzing` Cargo feature
  (`mumble-file-server`, `mumble-plugin-host`) and the `OpenGraphPlugin::fuzzParse`
  hook — none of it compiles into production builds.
* The C++ harnesses link AddressSanitizer against the system Qt (which is not
  ASan-instrumented). That is fine for finding bugs in *our* code; if you see
  noise originating inside Qt, build against an ASan-instrumented Qt or add a
  suppression.
* These harnesses had to be authored without a local Qt/protobuf build, so on
  the very first `cmake` you may need to nudge a package path (the CMake skips,
  rather than fails, any target whose deps it can't find — check the configure
  output).
