# TypeSpec PoC: file-server REST + Mumble.proto / MumbleUDP.proto

This directory is a **proof of concept** demonstrating how
[TypeSpec](https://typespec.io/) can be the single source of truth for
**all** wire formats Fancy Mumble currently maintains by hand:

1. The HTTP+JSON file-server REST API (today scattered across
   `3rdparty/mumble-plugin-host/file-server/src/http/*.rs` and the
   `serde::Serialize` structs next to each handler).
2. The Mumble TCP control protocol (`src/Mumble.proto`, proto2,
   ~130 messages including all Fancy extensions).
3. The Mumble UDP voice protocol (`src/MumbleUDP.proto`, proto3).

**Status:** the REST surface is now wired end-to-end — the
`mumble-file-server` crate's `GET /capabilities` handler consumes
types generated from `main.tsp` via the `mumble-file-server-types`
crate (typify build script). A wire-format contract test
(`tests/typespec_contract.rs`) pins the JSON shape so a `.tsp` change
that would break clients fails CI. The protobuf surfaces are still
documentation-only because of the upstream emitter limitations
listed at the bottom of this README; a drift-report script
(`npm run diff-cpp-protos`) makes the gap visible.

## What's in here

| File                  | Purpose                                                          |
| --------------------- | ---------------------------------------------------------------- |
| `main.tsp`            | REST API definition (capabilities, files, emotes, auth).         |
| `mumble-proto-poc.tsp`| Representative subset of `Mumble.proto`.                         |
| `mumble-udp-poc.tsp`  | Full port of `MumbleUDP.proto` (Audio, Ping).                    |
| `tspconfig.yaml`      | Selects the OpenAPI 3.1 + protobuf emitters.                     |
| `package.json`        | Pinned TypeSpec compiler + emitter versions.                     |
| `tsp-output/`         | **Checked in.** Generated OpenAPI + .proto artifacts.            |
| `scripts/verify-generated.ps1`     | CI guard: regenerate + `git diff --exit-code`.      |
| `scripts/diff-against-cpp-protos.ps1` | Drift report vs `src/Mumble.proto` etc.          |
| `.gitignore`          | Keeps `node_modules/` out of the tree.                           |

## End-to-end wiring (REST surface)

```
  main.tsp ──tsp compile──▶ tsp-output/openapi3/openapi.yaml
                                       │
                                       ▼ (build.rs + typify)
               crates/mumble-file-server-types/src/lib.rs
                                       │
                                       ▼
   file-server/src/http/capabilities.rs ── handler returns
                                          generated types directly
                                       │
                                       ▼
           file-server/tests/typespec_contract.rs ── pins JSON shape
```

- The `mumble-file-server-types` crate runs `typify` over the
  generated `openapi.yaml` at build time and re-exports every
  schema as a Rust type. It deliberately opts **out** of the
  workspace's strict lints because typify-generated code triggers
  several of them (no module docs, etc.) and the user's coding
  rules forbid `#[allow(...)]` in production code.
- `http::capabilities::get` constructs and returns the generated
  `CapabilitiesResponse` directly. There are no parallel
  hand-written structs left for this endpoint.
- `tests/typespec_contract.rs` asserts the on-the-wire JSON shape.
  Any breaking schema change in `main.tsp` makes this test fail.

## How to run

Requires Node.js ≥ 20.

```bash
cd 3rdparty/mumble-plugin-host/file-server/typespec-poc
npm install
npx tsp compile .
```

Output (checked in under `tsp-output/`):

```
tsp-output/
├── openapi3/openapi.yaml          # OpenAPI 3.1, consumed by Rust build
└── protobuf/
    ├── MumbleProto.proto          # proto3, regenerated from .tsp
    └── MumbleUDP.proto            # proto3, regenerated from .tsp
```

To verify the committed artifacts match the .tsp sources (the same
check CI should run):

```bash
npm run verify
```

To see how far the generated `.proto` files have drifted from the
canonical `src/Mumble.proto` / `src/MumbleUDP.proto` consumed by the
C++ build:

```bash
npm run diff-cpp-protos
```

Verified clean compile against `@typespec/compiler@0.65.3`,
`@typespec/protobuf@0.65.x`, `@typespec/openapi3@0.65.x`.

## Why TypeSpec for this codebase

Three independent wire formats are currently maintained as three
separate hand-written sources of truth, and each one is duplicated again
on the client side:

| Surface           | Server source                     | Client side                                |
| ----------------- | --------------------------------- | ------------------------------------------ |
| File-server REST  | Rust handlers + `serde` structs   | TS DTOs in FancyMumbleNext webview         |
| Mumble TCP proto2 | `src/Mumble.proto`                | `Mumble.proto` re-checked-in per client    |
| Mumble UDP proto3 | `src/MumbleUDP.proto`             | re-checked-in per client                   |

A single TypeSpec project lets us:

- Generate **OpenAPI** for the REST surface (Swagger UI, mock servers,
  `progenitor`/`utoipa`-style Rust clients).
- Generate the canonical **`.proto`** files for the protobuf surfaces
  (still consumed by `protoc` for the C++ host and `prost` for the Rust
  plugins — TypeSpec just becomes the editing surface).
- Generate **TypeScript** clients/types for the Tauri webview from the
  same source.
- Catch breaking-change drift between the Mumble core protocol and the
  Fancy extensions (fields 100+) at compile time, by keeping them in
  one file.

## Mapping back to current sources

### REST → `src/http/*.rs`

| TypeSpec construct               | Replaces in the file-server crate                       |
| -------------------------------- | ------------------------------------------------------- |
| `interface Files` (`@route`)     | The `.route("/files", ...)` chain in `http/mod.rs`.     |
| `model UploadResponse`           | `http::upload::UploadResponse`.                         |
| `model AuthResponse`             | `http::auth::AuthResponse`.                             |
| `model CapabilitiesResponse`     | `http::capabilities::CapabilitiesResponse`.             |
| `model EmoteDto` + responses     | `http::emotes::EmoteDto`/`EmoteListResponse`/...        |
| `enum AccessMode`                | `storage::AccessMode` (serde-tagged "lowercase").       |
| `model ApiError`                 | `http::common::ApiError` JSON shape.                    |

### Protobuf → `src/Mumble.proto` + `src/MumbleUDP.proto`

| TypeSpec model                     | `.proto` message                                      |
| ---------------------------------- | ----------------------------------------------------- |
| `MumbleProto.Version`              | `Mumble.proto: message Version`                       |
| `MumbleProto.Authenticate`         | `Mumble.proto: message Authenticate`                  |
| `MumbleProto.Ping`                 | `Mumble.proto: message Ping` (TCP)                    |
| `MumbleProto.ServerSync`           | `Mumble.proto: message ServerSync`                    |
| `MumbleProto.TextMessage`          | `Mumble.proto: message TextMessage`                   |
| `MumbleProto.FancyTypingIndicator` | wire ID 131                                           |
| `MumbleProto.FancyLinkPreview*`    | wire IDs 132 / 133 (flattened nested types)           |
| `MumbleProto.FancyWatchSync`       | wire ID 134                                           |
| `MumbleUDP.Audio` / `Ping`         | full port of `MumbleUDP.proto`                        |

Field numbers are preserved verbatim via `@field(N)`, so the emitted
`.proto` is wire-compatible with existing peers for the ported messages.

## Known limitations of TypeSpec for this codebase

1. **proto2 → proto3.** TypeSpec's protobuf emitter only writes
   `syntax = "proto3"`. `Mumble.proto` is `proto2` and uses
   `required` / `optional` / `[default = X]`. The migration path is:
   - proto2 `optional` ≈ proto3 `optional` (both supported by modern
     protoc and by `prost`/`protobuf-rust`).
   - proto2 `required` is treated as plain `optional` on the wire by
     all current generators — semantic enforcement moves into the
     handler. This is what the PoC does.
   - Per-field `[default = X]` is **dropped**. Code generators in the
     proto3 world expect callers/handlers to apply defaults. A diff
     of the regenerated `.proto` against the hand-written one will
     flag every defaulted field that needs follow-up handler logic.
2. **`oneof` decorator is not stable in `@typespec/protobuf@0.65`.**
   The PoC degrades the `oneof Header { target | context }` (UDP
   Audio) and `oneof event` (FancyWatchSync) to a flat list of
   `optional` fields with the original wire IDs preserved. The
   "exactly one set" invariant is already enforced server-side.
3. **Nested messages get flattened.** Compare the hand-written
   `FancyLinkPreviewResponse.Embed.Media` nesting with the PoC's flat
   `FancyLinkPreviewMedia`. The emitter does not nest messages inside
   other messages. Wire encoding is unaffected, but generated symbol
   names differ.
4. **`@typespec/json-schema` is not enabled.** It silently emits
   nothing without explicit `@jsonSchema` annotations on every model.
   OpenAPI 3.1 already embeds JSON Schema for every request/response
   body, so it would be redundant for the REST surface anyway.
5. **Not a literal port.** Only ~10 of ~130 `Mumble.proto` messages
   are included. The pchat / E2EE family was excluded to keep the
   PoC reviewable; the patterns used here cover every shape needed
   by the rest.

## Why we can't flip the protobuf source of truth today

The Mumble TCP/UDP protocols are wire-frozen for backwards
compatibility with every shipped client. Switching the source of truth
from `.proto` to `.tsp` is **only safe** if the diff between the
regenerated `.proto` and `src/Mumble.proto` / `src/MumbleUDP.proto` is
empty (or differs only in cosmetic ways tolerated by all generators).

The three limitations above (proto2→proto3, no `oneof`, no nested
messages) currently make a literal swap unsafe. The right next step is
to file upstream feature requests with `@typespec/protobuf` for the
missing pieces; until those ship, TypeSpec is best applied **only to
the REST surface** and to **new** protobuf messages.

## Next steps

1. **Done:** CI guard via `npm run verify` (regenerate +
   `git diff --exit-code`).
2. **Done:** OpenAPI → Rust types via `mumble-file-server-types`
   (typify), consumed by `http::capabilities`. Wire-format pinned by
   `tests/typespec_contract.rs`.
3. Migrate the remaining REST handlers (`http::auth`, `http::upload`,
   `http::files`, `http::emotes`) to the same pattern: delete the
   hand-written response/request structs and import them from
   `mumble_file_server_types`.
4. Generate TS clients for FancyMumbleNext from the same
   `openapi.yaml` and delete the duplicated DTOs in the webview.
5. Once `@typespec/protobuf` exposes `oneof`, nested messages, and
   proto2 syntax, regenerate `Mumble.proto` / `MumbleUDP.proto` from
   `.tsp` and replace `src/Mumble.proto` / `src/MumbleUDP.proto`.
   Until then, `npm run diff-cpp-protos` is the early-warning system
   for accidental drift between TypeSpec docs and the canonical
   `.proto`.
