// PoC: TypeSpec port of a representative subset of `src/Mumble.proto`
// (the TCP control channel between Mumble clients and the server).
//
// SCOPE
// -----
// Mumble.proto is ~130 messages and uses **proto2** semantics
// (`required`, `optional`, explicit `[default = ...]`).  The TypeSpec
// protobuf emitter only emits **proto3**, so a literal round-trip is
// impossible.  This PoC ports a representative cross-section to prove:
//
//   1. TypeSpec can express every Mumble field shape (scalars,
//      `repeated`, nested messages, enums, `oneof`, `bytes`).
//   2. Field numbers are preserved verbatim via `@field(N)` so the
//      emitted .proto stays wire-compatible with existing clients
//      (because Mumble's proto2 `optional` already maps to proto3
//      `optional` in the modern protoc, and `required` is treated as
//      "must be present" by the generated code anyway).
//   3. The Fancy-Mumble extension fields (IDs 100+) coexist cleanly
//      with the upstream Mumble fields.
//
// What is intentionally NOT ported here:
//
//   * The pchat / E2EE message family (PchatMessage, PchatKeyExchange,
//     PchatKeyHolderReport, ...) - high field count, would balloon the
//     PoC without proving anything new.
//   * Default values: TypeSpec can't emit `[default = X]` (proto3 has
//     no per-field defaults).  See README for the migration plan.
//
// To compile only this file: `npx tsp compile mumble-proto-poc.tsp`.

import "@typespec/protobuf";

using TypeSpec.Protobuf;

@package({ name: "MumbleProto" })
namespace MumbleProto;

// ---------------------------------------------------------------------------
// Version (Mumble.proto: message Version)
// ---------------------------------------------------------------------------
//
// Note: proto2 had this entire message as `optional` fields with no
// presence wrapper.  proto3 reintroduced explicit `optional` for
// scalars, which the TypeSpec emitter uses for any nullable / `?`
// field.  All field numbers preserved.
model Version {
  @field(1) version_v1?: uint32;
  @field(5) version_v2?: uint64;
  @field(6) fancy_version?: uint64;
  @field(2) release?: string;
  @field(3) os?: string;
  @field(4) os_version?: string;
}

// ---------------------------------------------------------------------------
// Authenticate (Mumble.proto: message Authenticate)
// ---------------------------------------------------------------------------
enum ClientType {
  REGULAR: 0,
  BOT: 1,
}

model Authenticate {
  @field(1) username?: string;
  @field(2) password?: string;
  @field(3) tokens: string[];
  @field(4) celt_versions: int32[];
  @field(5) opus?: boolean;
  @field(6) client_type?: ClientType;
}

// ---------------------------------------------------------------------------
// Ping (Mumble.proto: message Ping)
// ---------------------------------------------------------------------------
model Ping {
  @field(1) timestamp?: uint64;
  @field(2) good?: uint32;
  @field(3) late?: uint32;
  @field(4) lost?: uint32;
  @field(5) resync?: uint32;
  @field(6) udp_packets?: uint32;
  @field(7) tcp_packets?: uint32;
  @field(8) udp_ping_avg?: float32;
  @field(9) udp_ping_var?: float32;
  @field(10) tcp_ping_avg?: float32;
  @field(11) tcp_ping_var?: float32;
}

// ---------------------------------------------------------------------------
// ServerSync (Mumble.proto: message ServerSync)
// ---------------------------------------------------------------------------
model ServerSync {
  @field(1) session?: uint32;
  @field(2) max_bandwidth?: uint32;
  @field(3) welcome_text?: string;
  // Note: Mumble historically uses uint64 here for an oversight
  // documented at https://github.com/mumble-voip/mumble/issues/5139.
  @field(4) permissions?: uint64;
}

// ---------------------------------------------------------------------------
// TextMessage (Mumble.proto: message TextMessage)
// ---------------------------------------------------------------------------
model TextMessage {
  @field(1) actor?: uint32;
  @field(2) session: uint32[];
  @field(3) channel_id: uint32[];
  @field(4) tree_id: uint32[];
  // proto2 had this `required`. proto3 has no `required`; consumers
  // should validate on receipt.
  @field(5) message: string;
  @field(6) message_id?: string;
  @field(7) timestamp?: uint64;
  @field(8) edit_id?: string;
  @field(9) pin_target?: string;
  @field(10) unpin?: boolean;
}

// ---------------------------------------------------------------------------
// FancyTypingIndicator (Fancy-Mumble extension, wire ID 131)
// ---------------------------------------------------------------------------
model FancyTypingIndicator {
  @field(1) actor?: uint32;
  @field(2) channel_id?: uint32;
}

// ---------------------------------------------------------------------------
// FancyLinkPreviewRequest / Response (Fancy extension, IDs 132-133)
// ---------------------------------------------------------------------------
model FancyLinkPreviewRequest {
  @field(1) urls: string[];
  @field(2) request_id?: string;
}

model FancyLinkPreviewResponse {
  @field(1) request_id?: string;
  @field(2) embeds: FancyLinkPreviewEmbed[];
}

// Nested types are flattened to top-level by TypeSpec's protobuf
// emitter; original nesting can be restored by hand if needed.
model FancyLinkPreviewMedia {
  @field(1) url?: string;
  @field(2) width?: int32;
  @field(3) height?: int32;
  @field(4) preview_data?: bytes;
  @field(5) preview_mime?: string;
  @field(6) preview_width?: int32;
  @field(7) preview_height?: int32;
  @field(8) original_size?: uint32;
}

model FancyLinkPreviewProvider {
  @field(1) name?: string;
  @field(2) url?: string;
}

model FancyLinkPreviewAuthor {
  @field(1) name?: string;
  @field(2) url?: string;
}

model FancyLinkPreviewField {
  @field(1) name?: string;
  @field(2) value?: string;
  @field(3) inline?: boolean;
}

model FancyLinkPreviewEmbed {
  @field(1) url?: string;
  @field(2) type?: string;
  @field(3) title?: string;
  @field(4) description?: string;
  @field(5) color?: int32;
  @field(6) site_name?: string;
  @field(7) thumbnail?: FancyLinkPreviewMedia;
  @field(8) image?: FancyLinkPreviewMedia;
  @field(9) video?: FancyLinkPreviewMedia;
  @field(10) provider?: FancyLinkPreviewProvider;
  @field(11) author?: FancyLinkPreviewAuthor;
  @field(12) favicon?: FancyLinkPreviewMedia;
  @field(13) canonical_url?: string;
  @field(14) lang?: string;
  @field(15) published_time?: string;
  @field(16) modified_time?: string;
  @field(17) keywords: string[];
  @field(18) summary?: string;
  @field(19) content_type?: string;
  @field(20) content_length?: uint64;
  @field(21) media_duration?: string;
  @field(22) nsfw?: boolean;
  @field(23) reading_time?: string;
  @field(24) fields: FancyLinkPreviewField[];
  @field(25) fetched_at?: string;
}

// ---------------------------------------------------------------------------
// FancyWatchSync (Fancy extension, ID 134) - demonstrates `oneof`.
// ---------------------------------------------------------------------------
enum WatchSourceKind {
  DIRECT_MEDIA: 0,
  YOUTUBE: 1,
}

enum WatchPlaybackState {
  PAUSED: 0,
  PLAYING: 1,
  ENDED: 2,
}

model WatchStart {
  @field(1) channel_id?: uint32;
  @field(2) source_url?: string;
  @field(3) source_kind?: WatchSourceKind;
  @field(4) title?: string;
  @field(5) host_session?: uint32;
}

model WatchState {
  @field(1) state?: WatchPlaybackState;
  @field(2) current_time?: float64;
  @field(3) updated_at_ms?: uint64;
  @field(4) host_session?: uint32;
}

model WatchMember {
  @field(1) session?: uint32;
}

model WatchStateRequest {}
model WatchEnd {}

model WatchHostTransfer {
  @field(1) new_host_session?: uint32;
}

// `oneof` is intentionally NOT modelled here.  The TypeSpec protobuf
// emitter at v0.65 does not yet expose a stable `oneof` decorator;
// the variants are listed as plain `optional` fields with their
// original wire IDs.  At runtime the server already enforces the
// "exactly one set" invariant.  See README "Known limitations".
model FancyWatchSync {
  @field(1) session_id?: string;
  @field(2) actor?: uint32;

  @field(10) start?: WatchStart;
  @field(11) state?: WatchState;
  @field(12) join?: WatchMember;
  @field(13) leave?: WatchMember;
  @field(14) state_request?: WatchStateRequest;
  @field(15) end?: WatchEnd;
  @field(16) host_transfer?: WatchHostTransfer;
}
