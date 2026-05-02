// PoC: TypeSpec definition of the Mumble Fancy file-server REST API.
//
// This file is the schema-first source of truth for the HTTP surface
// currently hand-written in `src/http/*.rs`. It compiles to OpenAPI 3
// and JSON Schema via `npx tsp compile .`.
//
// The intent is to demonstrate that a single .tsp file can replace the
// scattered `serde::Serialize` structs, the implicit route table in
// `http/mod.rs`, and the ad-hoc `{"error": "<msg>"}` shape, while
// staying language-agnostic enough to also generate clients (TS for the
// Tauri webview, Rust via progenitor, etc).

import "@typespec/http";
import "@typespec/openapi";
import "@typespec/openapi3";

// Pull in the protobuf-side PoCs (Mumble.proto / MumbleUDP.proto port).
// Their namespaces are isolated by `@package(...)`, so the OpenAPI
// emitter ignores them automatically.
import "./mumble-proto-poc.tsp";
import "./mumble-udp-poc.tsp";

using Http;
using OpenAPI;

@service({ title: "Mumble Fancy File Server" })
@server("http://127.0.0.1:64739", "Default loopback bind from FileServerConfig")
namespace MumbleFileServer;

// -- Shared error model ------------------------------------------------

@error
model ApiError {
  /** Human-readable message safe to surface to clients. */
  error: string;
}

// -- Shared scalars / enums -------------------------------------------

/** Access mode chosen by the uploader. */
enum AccessMode {
  Public: "public",
  Password: "password",
  Session: "session",
}

/** Hex-encoded unsigned integer (lowercase, no `0x` prefix). */
@format("hex")
scalar HexString extends string;

/** Opaque bearer credential (password or session JWT). */
@format("password")
scalar Bearer extends string;

// -- /capabilities -----------------------------------------------------

model VersionInfo {
  major: uint16 | null;
  minor: uint16 | null;
  patch: uint16 | null;
  /** Pre-formatted "MAJOR.MINOR.PATCH" or "unknown". */
  display: string;
}

model PluginInfo {
  name: string;
  version: string;
}

model Features {
  file_uploads: boolean;
  custom_emotes: boolean;
  file_ttl: boolean;
  delete_on_download: boolean;
  delete_on_disconnect: boolean;
}

model Limits {
  max_file_size_bytes: uint64;
  max_total_storage_bytes: uint64;
  ttl_seconds: uint64;
}

model CapabilitiesResponse {
  plugin: PluginInfo;
  mumble_version: VersionInfo;
  fancy_version: VersionInfo;
  features: Features;
  limits: Limits;
}

@route("/capabilities")
@tag("discovery")
interface Capabilities {
  /** Public, unauthenticated discovery endpoint. */
  @get get(): CapabilitiesResponse;
}

// -- /files (upload + download + auth) --------------------------------

model UploadResponse {
  file_id: string;
  download_url: url;
  access_mode: AccessMode;
  /** Unix-seconds expiry, or null if TTL disabled. */
  expires_at: uint64 | null;
  size_bytes: uint64;
}

/** Multipart fields accepted by `POST /files`. */
model UploadForm {
  /** Required: the file bytes. */
  @multipartBody file: HttpPart<File>;
  /** Channel id the upload is announced in. */
  channel_id: HttpPart<uint32>;
  /** One of "public" | "password" | "session". */
  mode: HttpPart<AccessMode>;
  /** Required iff `mode == "password"`. */
  password?: HttpPart<string>;
}

model AuthResponse {
  /** Opaque single-use ticket appended to the GET URL as `?ticket=`. */
  ticket: string;
  ttl_seconds: uint64;
}

@route("/files")
@tag("files")
interface Files {
  /**
   * Multipart upload. The session id and per-session upload token are
   * passed as query params (the token was previously delivered to the
   * client via plugin data).
   */
  @post
  upload(
    @query session: uint32,
    @query token: string,
    @header contentType: "multipart/form-data",
    @body form: UploadForm,
  ): UploadResponse | ApiError;

  /**
   * Signed-URL download. The triplet (`ex`, `is`, `hm`) is the HMAC
   * envelope minted at upload time. `ticket` is required for non-public
   * files and is obtained from `POST /files/{file_id}/auth`.
   */
  @route("/{file_id}")
  @get
  download(
    @path file_id: string,
    @query ex: HexString,
    @query("is") issued: HexString,
    @query hm: HexString,
    @query ticket?: string,
  ): {
    @statusCode statusCode: 200;
    @header contentType: string;
    @header contentLength: uint64;
    @header contentDisposition: string;
    @body bytes: bytes;
  } | ApiError;

  /**
   * Exchange a credential (password or session JWT) for a single-use
   * download ticket. The credential travels in the `Authorization`
   * header, never in the URL.
   */
  @route("/{file_id}/auth")
  @post
  preAuth(
    @path file_id: string,
    @header authorization: Bearer,
  ): AuthResponse | ApiError;
}

// -- /emotes (admin-managed custom server emotes) ---------------------

model EmoteDto {
  shortcode: string;
  alias_emoji: string;
  description?: string;
  /** `data:` URL containing the base64-encoded image bytes. */
  image_data_url: url;
}

model EmoteListResponse {
  emotes: EmoteDto[];
}

model EmoteUploadResponse {
  shortcode: string;
}

model EmoteDeleteResponse {
  ok: true;
}

model EmoteUploadForm {
  shortcode: HttpPart<string>;
  alias_emoji: HttpPart<string>;
  description?: HttpPart<string>;
  /** Image bytes (PNG/JPEG/GIF/WebP/SVG). */
  @multipartBody file: HttpPart<File>;
}

@route("/emotes")
@tag("emotes")
interface Emotes {
  /** Public list of every server emote. No auth required. */
  @get list(): EmoteListResponse | ApiError;

  /** Admin-only: upload a new emote. */
  @post
  upload(
    @header authorization: Bearer,
    @header contentType: "multipart/form-data",
    @body form: EmoteUploadForm,
  ): EmoteUploadResponse | ApiError;

  /** Admin-only: delete an emote by shortcode. */
  @route("/{shortcode}")
  @delete
  remove(
    @path shortcode: string,
    @header authorization: Bearer,
  ): EmoteDeleteResponse | ApiError;
}
