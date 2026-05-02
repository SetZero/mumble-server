// PoC: TypeSpec port of `src/MumbleUDP.proto` (the proto3 UDP voice
// channel).  Unlike Mumble.proto this one is small enough to port in
// full without losing fidelity.
//
// To compile only this file: `npx tsp compile mumble-udp-poc.tsp`.

import "@typespec/protobuf";

using TypeSpec.Protobuf;

@package({ name: "MumbleUDP" })
namespace MumbleUDP;

// ---------------------------------------------------------------------------
// Audio packet
// ---------------------------------------------------------------------------
//
// Notes on the field-index gap (5 -> 16):
//   The original .proto deliberately reserves slots 6-15 for future
//   "hot-path" fields so they keep their 1-byte encoding overhead
//   (varint tag <= 15 fits in one byte).  The same reservation
//   discipline is preserved here by the explicit field numbers.
// The original .proto uses a `oneof Header { target | context }` so
// that exactly one of the two is present.  v0.65 of the protobuf
// emitter has no stable `oneof` decorator yet, so we drop down to two
// `optional` fields with the same wire IDs.  See README "Known
// limitations".
model Audio {
  @field(1) target?: uint32;
  @field(2) context?: uint32;

  @field(3) sender_session?: uint32;
  @field(4) frame_number?: uint64;
  @field(5) opus_data?: bytes;
  @field(6) positional_data: float32[];
  @field(7) volume_adjustment?: float32;
  @field(16) is_terminator?: boolean;
}

// ---------------------------------------------------------------------------
// Ping packet (UDP).  Distinct from MumbleProto.Ping over TCP.
// ---------------------------------------------------------------------------
model Ping {
  @field(1) timestamp?: uint64;
  @field(2) request_extended_information?: boolean;
  @field(3) server_version_v2?: uint64;
  @field(4) user_count?: uint32;
  @field(5) max_user_count?: uint32;
  @field(6) max_bandwidth_per_user?: uint32;
}
