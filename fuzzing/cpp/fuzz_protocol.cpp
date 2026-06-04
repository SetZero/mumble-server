// libFuzzer harness for the Mumble TCP protocol message layer.
//
// The server decodes every TCP control message with
// `MumbleProto::<Type>::ParseFromArray(...)` (see Server::message() in
// src/murmur/Server.cpp) before dispatching to a handler.  This harness
// reproduces that parse step for a representative set of message types,
// with an emphasis on the custom Fancy*/Pchat* messages whose handlers do
// the most manual byte/string processing.
//
// Wire format consumed by the fuzzer:
//   byte 0   : message-type selector (mod N)
//   byte 1.. : protobuf payload fed to ParseFromArray
//
// Parsing is followed by DiscardUnknownFields() + SerializeToString() to
// exercise the round-trip the server performs before relaying.
//
// NOTE: this fuzzes the *parse/serialize* layer only. Exercising the stateful
// msgXxx() handlers requires a constructed Server + ServerUser and is left as
// a follow-up (those would need a heavy in-process harness).

#include "Mumble.pb.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace {

template < typename T > void roundTrip(const uint8_t *payload, size_t len) {
	T msg;
	// Partial variants so proto2 messages with unset `required` fields still
	// drive the parser/serializer (instead of being rejected up front) and so
	// serialization never trips a required-field assertion on a fuzz input.
	if (msg.ParsePartialFromArray(payload, static_cast< int >(len))) {
		msg.DiscardUnknownFields();
		std::string out;
		(void) msg.SerializePartialToString(&out);
	}
}

using ParseFn = void (*)(const uint8_t *, size_t);

// Representative parsers, weighted towards the custom message types.
constexpr ParseFn kParsers[] = {
	&roundTrip< MumbleProto::Authenticate >,
	&roundTrip< MumbleProto::TextMessage >,
	&roundTrip< MumbleProto::UserState >,
	&roundTrip< MumbleProto::ChannelState >,
	&roundTrip< MumbleProto::ACL >,
	&roundTrip< MumbleProto::PluginDataTransmission >,
	&roundTrip< MumbleProto::PchatMessage >,
	&roundTrip< MumbleProto::PchatFetch >,
	&roundTrip< MumbleProto::PchatKeyExchange >,
	&roundTrip< MumbleProto::PchatKeyRequest >,
	&roundTrip< MumbleProto::PchatKeyChallengeResponse >,
	&roundTrip< MumbleProto::PchatReaction >,
	&roundTrip< MumbleProto::WebRtcSignal >,
	&roundTrip< MumbleProto::FancyLinkPreviewRequest >,
	&roundTrip< MumbleProto::FancyPushRegister >,
	&roundTrip< MumbleProto::FancyWatchSync >,
	&roundTrip< MumbleProto::FancyDrawStroke >,
	&roundTrip< MumbleProto::PluginMessage >,
};

constexpr size_t kNumParsers = sizeof(kParsers) / sizeof(kParsers[0]);

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 1) {
		return 0;
	}
	const size_t selector = data[0] % kNumParsers;
	kParsers[selector](data + 1, size - 1);
	return 0;
}
