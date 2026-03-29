// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_MURMUR_PCHAT_TYPES_H_
#define MUMBLE_MURMUR_PCHAT_TYPES_H_

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace pchat {

/// Persistent chat protocol matching protobuf PchatProtocol values.
enum class Protocol : uint32_t {
	None             = 0,
	FancyV1PostJoin  = 1,
	FancyV1FullArchive = 2,
	ServerManaged    = 3,
	SignalV1         = 4,
};

/// A stored persistent chat message (opaque ciphertext).
struct StoredMessage {
	std::string messageId;
	uint32_t channelId = 0;
	int64_t timestamp  = 0;
	std::string senderHash;
	Protocol protocol = Protocol::None;
	std::vector< uint8_t > payload;
	std::optional< std::string > replacesId;
	std::optional< std::string > supersededBy;
	int64_t createdAt = 0;
};

/// Channel persistence configuration.
struct ChannelConfig {
	uint32_t channelId      = 0;
	Protocol protocol          = Protocol::None;
	uint32_t maxHistory     = 5000;
	uint32_t retentionDays  = 90;
};

/// A user's public keys for key exchange.
struct UserKeys {
	std::string certHash;
	uint32_t algorithmVersion = 0;
	std::vector< uint8_t > identityPublic;
	std::vector< uint8_t > signingPublic;
	std::vector< uint8_t > signature;
	int64_t updatedAt = 0;
};

/// FANCY_V1_POST_JOIN member join record.
struct MemberJoin {
	uint32_t channelId = 0;
	std::string certHash;
	int64_t joinedAt    = 0;
	uint32_t epochAtJoin = 0;
};

/// A pending key distribution request.
struct PendingKeyRequest {
	std::string requestId;
	uint32_t channelId = 0;
	Protocol protocol  = Protocol::None;
	std::string requesterHash;
	std::vector< uint8_t > requesterPublic;
	uint32_t relayCap  = 7;
	uint32_t relaysSent = 0;
	int64_t createdAt   = 0;
	std::optional< int64_t > fulfilledAt;
	std::optional< std::string > fulfilledBy;
};

/// Acknowledgement sent back to the client.
struct Ack {
	std::string messageId;
	std::string status; // "stored", "rejected"
	std::string reason; // optional reason for rejection
};

/// An offline-queued message awaiting delivery on reconnect.
struct QueuedMessage {
	std::string certHash;
	uint32_t channelId  = 0;
	std::string messageId;
	std::string senderHash;
	int64_t timestamp   = 0;
	std::string envelope;
	int64_t createdAt   = 0;
};

} // namespace pchat

#endif // MUMBLE_MURMUR_PCHAT_TYPES_H_
