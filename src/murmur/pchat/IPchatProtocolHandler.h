// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_MURMUR_PCHAT_IPCHATPROTOCOLHANDLER_H_
#define MUMBLE_MURMUR_PCHAT_IPCHATPROTOCOLHANDLER_H_

#include "Mumble.pb.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace pchat {

/// Context passed to protocol handlers for message store/relay decisions.
struct MessageContext {
	unsigned int serverNum;                    ///< Virtual server number.
	unsigned int channelId;                    ///< Target channel for the message.
	std::string senderHash;                    ///< Certificate hash of the sender.
	std::string messageId;                     ///< Unique message identifier (UUID).
	int64_t clientTs;                          ///< Client-supplied timestamp (ms since epoch).
	int64_t serverTs;                          ///< Server-assigned timestamp (ms since epoch).
	MumbleProto::PchatProtocol protocol;       ///< Protocol variant for this channel.
	std::string payload;                       ///< Opaque encrypted envelope from the client.
	std::optional< std::string > replacesId;   ///< If set, the message ID this edit supersedes.
};

/// Result of a protocol-specific message store/relay operation.
struct StoreResult {
	bool accepted = true;           ///< Whether the message was accepted for storage/relay.
	std::string replacesId;         ///< Message ID that was superseded (empty if none).
	std::string rejectionReason;    ///< Human-readable reason when @c accepted is false.
};

/// Context passed to protocol handlers for fetch operations.
struct FetchContext {
	unsigned int serverNum;      ///< Virtual server number.
	unsigned int channelId;      ///< Channel to fetch messages from.
	unsigned int senderSession;  ///< Session ID of the requesting user.
	std::string requesterHash;   ///< Certificate hash of the requesting user.
	unsigned int limit;          ///< Maximum number of messages to return.
	std::string beforeId;        ///< Pagination cursor: fetch messages before this ID.
};

/// Result of a protocol-specific fetch operation.
struct FetchResult {
	/// Handler already sent a complete response via the bridge. Manager should return.
	bool handled = false;
	/// Fetch should be silently rejected (no response sent). Manager should return.
	bool rejected = false;
	/// Time filter for the DB fetch query (0 = no time filter).
	long long joinedAtTs = 0;
};

/// Interface for protocol-specific behavior in persistent chat.
///
/// Each protocol (PostJoin, FullArchive, ServerManaged, SignalV1) implements
/// this interface to encapsulate its specific storage, fetch, and verification
/// logic. The PersistentChatManager dispatches to the appropriate handler
/// without needing protocol-specific branching in the common code paths.
struct IPchatProtocolHandler {
	virtual ~IPchatProtocolHandler() = default;

	/// Human-readable protocol name for DB storage (e.g. "SIGNAL_V1").
	virtual std::string_view protocolName() const = 0;

	/// Does this protocol store messages server-side?
	virtual bool storesMessages() const = 0;

	/// Should the server record a member-join when a user enters the channel?
	virtual bool recordsJoin() const = 0;

	/// Should the session be auto-verified on key holder report (skip HMAC challenge)?
	virtual bool autoVerifiesOnReport() const = 0;

	/// Compute the relay cap for key distribution requests.
	virtual unsigned int computeRelayCap(unsigned int onlineMembers) const = 0;

	/// Protocol enum to use in PchatKeyRequest messages broadcast to the channel.
	virtual MumbleProto::PchatProtocol keyRequestProtocol() const = 0;

	/// Handle the protocol-specific message store/relay.
	virtual StoreResult handleMessageStore(const MessageContext &ctx) = 0;

	/// Handle the protocol-specific fetch.
	///
	/// If FetchResult::handled is true, the handler already sent a response.
	/// If FetchResult::rejected is true, the fetch should be silently dropped.
	/// Otherwise, the manager continues with a DB fetch using joinedAtTs for filtering.
	virtual FetchResult handleFetch(const FetchContext &ctx) = 0;
};

} // namespace pchat

#endif // MUMBLE_MURMUR_PCHAT_IPCHATPROTOCOLHANDLER_H_
