// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "PchatProtocolHandlers.h"
#include "PersistentChatManager.h"

#include "database/PChatMemberJoinTable.h"
#include "database/PChatMessageTable.h"

#include <QDebug>

#include <algorithm>

namespace msdb = ::mumble::server::db;

namespace pchat {

// Maps protobuf enum to the string stored in the database.
static std::string protocolToString(MumbleProto::PchatProtocol protocol) {
	switch (protocol) {
		case MumbleProto::PCHAT_PROTOCOL_FANCY_V1_POST_JOIN: return "FANCY_V1_POST_JOIN";
		case MumbleProto::PCHAT_PROTOCOL_FANCY_V1_FULL_ARCHIVE: return "FANCY_V1_FULL_ARCHIVE";
		case MumbleProto::PCHAT_PROTOCOL_SERVER_MANAGED: return "SERVER_MANAGED";
		case MumbleProto::PCHAT_PROTOCOL_SIGNAL_V1: return "SIGNAL_V1";
		default: return "NONE";
	}
}

// ---- ServerSideStorage (composition helper) ----

ServerSideStorage::ServerSideStorage(msdb::PChatMessageTable &msgTable) : m_msgTable(msgTable) {}

StoreResult ServerSideStorage::storeMessage(const MessageContext &ctx) {
	StoreResult result;

	if (m_msgTable.messageExists(ctx.serverNum, ctx.channelId, ctx.senderHash, ctx.messageId)) {
		result.accepted = false;
		result.rejectionReason = "duplicate";
		return result;
	}

	// Only accept (and relay) a replaces_id that names a message THIS sender
	// stored in this channel. Copying the client-supplied value through
	// unconditionally let a malicious sender put someone ELSE's message id in
	// replaces_id: the sender-scoped supersede below correctly refused to touch
	// the victim's row, but the relayed PchatMessageDeliver still carried the
	// id and every online client replaced the victim's message in its view.
	if (ctx.replacesId && !ctx.replacesId->empty()
		&& m_msgTable.messageExists(ctx.serverNum, ctx.channelId, ctx.senderHash, *ctx.replacesId)) {
		result.replacesId = *ctx.replacesId;
		m_msgTable.markSuperseded(ctx.serverNum, ctx.channelId, ctx.senderHash, result.replacesId, ctx.messageId);
	}

	msdb::PChatStoredMessage storedMsg;
	storedMsg.serverID    = ctx.serverNum;
	storedMsg.messageId   = ctx.messageId;
	storedMsg.channelId   = ctx.channelId;
	storedMsg.timestamp   = ctx.clientTs;
	storedMsg.senderHash  = ctx.senderHash;
	storedMsg.protocol    = protocolToString(ctx.protocol);
	storedMsg.payload     = ctx.payload;
	storedMsg.payloadSize = static_cast< int >(ctx.payload.size());
	storedMsg.replacesId  = result.replacesId;
	storedMsg.createdAt   = ctx.serverTs;

	if (!m_msgTable.storeMessage(storedMsg)) {
		result.accepted = false;
		result.rejectionReason = "store_failed";
		return result;
	}

	qWarning("pchat: stored msg id=%s in channel=%u from hash=%s (payload=%zu bytes)",
			 ctx.messageId.c_str(), ctx.channelId, ctx.senderHash.c_str(), ctx.payload.size());

	return result;
}

// ---- PostJoinProtocolHandler ----

PostJoinProtocolHandler::PostJoinProtocolHandler(msdb::PChatMessageTable &msgTable,
												 msdb::PChatMemberJoinTable &joinTable)
	: m_storage(msgTable), m_joinTable(joinTable) {}

std::string_view PostJoinProtocolHandler::protocolName() const { return "FANCY_V1_POST_JOIN"; }
bool PostJoinProtocolHandler::storesMessages() const { return true; }
bool PostJoinProtocolHandler::recordsJoin() const { return true; }
bool PostJoinProtocolHandler::autoVerifiesOnReport() const { return false; }

unsigned int PostJoinProtocolHandler::computeRelayCap(unsigned int /*onlineMembers*/) const {
	return 3;
}

MumbleProto::PchatProtocol PostJoinProtocolHandler::keyRequestProtocol() const {
	return MumbleProto::PCHAT_PROTOCOL_FANCY_V1_POST_JOIN;
}

StoreResult PostJoinProtocolHandler::handleMessageStore(const MessageContext &ctx) {
	return m_storage.storeMessage(ctx);
}

FetchResult PostJoinProtocolHandler::handleFetch(const FetchContext &ctx) {
	auto joinRecord = m_joinTable.getJoinRecord(ctx.serverNum, ctx.channelId, ctx.requesterHash);
	if (!joinRecord.has_value()) {
		return { false, true, 0 };
	}
	return { false, false, joinRecord->joinedAt };
}

// ---- FullArchiveProtocolHandler ----

FullArchiveProtocolHandler::FullArchiveProtocolHandler(msdb::PChatMessageTable &msgTable)
	: m_storage(msgTable) {}

std::string_view FullArchiveProtocolHandler::protocolName() const { return "FANCY_V1_FULL_ARCHIVE"; }
bool FullArchiveProtocolHandler::storesMessages() const { return true; }
bool FullArchiveProtocolHandler::recordsJoin() const { return false; }
bool FullArchiveProtocolHandler::autoVerifiesOnReport() const { return false; }

unsigned int FullArchiveProtocolHandler::computeRelayCap(unsigned int onlineMembers) const {
	unsigned int base = onlineMembers / 2;
	return std::clamp(base, 1u, 5u) + 2;
}

MumbleProto::PchatProtocol FullArchiveProtocolHandler::keyRequestProtocol() const {
	return MumbleProto::PCHAT_PROTOCOL_FANCY_V1_FULL_ARCHIVE;
}

StoreResult FullArchiveProtocolHandler::handleMessageStore(const MessageContext &ctx) {
	return m_storage.storeMessage(ctx);
}

FetchResult FullArchiveProtocolHandler::handleFetch(const FetchContext & /*ctx*/) {
	return { false, false, 0 };
}

// ---- ServerManagedProtocolHandler ----

ServerManagedProtocolHandler::ServerManagedProtocolHandler(msdb::PChatMessageTable &msgTable)
	: m_storage(msgTable) {}

std::string_view ServerManagedProtocolHandler::protocolName() const { return "SERVER_MANAGED"; }
bool ServerManagedProtocolHandler::storesMessages() const { return true; }
bool ServerManagedProtocolHandler::recordsJoin() const { return false; }
bool ServerManagedProtocolHandler::autoVerifiesOnReport() const { return false; }

unsigned int ServerManagedProtocolHandler::computeRelayCap(unsigned int onlineMembers) const {
	unsigned int base = onlineMembers / 2;
	return std::clamp(base, 1u, 5u) + 2;
}

MumbleProto::PchatProtocol ServerManagedProtocolHandler::keyRequestProtocol() const {
	return MumbleProto::PCHAT_PROTOCOL_FANCY_V1_FULL_ARCHIVE;
}

StoreResult ServerManagedProtocolHandler::handleMessageStore(const MessageContext &ctx) {
	return m_storage.storeMessage(ctx);
}

FetchResult ServerManagedProtocolHandler::handleFetch(const FetchContext & /*ctx*/) {
	return { false, false, 0 };
}

// ---- SignalV1ProtocolHandler ----

SignalV1ProtocolHandler::SignalV1ProtocolHandler(IServerBridge &bridge) : m_bridge(bridge) {}

std::string_view SignalV1ProtocolHandler::protocolName() const { return "SIGNAL_V1"; }
bool SignalV1ProtocolHandler::storesMessages() const { return false; }
bool SignalV1ProtocolHandler::recordsJoin() const { return true; }
bool SignalV1ProtocolHandler::autoVerifiesOnReport() const { return true; }

unsigned int SignalV1ProtocolHandler::computeRelayCap(unsigned int /*onlineMembers*/) const {
	return 3;
}

MumbleProto::PchatProtocol SignalV1ProtocolHandler::keyRequestProtocol() const {
	return MumbleProto::PCHAT_PROTOCOL_FANCY_V1_POST_JOIN;
}

StoreResult SignalV1ProtocolHandler::handleMessageStore(const MessageContext &ctx) {
	qWarning("pchat: relaying SignalV1 msg id=%s in channel=%u (no server storage)",
			 ctx.messageId.c_str(), ctx.channelId);

	StoreResult result;
	if (ctx.replacesId) {
		result.replacesId = *ctx.replacesId;
	}
	return result;
}

FetchResult SignalV1ProtocolHandler::handleFetch(const FetchContext &ctx) {
	qWarning("pchat: fetch for SignalV1 channel=%u session=%u - no server storage, returning empty",
			 ctx.channelId, ctx.senderSession);

	MumbleProto::PchatFetchResponse resp;
	resp.set_channel_id(ctx.channelId);
	resp.set_has_more(false);
	resp.set_total_stored(0);
	m_bridge.sendPchatFetchResponse(ctx.senderSession, resp);

	return { true, false, 0 };
}

} // namespace pchat
