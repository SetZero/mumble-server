// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "PersistentChatManager.h"
#include "PchatProtocolHandlers.h"

#include "ACL.h"
#include "crypto/CryptographicRandom.h"
#include "database/PChatMemberJoinTable.h"
#include "database/PChatMessageTable.h"
#include "database/PChatOfflineQueueTable.h"
#include "database/PChatPendingKeyRequestsTable.h"
#include "database/PChatUserKeysTable.h"
#include "database/PChatKeyHoldersTable.h"

#include <QDebug>

#include <algorithm>
#include <chrono>
#include <limits>

namespace msdb = ::mumble::server::db;

namespace pchat {

// Helper to convert ChannelState pchat_protocol (1=POST_JOIN, 2=FULL_ARCHIVE, 4=SIGNAL_V1) to proto enum
static MumbleProto::PchatProtocol channelProtocolToProto(Protocol channelProtocol) {
	switch (channelProtocol) {
		case Protocol::FancyV1PostJoin: return MumbleProto::PCHAT_PROTOCOL_FANCY_V1_POST_JOIN;
		case Protocol::FancyV1FullArchive: return MumbleProto::PCHAT_PROTOCOL_FANCY_V1_FULL_ARCHIVE;
		case Protocol::ServerManaged: return MumbleProto::PCHAT_PROTOCOL_SERVER_MANAGED;
		case Protocol::SignalV1: return MumbleProto::PCHAT_PROTOCOL_SIGNAL_V1;
		default: return MumbleProto::PCHAT_PROTOCOL_NONE;
	}
}

// Convert a stored protocol string back to the protobuf enum.
// Unlike the handler's protocolName(), this preserves the exact protocol value
// and handles legacy string variants for backward compatibility.
static MumbleProto::PchatProtocol storedProtocolToProto(const std::string &s) {
	if (s == "SIGNAL_V1")
		return MumbleProto::PCHAT_PROTOCOL_SIGNAL_V1;
	if (s == "FANCY_V1_POST_JOIN" || s == "POST_JOIN")
		return MumbleProto::PCHAT_PROTOCOL_FANCY_V1_POST_JOIN;
	if (s == "FANCY_V1_FULL_ARCHIVE" || s == "FULL_ARCHIVE")
		return MumbleProto::PCHAT_PROTOCOL_FANCY_V1_FULL_ARCHIVE;
	if (s == "SERVER_MANAGED")
		return MumbleProto::PCHAT_PROTOCOL_SERVER_MANAGED;
	return MumbleProto::PCHAT_PROTOCOL_NONE;
}

PersistentChatManager::PersistentChatManager(msdb::PChatMessageTable &msgTable,
											 msdb::PChatUserKeysTable &keysTable,
											 msdb::PChatMemberJoinTable &joinTable,
											 msdb::PChatPendingKeyRequestsTable &pendingTable,
											 msdb::PChatKeyHoldersTable &holdersTable,
											 msdb::PChatOfflineQueueTable &queueTable,
											 IServerBridge &bridge,
											 IRateLimiter &rateLimiter,
											 Config config)
	: m_msgTable(msgTable), m_keysTable(keysTable), m_joinTable(joinTable), m_pendingTable(pendingTable),
	  m_holdersTable(holdersTable), m_queueTable(queueTable), m_bridge(bridge), m_rateLimiter(rateLimiter), m_config(config) {
	m_handlers[Protocol::FancyV1PostJoin] = std::make_unique< PostJoinProtocolHandler >(m_msgTable, m_joinTable);
	m_handlers[Protocol::FancyV1FullArchive] = std::make_unique< FullArchiveProtocolHandler >(m_msgTable);
	m_handlers[Protocol::ServerManaged] = std::make_unique< ServerManagedProtocolHandler >(m_msgTable);
	m_handlers[Protocol::SignalV1] = std::make_unique< SignalV1ProtocolHandler >(m_bridge);
}

// ---- Legacy PluginData dispatch (kept for backward compat) ----

bool PersistentChatManager::handlePluginData(unsigned int /*senderSession*/, const std::string &dataId,
											 const std::vector< uint8_t > & /*data*/) {
	// Legacy path: just check if this is a pchat message and consume it.
	// New Fancy clients use native proto messages directly (PchatMessage, PchatFetch, etc.)
	// which are dispatched by the msg* handlers in Messages.cpp.
	if (dataId.rfind("fancy-pchat-", 0) == 0) {
		qWarning("pchat: received legacy PluginData dataId=%s - ignoring (use native messages)",
				 dataId.c_str());
		return true; // consume but ignore
	}
	return false;
}

// ---- Helper: send ack ----

void PersistentChatManager::sendAck(unsigned int sessionId, const std::string &messageId,
									MumbleProto::PchatAckStatus status, const std::string &reason) {
	MumbleProto::PchatAck ack;
	ack.add_message_ids(messageId);
	ack.set_status(status);

	if (!reason.empty()) {
		ack.set_reason(reason);
	}

	m_bridge.sendPchatAck(sessionId, ack);
}

// ---- handlePchatMessage ----

void PersistentChatManager::handlePchatMessage(unsigned int senderSession, const MumbleProto::PchatMessage &msg) {
	if (!m_config.enabled) {
		return;
	}
	if (m_config.requireRegistration && !m_bridge.isUserRegistered(senderSession)) {
		return;
	}
	if (!m_rateLimiter.allow(std::to_string(senderSession), "msg")) {
		qWarning("pchat: rate-limited msg from session=%u", senderSession);
		return;
	}

	const auto serverNum = m_bridge.serverNum();
	const std::string senderHash = m_bridge.getCertHash(senderSession);
	const std::string messageId = msg.message_id();
	const unsigned int channelId = msg.channel_id();

	qWarning("pchat: handlePchatMessage session=%u hash=%s msgId=%s", senderSession, senderHash.c_str(), messageId.c_str());

	// Validate sender_hash matches session
	if (msg.sender_hash() != senderHash) {
		qWarning("pchat: REJECTED msgId=%s reason=sender_hash_mismatch (got=%s expected=%s)",
			   messageId.c_str(), msg.sender_hash().c_str(), senderHash.c_str());
		sendAck(senderSession, messageId, MumbleProto::PCHAT_ACK_REJECTED, "sender_hash_mismatch");
		return;
	}

	if (messageId.empty() || !msg.has_channel_id() || !msg.has_protocol()) {
		qWarning("pchat: REJECTED msgId=%s reason=missing_fields (id_empty=%d has_channel=%d has_protocol=%d)",
			   messageId.c_str(), messageId.empty(), msg.has_channel_id(), msg.has_protocol());
		sendAck(senderSession, messageId, MumbleProto::PCHAT_ACK_REJECTED, "missing_fields");
		return;
	}

	// Validate channel exists and has the claimed mode
	Protocol channelProtocol = m_bridge.getChannelPChatProtocol(channelId);
	if (channelProtocol == Protocol::None) {
		qWarning("pchat: REJECTED msgId=%s reason=channel_not_persistent channelId=%u",
			   messageId.c_str(), channelId);
		sendAck(senderSession, messageId, MumbleProto::PCHAT_ACK_REJECTED, "channel_not_persistent");
		return;
	}

	// Validate mode matches
	MumbleProto::PchatProtocol expectedMode = channelProtocolToProto(channelProtocol);
	if (msg.protocol() != expectedMode) {
		qWarning("pchat: REJECTED msgId=%s reason=protocol_mismatch (got=%d expected=%d)",
			   messageId.c_str(), msg.protocol(), expectedMode);
		sendAck(senderSession, messageId, MumbleProto::PCHAT_ACK_REJECTED, "protocol_mismatch");
		return;
	}

	// Check for envelope
	if (!msg.has_envelope()) {
		qWarning("pchat: REJECTED msgId=%s reason=missing_envelope", messageId.c_str());
		sendAck(senderSession, messageId, MumbleProto::PCHAT_ACK_REJECTED, "missing_envelope");
		return;
	}

	const std::string &payload = msg.envelope();
	if (payload.size() > static_cast< size_t >(m_config.maxPayloadSize)) {
		qWarning("pchat: REJECTED msgId=%s reason=payload_too_large (size=%zu max=%d)",
			   messageId.c_str(), payload.size(), m_config.maxPayloadSize);
		sendAck(senderSession, messageId, MumbleProto::PCHAT_ACK_REJECTED, "payload_too_large");
		return;
	}

	// Verify sender has passed the key-possession challenge for this channel
	if (!m_challengeState.contains(channelId)
		|| !m_challengeState.at(channelId).verifiedSessions.contains(senderSession)) {
		qWarning("pchat: REJECTED msgId=%s reason=key_challenge_not_passed session=%u channel=%u",
			   messageId.c_str(), senderSession, channelId);
		sendAck(senderSession, messageId, MumbleProto::PCHAT_ACK_REJECTED, "key_challenge_not_passed");
		return;
	}

	auto *handler = getHandler(channelProtocol);
	if (!handler) {
		sendAck(senderSession, messageId, MumbleProto::PCHAT_ACK_REJECTED, "unsupported_protocol");
		return;
	}

	int64_t clientTs = static_cast< int64_t >(msg.timestamp());
	int64_t serverTs = m_bridge.serverTimeMs();
	if (clientTs == 0) {
		clientTs = serverTs;
	}

	MessageContext ctx;
	ctx.serverNum     = serverNum;
	ctx.channelId     = channelId;
	ctx.senderHash    = senderHash;
	ctx.messageId     = messageId;
	ctx.clientTs      = clientTs;
	ctx.serverTs      = serverTs;
	ctx.protocol      = msg.protocol();
	ctx.payload       = msg.envelope();
	ctx.replacesId    = msg.has_replaces_id() ? std::optional< std::string >(msg.replaces_id()) : std::nullopt;

	StoreResult storeResult = handler->handleMessageStore(ctx);
	if (!storeResult.accepted) {
		qWarning("pchat: REJECTED msgId=%s reason=%s", messageId.c_str(), storeResult.rejectionReason.c_str());
		sendAck(senderSession, messageId, MumbleProto::PCHAT_ACK_REJECTED, storeResult.rejectionReason);
		return;
	}

	sendAck(senderSession, messageId, MumbleProto::PCHAT_ACK_STORED);

	// Relay to other Fancy clients in the channel
	MumbleProto::PchatMessageDeliver deliver;
	deliver.set_message_id(messageId);
	deliver.set_channel_id(channelId);
	deliver.set_timestamp(static_cast< uint64_t >(clientTs));
	deliver.set_sender_hash(senderHash);
	deliver.set_protocol(msg.protocol());
	deliver.set_envelope(msg.envelope());
	if (!storeResult.replacesId.empty()) {
		deliver.set_replaces_id(storeResult.replacesId);
	}

	// Relay to verified Fancy clients in the channel (skip unverified sessions
	// that cannot decrypt the message).
	if (m_challengeState.contains(channelId)) {
		for (unsigned int session : m_challengeState.at(channelId).verifiedSessions) {
			if (session == senderSession)
				continue;
			m_bridge.sendPchatMessageDeliver(session, deliver);
		}
	}

	// Enqueue for verified offline recipients (only for protocols that don't store server-side).
	if (handler && !handler->storesMessages()) {
		enqueueForOfflineRecipients(channelId, senderSession, deliver);
	}
}

// ---- handlePchatFetch ----

void PersistentChatManager::handlePchatFetch(unsigned int senderSession, const MumbleProto::PchatFetch &msg) {
	if (!m_config.enabled) {
		return;
	}
	if (m_config.requireRegistration && !m_bridge.isUserRegistered(senderSession)) {
		return;
	}
	if (!m_rateLimiter.allow(std::to_string(senderSession), "fetch")) {
		qWarning("pchat: rate-limited fetch from session=%u", senderSession);
		return;
	}

	const auto serverNum = m_bridge.serverNum();
	const std::string requesterHash = m_bridge.getCertHash(senderSession);
	const unsigned int channelId = msg.channel_id();
	const unsigned int limit = msg.has_limit() ? msg.limit() : 50u;

	qWarning("pchat: handlePchatFetch session=%u channel=%u limit=%u hash=%s",
		   senderSession, channelId, limit, requesterHash.c_str());

	if (!msg.has_channel_id()) {
		return;
	}

	// Only serve messages to sessions that have passed the key-possession challenge.
	if (!isSessionVerified(channelId, senderSession)) {
		qWarning("pchat: REJECTED fetch session=%u channel=%u reason=key_challenge_not_passed",
				 senderSession, channelId);
		return;
	}

	// Check channel access
	if (!m_bridge.hasEnterPermission(senderSession, channelId)) {
		return;
	}

	Protocol channelProtocol = m_bridge.getChannelPChatProtocol(channelId);
	if (channelProtocol == Protocol::None) {
		return;
	}

	auto *handler = getHandler(channelProtocol);
	if (!handler) {
		return;
	}

	FetchContext fetchCtx;
	fetchCtx.serverNum     = serverNum;
	fetchCtx.channelId     = channelId;
	fetchCtx.senderSession = senderSession;
	fetchCtx.requesterHash = requesterHash;
	fetchCtx.limit         = limit;
	fetchCtx.beforeId      = msg.has_before_id() ? msg.before_id() : "";

	FetchResult fetchResult = handler->handleFetch(fetchCtx);
	if (fetchResult.handled || fetchResult.rejected) {
		return;
	}

	auto result = m_msgTable.fetchMessages(serverNum, channelId, requesterHash, fetchCtx.beforeId,
										   std::min(limit, 100u), fetchResult.joinedAtTs);

	qWarning("pchat: fetchMessages returned %zu messages (hasMore=%d, totalStored=%u) for channel=%u session=%u",
			 result.messages.size(), result.hasMore ? 1 : 0, result.totalStored, channelId, senderSession);

	// Build response
	MumbleProto::PchatFetchResponse resp;
	resp.set_channel_id(channelId);
	resp.set_has_more(result.hasMore);
	resp.set_total_stored(result.totalStored);

	for (const auto &storedMsg : result.messages) {
		auto *m = resp.add_messages();
		m->set_message_id(storedMsg.messageId);
		m->set_channel_id(storedMsg.channelId);
		m->set_timestamp(static_cast< uint64_t >(storedMsg.timestamp));
		m->set_sender_hash(storedMsg.senderHash);
		// Convert stored protocol string back to exact enum value.
		m->set_protocol(storedProtocolToProto(storedMsg.protocol));
		m->set_envelope(storedMsg.payload);
		if (!storedMsg.replacesId.empty()) {
			m->set_replaces_id(storedMsg.replacesId);
		}
	}

	m_bridge.sendPchatFetchResponse(senderSession, resp);
}

// ---- handlePchatKeyAnnounce ----

void PersistentChatManager::handlePchatKeyAnnounce(unsigned int senderSession, const MumbleProto::PchatKeyAnnounce &msg) {
	if (!m_config.enabled) {
		return;
	}
	if (m_config.requireRegistration && !m_bridge.isUserRegistered(senderSession)) {
		return;
	}
	if (!m_rateLimiter.allow(std::to_string(senderSession), "key_announce")) {
		return;
	}

	const auto serverNum = m_bridge.serverNum();
	const std::string sessionCertHash = m_bridge.getCertHash(senderSession);

	// Validate cert_hash matches session
	if (msg.cert_hash() != sessionCertHash) {
		return;
	}

	// Validate algorithm_version
	if (!m_config.supportedAlgorithmVersions.empty()
		&& m_config.supportedAlgorithmVersions.find(msg.algorithm_version())
			   == m_config.supportedAlgorithmVersions.end()) {
		return;
	}

	// Anti-rollback: check existing timestamp
	auto existingKeys = m_keysTable.getKeys(serverNum, sessionCertHash);
	int64_t incomingTimestamp = static_cast< int64_t >(msg.timestamp());
	if (existingKeys.has_value() && existingKeys->updatedAt >= incomingTimestamp) {
		return;
	}

	// Store keys
	msdb::PChatUserKeys keys;
	keys.serverID         = serverNum;
	keys.certHash         = sessionCertHash;
	keys.algorithmVersion = static_cast< int >(msg.algorithm_version());
	keys.identityPublic   = msg.identity_public();
	keys.signingPublic    = msg.signing_public();
	keys.signature        = msg.signature();
	keys.updatedAt        = incomingTimestamp;

	m_keysTable.storeKeys(keys);

	// Send all previously stored public keys to the new client
	auto allKeys = m_keysTable.getAllKeys(serverNum);
	for (const auto &k : allKeys) {
		if (k.certHash == sessionCertHash) {
			continue;
		}

		MumbleProto::PchatKeyAnnounce keyMsg;
		keyMsg.set_algorithm_version(static_cast< uint32_t >(k.algorithmVersion));
		keyMsg.set_identity_public(k.identityPublic);
		keyMsg.set_signing_public(k.signingPublic);
		keyMsg.set_cert_hash(k.certHash);
		keyMsg.set_timestamp(static_cast< uint64_t >(k.updatedAt));
		keyMsg.set_signature(k.signature);

		m_bridge.sendPchatKeyAnnounce(senderSession, keyMsg);
	}

	// Broadcast the new client's public key to all other connected Fancy sessions
	m_bridge.broadcastPchatKeyAnnounce(msg, senderSession);
}

// ---- handlePchatKeyExchange ----

void PersistentChatManager::handlePchatKeyExchange(unsigned int senderSession, const MumbleProto::PchatKeyExchange &msg) {
	if (!m_config.enabled) {
		return;
	}
	if (m_config.requireRegistration && !m_bridge.isUserRegistered(senderSession)) {
		return;
	}
	if (!m_rateLimiter.allow(std::to_string(senderSession), "key_exchange")) {
		return;
	}

	const std::string sessionCertHash = m_bridge.getCertHash(senderSession);

	// Hard-validate sender_hash matches session
	if (msg.sender_hash() != sessionCertHash) {
		return;
	}

	if (!msg.has_recipient_hash() || msg.recipient_hash().empty()) {
		return;
	}

	// Relay tracking (if request_id is present)
	const auto serverNum = m_bridge.serverNum();
	if (msg.has_request_id() && !msg.request_id().empty()) {
		if (!m_pendingTable.recordRelay(serverNum, msg.request_id(), sessionCertHash)) {
			return; // Cap reached or duplicate sender
		}
	}

	// Look up recipient session
	unsigned int recipientSession = m_bridge.getSessionForCertHash(msg.recipient_hash());
	if (recipientSession == 0) {
		return; // recipient offline
	}

	// Forward to recipient
	m_bridge.sendPchatKeyExchange(recipientSession, msg);
}

// ---- handlePchatEpochCountersig ----

void PersistentChatManager::handlePchatEpochCountersig(unsigned int senderSession, const MumbleProto::PchatEpochCountersig &msg) {
	if (!m_config.enabled) {
		return;
	}

	const std::string sessionCertHash = m_bridge.getCertHash(senderSession);

	if (!msg.has_channel_id()) {
		return;
	}

	const unsigned int channelId = msg.channel_id();

	// Validate sender is a key custodian
	if (msg.signer_hash() != sessionCertHash) {
		return;
	}

	auto custodians = m_bridge.getChannelKeyCustodians(channelId);
	bool isCustodian = std::find(custodians.begin(), custodians.end(), sessionCertHash) != custodians.end();
	if (!isCustodian) {
		return;
	}

	// Validate timestamp freshness
	long long ts = static_cast< long long >(msg.timestamp());
	long long serverTime = m_bridge.serverTimeMs();
	if (std::abs(serverTime - ts) > 5000) {
		return;
	}

	// Broadcast to all other Fancy clients in the channel
	m_bridge.broadcastPchatEpochCountersig(channelId, msg, senderSession);
}

// ---- generateKeyRequest ----

void PersistentChatManager::generateKeyRequest(unsigned int channelId, const std::string &requesterHash,
											   const std::string &requesterPublic, IPchatProtocolHandler &handler) {
	const auto serverNum = m_bridge.serverNum();

	// Enforce per-user limit
	unsigned int userCount = m_pendingTable.countForUser(serverNum, requesterHash);
	if (userCount >= static_cast< unsigned int >(m_config.perUserPendingLimit)) {
		unsigned int requesterSession = m_bridge.getSessionForCertHash(requesterHash);
		if (requesterSession > 0) {
			sendAck(requesterSession, "", MumbleProto::PCHAT_ACK_REJECTED, "key_request_limit_exceeded");
		}
		return;
	}

	// Enforce per-channel soft cap with FIFO eviction
	unsigned int channelCount = m_pendingTable.countForChannel(serverNum, channelId);
	if (channelCount >= static_cast< unsigned int >(m_config.perChannelPendingSoftCap)) {
		m_pendingTable.evictOldest(serverNum, channelId);
	}

	unsigned int onlineMembers = m_bridge.countFancyClientsInChannel(channelId);
	unsigned int relayCap = handler.computeRelayCap(onlineMembers);

	std::string requestId = generateUUID();
	int64_t now = m_bridge.serverTimeMs();

	msdb::PChatPendingKeyRequest req;
	req.serverID        = serverNum;
	req.requestId       = requestId;
	req.channelId       = channelId;
	req.protocol        = handler.protocolName();
	req.requesterHash   = requesterHash;
	req.requesterPublic = requesterPublic;
	req.relayCap        = static_cast< int >(relayCap);
	req.relaysSent      = 0;
	req.createdAt       = now;

	m_pendingTable.createRequest(req);

	// Build and broadcast key request
	MumbleProto::PchatKeyRequest keyReq;
	keyReq.set_channel_id(channelId);
	keyReq.set_protocol(handler.keyRequestProtocol());
	keyReq.set_requester_hash(requesterHash);
	keyReq.set_requester_public(requesterPublic);
	keyReq.set_request_id(requestId);
	keyReq.set_timestamp(static_cast< uint64_t >(now));
	keyReq.set_relay_cap(relayCap);

	unsigned int requesterSession = m_bridge.getSessionForCertHash(requesterHash);
	m_bridge.broadcastPchatKeyRequest(channelId, keyReq, requesterSession);
}

// ---- onFancyClientJoinedChannel ----

void PersistentChatManager::onFancyClientJoinedChannel(unsigned int sessionId, unsigned int channelId) {
	if (!m_config.enabled) {
		return;
	}

	const auto serverNum = m_bridge.serverNum();
	const std::string certHash = m_bridge.getCertHash(sessionId);
	Protocol channelProtocol = m_bridge.getChannelPChatProtocol(channelId);

	qWarning("pchat: onFancyClientJoinedChannel session=%u channel=%u mode=%u hash=%s",
		   sessionId, channelId, static_cast< uint32_t >(channelProtocol), certHash.c_str());

	if (channelProtocol == Protocol::None) {
		return;
	}

	auto *handler = getHandler(channelProtocol);
	if (!handler) {
		return;
	}

	// Record member join for protocols that require it
	if (handler->recordsJoin()) {
		msdb::PChatMemberJoin join;
		join.serverID  = serverNum;
		join.channelId = channelId;
		join.certHash  = certHash;
		join.joinedAt  = m_bridge.serverTimeMs();
		join.epochAtJoin = 0;
		m_joinTable.recordJoin(join);
	}

	// Deliver pending key requests for this channel
	auto pendingRequests = m_pendingTable.getPendingRequests(serverNum, channelId);
	for (const auto &req : pendingRequests) {
		if (req.requesterHash == certHash) {
			continue;
		}

		MumbleProto::PchatKeyRequest keyReq;
		keyReq.set_channel_id(req.channelId);
		keyReq.set_protocol(storedProtocolToProto(req.protocol));
		keyReq.set_requester_hash(req.requesterHash);
		keyReq.set_requester_public(req.requesterPublic);
		keyReq.set_request_id(req.requestId);
		keyReq.set_timestamp(static_cast< uint64_t >(req.createdAt));
		keyReq.set_relay_cap(static_cast< uint32_t >(req.relayCap));

		m_bridge.sendPchatKeyRequest(sessionId, keyReq);
	}

	// If this user has keys announced, check if they need a key request generated
	auto userKeys = m_keysTable.getKeys(serverNum, certHash);
	if (userKeys.has_value()) {
		// Skip if the user is already a known key holder for this channel.
		if (m_holdersTable.isHolder(serverNum, channelId, certHash)) {
			qDebug("pchat: user %s is already a key holder for channel=%u, skipping key request",
				   certHash.c_str(), channelId);
		} else {
			auto existing = m_pendingTable.getPendingRequests(serverNum, channelId);
			bool hasPending = std::any_of(existing.begin(), existing.end(), [&](const auto &r) {
				return r.requesterHash == certHash;
			});

			if (!hasPending) {
				generateKeyRequest(channelId, certHash, userKeys->identityPublic, *handler);
			}
		}
	}
}

// ---- Channel removal / user disconnect ----

void PersistentChatManager::onUserDisconnected(unsigned int sessionId, const std::string &certHash) {
	if (!m_config.enabled || certHash.empty())
		return;

	const auto serverNum = m_bridge.serverNum();
	m_pendingTable.clearForRequester(serverNum, certHash);

	// Remove the disconnected session from all channel verified-sessions sets
	// so the session ID cannot be reused by a different user to bypass the challenge.
	for (auto &[chId, state] : m_challengeState) {
		state.verifiedSessions.erase(sessionId);
		state.pendingChallenges.erase(sessionId);
	}

	qDebug("pchat: cleared pending key requests and verified sessions for disconnected user session=%u cert_hash=%s",
		   sessionId, certHash.c_str());
}

void PersistentChatManager::onPersistentChannelCreated(unsigned int channelId, unsigned int creatorSession) {
	if (!m_config.enabled)
		return;

	auto &state = m_challengeState[channelId];
	state.verifiedSessions.insert(creatorSession);

	qDebug("pchat: auto-verified creator session=%u for new persistent channel=%u",
		   creatorSession, channelId);
}

void PersistentChatManager::onChannelRemoved(unsigned int channelId) {
	const auto serverNum = m_bridge.serverNum();

	qWarning("pchat: clearing data for removed channel=%u server=%u", channelId, serverNum);

	m_msgTable.clearChannel(serverNum, channelId);
	m_joinTable.clearChannel(serverNum, channelId);
	m_pendingTable.clearChannel(serverNum, channelId);
	m_holdersTable.clearChannel(serverNum, channelId);
	m_queueTable.clearChannel(serverNum, channelId);
	m_challengeState.erase(channelId);
}

// ---- Cleanup / UUID ----

void PersistentChatManager::runCleanup() {
	const auto serverNum = m_bridge.serverNum();
	m_pendingTable.cleanupExpired(serverNum, m_config.pendingKeyRequestMaxDays);
	m_pendingTable.cleanupFulfilled(serverNum, m_config.pendingFulfilledMaxHours);
	// Remove corrupted key rows that were written before the hex-encoding fix.
	// Safe to call repeatedly -- only deletes rows with wrong decoded lengths.
	m_keysTable.cleanupCorruptedKeys(serverNum);

	// Expire old offline queue entries.
	if (m_config.offlineQueueMaxAgeDays > 0) {
		long long cutoffMs = m_bridge.serverTimeMs()
			- static_cast< long long >(m_config.offlineQueueMaxAgeDays) * 24LL * 3600LL * 1000LL;
		m_queueTable.deleteExpired(serverNum, cutoffMs);
	}
}

bool PersistentChatManager::isSessionVerified(unsigned int channelId, unsigned int sessionId) const {
	if (!m_challengeState.contains(channelId)) {
		return false;
	}
	return m_challengeState.at(channelId).verifiedSessions.contains(sessionId);
}

IPchatProtocolHandler *PersistentChatManager::getHandler(Protocol channelProtocol) {
	auto it = m_handlers.find(channelProtocol);
	if (it != m_handlers.end()) {
		return it->second.get();
	}
	return nullptr;
}

// ---- Offline queue: enqueue ----

void PersistentChatManager::enqueueForOfflineRecipients(unsigned int channelId, unsigned int senderSession,
														const MumbleProto::PchatMessageDeliver &deliver) {
	const auto serverNum = m_bridge.serverNum();

	// Get all known key holders for this channel.
	auto holders = m_holdersTable.getChannelHolders(serverNum, channelId);
	if (holders.empty()) {
		return;
	}

	const std::string senderHash = m_bridge.getCertHash(senderSession);
	int64_t now = m_bridge.serverTimeMs();

	// Serialize the PchatMessageDeliver proto to store as the envelope.
	std::string serialized;
	deliver.SerializeToString(&serialized);

	for (const auto &holder : holders) {
		// Skip the sender.
		if (holder.certHash == senderHash) {
			continue;
		}

		// Skip holders that are currently online and verified
		// (they already received the relay above).
		unsigned int holderSession = m_bridge.getSessionForCertHash(holder.certHash);
		if (holderSession != 0 && isSessionVerified(channelId, holderSession)) {
			continue;
		}

		// Enqueue for this offline/unverified holder.
		msdb::PChatOfflineQueueEntry entry;
		entry.serverID  = serverNum;
		entry.certHash  = holder.certHash;
		entry.channelId = channelId;
		entry.messageId = deliver.message_id();
		entry.senderHash = deliver.sender_hash();
		entry.timestamp = static_cast< long long >(deliver.timestamp());
		entry.envelope  = serialized;
		entry.createdAt = now;

		m_queueTable.enqueue(entry);

		// Enforce capacity limit (FIFO eviction).
		m_queueTable.enforceCapacity(serverNum, holder.certHash, channelId,
									 static_cast< unsigned int >(m_config.offlineQueueMaxCapacity));
	}
}

// ---- Offline queue: drain ----

void PersistentChatManager::drainOfflineQueue(unsigned int sessionId, unsigned int channelId,
											  const std::string &certHash) {
	const auto serverNum = m_bridge.serverNum();

	auto queued = m_queueTable.fetchQueue(serverNum, certHash, channelId);
	if (queued.empty()) {
		return;
	}

	qDebug("pchat: draining %zu offline-queued messages for cert_hash=%s channel=%u",
		   queued.size(), certHash.c_str(), channelId);

	MumbleProto::PchatOfflineQueueDrain drain;
	drain.set_channel_id(channelId);

	for (const auto &entry : queued) {
		// Deserialize the stored PchatMessageDeliver from the envelope.
		MumbleProto::PchatMessageDeliver deliver;
		if (!deliver.ParseFromString(entry.envelope)) {
			qWarning("pchat: failed to parse queued envelope msgId=%s - skipping",
					 entry.messageId.c_str());
			continue;
		}
		*drain.add_messages() = std::move(deliver);
	}

	if (drain.messages_size() > 0) {
		m_bridge.sendPchatOfflineQueueDrain(sessionId, drain);
	}
}

// ---- Offline queue: ack (client confirms receipt) ----

void PersistentChatManager::handlePchatAck(unsigned int senderSession, const MumbleProto::PchatAck &msg) {
	if (!m_config.enabled) {
		return;
	}

	// Only process acks that have a channel_id (offline queue acks).
	// Server-originated acks do not have channel_id and are not sent from clients.
	if (!msg.has_channel_id()) {
		return;
	}

	if (msg.message_ids_size() == 0) {
		return;
	}

	const unsigned int channelId = msg.channel_id();
	const std::string certHash = m_bridge.getCertHash(senderSession);
	const auto serverNum = m_bridge.serverNum();

	std::vector< std::string > ids(msg.message_ids().begin(), msg.message_ids().end());

	qDebug("pchat: offline queue ack from session=%u cert_hash=%s channel=%u ids=%d",
		   senderSession, certHash.c_str(), channelId, static_cast< int >(ids.size()));

	m_queueTable.deleteByIds(serverNum, certHash, channelId, ids);
}

std::string PersistentChatManager::generateUUID() {
	uint32_t parts[4];
	CryptographicRandom::fillBuffer(parts, sizeof(parts));

	uint32_t a = parts[0], b = parts[1], c = parts[2], d = parts[3];
	b = (b & 0xFFFF0FFF) | 0x00004000;
	c = (c & 0x3FFFFFFF) | 0x80000000;

	char buf[37];
	std::snprintf(buf, sizeof(buf), "%08x-%04x-%04x-%04x-%04x%08x",
				  a, (b >> 16) & 0xFFFF, b & 0xFFFF,
				  (c >> 16) & 0xFFFF, c & 0xFFFF, d);
	return std::string(buf);
}

// ---- Key holder tracking ----

void PersistentChatManager::broadcastKeyHoldersList(unsigned int channelId) {
	unsigned int serverNum = m_bridge.serverNum();
	auto holders = m_holdersTable.getChannelHolders(serverNum, channelId);

	MumbleProto::PchatKeyHoldersList response;
	response.set_channel_id(channelId);

	for (const auto &h : holders) {
		auto *entry = response.add_holders();
		entry->set_cert_hash(h.certHash);
		entry->set_name(h.lastKnownName.empty() ? h.certHash : h.lastKnownName);
	}

	auto channelIt = m_challengeState.find(channelId);
	if (channelIt == m_challengeState.end())
		return;

	for (unsigned int session : channelIt->second.verifiedSessions) {
		m_bridge.sendPchatKeyHoldersList(session, response);
	}
}

void PersistentChatManager::handleKeyOwnerTakeover(unsigned int senderSession, unsigned int channelId,
												   const std::string &certHash,
												   MumbleProto::PchatKeyHolderReport::KeyTakeoverMode mode) {
	if (!m_bridge.hasKeyOwnerPermission(senderSession, channelId)) {
		qWarning("pchat: takeover rejected - no KeyOwner permission session=%u channel=%u",
				 senderSession, channelId);
		m_bridge.sendPermissionDenied(senderSession, channelId,
									  static_cast< unsigned int >(ChanACL::KeyOwner));
		return;
	}

	const bool fullWipe = (mode == MumbleProto::PchatKeyHolderReport::FULL_WIPE);
	unsigned int serverNum = m_bridge.serverNum();

	qWarning("pchat: KeyOwner takeover (%s) - channel=%u by session=%u cert_hash=%s",
			 fullWipe ? "FULL_WIPE" : "KEY_ONLY",
			 channelId, senderSession, certHash.c_str());

	if (fullWipe) {
		m_msgTable.clearChannel(serverNum, channelId);
	}

	m_holdersTable.clearChannel(serverNum, channelId);

	m_challengeState.erase(channelId);

	msdb::PChatKeyHolder holder;
	holder.serverID      = serverNum;
	holder.channelId     = channelId;
	holder.certHash      = certHash;
	holder.lastKnownName = {};
	holder.reportedAt    = m_bridge.serverTimeMs();
	m_holdersTable.recordHolder(holder);

	auto &state = m_challengeState[channelId];
	state.sharedChallenge.resize(32);
	CryptographicRandom::fillBuffer(state.sharedChallenge.data(), static_cast< int >(state.sharedChallenge.size()));
	state.pendingChallenges[senderSession] = state.sharedChallenge;

	MumbleProto::PchatKeyChallenge challengeMsg;
	challengeMsg.set_channel_id(channelId);
	challengeMsg.set_challenge(std::string(state.sharedChallenge.begin(), state.sharedChallenge.end()));
	m_bridge.sendPchatKeyChallenge(senderSession, challengeMsg);

	MumbleProto::PchatKeyHoldersList response;
	response.set_channel_id(channelId);
	auto *entry = response.add_holders();
	entry->set_cert_hash(certHash);
	entry->set_name(certHash);
	m_bridge.sendPchatKeyHoldersList(senderSession, response);

	qDebug("pchat: takeover complete - channel=%u new sole holder=%s",
		   channelId, certHash.c_str());
}

void PersistentChatManager::handlePchatKeyHolderReport(unsigned int senderSession,
													   const MumbleProto::PchatKeyHolderReport &msg) {
	if (!m_config.enabled)
		return;

	if (!msg.has_channel_id() || !msg.has_cert_hash())
		return;

	unsigned int channelId = msg.channel_id();
	const std::string &certHash = msg.cert_hash();
	unsigned int serverNum = m_bridge.serverNum();

	if (msg.has_takeover_mode()) {
		handleKeyOwnerTakeover(senderSession, channelId, certHash, msg.takeover_mode());
		return;
	}

	// ---- Normal key holder report path ----

	// Look up the name for this cert hash from online users, or fall back to cert hash.
	unsigned int holderSession = m_bridge.getSessionForCertHash(certHash);
	std::string name;
	if (holderSession != 0) {
		name = m_bridge.getCertHash(holderSession); // reuse cert hash if no name lookup available
		// The bridge does not expose a username getter - we store the cert hash as last resort.
		// However, the query handler resolves online names on the fly.
	}

	msdb::PChatKeyHolder holder;
	holder.serverID      = serverNum;
	holder.channelId     = channelId;
	holder.certHash      = certHash;
	holder.lastKnownName = name;
	holder.reportedAt    = m_bridge.serverTimeMs();

	m_holdersTable.recordHolder(holder);

	// Fulfill the pending key request for this holder since they now have the key.
	m_pendingTable.fulfillForRequester(serverNum, channelId, certHash);

	// Protocols that use per-sender keys (e.g. Signal Sender Keys) instead of a
	// shared archive key cannot use the HMAC-based key-possession challenge.
	// Auto-verify the session and send a passed result directly.
	auto *handler = getHandler(m_bridge.getChannelPChatProtocol(channelId));
	if (handler && handler->autoVerifiesOnReport()) {
		auto &state = m_challengeState[channelId];
		state.verifiedSessions.insert(senderSession);

		MumbleProto::PchatKeyChallengeResult result;
		result.set_channel_id(channelId);
		result.set_passed(true);
		m_bridge.sendPchatKeyChallengeResult(senderSession, result);

		qDebug("pchat: key holder reported (auto-verified) - channel=%u cert_hash=%s by session=%u",
			   channelId, certHash.c_str(), senderSession);

		// Auto-fetch after verification so the client receives stored messages.
		MumbleProto::PchatFetch autoFetch;
		autoFetch.set_channel_id(channelId);
		autoFetch.set_limit(50);
		handlePchatFetch(senderSession, autoFetch);

		// Drain any offline-queued messages for this user/channel.
		drainOfflineQueue(senderSession, channelId, certHash);

		broadcastKeyHoldersList(channelId);
		return;
	}

	// Use a shared challenge nonce per channel so all key holders receive the same
	// nonce and their HMAC proofs are comparable.  Only generate a new nonce when
	// the channel has no challenge state yet (first report or after channel removal).
	auto &state = m_challengeState[channelId];
	if (state.sharedChallenge.empty()) {
		state.sharedChallenge.resize(32);
		CryptographicRandom::fillBuffer(state.sharedChallenge.data(), static_cast< int >(state.sharedChallenge.size()));
	}

	// Store the pending challenge for this session+channel.
	state.pendingChallenges[senderSession] = state.sharedChallenge;

	MumbleProto::PchatKeyChallenge challengeMsg;
	challengeMsg.set_channel_id(channelId);
	challengeMsg.set_challenge(std::string(state.sharedChallenge.begin(), state.sharedChallenge.end()));
	m_bridge.sendPchatKeyChallenge(senderSession, challengeMsg);

	qDebug("pchat: key holder reported - channel=%u cert_hash=%s by session=%u",
		   channelId, certHash.c_str(), senderSession);
}

void PersistentChatManager::handlePchatKeyHoldersQuery(unsigned int senderSession,
													   const MumbleProto::PchatKeyHoldersQuery &msg) {
	if (!m_config.enabled)
		return;

	if (!msg.has_channel_id())
		return;

	unsigned int channelId = msg.channel_id();
	unsigned int serverNum = m_bridge.serverNum();

	auto holders = m_holdersTable.getChannelHolders(serverNum, channelId);

	MumbleProto::PchatKeyHoldersList response;
	response.set_channel_id(channelId);

	for (const auto &h : holders) {
		auto *entry = response.add_holders();
		entry->set_cert_hash(h.certHash);

		// Prefer the online username if the user is currently connected.
		unsigned int session = m_bridge.getSessionForCertHash(h.certHash);
		if (session != 0) {
			// The bridge getCertHash returns the hash, not the name.
			// We store lastKnownName from the DB; the client resolves online names itself.
			entry->set_name(h.lastKnownName.empty() ? h.certHash : h.lastKnownName);
		} else {
			entry->set_name(h.lastKnownName.empty() ? h.certHash : h.lastKnownName);
		}
	}

	m_bridge.sendPchatKeyHoldersList(senderSession, response);

	qDebug("pchat: key holders query - channel=%u holders=%d requested by session=%u",
		   channelId, response.holders_size(), senderSession);
}


void PersistentChatManager::handlePchatKeyChallengeResponse(unsigned int senderSession,
																			   const MumbleProto::PchatKeyChallengeResponse &msg) {
	if (!m_config.enabled)
		return;

	if (!msg.has_channel_id() || !msg.has_proof())
		return;

	unsigned int channelId = msg.channel_id();
	const std::string &proof = msg.proof();

	// Look up the pending challenge for this session.
	auto channelIt = m_challengeState.find(channelId);
	if (channelIt == m_challengeState.end()) {
		qWarning("pchat: challenge response for channel %u but no challenge state", channelId);
		return;
	}

	auto &state = channelIt->second;
	auto pendingIt = state.pendingChallenges.find(senderSession);
	if (pendingIt == state.pendingChallenges.end()) {
		qWarning("pchat: challenge response from session %u but no pending challenge for channel %u",
				 senderSession, channelId);
		return;
	}

	// Remove the pending challenge (one-shot).
	state.pendingChallenges.erase(pendingIt);

	std::vector< uint8_t > proofBytes(proof.begin(), proof.end());

	MumbleProto::PchatKeyChallengeResult result;
	result.set_channel_id(channelId);

	if (state.referenceHmac.empty()) {
		// First prover sets the reference.
		state.referenceHmac = proofBytes;
		state.verifiedSessions.insert(senderSession);
		result.set_passed(true);
		qDebug("pchat: challenge for channel %u - first prover (session %u) set reference",
			   channelId, senderSession);
	} else if (state.referenceHmac == proofBytes) {
		// Proof matches.
		state.verifiedSessions.insert(senderSession);
		result.set_passed(true);
		qDebug("pchat: challenge for channel %u - session %u passed", channelId, senderSession);
	} else {
		// Proof does not match - the client holds a wrong key.
		result.set_passed(false);

		// Remove this user as a key holder since their key is invalid.
		std::string certHash = m_bridge.getCertHash(senderSession);
		if (!certHash.empty()) {
			m_holdersTable.removeHolder(m_bridge.serverNum(), channelId, certHash);
		}

		qWarning("pchat: challenge for channel %u - session %u FAILED (wrong key)",
				 channelId, senderSession);
	}

	m_bridge.sendPchatKeyChallengeResult(senderSession, result);

	// After successful verification, automatically deliver stored messages.
	// The client's initial PchatFetch was likely rejected before the challenge completed.
	if (result.passed()) {
		MumbleProto::PchatFetch autoFetch;
		autoFetch.set_channel_id(channelId);
		autoFetch.set_limit(50);
		handlePchatFetch(senderSession, autoFetch);

		// Drain any offline-queued messages for this user/channel.
		std::string certHash = m_bridge.getCertHash(senderSession);
		drainOfflineQueue(senderSession, channelId, certHash);
	}

	// Broadcast the current holders list to all verified sessions so every
	// client stays in sync (e.g. after a takeover cleared the old list and
	// new holders gradually reconnect).
	broadcastKeyHoldersList(channelId);
}

// ---- handlePchatDeleteMessages ----

void PersistentChatManager::handlePchatDeleteMessages(unsigned int senderSession, const MumbleProto::PchatDeleteMessages &msg) {
	if (!m_config.enabled) {
		return;
	}

	if (!msg.has_channel_id()) {
		qWarning("pchat: deleteMessages rejected - missing channel_id session=%u", senderSession);
		return;
	}

	const unsigned int channelId = msg.channel_id();
	const auto serverNum = m_bridge.serverNum();

	// Permission check: DeleteMessage
	if (!m_bridge.hasDeleteMessagePermission(senderSession, channelId)) {
		qWarning("pchat: deleteMessages rejected - no permission session=%u channel=%u", senderSession, channelId);
		return;
	}

	// Verify channel is persistent
	Protocol channelProtocol = m_bridge.getChannelPChatProtocol(channelId);
	if (channelProtocol == Protocol::None) {
		qWarning("pchat: deleteMessages rejected - channel not persistent session=%u channel=%u", senderSession, channelId);
		return;
	}

	unsigned int deletedCount = 0;
	std::vector< std::string > deletedIds;

	if (msg.message_ids_size() > 0) {
		std::vector< std::string > ids(msg.message_ids().begin(), msg.message_ids().end());
		deletedCount += m_msgTable.deleteByIds(serverNum, channelId, ids);
		deletedIds.insert(deletedIds.end(), ids.begin(), ids.end());
	}

	if (msg.has_time_range()) {
		const auto &tr = msg.time_range();
		long long fromMs = tr.has_from() ? static_cast< long long >(tr.from()) : 0;
		long long toMs = tr.has_to() ? static_cast< long long >(tr.to()) : std::numeric_limits< long long >::max();
		deletedCount += m_msgTable.deleteByTimeRange(serverNum, channelId, fromMs, toMs);
	}

	if (msg.has_sender_hash()) {
		deletedCount += m_msgTable.deleteBySender(serverNum, channelId, msg.sender_hash());
	}

	qWarning("pchat: deleted %u messages in channel=%u by session=%u", deletedCount, channelId, senderSession);

	// Send ack to requester
	MumbleProto::PchatAck ack;
	ack.set_status(MumbleProto::PCHAT_ACK_DELETED);
	for (const auto &id : deletedIds) {
		ack.add_message_ids(id);
	}
	ack.set_reason(std::to_string(deletedCount));
	m_bridge.sendPchatAck(senderSession, ack);

	// Broadcast deletion to other Fancy clients in the channel
	m_bridge.broadcastPchatDeleteMessages(channelId, msg, senderSession);
}
} // namespace pchat
