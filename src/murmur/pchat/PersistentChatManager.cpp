// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "PersistentChatManager.h"

#include "database/PChatMemberJoinTable.h"
#include "database/PChatMessageTable.h"
#include "database/PChatPendingKeyRequestsTable.h"
#include "database/PChatUserKeysTable.h"
#include "database/PChatKeyHoldersTable.h"

#include <QDebug>

#include <algorithm>
#include <chrono>
#include <random>

namespace msdb = ::mumble::server::db;

namespace pchat {

// Helper to convert ChannelState pchat_mode (1=POST_JOIN, 2=FULL_ARCHIVE) to proto enum
static MumbleProto::PchatPersistenceMode channelModeToPersistenceMode(uint32_t channelMode) {
	return (channelMode == 1) ? MumbleProto::PCHAT_MODE_POST_JOIN : MumbleProto::PCHAT_MODE_FULL_ARCHIVE;
}

static std::string persistenceModeToString(MumbleProto::PchatPersistenceMode mode) {
	return (mode == MumbleProto::PCHAT_MODE_POST_JOIN) ? "POST_JOIN" : "FULL_ARCHIVE";
}

PersistentChatManager::PersistentChatManager(msdb::PChatMessageTable &msgTable,
											 msdb::PChatUserKeysTable &keysTable,
											 msdb::PChatMemberJoinTable &joinTable,
											 msdb::PChatPendingKeyRequestsTable &pendingTable,
											 msdb::PChatKeyHoldersTable &holdersTable,
											 IServerBridge &bridge,
											 IRateLimiter &rateLimiter,
											 Config config)
	: m_msgTable(msgTable), m_keysTable(keysTable), m_joinTable(joinTable), m_pendingTable(pendingTable),
	  m_holdersTable(holdersTable), m_bridge(bridge), m_rateLimiter(rateLimiter), m_config(config) {}

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
									const std::string &status, const std::string &reason) {
	MumbleProto::PchatAck ack;
	ack.set_message_id(messageId);

	if (status == "stored") {
		ack.set_status(MumbleProto::PCHAT_ACK_STORED);
	} else if (status == "quota_exceeded") {
		ack.set_status(MumbleProto::PCHAT_ACK_QUOTA_EXCEEDED);
	} else {
		ack.set_status(MumbleProto::PCHAT_ACK_REJECTED);
	}

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
		sendAck(senderSession, messageId, "rejected", "sender_hash_mismatch");
		return;
	}

	if (messageId.empty() || !msg.has_channel_id() || !msg.has_mode()) {
		qWarning("pchat: REJECTED msgId=%s reason=missing_fields (id_empty=%d has_channel=%d has_mode=%d)",
			   messageId.c_str(), messageId.empty(), msg.has_channel_id(), msg.has_mode());
		sendAck(senderSession, messageId, "rejected", "missing_fields");
		return;
	}

	// Validate channel exists and has the claimed mode
	uint32_t channelMode = m_bridge.getChannelPChatMode(channelId);
	if (channelMode == 0) {
		qWarning("pchat: REJECTED msgId=%s reason=channel_not_persistent channelId=%u",
			   messageId.c_str(), channelId);
		sendAck(senderSession, messageId, "rejected", "channel_not_persistent");
		return;
	}

	// Validate mode matches
	MumbleProto::PchatPersistenceMode expectedMode = channelModeToPersistenceMode(channelMode);
	if (msg.mode() != expectedMode) {
		qWarning("pchat: REJECTED msgId=%s reason=mode_mismatch (got=%d expected=%d)",
			   messageId.c_str(), msg.mode(), expectedMode);
		sendAck(senderSession, messageId, "rejected", "mode_mismatch");
		return;
	}

	// Check for envelope
	if (!msg.has_envelope()) {
		qWarning("pchat: REJECTED msgId=%s reason=missing_envelope", messageId.c_str());
		sendAck(senderSession, messageId, "rejected", "missing_envelope");
		return;
	}

	const std::string &payload = msg.envelope();
	if (payload.size() > static_cast< size_t >(m_config.maxPayloadSize)) {
		qWarning("pchat: REJECTED msgId=%s reason=payload_too_large (size=%zu max=%d)",
			   messageId.c_str(), payload.size(), m_config.maxPayloadSize);
		sendAck(senderSession, messageId, "rejected", "payload_too_large");
		return;
	}

	// Verify sender has passed the key-possession challenge for this channel
	if (!m_challengeState.contains(channelId)
		|| !m_challengeState.at(channelId).verifiedSessions.contains(senderSession)) {
		qWarning("pchat: REJECTED msgId=%s reason=key_challenge_not_passed session=%u channel=%u",
			   messageId.c_str(), senderSession, channelId);
		sendAck(senderSession, messageId, "rejected", "key_challenge_not_passed");
		return;
	}

	// Check for duplicate
	if (m_msgTable.messageExists(serverNum, channelId, senderHash, messageId)) {
		qWarning("pchat: REJECTED msgId=%s reason=duplicate", messageId.c_str());
		sendAck(senderSession, messageId, "rejected", "duplicate");
		return;
	}

	// Handle replaces_id
	std::string replacesId;
	if (msg.has_replaces_id()) {
		replacesId = msg.replaces_id();
		if (!replacesId.empty() && m_msgTable.messageExists(serverNum, channelId, senderHash, replacesId)) {
			m_msgTable.markSuperseded(serverNum, channelId, senderHash, replacesId, messageId);
		}
	}

	uint64_t clientTs = msg.timestamp();
	int64_t serverTs = m_bridge.serverTimeMs();
	if (clientTs == 0) {
		clientTs = static_cast< uint64_t >(serverTs);
	}

	const std::string mode = persistenceModeToString(msg.mode());

	msdb::PChatStoredMessage storedMsg;
	storedMsg.serverID    = serverNum;
	storedMsg.messageId   = messageId;
	storedMsg.channelId   = channelId;
	storedMsg.timestamp   = static_cast< long long >(clientTs);
	storedMsg.senderHash  = senderHash;
	storedMsg.mode        = mode;
	storedMsg.payload     = payload;
	storedMsg.payloadSize = static_cast< int >(payload.size());
	storedMsg.replacesId  = replacesId;
	storedMsg.createdAt   = serverTs;

	if (!m_msgTable.storeMessage(storedMsg)) {
		qWarning("pchat: REJECTED msgId=%s reason=store_failed", messageId.c_str());
		sendAck(senderSession, messageId, "rejected", "store_failed");
		return;
	}

	qWarning("pchat: stored msg id=%s in channel=%u from hash=%s (payload=%zu bytes)",
		   messageId.c_str(), channelId, senderHash.c_str(), payload.size());
	sendAck(senderSession, messageId, "stored");

	// Relay to other Fancy clients in the channel
	MumbleProto::PchatMessageDeliver deliver;
	deliver.set_message_id(messageId);
	deliver.set_channel_id(channelId);
	deliver.set_timestamp(clientTs);
	deliver.set_sender_hash(senderHash);
	deliver.set_mode(msg.mode());
	deliver.set_envelope(payload);
	if (!replacesId.empty()) {
		deliver.set_replaces_id(replacesId);
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

	uint32_t channelMode = m_bridge.getChannelPChatMode(channelId);
	if (channelMode == 0) {
		return;
	}

	// Mode-based filtering: POST_JOIN uses joined_at timestamp
	long long joinedAtTs = 0;
	if (channelMode == 1) { // POST_JOIN
		auto joinRecord = m_joinTable.getJoinRecord(serverNum, channelId, requesterHash);
		if (!joinRecord.has_value()) {
			return;
		}
		joinedAtTs = joinRecord->joinedAt;
	}

	std::string beforeId;
	if (msg.has_before_id()) {
		beforeId = msg.before_id();
	}

	auto result = m_msgTable.fetchMessages(serverNum, channelId, requesterHash, beforeId,
										   std::min(limit, 100u), joinedAtTs);

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
		// Convert stored mode string back to enum
		if (storedMsg.mode == "POST_JOIN") {
			m->set_mode(MumbleProto::PCHAT_MODE_POST_JOIN);
		} else {
			m->set_mode(MumbleProto::PCHAT_MODE_FULL_ARCHIVE);
		}
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
	if (msg.algorithm_version() != 1) {
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
											   const std::string &requesterPublic, const std::string &mode) {
	const auto serverNum = m_bridge.serverNum();

	// Enforce per-user limit
	unsigned int userCount = m_pendingTable.countForUser(serverNum, requesterHash);
	if (userCount >= static_cast< unsigned int >(m_config.perUserPendingLimit)) {
		unsigned int requesterSession = m_bridge.getSessionForCertHash(requesterHash);
		if (requesterSession > 0) {
			sendAck(requesterSession, "", "rejected", "key_request_limit_exceeded");
		}
		return;
	}

	// Enforce per-channel soft cap with FIFO eviction
	unsigned int channelCount = m_pendingTable.countForChannel(serverNum, channelId);
	if (channelCount >= static_cast< unsigned int >(m_config.perChannelPendingSoftCap)) {
		m_pendingTable.evictOldest(serverNum, channelId);
	}

	// Determine relay_cap
	unsigned int relayCap;
	if (mode == "POST_JOIN") {
		relayCap = 3;
	} else {
		unsigned int onlineMembers = m_bridge.countFancyClientsInChannel(channelId);
		unsigned int base = onlineMembers / 2;
		relayCap = std::clamp(base, 1u, 5u) + 2;
	}

	std::string requestId = generateUUID();
	int64_t now = m_bridge.serverTimeMs();

	msdb::PChatPendingKeyRequest req;
	req.serverID        = serverNum;
	req.requestId       = requestId;
	req.channelId       = channelId;
	req.mode            = mode;
	req.requesterHash   = requesterHash;
	req.requesterPublic = requesterPublic;
	req.relayCap        = static_cast< int >(relayCap);
	req.relaysSent      = 0;
	req.createdAt       = now;

	m_pendingTable.createRequest(req);

	// Build and broadcast key request
	MumbleProto::PchatKeyRequest keyReq;
	keyReq.set_channel_id(channelId);
	keyReq.set_mode((mode == "POST_JOIN") ? MumbleProto::PCHAT_MODE_POST_JOIN : MumbleProto::PCHAT_MODE_FULL_ARCHIVE);
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
	uint32_t channelMode = m_bridge.getChannelPChatMode(channelId);

	qWarning("pchat: onFancyClientJoinedChannel session=%u channel=%u mode=%u hash=%s",
		   sessionId, channelId, channelMode, certHash.c_str());

	if (channelMode == 0) {
		return;
	}

	// Record member join for POST_JOIN mode
	if (channelMode == 1) {
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
		keyReq.set_mode((req.mode == "POST_JOIN") ? MumbleProto::PCHAT_MODE_POST_JOIN : MumbleProto::PCHAT_MODE_FULL_ARCHIVE);
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
				const std::string mode = (channelMode == 1) ? "POST_JOIN" : "FULL_ARCHIVE";
				generateKeyRequest(channelId, certHash, userKeys->identityPublic, mode);
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
}

bool PersistentChatManager::isSessionVerified(unsigned int channelId, unsigned int sessionId) const {
	if (!m_challengeState.contains(channelId)) {
		return false;
	}
	return m_challengeState.at(channelId).verifiedSessions.contains(sessionId);
}

std::string PersistentChatManager::generateUUID() {
	static std::random_device rd;
	static std::mt19937 gen(rd());
	static std::uniform_int_distribution< uint32_t > dist(0, 0xFFFFFFFF);

	auto r = [&]() { return dist(gen); };

	uint32_t a = r(), b = r(), c = r(), d = r();
	b = (b & 0xFFFF0FFF) | 0x00004000;
	c = (c & 0x3FFFFFFF) | 0x80000000;

	char buf[37];
	std::snprintf(buf, sizeof(buf), "%08x-%04x-%04x-%04x-%04x%08x",
				  a, (b >> 16) & 0xFFFF, b & 0xFFFF,
				  (c >> 16) & 0xFFFF, c & 0xFFFF, d);
	return std::string(buf);
}

// ---- Key holder tracking ----

void PersistentChatManager::handlePchatKeyHolderReport(unsigned int senderSession,
													   const MumbleProto::PchatKeyHolderReport &msg) {
	if (!m_config.enabled)
		return;

	if (!msg.has_channel_id() || !msg.has_cert_hash())
		return;

	unsigned int channelId = msg.channel_id();
	const std::string &certHash = msg.cert_hash();
	unsigned int serverNum = m_bridge.serverNum();

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

	// Use a shared challenge nonce per channel so all key holders receive the same
	// nonce and their HMAC proofs are comparable.  Only generate a new nonce when
	// the channel has no challenge state yet (first report or after channel removal).
	auto &state = m_challengeState[channelId];
	if (state.sharedChallenge.empty()) {
		state.sharedChallenge.resize(32);
		std::random_device rd;
		std::mt19937 gen(rd());
		std::uniform_int_distribution< int > dist(0, 255);
		for (auto &b : state.sharedChallenge) {
			b = static_cast< uint8_t >(dist(gen));
		}
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
	}
}
} // namespace pchat
