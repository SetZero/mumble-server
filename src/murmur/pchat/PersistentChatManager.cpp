// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "PersistentChatManager.h"

#include "database/PChatMemberJoinTable.h"
#include "database/PChatMessageTable.h"
#include "database/PChatPendingKeyRequestsTable.h"
#include "database/PChatUserKeysTable.h"

#include <nlohmann/json.hpp>

#include <QDebug>

#include <algorithm>
#include <chrono>
#include <random>

using json = nlohmann::json;
namespace msdb = ::mumble::server::db;

namespace pchat {

static constexpr const char *PCHAT_MSG              = "fancy-pchat-msg";
static constexpr const char *PCHAT_FETCH            = "fancy-pchat-fetch";
static constexpr const char *PCHAT_KEY_ANNOUNCE     = "fancy-pchat-key-announce";
static constexpr const char *PCHAT_KEY_EXCHANGE     = "fancy-pchat-key-exchange";
static constexpr const char *PCHAT_EPOCH_COUNTERSIG = "fancy-pchat-epoch-countersig";
static constexpr const char *PCHAT_MSG_DELIVER      = "fancy-pchat-msg-deliver";
static constexpr const char *PCHAT_FETCH_RESP       = "fancy-pchat-fetch-resp";
static constexpr const char *PCHAT_KEY_REQUEST      = "fancy-pchat-key-request";
static constexpr const char *PCHAT_ACK              = "fancy-pchat-ack";

PersistentChatManager::PersistentChatManager(msdb::PChatMessageTable &msgTable,
											 msdb::PChatUserKeysTable &keysTable,
											 msdb::PChatMemberJoinTable &joinTable,
											 msdb::PChatPendingKeyRequestsTable &pendingTable,
											 IServerBridge &bridge,
											 IRateLimiter &rateLimiter,
											 Config config)
	: m_msgTable(msgTable), m_keysTable(keysTable), m_joinTable(joinTable), m_pendingTable(pendingTable),
	  m_bridge(bridge), m_rateLimiter(rateLimiter), m_config(config) {}

bool PersistentChatManager::handlePluginData(unsigned int senderSession, const std::string &dataId,
											 const std::vector< uint8_t > &data) {
	if (!m_config.enabled) {
		qDebug("pchat: disabled, ignoring dataId=%s from session=%u", dataId.c_str(), senderSession);
		return false;
	}

	// Check if this is a pchat message
	if (dataId.rfind("fancy-pchat-", 0) != 0) {
		return false;
	}

	qDebug("pchat: received dataId=%s from session=%u (dataSize=%zu)", dataId.c_str(), senderSession, data.size());

	// Check registration requirement
	if (m_config.requireRegistration && !m_bridge.isUserRegistered(senderSession)) {
		qWarning("pchat: rejecting dataId=%s from unregistered session=%u (requireRegistration=true)",
				 dataId.c_str(), senderSession);
		return true; // Silently consume - unregistered users cannot use pchat
	}

	if (dataId == PCHAT_MSG) {
		handleMsg(senderSession, data);
	} else if (dataId == PCHAT_FETCH) {
		handleFetch(senderSession, data);
	} else if (dataId == PCHAT_KEY_ANNOUNCE) {
		handleKeyAnnounce(senderSession, data);
	} else if (dataId == PCHAT_KEY_EXCHANGE) {
		handleKeyExchange(senderSession, data);
	} else if (dataId == PCHAT_EPOCH_COUNTERSIG) {
		handleEpochCountersig(senderSession, data);
	} else {
		qDebug("pchat: unknown pchat dataId=%s from session=%u, consuming", dataId.c_str(), senderSession);
		return true;
	}

	return true;
}

void PersistentChatManager::handleMsg(unsigned int senderSession, const std::vector< uint8_t > &data) {
	if (!m_rateLimiter.allow(std::to_string(senderSession), "msg")) {
		qDebug("pchat: rate-limited msg from session=%u", senderSession);
		return;
	}

	json j;
	try {
		j = json::from_msgpack(data);
	} catch (const json::exception &e) {
		qWarning("pchat: failed to parse msgpack from session=%u: %s", senderSession, e.what());
		return;
	}

	const auto serverNum = m_bridge.serverNum();
	const std::string senderHash = m_bridge.getCertHash(senderSession);
	qDebug("pchat: handleMsg session=%u hash=%s", senderSession, senderHash.c_str());

	// Validate sender_hash matches session
	if (!j.contains("sender_hash") || j["sender_hash"].get< std::string >() != senderHash) {
		sendAck(senderSession, j.value("message_id", ""), "rejected", "sender_hash_mismatch");
		return;
	}

	const std::string messageId = j.value("message_id", "");
	const unsigned int channelId = j.value("channel_id", 0u);
	const std::string mode = j.value("mode", "");

	if (messageId.empty() || channelId == 0 || mode.empty()) {
		sendAck(senderSession, messageId, "rejected", "missing_fields");
		return;
	}

	// Validate channel exists and has the claimed mode
	uint32_t channelMode = m_bridge.getChannelPChatMode(channelId);
	qDebug("pchat: handleMsg channelId=%u channelMode=%u msgMode=%s msgId=%s",
		   channelId, channelMode, mode.c_str(), messageId.c_str());
	if (channelMode == 0) {
		qWarning("pchat: rejected msg from session=%u - channel %u is not persistent (mode=0)",
				 senderSession, channelId);
		sendAck(senderSession, messageId, "rejected", "channel_not_persistent");
		return;
	}

	// Validate mode matches
	const std::string expectedMode = (channelMode == 1) ? "POST_JOIN" : "FULL_ARCHIVE";
	if (mode != expectedMode) {
		qWarning("pchat: rejected msg - mode mismatch: expected=%s got=%s channelId=%u",
				 expectedMode.c_str(), mode.c_str(), channelId);
		sendAck(senderSession, messageId, "rejected", "mode_mismatch");
		return;
	}

	// Check for envelope
	if (!j.contains("envelope")) {
		sendAck(senderSession, messageId, "rejected", "missing_envelope");
		return;
	}

	// Get the envelope as raw bytes
	std::string payload;
	if (j["envelope"].is_binary()) {
		auto bin = j["envelope"].get_binary();
		payload.assign(bin.begin(), bin.end());
	} else if (j["envelope"].is_string()) {
		payload = j["envelope"].get< std::string >();
	} else {
		sendAck(senderSession, messageId, "rejected", "invalid_envelope");
		return;
	}

	if (static_cast< int >(payload.size()) > m_config.maxPayloadSize) {
		sendAck(senderSession, messageId, "rejected", "payload_too_large");
		return;
	}

	// Check for duplicate
	if (m_msgTable.messageExists(serverNum, channelId, senderHash, messageId)) {
		sendAck(senderSession, messageId, "rejected", "duplicate");
		return;
	}

	// Handle replaces_id
	std::string replacesId;
	if (j.contains("replaces_id") && !j["replaces_id"].is_null()) {
		replacesId = j["replaces_id"].get< std::string >();
		// Verify the original message belongs to the same sender
		if (!replacesId.empty() && m_msgTable.messageExists(serverNum, channelId, senderHash, replacesId)) {
			m_msgTable.markSuperseded(serverNum, channelId, senderHash, replacesId, messageId);
		}
		// If original doesn't exist (e.g. purged by retention), accept normally
	}

	// Use server timestamp (override mode)
	long long serverTs = m_bridge.serverTimeMs();

	msdb::PChatStoredMessage storedMsg;
	storedMsg.serverID    = serverNum;
	storedMsg.messageId   = messageId;
	storedMsg.channelId   = channelId;
	storedMsg.timestamp   = serverTs;
	storedMsg.senderHash  = senderHash;
	storedMsg.mode        = mode;
	storedMsg.payload     = payload;
	storedMsg.payloadSize = static_cast< int >(payload.size());
	storedMsg.replacesId  = replacesId;
	storedMsg.createdAt   = serverTs;

	if (!m_msgTable.storeMessage(storedMsg)) {
		qWarning("pchat: failed to store msg id=%s in channel=%u from hash=%s",
				 messageId.c_str(), channelId, senderHash.c_str());
		sendAck(senderSession, messageId, "rejected", "store_failed");
		return;
	}

	qDebug("pchat: stored msg id=%s in channel=%u from hash=%s (payload=%d bytes)",
		   messageId.c_str(), channelId, senderHash.c_str(), static_cast< int >(payload.size()));
	sendAck(senderSession, messageId, "stored");

	// Relay to other Fancy clients in the channel
	json deliver;
	deliver["message_id"]   = messageId;
	deliver["channel_id"]   = channelId;
	deliver["timestamp"]    = serverTs;
	deliver["sender_hash"]  = senderHash;
	deliver["mode"]         = mode;
	deliver["envelope"]     = j["envelope"];
	if (!replacesId.empty()) {
		deliver["replaces_id"] = replacesId;
	}

	auto deliverData = json::to_msgpack(deliver);
	m_bridge.broadcastPluginDataToFancyClients(channelId, PCHAT_MSG_DELIVER, deliverData, senderSession);
}

void PersistentChatManager::handleFetch(unsigned int senderSession, const std::vector< uint8_t > &data) {
	if (!m_rateLimiter.allow(std::to_string(senderSession), "fetch")) {
		qDebug("pchat: rate-limited fetch from session=%u", senderSession);
		return;
	}

	json j;
	try {
		j = json::from_msgpack(data);
	} catch (const json::exception &e) {
		qWarning("pchat: failed to parse fetch msgpack from session=%u: %s", senderSession, e.what());
		return;
	}

	const auto serverNum = m_bridge.serverNum();
	const std::string requesterHash = m_bridge.getCertHash(senderSession);
	const unsigned int channelId = j.value("channel_id", 0u);
	const unsigned int limit = j.value("limit", 50u);

	qDebug("pchat: handleFetch session=%u channel=%u limit=%u hash=%s",
		   senderSession, channelId, limit, requesterHash.c_str());

	if (channelId == 0) {
		qWarning("pchat: fetch rejected - channelId=0 from session=%u", senderSession);
		return;
	}

	// Check channel access
	if (!m_bridge.hasEnterPermission(senderSession, channelId)) {
		qDebug("pchat: fetch rejected - no Enter permission session=%u channel=%u", senderSession, channelId);
		return;
	}

	uint32_t channelMode = m_bridge.getChannelPChatMode(channelId);
	if (channelMode == 0) {
		qDebug("pchat: fetch rejected - channel %u has pchat_mode=0", channelId);
		return;
	}

	// Mode-based filtering: POST_JOIN uses joined_at timestamp
	long long joinedAtTs = 0;
	if (channelMode == 1) { // POST_JOIN
		auto joinRecord = m_joinTable.getJoinRecord(serverNum, channelId, requesterHash);
		if (!joinRecord.has_value()) {
			// User hasn't joined this channel in POST_JOIN mode
			return;
		}
		joinedAtTs = joinRecord->joinedAt;
	}

	std::string beforeId;
	if (j.contains("before_id") && !j["before_id"].is_null()) {
		beforeId = j["before_id"].get< std::string >();
	}

	auto result = m_msgTable.fetchMessages(serverNum, channelId, requesterHash, beforeId,
										   std::min(limit, 100u), joinedAtTs);

	// Build response
	json resp;
	resp["channel_id"] = channelId;
	resp["has_more"]   = result.hasMore;
	resp["total_stored"] = result.totalStored;

	json messages = json::array();
	for (const auto &msg : result.messages) {
		json m;
		m["message_id"]  = msg.messageId;
		m["channel_id"]  = msg.channelId;
		m["timestamp"]   = msg.timestamp;
		m["sender_hash"] = msg.senderHash;
		m["mode"]        = msg.mode;
		// Store payload as binary
		m["envelope"]    = json::binary_t(std::vector< uint8_t >(msg.payload.begin(), msg.payload.end()));
		if (!msg.replacesId.empty()) {
			m["replaces_id"] = msg.replacesId;
		}
		messages.push_back(std::move(m));
	}
	resp["messages"] = std::move(messages);

	auto respData = json::to_msgpack(resp);
	m_bridge.sendPluginData(senderSession, PCHAT_FETCH_RESP, respData);
}

void PersistentChatManager::handleKeyAnnounce(unsigned int senderSession, const std::vector< uint8_t > &data) {
	if (!m_rateLimiter.allow(std::to_string(senderSession), "key_announce")) {
		return;
	}

	json j;
	try {
		j = json::from_msgpack(data);
	} catch (const json::exception &) {
		return;
	}

	const auto serverNum = m_bridge.serverNum();
	const std::string sessionCertHash = m_bridge.getCertHash(senderSession);

	// Validate cert_hash matches session
	const std::string certHash = j.value("cert_hash", "");
	if (certHash != sessionCertHash) {
		return; // Reject - cannot register keys under another user's identity
	}

	// Validate algorithm_version
	int algVersion = j.value("algorithm_version", 0);
	if (algVersion != 1) {
		return; // Only version 1 (X25519 + Ed25519) is supported
	}

	// Anti-rollback: check existing timestamp
	auto existingKeys = m_keysTable.getKeys(serverNum, certHash);
	long long incomingTimestamp = j.value("timestamp", 0LL);
	if (existingKeys.has_value() && existingKeys->updatedAt >= incomingTimestamp) {
		return; // Reject replay / rollback
	}

	// Extract public keys
	std::string identityPublic, signingPublic, signature;
	if (j.contains("identity_public") && j["identity_public"].is_binary()) {
		auto bin = j["identity_public"].get_binary();
		identityPublic.assign(bin.begin(), bin.end());
	}
	if (j.contains("signing_public") && j["signing_public"].is_binary()) {
		auto bin = j["signing_public"].get_binary();
		signingPublic.assign(bin.begin(), bin.end());
	}
	if (j.contains("signature") && j["signature"].is_binary()) {
		auto bin = j["signature"].get_binary();
		signature.assign(bin.begin(), bin.end());
	}

	// TODO: Verify tls_signature over (algorithm_version || cert_hash || timestamp ||
	//       identity_public || signing_public) using the client's TLS certificate public key.
	//       This requires access to the client's TLS certificate which needs Server integration.

	// Store keys
	msdb::PChatUserKeys keys;
	keys.serverID         = serverNum;
	keys.certHash         = certHash;
	keys.algorithmVersion = algVersion;
	keys.identityPublic   = identityPublic;
	keys.signingPublic    = signingPublic;
	keys.signature        = signature;
	keys.updatedAt        = m_bridge.serverTimeMs();

	m_keysTable.storeKeys(keys);

	// Send all previously stored public keys to the new client
	auto allKeys = m_keysTable.getAllKeys(serverNum);
	for (const auto &k : allKeys) {
		if (k.certHash == certHash) {
			continue; // Don't send own keys back
		}

		json keyMsg;
		keyMsg["algorithm_version"] = k.algorithmVersion;
		keyMsg["identity_public"]   = json::binary_t(std::vector< uint8_t >(k.identityPublic.begin(),
																			k.identityPublic.end()));
		keyMsg["signing_public"]    = json::binary_t(std::vector< uint8_t >(k.signingPublic.begin(),
																			k.signingPublic.end()));
		keyMsg["cert_hash"]         = k.certHash;
		keyMsg["timestamp"]         = k.updatedAt;
		keyMsg["signature"]         = json::binary_t(std::vector< uint8_t >(k.signature.begin(),
																			k.signature.end()));

		auto keyData = json::to_msgpack(keyMsg);
		m_bridge.sendPluginData(senderSession, PCHAT_KEY_ANNOUNCE, keyData);
	}

	// Broadcast the new client's public key to all other connected Fancy sessions
	auto announceData = data; // forward the original announcement
	m_bridge.broadcastPluginDataToAllFancyClients(PCHAT_KEY_ANNOUNCE, announceData, senderSession);

	// Check if this client needs key material for any persistent channels
	// (Generate key requests for channels the client is in)
	// This is triggered by the client joining a channel, handled via onFancyClientJoinedChannel
}

void PersistentChatManager::handleKeyExchange(unsigned int senderSession, const std::vector< uint8_t > &data) {
	if (!m_rateLimiter.allow(std::to_string(senderSession), "key_exchange")) {
		return;
	}

	json j;
	try {
		j = json::from_msgpack(data);
	} catch (const json::exception &) {
		return;
	}

	const std::string sessionCertHash = m_bridge.getCertHash(senderSession);

	// Hard-validate sender_hash matches session
	const std::string senderHash = j.value("sender_hash", "");
	if (senderHash != sessionCertHash) {
		return; // Reject impersonation
	}

	const std::string recipientHash = j.value("recipient_hash", "");
	if (recipientHash.empty()) {
		return;
	}

	// Relay tracking (if request_id is present and non-null)
	std::string requestId;
	if (j.contains("request_id") && !j["request_id"].is_null()) {
		requestId = j["request_id"].get< std::string >();
	}

	const auto serverNum = m_bridge.serverNum();

	if (!requestId.empty()) {
		// Tracked relay: check pending key request
		if (!m_pendingTable.recordRelay(serverNum, requestId, senderHash)) {
			return; // Cap reached or duplicate sender
		}
	}
	// If request_id is null, this is an epoch broadcast - relay unconditionally

	// Look up recipient session
	unsigned int recipientSession = m_bridge.getSessionForCertHash(recipientHash);
	if (recipientSession == 0) {
		// Recipient offline - could queue for later delivery
		// For now, silently drop (spec says "queue for next connect" but that's optional)
		return;
	}

	// Forward to recipient
	m_bridge.sendPluginData(recipientSession, PCHAT_KEY_EXCHANGE, data);
}

void PersistentChatManager::handleEpochCountersig(unsigned int senderSession, const std::vector< uint8_t > &data) {
	json j;
	try {
		j = json::from_msgpack(data);
	} catch (const json::exception &) {
		return;
	}

	const std::string sessionCertHash = m_bridge.getCertHash(senderSession);
	const unsigned int channelId = j.value("channel_id", 0u);

	if (channelId == 0) {
		return;
	}

	// Validate sender is a key custodian or channel creator
	const std::string signerHash = j.value("signer_hash", "");
	if (signerHash != sessionCertHash) {
		return;
	}

	auto custodians = m_bridge.getChannelKeyCustodians(channelId);
	bool isCustodian = std::find(custodians.begin(), custodians.end(), sessionCertHash) != custodians.end();

	// TODO: Also check if sender is channel creator (needs Server integration for channel creator lookup)
	if (!isCustodian) {
		return;
	}

	// Validate timestamp freshness
	long long ts = j.value("timestamp", 0LL);
	long long serverTime = m_bridge.serverTimeMs();
	if (std::abs(serverTime - ts) > 5000) {
		return;
	}

	// Broadcast to all other Fancy clients in the channel
	m_bridge.broadcastPluginDataToFancyClients(channelId, PCHAT_EPOCH_COUNTERSIG, data, senderSession);
}

void PersistentChatManager::sendAck(unsigned int sessionId, const std::string &messageId,
									const std::string &status, const std::string &reason) {
	json ack;
	ack["message_id"] = messageId;
	ack["status"]     = status;
	if (!reason.empty()) {
		ack["reason"] = reason;
	}

	auto ackData = json::to_msgpack(ack);
	m_bridge.sendPluginData(sessionId, PCHAT_ACK, ackData);
}

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
	int relayCap;
	if (mode == "POST_JOIN") {
		relayCap = 3;
	} else {
		unsigned int onlineMembers = m_bridge.countFancyClientsInChannel(channelId);
		int base = static_cast< int >(onlineMembers) / 2;
		relayCap = std::clamp(base, 1, 5) + 2;
	}

	std::string requestId = generateUUID();
	long long now = m_bridge.serverTimeMs();

	msdb::PChatPendingKeyRequest req;
	req.serverID        = serverNum;
	req.requestId       = requestId;
	req.channelId       = channelId;
	req.mode            = mode;
	req.requesterHash   = requesterHash;
	req.requesterPublic = requesterPublic;
	req.relayCap        = relayCap;
	req.relaysSent      = 0;
	req.createdAt       = now;

	m_pendingTable.createRequest(req);

	// Broadcast key request to all other Fancy clients in the channel
	json keyReq;
	keyReq["channel_id"]       = channelId;
	keyReq["mode"]             = mode;
	keyReq["requester_hash"]   = requesterHash;
	keyReq["requester_public"] = json::binary_t(
		std::vector< uint8_t >(requesterPublic.begin(), requesterPublic.end()));
	keyReq["request_id"]       = requestId;
	keyReq["timestamp"]        = now;
	keyReq["relay_cap"]        = relayCap;

	auto reqData = json::to_msgpack(keyReq);

	unsigned int requesterSession = m_bridge.getSessionForCertHash(requesterHash);
	m_bridge.broadcastPluginDataToFancyClients(channelId, PCHAT_KEY_REQUEST, reqData, requesterSession);
}

void PersistentChatManager::onFancyClientJoinedChannel(unsigned int sessionId, unsigned int channelId) {
	if (!m_config.enabled) {
		qDebug("pchat: onFancyClientJoinedChannel disabled, ignoring session=%u channel=%u",
			   sessionId, channelId);
		return;
	}

	const auto serverNum = m_bridge.serverNum();
	const std::string certHash = m_bridge.getCertHash(sessionId);
	uint32_t channelMode = m_bridge.getChannelPChatMode(channelId);

	qDebug("pchat: onFancyClientJoinedChannel session=%u channel=%u mode=%u hash=%s",
		   sessionId, channelId, channelMode, certHash.c_str());

	if (channelMode == 0) {
		return; // Not a persistent channel
	}

	// Record member join for POST_JOIN mode
	if (channelMode == 1) { // POST_JOIN
		msdb::PChatMemberJoin join;
		join.serverID  = serverNum;
		join.channelId = channelId;
		join.certHash  = certHash;
		join.joinedAt  = m_bridge.serverTimeMs();
		join.epochAtJoin = 0; // Will be updated when key exchange completes
		m_joinTable.recordJoin(join);
	}

	// Deliver pending key requests for this channel to the newly connected member
	auto pendingRequests = m_pendingTable.getPendingRequests(serverNum, channelId);
	for (const auto &req : pendingRequests) {
		if (req.requesterHash == certHash) {
			continue; // Don't send own request back
		}

		json keyReq;
		keyReq["channel_id"]       = req.channelId;
		keyReq["mode"]             = req.mode;
		keyReq["requester_hash"]   = req.requesterHash;
		keyReq["requester_public"] = json::binary_t(
			std::vector< uint8_t >(req.requesterPublic.begin(), req.requesterPublic.end()));
		keyReq["request_id"]       = req.requestId;
		keyReq["timestamp"]        = req.createdAt;
		keyReq["relay_cap"]        = req.relayCap;

		auto reqData = json::to_msgpack(keyReq);
		m_bridge.sendPluginData(sessionId, PCHAT_KEY_REQUEST, reqData);
	}

	// If this user has keys announced, check if they need a key request generated
	auto userKeys = m_keysTable.getKeys(serverNum, certHash);
	if (userKeys.has_value()) {
		// Check if there's already a pending request for this user+channel
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

void PersistentChatManager::runCleanup() {
	const auto serverNum = m_bridge.serverNum();

	// Cleanup expired pending key requests
	m_pendingTable.cleanupExpired(serverNum, m_config.pendingKeyRequestMaxDays);
	m_pendingTable.cleanupFulfilled(serverNum, m_config.pendingFulfilledMaxHours);

	// Note: Message cleanup by retention_days is handled per-channel and requires
	// iterating channels with their retention settings. This should be called
	// from the server's periodic cleanup timer with channel config info.
}

std::string PersistentChatManager::generateUUID() {
	// Simple UUID v4 generation
	static std::random_device rd;
	static std::mt19937 gen(rd());
	static std::uniform_int_distribution< uint32_t > dist(0, 0xFFFFFFFF);

	auto r = [&]() { return dist(gen); };

	uint32_t a = r(), b = r(), c = r(), d = r();

	// Set version (4) and variant (10xx)
	b = (b & 0xFFFF0FFF) | 0x00004000;
	c = (c & 0x3FFFFFFF) | 0x80000000;

	char buf[37];
	std::snprintf(buf, sizeof(buf), "%08x-%04x-%04x-%04x-%04x%08x",
				  a, (b >> 16) & 0xFFFF, b & 0xFFFF,
				  (c >> 16) & 0xFFFF, c & 0xFFFF, d);
	return std::string(buf);
}

} // namespace pchat
