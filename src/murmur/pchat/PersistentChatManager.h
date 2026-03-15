// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_MURMUR_PCHAT_PERSISTENTCHATMANAGER_H_
#define MUMBLE_MURMUR_PCHAT_PERSISTENTCHATMANAGER_H_

#include "IRateLimiter.h"
#include "PChatTypes.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace mumble {
namespace server {
	namespace db {
		class PChatMessageTable;
		class PChatUserKeysTable;
		class PChatMemberJoinTable;
		class PChatPendingKeyRequestsTable;
	} // namespace db
} // namespace server
} // namespace mumble

class ServerUser;
class Channel;

namespace pchat {

/// Callback interface for the PersistentChatManager to send messages back to clients.
/// This decouples the manager from Server's send infrastructure.
struct IServerBridge {
	virtual ~IServerBridge() = default;

	/// Send a PluginDataTransmission message to a specific user session.
	virtual void sendPluginData(unsigned int sessionId, const std::string &dataId,
								const std::vector< uint8_t > &data) = 0;

	/// Send a PluginDataTransmission message to all Fancy Mumble v2+ sessions in a channel,
	/// optionally excluding one session.
	virtual void broadcastPluginDataToFancyClients(unsigned int channelId, const std::string &dataId,
												   const std::vector< uint8_t > &data,
												   unsigned int excludeSession = 0) = 0;

	/// Send a PluginDataTransmission message to all Fancy Mumble v2+ sessions on the server,
	/// optionally excluding one session.
	virtual void broadcastPluginDataToAllFancyClients(const std::string &dataId,
													  const std::vector< uint8_t > &data,
													  unsigned int excludeSession = 0) = 0;

	/// Get the TLS certificate hash for a session.
	virtual std::string getCertHash(unsigned int sessionId) const = 0;

	/// Check if a session is a Fancy Mumble v2+ client.
	virtual bool isFancyClient(unsigned int sessionId) const = 0;

	/// Check if a user has Write permission on a channel.
	virtual bool hasWritePermission(unsigned int sessionId, unsigned int channelId) const = 0;

	/// Check if a user has Enter permission on a channel.
	virtual bool hasEnterPermission(unsigned int sessionId, unsigned int channelId) const = 0;

	/// Get the channel mode for a channel (from Channel object).
	virtual uint32_t getChannelPChatMode(unsigned int channelId) const = 0;

	/// Get the key custodians list for a channel.
	virtual std::vector< std::string > getChannelKeyCustodians(unsigned int channelId) const = 0;

	/// Get the number of online Fancy Mumble v2+ clients in a channel.
	virtual unsigned int countFancyClientsInChannel(unsigned int channelId) const = 0;

	/// Get server time in milliseconds since epoch.
	virtual int64_t serverTimeMs() const = 0;

	/// Get the server's numeric ID.
	virtual unsigned int serverNum() const = 0;

	/// Check if a user is registered (has a registered Mumble account).
	virtual bool isUserRegistered(unsigned int sessionId) const = 0;

	/// Get the session ID for a user with a given cert hash (0 if offline).
	virtual unsigned int getSessionForCertHash(const std::string &certHash) const = 0;
};

/// Server-side persistent chat companion manager.
///
/// Intercepts PluginDataTransmission messages with "fancy-pchat-" prefix
/// and handles storage, retrieval, key exchange relay, and key request generation.
class PersistentChatManager {
public:
	/// Configuration for the persistent chat manager.
	struct Config {
		bool enabled                  = true;
		bool requireRegistration      = true;
		int defaultMaxHistory         = 5000;
		int defaultRetentionDays      = 90;
		int maxPayloadSize            = 65536;
		int pendingKeyRequestMaxDays  = 7;
		int pendingFulfilledMaxHours  = 24;
		int perUserPendingLimit       = 5;
		int perChannelPendingSoftCap  = 100;
	};

	PersistentChatManager(::mumble::server::db::PChatMessageTable &msgTable,
						  ::mumble::server::db::PChatUserKeysTable &keysTable,
						  ::mumble::server::db::PChatMemberJoinTable &joinTable,
						  ::mumble::server::db::PChatPendingKeyRequestsTable &pendingTable,
						  IServerBridge &bridge,
						  IRateLimiter &rateLimiter,
						  Config config);

	PersistentChatManager(::mumble::server::db::PChatMessageTable &msgTable,
						  ::mumble::server::db::PChatUserKeysTable &keysTable,
						  ::mumble::server::db::PChatMemberJoinTable &joinTable,
						  ::mumble::server::db::PChatPendingKeyRequestsTable &pendingTable,
						  IServerBridge &bridge,
						  IRateLimiter &rateLimiter)
		: PersistentChatManager(msgTable, keysTable, joinTable, pendingTable, bridge, rateLimiter, Config{}) {}

	/// Returns true if the dataID is a pchat message that was handled.
	/// Returns false if the dataID is not a pchat message (should be forwarded normally).
	bool handlePluginData(unsigned int senderSession, const std::string &dataId,
						  const std::vector< uint8_t > &data);

	/// Called when a Fancy client connects and joins a persistent channel.
	/// Delivers pending key requests for that channel.
	void onFancyClientJoinedChannel(unsigned int sessionId, unsigned int channelId);

	/// Run periodic cleanup (retention, expired key requests).
	void runCleanup();

private:
	void handleMsg(unsigned int senderSession, const std::vector< uint8_t > &data);
	void handleFetch(unsigned int senderSession, const std::vector< uint8_t > &data);
	void handleKeyAnnounce(unsigned int senderSession, const std::vector< uint8_t > &data);
	void handleKeyExchange(unsigned int senderSession, const std::vector< uint8_t > &data);
	void handleEpochCountersig(unsigned int senderSession, const std::vector< uint8_t > &data);

	void sendAck(unsigned int sessionId, const std::string &messageId,
				 const std::string &status, const std::string &reason = "");

	/// Generate and broadcast a key request for a new user in a persistent channel.
	void generateKeyRequest(unsigned int channelId, const std::string &requesterHash,
							const std::string &requesterPublic, const std::string &mode);

	std::string generateUUID();

	::mumble::server::db::PChatMessageTable &m_msgTable;
	::mumble::server::db::PChatUserKeysTable &m_keysTable;
	::mumble::server::db::PChatMemberJoinTable &m_joinTable;
	::mumble::server::db::PChatPendingKeyRequestsTable &m_pendingTable;
	IServerBridge &m_bridge;
	IRateLimiter &m_rateLimiter;
	Config m_config;
};

} // namespace pchat

#endif // MUMBLE_MURMUR_PCHAT_PERSISTENTCHATMANAGER_H_
