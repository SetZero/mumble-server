// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_MURMUR_PCHAT_PERSISTENTCHATMANAGER_H_
#define MUMBLE_MURMUR_PCHAT_PERSISTENTCHATMANAGER_H_

#include "IRateLimiter.h"
#include "PChatTypes.h"

#include "Mumble.pb.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace mumble {
namespace server {
	namespace db {
		class PChatMessageTable;
		class PChatUserKeysTable;
		class PChatMemberJoinTable;
		class PChatPendingKeyRequestsTable;
	class PChatKeyHoldersTable;
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

	/// Send a PchatAck to a specific user session.
	virtual void sendPchatAck(unsigned int sessionId, const MumbleProto::PchatAck &msg) = 0;

	/// Send a PchatFetchResponse to a specific user session.
	virtual void sendPchatFetchResponse(unsigned int sessionId, const MumbleProto::PchatFetchResponse &msg) = 0;

	/// Send a PchatKeyAnnounce to a specific user session.
	virtual void sendPchatKeyAnnounce(unsigned int sessionId, const MumbleProto::PchatKeyAnnounce &msg) = 0;

	/// Send a PchatKeyExchange to a specific user session.
	virtual void sendPchatKeyExchange(unsigned int sessionId, const MumbleProto::PchatKeyExchange &msg) = 0;

	/// Send a PchatKeyRequest to a specific user session.
	virtual void sendPchatKeyRequest(unsigned int sessionId, const MumbleProto::PchatKeyRequest &msg) = 0;

	/// Send a PchatMessageDeliver to a specific user session.
	virtual void sendPchatMessageDeliver(unsigned int sessionId, const MumbleProto::PchatMessageDeliver &msg) = 0;

	/// Broadcast a PchatMessageDeliver to all Fancy Mumble v2+ sessions in a channel,
	/// optionally excluding one session.
	virtual void broadcastPchatMessageDeliver(unsigned int channelId, const MumbleProto::PchatMessageDeliver &msg,
											  unsigned int excludeSession = 0) = 0;

	/// Broadcast a PchatKeyAnnounce to all Fancy Mumble v2+ sessions on the server,
	/// optionally excluding one session.
	virtual void broadcastPchatKeyAnnounce(const MumbleProto::PchatKeyAnnounce &msg,
										   unsigned int excludeSession = 0) = 0;

	/// Broadcast a PchatKeyRequest to all Fancy Mumble v2+ sessions in a channel,
	/// optionally excluding one session.
	virtual void broadcastPchatKeyRequest(unsigned int channelId, const MumbleProto::PchatKeyRequest &msg,
										  unsigned int excludeSession = 0) = 0;

	/// Broadcast a PchatEpochCountersig to all Fancy Mumble v2+ sessions in a channel,
	/// optionally excluding one session.
	virtual void broadcastPchatEpochCountersig(unsigned int channelId, const MumbleProto::PchatEpochCountersig &msg,
											   unsigned int excludeSession = 0) = 0;

	/// Broadcast a PchatDeleteMessages to all Fancy Mumble v2+ sessions in a channel,
	/// optionally excluding one session.
	virtual void broadcastPchatDeleteMessages(unsigned int channelId, const MumbleProto::PchatDeleteMessages &msg,
	                                           unsigned int excludeSession = 0) = 0;

	/// Get the TLS certificate hash for a session.
	virtual std::string getCertHash(unsigned int sessionId) const = 0;

	/// Send a PchatKeyHoldersList to a specific user session.
	virtual void sendPchatKeyHoldersList(unsigned int sessionId, const MumbleProto::PchatKeyHoldersList &msg) = 0;

	/// Send a PchatKeyChallenge to a specific user session.
	virtual void sendPchatKeyChallenge(unsigned int sessionId, const MumbleProto::PchatKeyChallenge &msg) = 0;

	/// Send a PchatKeyChallengeResult to a specific user session.
	virtual void sendPchatKeyChallengeResult(unsigned int sessionId, const MumbleProto::PchatKeyChallengeResult &msg) = 0;

	/// Check if a session is a Fancy Mumble v2+ client.
	virtual bool isFancyClient(unsigned int sessionId) const = 0;

	/// Check if a user has Write permission on a channel.
	virtual bool hasWritePermission(unsigned int sessionId, unsigned int channelId) const = 0;

	/// Check if a user has Enter permission on a channel.
	virtual bool hasEnterPermission(unsigned int sessionId, unsigned int channelId) const = 0;

	/// Check if a user has DeleteMessage permission on a channel.
	virtual bool hasDeleteMessagePermission(unsigned int sessionId, unsigned int channelId) const = 0;

	/// Check if a user has KeyOwner permission on a channel.
	virtual bool hasKeyOwnerPermission(unsigned int sessionId, unsigned int channelId) const = 0;

	/// Send a PermissionDenied message to a specific user session.
	virtual void sendPermissionDenied(unsigned int sessionId, unsigned int channelId, unsigned int permission) = 0;

	/// Get the channel protocol for a channel (from Channel object).
	virtual uint32_t getChannelPChatProtocol(unsigned int channelId) const = 0;

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
/// Receives native protobuf messages from the msg* handlers in Messages.cpp
/// and handles storage, retrieval, key exchange relay, and key request generation.
class PersistentChatManager {
public:
	/// Configuration for the persistent chat manager.
	struct Config {
		bool enabled                  = true;
		bool requireRegistration      = false;
		int defaultMaxHistory         = 5000;
		int defaultRetentionDays      = 90;
		int maxPayloadSize            = 1048576;
		int pendingKeyRequestMaxDays  = 7;
		int pendingFulfilledMaxHours  = 24;
		int perUserPendingLimit       = 5;
		int perChannelPendingSoftCap  = 100;
		/// Accepted E2EE algorithm versions. Empty means accept all.
		std::unordered_set< uint32_t > supportedAlgorithmVersions = { 1 };
	};

	PersistentChatManager(::mumble::server::db::PChatMessageTable &msgTable,
						  ::mumble::server::db::PChatUserKeysTable &keysTable,
						  ::mumble::server::db::PChatMemberJoinTable &joinTable,
						  ::mumble::server::db::PChatPendingKeyRequestsTable &pendingTable,
						  ::mumble::server::db::PChatKeyHoldersTable &holdersTable,
						  IServerBridge &bridge,
						  IRateLimiter &rateLimiter,
						  Config config);

	PersistentChatManager(::mumble::server::db::PChatMessageTable &msgTable,
						  ::mumble::server::db::PChatUserKeysTable &keysTable,
						  ::mumble::server::db::PChatMemberJoinTable &joinTable,
						  ::mumble::server::db::PChatPendingKeyRequestsTable &pendingTable,
						  ::mumble::server::db::PChatKeyHoldersTable &holdersTable,
						  IServerBridge &bridge,
						  IRateLimiter &rateLimiter)
		: PersistentChatManager(msgTable, keysTable, joinTable, pendingTable, holdersTable, bridge, rateLimiter, Config{}) {}

	/// Returns true if the dataID is a pchat message that was handled.
	/// Returns false if the dataID is not a pchat message (should be forwarded normally).
	bool handlePluginData(unsigned int senderSession, const std::string &dataId,
						  const std::vector< uint8_t > &data);

	/// Handle a PchatMessage (client wants to store an encrypted message).
	void handlePchatMessage(unsigned int senderSession, const MumbleProto::PchatMessage &msg);

	/// Handle a PchatFetch (client wants to retrieve stored messages).
	void handlePchatFetch(unsigned int senderSession, const MumbleProto::PchatFetch &msg);

	/// Handle a PchatKeyAnnounce (client announces E2EE identity public keys).
	void handlePchatKeyAnnounce(unsigned int senderSession, const MumbleProto::PchatKeyAnnounce &msg);

	/// Handle a PchatKeyExchange (client sends key material to another client).
	void handlePchatKeyExchange(unsigned int senderSession, const MumbleProto::PchatKeyExchange &msg);

	/// Handle a PchatEpochCountersig (key custodian countersignature).
	void handlePchatEpochCountersig(unsigned int senderSession, const MumbleProto::PchatEpochCountersig &msg);

	/// Handle a PchatKeyHolderReport (client reports a key holder).
	void handlePchatKeyHolderReport(unsigned int senderSession, const MumbleProto::PchatKeyHolderReport &msg);

	/// Handle a PchatKeyHoldersQuery (client requests key holders list).
	void handlePchatKeyHoldersQuery(unsigned int senderSession, const MumbleProto::PchatKeyHoldersQuery &msg);

	/// Handle a PchatKeyChallengeResponse (client proves key possession).
	void handlePchatKeyChallengeResponse(unsigned int senderSession, const MumbleProto::PchatKeyChallengeResponse &msg);

	/// Handle a PchatDeleteMessages (client wants to delete stored messages).
	void handlePchatDeleteMessages(unsigned int senderSession, const MumbleProto::PchatDeleteMessages &msg);

	/// Called when a Fancy client connects and joins a persistent channel.
	/// Delivers pending key requests for that channel.
	void onFancyClientJoinedChannel(unsigned int sessionId, unsigned int channelId);

	/// Called when a user disconnects. Clears their unfulfilled pending key requests
	/// and removes them from any channel challenge verified-sessions sets.
	void onUserDisconnected(unsigned int sessionId, const std::string &certHash);

	/// Called when a persistent channel is first created.
	/// Auto-verifies the creator so they can send messages immediately.
	void onPersistentChannelCreated(unsigned int channelId, unsigned int creatorSession);

	/// Called when a channel is removed. Clears all pchat data for the channel.
	void onChannelRemoved(unsigned int channelId);

	/// Run periodic cleanup (retention, expired key requests).
	void runCleanup();

	/// Check if a session has passed the key-possession challenge for a channel.
	bool isSessionVerified(unsigned int channelId, unsigned int sessionId) const;

private:
	void sendAck(unsigned int sessionId, const std::string &messageId,
				 MumbleProto::PchatAckStatus status, const std::string &reason = "");

	/// Handle a KeyOwner takeover request for a channel.
	void handleKeyOwnerTakeover(unsigned int senderSession, unsigned int channelId,
								const std::string &certHash,
								MumbleProto::PchatKeyHolderReport::KeyTakeoverMode mode);

	/// Send the current key holders list to all verified sessions in a channel.
	void broadcastKeyHoldersList(unsigned int channelId);

	/// Generate and broadcast a key request for a new user in a persistent channel.
	void generateKeyRequest(unsigned int channelId, const std::string &requesterHash,
							const std::string &requesterPublic, const std::string &mode);

	std::string generateUUID();

	::mumble::server::db::PChatMessageTable &m_msgTable;
	::mumble::server::db::PChatUserKeysTable &m_keysTable;
	::mumble::server::db::PChatMemberJoinTable &m_joinTable;
	::mumble::server::db::PChatPendingKeyRequestsTable &m_pendingTable;
	::mumble::server::db::PChatKeyHoldersTable &m_holdersTable;
	IServerBridge &m_bridge;
	IRateLimiter &m_rateLimiter;
	Config m_config;

	/// In-memory state for the key-possession challenge protocol.
	/// Maps channel_id to (shared challenge nonce, pending sessions, reference HMAC).
	struct ChannelChallengeState {
		/// Shared challenge nonce for the channel (all reporters receive the same nonce
		/// so their HMAC proofs are comparable).
		std::vector< uint8_t > sharedChallenge;
		/// Pending challenge indexed by session ID (value is always sharedChallenge).
		std::unordered_map< unsigned int, std::vector< uint8_t > > pendingChallenges;
		/// Reference HMAC set by the first prover (empty if no prover yet).
		std::vector< uint8_t > referenceHmac;
		/// Sessions that have passed the key-possession challenge.
		std::unordered_set< unsigned int > verifiedSessions;
	};
	std::unordered_map< unsigned int, ChannelChallengeState > m_challengeState;
};

} // namespace pchat

#endif // MUMBLE_MURMUR_PCHAT_PERSISTENTCHATMANAGER_H_
