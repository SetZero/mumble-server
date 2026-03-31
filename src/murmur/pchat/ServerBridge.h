// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_MURMUR_PCHAT_SERVERBRIDGE_H_
#define MUMBLE_MURMUR_PCHAT_SERVERBRIDGE_H_

#include "PersistentChatManager.h"

class Server;

namespace pchat {

/// Concrete implementation of IServerBridge that delegates to a Server instance.
class ServerBridge : public IServerBridge {
public:
	explicit ServerBridge(Server &server);

	void sendPchatAck(unsigned int sessionId, const MumbleProto::PchatAck &msg) override;
	void sendPchatFetchResponse(unsigned int sessionId, const MumbleProto::PchatFetchResponse &msg) override;
	void sendPchatKeyAnnounce(unsigned int sessionId, const MumbleProto::PchatKeyAnnounce &msg) override;
	void sendPchatKeyExchange(unsigned int sessionId, const MumbleProto::PchatKeyExchange &msg) override;
	void sendPchatKeyRequest(unsigned int sessionId, const MumbleProto::PchatKeyRequest &msg) override;
	void sendPchatMessageDeliver(unsigned int sessionId, const MumbleProto::PchatMessageDeliver &msg) override;
	void sendPchatKeyHoldersList(unsigned int sessionId, const MumbleProto::PchatKeyHoldersList &msg) override;
	void sendPchatKeyChallenge(unsigned int sessionId, const MumbleProto::PchatKeyChallenge &msg) override;
	void sendPchatKeyChallengeResult(unsigned int sessionId, const MumbleProto::PchatKeyChallengeResult &msg) override;
	void sendPchatOfflineQueueDrain(unsigned int sessionId, const MumbleProto::PchatOfflineQueueDrain &msg) override;
        void sendPchatReactionDeliver(unsigned int sessionId, const MumbleProto::PchatReactionDeliver &msg) override;
        void sendPchatReactionFetchResponse(unsigned int sessionId, const MumbleProto::PchatReactionFetchResponse &msg) override;

	void broadcastPchatMessageDeliver(unsigned int channelId, const MumbleProto::PchatMessageDeliver &msg,
									  unsigned int excludeSession = 0) override;
	void broadcastPchatKeyAnnounce(const MumbleProto::PchatKeyAnnounce &msg,
								   unsigned int excludeSession = 0) override;
	void broadcastPchatKeyRequest(unsigned int channelId, const MumbleProto::PchatKeyRequest &msg,
								  unsigned int excludeSession = 0) override;
	void broadcastPchatEpochCountersig(unsigned int channelId, const MumbleProto::PchatEpochCountersig &msg,
									   unsigned int excludeSession = 0) override;
	void broadcastPchatDeleteMessages(unsigned int channelId, const MumbleProto::PchatDeleteMessages &msg,
	                                  unsigned int excludeSession = 0) override;
        void broadcastPchatReactionDeliver(unsigned int channelId, const MumbleProto::PchatReactionDeliver &msg,
                                           unsigned int excludeSession = 0) override;

	std::string getCertHash(unsigned int sessionId) const override;
	bool isFancyClient(unsigned int sessionId) const override;
	bool hasWritePermission(unsigned int sessionId, unsigned int channelId) const override;
	bool hasEnterPermission(unsigned int sessionId, unsigned int channelId) const override;
	bool hasDeleteMessagePermission(unsigned int sessionId, unsigned int channelId) const override;
	bool hasKeyOwnerPermission(unsigned int sessionId, unsigned int channelId) const override;
	void sendPermissionDenied(unsigned int sessionId, unsigned int channelId, unsigned int permission) override;
	Protocol getChannelPChatProtocol(unsigned int channelId) const override;
	std::vector< std::string > getChannelKeyCustodians(unsigned int channelId) const override;
	unsigned int countFancyClientsInChannel(unsigned int channelId) const override;
	int64_t serverTimeMs() const override;
	unsigned int serverNum() const override;
	bool isUserRegistered(unsigned int sessionId) const override;
	unsigned int getSessionForCertHash(const std::string &certHash) const override;

private:
	Server &m_server;
};

} // namespace pchat

#endif // MUMBLE_MURMUR_PCHAT_SERVERBRIDGE_H_
