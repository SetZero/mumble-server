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

	void sendPluginData(unsigned int sessionId, const std::string &dataId,
						const std::vector< uint8_t > &data) override;

	void broadcastPluginDataToFancyClients(unsigned int channelId, const std::string &dataId,
										   const std::vector< uint8_t > &data,
										   unsigned int excludeSession = 0) override;

	void broadcastPluginDataToAllFancyClients(const std::string &dataId,
											  const std::vector< uint8_t > &data,
											  unsigned int excludeSession = 0) override;

	std::string getCertHash(unsigned int sessionId) const override;
	bool isFancyClient(unsigned int sessionId) const override;
	bool hasWritePermission(unsigned int sessionId, unsigned int channelId) const override;
	bool hasEnterPermission(unsigned int sessionId, unsigned int channelId) const override;
	uint32_t getChannelPChatMode(unsigned int channelId) const override;
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
