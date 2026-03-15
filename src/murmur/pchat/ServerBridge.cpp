// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "ServerBridge.h"

#include "Channel.h"
#include "Server.h"
#include "ServerUser.h"

#include "Mumble.pb.h"

#include <chrono>

namespace pchat {

ServerBridge::ServerBridge(Server &server) : m_server(server) {}

void ServerBridge::sendPluginData(unsigned int sessionId, const std::string &dataId,
								  const std::vector< uint8_t > &data) {
	ServerUser *user = m_server.qhUsers.value(sessionId);
	if (!user || user->sState != ServerUser::Authenticated) {
		return;
	}

	MumbleProto::PluginDataTransmission msg;
	msg.set_sendersession(0); // Server-originated
	msg.set_dataid(dataId);
	msg.set_data(data.data(), data.size());

	m_server.sendMessage(user, msg);
}

void ServerBridge::broadcastPluginDataToFancyClients(unsigned int channelId, const std::string &dataId,
													 const std::vector< uint8_t > &data,
													 unsigned int excludeSession) {
	Channel *c = m_server.qhChannels.value(channelId);
	if (!c) {
		return;
	}

	MumbleProto::PluginDataTransmission msg;
	msg.set_sendersession(0);
	msg.set_dataid(dataId);
	msg.set_data(data.data(), data.size());

	for (User *pUser : c->qlUsers) {
		ServerUser *su = static_cast< ServerUser * >(pUser);
		if (su->uiSession == excludeSession) {
			continue;
		}
		if (su->sState != ServerUser::Authenticated) {
			continue;
		}
		if (!su->m_FancyVersion.has_value() || su->m_FancyVersion.value() < Version::fromComponents(0, 2, 0)) {
			continue;
		}
		m_server.sendMessage(su, msg);
	}
}

void ServerBridge::broadcastPluginDataToAllFancyClients(const std::string &dataId,
														const std::vector< uint8_t > &data,
														unsigned int excludeSession) {
	MumbleProto::PluginDataTransmission msg;
	msg.set_sendersession(0);
	msg.set_dataid(dataId);
	msg.set_data(data.data(), data.size());

	for (ServerUser *su : m_server.qhUsers) {
		if (su->uiSession == excludeSession) {
			continue;
		}
		if (su->sState != ServerUser::Authenticated) {
			continue;
		}
		if (!su->m_FancyVersion.has_value() || su->m_FancyVersion.value() < Version::fromComponents(0, 2, 0)) {
			continue;
		}
		m_server.sendMessage(su, msg);
	}
}

std::string ServerBridge::getCertHash(unsigned int sessionId) const {
	ServerUser *user = m_server.qhUsers.value(sessionId);
	if (!user) {
		return {};
	}
	return user->qsHash.toStdString();
}

bool ServerBridge::isFancyClient(unsigned int sessionId) const {
	ServerUser *user = m_server.qhUsers.value(sessionId);
	if (!user) {
		return false;
	}
	return user->m_FancyVersion.has_value() && user->m_FancyVersion.value() >= Version::fromComponents(0, 2, 0);
}

bool ServerBridge::hasWritePermission(unsigned int sessionId, unsigned int channelId) const {
	ServerUser *user = m_server.qhUsers.value(sessionId);
	Channel *c       = m_server.qhChannels.value(channelId);
	if (!user || !c) {
		return false;
	}
	return m_server.hasPermission(user, c, ChanACL::Write);
}

bool ServerBridge::hasEnterPermission(unsigned int sessionId, unsigned int channelId) const {
	ServerUser *user = m_server.qhUsers.value(sessionId);
	Channel *c       = m_server.qhChannels.value(channelId);
	if (!user || !c) {
		return false;
	}
	return m_server.hasPermission(user, c, ChanACL::Enter);
}

uint32_t ServerBridge::getChannelPChatMode(unsigned int channelId) const {
	Channel *c = m_server.qhChannels.value(channelId);
	if (!c) {
		return 0;
	}
	return c->uiPChatMode;
}

std::vector< std::string > ServerBridge::getChannelKeyCustodians(unsigned int channelId) const {
	Channel *c = m_server.qhChannels.value(channelId);
	if (!c) {
		return {};
	}
	std::vector< std::string > result;
	for (const auto &s : c->qslPChatKeyCustodians) {
		result.push_back(s.toStdString());
	}
	return result;
}

unsigned int ServerBridge::countFancyClientsInChannel(unsigned int channelId) const {
	Channel *c = m_server.qhChannels.value(channelId);
	if (!c) {
		return 0;
	}
	unsigned int count = 0;
	for (User *pUser : c->qlUsers) {
		ServerUser *su = static_cast< ServerUser * >(pUser);
		if (su->m_FancyVersion.has_value() && su->m_FancyVersion.value() >= Version::fromComponents(0, 2, 0)) {
			++count;
		}
	}
	return count;
}

int64_t ServerBridge::serverTimeMs() const {
	return std::chrono::duration_cast< std::chrono::milliseconds >(
			   std::chrono::system_clock::now().time_since_epoch())
		.count();
}

unsigned int ServerBridge::serverNum() const {
	return m_server.iServerNum;
}

bool ServerBridge::isUserRegistered(unsigned int sessionId) const {
	ServerUser *user = m_server.qhUsers.value(sessionId);
	if (!user) {
		return false;
	}
	return user->iId >= 0; // Registered users have iId >= 0
}

unsigned int ServerBridge::getSessionForCertHash(const std::string &certHash) const {
	QString qCertHash = QString::fromStdString(certHash);
	for (ServerUser *su : m_server.qhUsers) {
		if (su->sState == ServerUser::Authenticated && su->qsHash == qCertHash) {
			return su->uiSession;
		}
	}
	return 0;
}

} // namespace pchat
