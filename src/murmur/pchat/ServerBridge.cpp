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

// -- Helper: check if a ServerUser is Fancy v2+ --
static bool isFancy(const ServerUser *su) {
	return su->m_FancyVersion.has_value() && su->m_FancyVersion.value() >= Version::fromComponents(0, 2, 0);
}

// -- Unicast sends --

void ServerBridge::sendPchatAck(unsigned int sessionId, const MumbleProto::PchatAck &msg) {
	ServerUser *user = m_server.qhUsers.value(sessionId);
	if (!user || user->sState != ServerUser::Authenticated) return;
	m_server.sendMessage(user, msg);
}

void ServerBridge::sendPchatFetchResponse(unsigned int sessionId, const MumbleProto::PchatFetchResponse &msg) {
	ServerUser *user = m_server.qhUsers.value(sessionId);
	if (!user || user->sState != ServerUser::Authenticated) return;
	m_server.sendMessage(user, msg);
}

void ServerBridge::sendPchatKeyAnnounce(unsigned int sessionId, const MumbleProto::PchatKeyAnnounce &msg) {
	ServerUser *user = m_server.qhUsers.value(sessionId);
	if (!user || user->sState != ServerUser::Authenticated) return;
	m_server.sendMessage(user, msg);
}

void ServerBridge::sendPchatKeyExchange(unsigned int sessionId, const MumbleProto::PchatKeyExchange &msg) {
	ServerUser *user = m_server.qhUsers.value(sessionId);
	if (!user || user->sState != ServerUser::Authenticated) return;
	m_server.sendMessage(user, msg);
}

void ServerBridge::sendPchatKeyRequest(unsigned int sessionId, const MumbleProto::PchatKeyRequest &msg) {
	ServerUser *user = m_server.qhUsers.value(sessionId);
	if (!user || user->sState != ServerUser::Authenticated) return;
	m_server.sendMessage(user, msg);
}

void ServerBridge::sendPchatMessageDeliver(unsigned int sessionId, const MumbleProto::PchatMessageDeliver &msg) {
	ServerUser *user = m_server.qhUsers.value(sessionId);
	if (!user || user->sState != ServerUser::Authenticated) return;
	m_server.sendMessage(user, msg);
}

void ServerBridge::sendPchatKeyHoldersList(unsigned int sessionId, const MumbleProto::PchatKeyHoldersList &msg) {
	ServerUser *user = m_server.qhUsers.value(sessionId);
	if (!user || user->sState != ServerUser::Authenticated) return;
	m_server.sendMessage(user, msg);
}

// -- Broadcast sends --

void ServerBridge::broadcastPchatMessageDeliver(unsigned int channelId, const MumbleProto::PchatMessageDeliver &msg,
												unsigned int excludeSession) {
	Channel *c = m_server.qhChannels.value(channelId);
	if (!c) return;

	for (User *pUser : c->qlUsers) {
		ServerUser *su = static_cast< ServerUser * >(pUser);
		if (su->uiSession == excludeSession) continue;
		if (su->sState != ServerUser::Authenticated) continue;
		if (!isFancy(su)) continue;
		m_server.sendMessage(su, msg);
	}
}

void ServerBridge::broadcastPchatKeyAnnounce(const MumbleProto::PchatKeyAnnounce &msg,
											 unsigned int excludeSession) {
	for (ServerUser *su : m_server.qhUsers) {
		if (su->uiSession == excludeSession) continue;
		if (su->sState != ServerUser::Authenticated) continue;
		if (!isFancy(su)) continue;
		m_server.sendMessage(su, msg);
	}
}

void ServerBridge::broadcastPchatKeyRequest(unsigned int channelId, const MumbleProto::PchatKeyRequest &msg,
											unsigned int excludeSession) {
	Channel *c = m_server.qhChannels.value(channelId);
	if (!c) return;

	for (User *pUser : c->qlUsers) {
		ServerUser *su = static_cast< ServerUser * >(pUser);
		if (su->uiSession == excludeSession) continue;
		if (su->sState != ServerUser::Authenticated) continue;
		if (!isFancy(su)) continue;
		m_server.sendMessage(su, msg);
	}
}

void ServerBridge::broadcastPchatEpochCountersig(unsigned int channelId, const MumbleProto::PchatEpochCountersig &msg,
												 unsigned int excludeSession) {
	Channel *c = m_server.qhChannels.value(channelId);
	if (!c) return;

	for (User *pUser : c->qlUsers) {
		ServerUser *su = static_cast< ServerUser * >(pUser);
		if (su->uiSession == excludeSession) continue;
		if (su->sState != ServerUser::Authenticated) continue;
		if (!isFancy(su)) continue;
		m_server.sendMessage(su, msg);
	}
}

void ServerBridge::broadcastPchatDeleteMessages(unsigned int channelId, const MumbleProto::PchatDeleteMessages &msg,
                                                unsigned int excludeSession) {
	Channel *c = m_server.qhChannels.value(channelId);
	if (!c) return;

	for (User *pUser : c->qlUsers) {
		ServerUser *su = static_cast< ServerUser * >(pUser);
		if (su->uiSession == excludeSession) continue;
		if (su->sState != ServerUser::Authenticated) continue;
		if (!isFancy(su)) continue;
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
	return user->hasPermission(c, ChanACL::Write);
}

bool ServerBridge::hasEnterPermission(unsigned int sessionId, unsigned int channelId) const {
	ServerUser *user = m_server.qhUsers.value(sessionId);
	Channel *c       = m_server.qhChannels.value(channelId);
	if (!user || !c) {
		return false;
	}
	return user->hasPermission(c, ChanACL::Enter);
}

bool ServerBridge::hasDeleteMessagePermission(unsigned int sessionId, unsigned int channelId) const {
	ServerUser *user = m_server.qhUsers.value(sessionId);
	Channel *c       = m_server.qhChannels.value(channelId);
	if (!user || !c) {
		return false;
	}
	return user->hasPermission(c, ChanACL::DeleteMessage);
}

bool ServerBridge::hasKeyOwnerPermission(unsigned int sessionId, unsigned int channelId) const {
	ServerUser *user = m_server.qhUsers.value(sessionId);
	Channel *c       = m_server.qhChannels.value(channelId);
	if (!user || !c) {
		return false;
	}
	return user->hasPermission(c, ChanACL::KeyOwner);
}

Protocol ServerBridge::getChannelPChatProtocol(unsigned int channelId) const {
	Channel *c = m_server.qhChannels.value(channelId);
	if (!c) {
		return Protocol::None;
	}
	return static_cast< Protocol >(c->uiPChatProtocol);
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

void ServerBridge::sendPchatKeyChallenge(unsigned int sessionId, const MumbleProto::PchatKeyChallenge &msg) {
	ServerUser *user = m_server.qhUsers.value(sessionId);
	if (!user || user->sState != ServerUser::Authenticated) return;
	m_server.sendMessage(user, msg);
}

void ServerBridge::sendPchatKeyChallengeResult(unsigned int sessionId, const MumbleProto::PchatKeyChallengeResult &msg) {
	ServerUser *user = m_server.qhUsers.value(sessionId);
	if (!user || user->sState != ServerUser::Authenticated) return;
	m_server.sendMessage(user, msg);
}

void ServerBridge::sendPchatOfflineQueueDrain(unsigned int sessionId, const MumbleProto::PchatOfflineQueueDrain &msg) {
	ServerUser *user = m_server.qhUsers.value(sessionId);
	if (!user || user->sState != ServerUser::Authenticated) return;
	m_server.sendMessage(user, msg);
}

void ServerBridge::sendPchatReactionDeliver(unsigned int sessionId, const MumbleProto::PchatReactionDeliver &msg) {
        ServerUser *user = m_server.qhUsers.value(sessionId);
        if (!user || user->sState != ServerUser::Authenticated) return;
        m_server.sendMessage(user, msg);
}

void ServerBridge::sendPchatReactionFetchResponse(unsigned int sessionId, const MumbleProto::PchatReactionFetchResponse &msg) {
        ServerUser *user = m_server.qhUsers.value(sessionId);
        if (!user || user->sState != ServerUser::Authenticated) return;
        m_server.sendMessage(user, msg);
}

void ServerBridge::sendPchatPinDeliver(unsigned int sessionId, const MumbleProto::PchatPinDeliver &msg) {
	ServerUser *user = m_server.qhUsers.value(sessionId);
	if (!user || user->sState != ServerUser::Authenticated) return;
	m_server.sendMessage(user, msg);
}

void ServerBridge::sendPchatPinFetchResponse(unsigned int sessionId, const MumbleProto::PchatPinFetchResponse &msg) {
	ServerUser *user = m_server.qhUsers.value(sessionId);
	if (!user || user->sState != ServerUser::Authenticated) return;
	m_server.sendMessage(user, msg);
}

void ServerBridge::sendPchatSenderKeyDistribution(unsigned int sessionId, const MumbleProto::PchatSenderKeyDistribution &msg) {
	ServerUser *user = m_server.qhUsers.value(sessionId);
	if (!user || user->sState != ServerUser::Authenticated) return;
	m_server.sendMessage(user, msg);
}

void ServerBridge::broadcastPchatReactionDeliver(unsigned int channelId, const MumbleProto::PchatReactionDeliver &msg,
                                                 unsigned int excludeSession) {
        Channel *c = m_server.qhChannels.value(channelId);
        if (!c) return;

        for (ServerUser *pUser : c->qlUsers
                | std::views::transform([](User *u) {
                         return static_cast< ServerUser * >(u);
                })
                | std::views::filter([excludeSession](ServerUser *su) {
                        return su->uiSession != excludeSession && su->sState == ServerUser::Authenticated && isFancy(su);
                })
        ) {
                m_server.sendMessage(pUser, msg);
        }
}

void ServerBridge::broadcastPchatPinDeliver(unsigned int channelId, const MumbleProto::PchatPinDeliver &msg,
                                            unsigned int excludeSession) {
	Channel *c = m_server.qhChannels.value(channelId);
	if (!c) return;

	for (ServerUser *pUser : c->qlUsers
		| std::views::transform([](User *u) {
			return static_cast< ServerUser * >(u);
		})
		| std::views::filter([excludeSession](ServerUser *su) {
			return su->uiSession != excludeSession && su->sState == ServerUser::Authenticated && isFancy(su);
		})
	) {
		m_server.sendMessage(pUser, msg);
	}
}

void ServerBridge::sendPermissionDenied(unsigned int sessionId, unsigned int channelId, unsigned int permission) {
	ServerUser *user = m_server.qhUsers.value(sessionId);
	if (!user || user->sState != ServerUser::Authenticated) return;

	MumbleProto::PermissionDenied mppd;
	mppd.set_permission(permission);
	mppd.set_channel_id(channelId);
	mppd.set_session(sessionId);
	mppd.set_type(MumbleProto::PermissionDenied_DenyType_Permission);
	m_server.sendMessage(user, mppd);
}

} // namespace pchat
