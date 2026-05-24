// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#include "PluginHostManager.h"

#include "Meta.h"
#include "Server.h"
#include "ServerUser.h"
#include "Channel.h"
#include "ACL.h"
#include "Mumble.pb.h"

#include <QtCore/QDebug>
#include <QtCore/QReadLocker>
#include <QtCore/QSettings>

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <string>

PluginHostManager::PluginHostManager(Server *server, QObject *parent)
	: QObject(parent), m_server(server), m_handle(nullptr) {

	PluginHostCallbacks cb;
	cb.user_data               = this;
	cb.send_plugin_data        = &PluginHostManager::sendPluginDataTrampoline;
	cb.is_session_active       = &PluginHostManager::isSessionActiveTrampoline;
	cb.user_has_channel_access = &PluginHostManager::userHasChannelAccessTrampoline;
	cb.has_permission          = &PluginHostManager::hasPermissionTrampoline;
	cb.current_channel         = &PluginHostManager::currentChannelTrampoline;
	cb.get_config              = &PluginHostManager::getConfigTrampoline;
	cb.free_string             = &PluginHostManager::freeStringTrampoline;
        cb.send_fancy_live_doc_invite = &PluginHostManager::sendFancyLiveDocInviteTrampoline;
	m_handle = plugin_host_create(&cb);
}

PluginHostManager::~PluginHostManager() {
	if (m_handle) {
		plugin_host_destroy(m_handle);
	}
}

void PluginHostManager::onClientConnected(uint32_t session, const QString &username,
                                          const QString &certHash) {
	if (!m_handle) {
		return;
	}
	const QByteArray usernameUtf8 = username.toUtf8();
	const QByteArray certUtf8     = certHash.toUtf8();
	plugin_host_on_client_connected(m_handle, static_cast< uint32_t >(m_server->iServerNum), session,
	                                usernameUtf8.constData(), certUtf8.constData());
}

void PluginHostManager::onClientDisconnected(uint32_t session) {
	if (!m_handle) {
		return;
	}
	plugin_host_on_client_disconnected(m_handle, static_cast< uint32_t >(m_server->iServerNum), session);
}

void PluginHostManager::onPluginData(uint32_t senderSession, const QString &dataId,
                                     const QByteArray &data) {
	if (!m_handle) {
		return;
	}
	const QByteArray idUtf8 = dataId.toUtf8();
	plugin_host_on_plugin_data(m_handle, static_cast< uint32_t >(m_server->iServerNum), senderSession,
	                           idUtf8.constData(), reinterpret_cast< const uint8_t * >(data.constData()),
	                           static_cast< size_t >(data.size()));
}

void PluginHostManager::onFancyLiveDocOpen(uint32_t senderSession, uint32_t channelId,
                                           const QString &slug, const QString &title) {
        if (!m_handle) {
                return;
        }
        const QByteArray slugUtf8  = slug.toUtf8();
        const QByteArray titleUtf8 = title.toUtf8();
        plugin_host_on_fancy_live_doc_open(m_handle, static_cast< uint32_t >(m_server->iServerNum),
                                           senderSession, channelId,
                                           slugUtf8.constData(), titleUtf8.constData());
}
int PluginHostManager::sendPluginDataTrampoline(void *userData, uint32_t /*serverId*/,
                                                uint32_t targetSession, const char *dataId,
                                                const uint8_t *data, size_t dataLen) {
	auto *self = static_cast< PluginHostManager * >(userData);
	if (!self || !self->m_server) {
		return -1;
	}
	QReadLocker rl(&self->m_server->qrwlVoiceThread);
	ServerUser *target = self->m_server->qhUsers.value(targetSession);
	if (!target) {
		return -2;
	}
	MumbleProto::PluginDataTransmission msg;
	msg.set_sendersession(0); // server-originated
	msg.add_receiversessions(targetSession);
	msg.set_dataid(dataId ? dataId : "");
	if (data && dataLen > 0) {
		msg.set_data(data, dataLen);
	}
	self->m_server->sendMessage(target, msg);
	return 0;
}

bool PluginHostManager::isSessionActiveTrampoline(void *userData, uint32_t /*serverId*/,
                                                  uint32_t session) {
	auto *self = static_cast< PluginHostManager * >(userData);
	if (!self || !self->m_server) {
		return false;
	}
	QReadLocker rl(&self->m_server->qrwlVoiceThread);
	return self->m_server->qhUsers.contains(session);
}

bool PluginHostManager::userHasChannelAccessTrampoline(void *userData, uint32_t /*serverId*/,
                                                       uint32_t session, uint32_t channel) {
	auto *self = static_cast< PluginHostManager * >(userData);
	if (!self || !self->m_server) {
		return false;
	}
	QReadLocker rl(&self->m_server->qrwlVoiceThread);
	ServerUser *user = self->m_server->qhUsers.value(session);
	::Channel *chan  = self->m_server->qhChannels.value(channel);
	if (!user || !chan) {
		return false;
	}
	return self->m_server->hasPermission(user, chan, ChanACL::Enter);
}

bool PluginHostManager::hasPermissionTrampoline(void *userData, uint32_t /*serverId*/,
                                                uint32_t session, uint32_t channel,
                                                uint32_t permissionFlags) {
	auto *self = static_cast< PluginHostManager * >(userData);
	if (!self || !self->m_server) {
		return false;
	}
	QReadLocker rl(&self->m_server->qrwlVoiceThread);
	ServerUser *user = self->m_server->qhUsers.value(session);
	::Channel *chan  = self->m_server->qhChannels.value(channel);
	if (!user || !chan) {
		return false;
	}
	const QFlags< ChanACL::Perm > perms(static_cast< ChanACL::Perm >(permissionFlags));
	return self->m_server->hasPermission(user, chan, perms);
}

bool PluginHostManager::currentChannelTrampoline(void *userData, uint32_t /*serverId*/,
                                                 uint32_t session, uint32_t *outChannel) {
	auto *self = static_cast< PluginHostManager * >(userData);
	if (!self || !self->m_server || !outChannel) {
		return false;
	}
	QReadLocker rl(&self->m_server->qrwlVoiceThread);
	ServerUser *user = self->m_server->qhUsers.value(session);
	if (!user || !user->cChannel) {
		return false;
	}
	*outChannel = static_cast< uint32_t >(user->cChannel->iId);
	return true;
}

namespace {
// Allocate a NUL-terminated copy of `s` using malloc so the Rust host can
// release it via the matching free() in `freeStringTrampoline`.
char *dupToMalloc(const std::string &s) {
	char *out = static_cast< char * >(std::malloc(s.size() + 1));
	if (!out) {
		return nullptr;
	}
	std::memcpy(out, s.data(), s.size());
	out[s.size()] = '\0';
	return out;
}

// Convert a snake_case key to camelCase so the .ini fallback respects
// Mumble's camelCase naming convention while the Rust plugin keeps its
// idiomatic snake_case keys.  Example: "storage_path" -> "storagePath".
std::string snakeToCamelCase(const std::string &snake) {
	std::string result;
	result.reserve(snake.size());
	bool capitalizeNext = false;
	for (char c : snake) {
		if (c == '_') {
			capitalizeNext = true;
		} else if (capitalizeNext) {
			result += static_cast< char >(std::toupper(static_cast< unsigned char >(c)));
			capitalizeNext = false;
		} else {
			result += c;
		}
	}
	return result;
}

// Resolve synthetic "__host_*" keys exposing host metadata (versions, ...)
// that aren't stored in the server config table. Returns nullptr if `key`
// is not a recognised host key.
char *resolveHostKey(const char *key) {
	const std::string k(key);
	if (k == "__host_mumble_version") {
		std::string v = std::to_string(MUMBLE_VERSION_MAJOR) + "."
						+ std::to_string(MUMBLE_VERSION_MINOR) + "."
						+ std::to_string(MUMBLE_VERSION_PATCH);
		return dupToMalloc(v);
	}
	if (k == "__host_fancy_version") {
		std::string v = std::to_string(FANCY_VERSION_MAJOR) + "."
						+ std::to_string(FANCY_VERSION_MINOR) + "."
						+ std::to_string(FANCY_VERSION_PATCH);
		return dupToMalloc(v);
	}
	return nullptr;
}
} // namespace

char *PluginHostManager::getConfigTrampoline(void *userData, const char *key) {
	auto *self = static_cast< PluginHostManager * >(userData);
	if (!self || !self->m_server || !key) {
		return nullptr;
	}

	// Synthetic "__host_*" keys are answered directly from compile-time
	// constants and never hit the server config table.
	if (std::strncmp(key, "__host_", 7) == 0) {
		return resolveHostKey(key);
	}

        // Plugins provide fully qualified keys (e.g. "plugin.live-doc.enabled")
        // so we look them up verbatim in the server configuration table.
        // For the .ini fallback we try the raw key first (snake_case) and
        // then a camelCase variant (e.g. "plugin.live-doc.state_path" ->
        // "plugin.live-doc.statePath") to match Mumble's camelCase naming
        // convention.  Operators may use either form in the .ini file.
        const std::string fullKey(key);
        QString value;
        self->m_server->m_dbWrapper.getConfigurationTo(
                static_cast< unsigned int >(self->m_server->iServerNum), fullKey, value);
        if (value.isEmpty() && Meta::mp && Meta::mp->qsSettings) {
                value = Meta::mp->qsSettings->value(QString::fromStdString(fullKey)).toString();
                if (value.isEmpty()) {
                        const std::string camelKey = snakeToCamelCase(fullKey);
                        if (camelKey != fullKey) {
                                value = Meta::mp->qsSettings
                                                ->value(QString::fromStdString(camelKey))
                                                .toString();
                        }
                }
        }
        if (value.isEmpty()) {
                return nullptr;
        }
        const QByteArray utf8 = value.toUtf8();
        return dupToMalloc(std::string(utf8.constData(), static_cast< size_t >(utf8.size())));
}

void PluginHostManager::freeStringTrampoline(void * /*userData*/, char *ptr) {
        if (ptr) {
                std::free(ptr);
        }
}

int PluginHostManager::sendFancyLiveDocInviteTrampoline(void *userData, uint32_t /*serverId*/,
                                                        uint32_t targetSession, uint32_t channelId,
                                                        const char *slug, const char *title,
                                                        const char *wsUrl, const char *token) {
        auto *self = static_cast< PluginHostManager * >(userData);
        if (!self || !self->m_server) {
                return -1;
        }
        QReadLocker rl(&self->m_server->qrwlVoiceThread);
        ServerUser *target = self->m_server->qhUsers.value(targetSession);
        if (!target) {
                return -2;
        }
        MumbleProto::FancyLiveDocInvite msg;
        msg.set_server_id(std::to_string(self->m_server->iServerNum));
        msg.set_channel_id(channelId);
        if (slug)  { msg.set_slug(slug); }
        if (title) { msg.set_title(title); }
        if (wsUrl) { msg.set_ws_url(wsUrl); }
        if (token) { msg.set_token(token); }
        self->m_server->sendMessage(target, msg);
        return 0;
}
