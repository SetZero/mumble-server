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
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonValue>
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
        cb.send_plugin_message    = &PluginHostManager::sendPluginMessageTrampoline;
        cb.set_config             = &PluginHostManager::setConfigTrampoline;
        cb.delete_config_prefix   = &PluginHostManager::deleteConfigPrefixTrampoline;
        cb.sessions_in_channel    = &PluginHostManager::sessionsInChannelTrampoline;
        cb.all_sessions           = &PluginHostManager::allSessionsTrampoline;
        cb.find_session_by_name   = &PluginHostManager::findSessionByNameTrampoline;
        cb.free_sessions          = &PluginHostManager::freeSessionsTrampoline;
	m_handle = plugin_host_create(&cb);
}

PluginHostManager::~PluginHostManager() {
	// Detach from the distributor while it is still alive (it is declared before
	// this object in Server, so it outlives us).
	if (m_server) {
		m_server->events().unregisterSubscriber(this);
	}
	if (m_handle) {
		plugin_host_destroy(m_handle);
	}
}

void PluginHostManager::onUserConnected(Server &, const User *user) {
	onClientConnected(user->uiSession, user->qsName, user->qsHash, static_cast< int64_t >(user->iId));
}

void PluginHostManager::onUserDisconnected(Server &, const User *user) {
	onClientDisconnected(user->uiSession);
}

void PluginHostManager::onPluginMessage(Server &, const PluginInbound &in) {
	if (in.kind == PluginInbound::Kind::DataTransmission) {
		onPluginData(in.senderSession, in.dataId, in.data);
	} else if (in.message) {
		onPluginMessage(in.senderSession, in.senderName, *in.message);
	}
}

void PluginHostManager::onClientConnected(uint32_t session, const QString &username,
                                          const QString &certHash, int64_t userId) {
	if (!m_handle) {
		return;
	}
	const QByteArray usernameUtf8 = username.toUtf8();
	const QByteArray certUtf8     = certHash.toUtf8();
	plugin_host_on_client_connected(m_handle, static_cast< uint32_t >(m_server->iServerNum), session,
	                                usernameUtf8.constData(), certUtf8.constData(), userId);
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

void PluginHostManager::onPluginMessage(uint32_t senderSession, const QString &senderName,
                                        const ::MumbleProto::PluginMessage &msg) {
        if (!m_handle) {
                return;
        }
        const QByteArray senderNameUtf8  = senderName.toUtf8();
        const QByteArray pluginNameUtf8  = QByteArray::fromStdString(msg.plugin_name());
        const QByteArray payloadTypeUtf8 = QByteArray::fromStdString(msg.payload_type());
        const std::string &payload       = msg.payload();
        QVector< uint32_t > targets;
        targets.reserve(msg.target_sessions_size());
        for (int i = 0; i < msg.target_sessions_size(); ++i) {
                targets.append(msg.target_sessions(i));
        }
        const bool channelPresent = msg.has_channel_id();
        const uint32_t channelId  = channelPresent ? msg.channel_id() : 0u;
        plugin_host_on_plugin_message(
                m_handle, static_cast< uint32_t >(m_server->iServerNum), senderSession,
                senderNameUtf8.constData(), pluginNameUtf8.constData(), payloadTypeUtf8.constData(),
                payload.empty() ? nullptr : reinterpret_cast< const uint8_t * >(payload.data()),
                payload.size(), targets.isEmpty() ? nullptr : targets.constData(),
                static_cast< size_t >(targets.size()), channelPresent, channelId);
}

void PluginHostManager::fillRegistry(::MumbleProto::PluginRegistry &out) const {
        out.Clear();
        if (!m_handle) {
                return;
        }
        char *json = plugin_host_get_registry_json(m_handle);
        if (!json) {
                return;
        }
        const QByteArray raw(json);
        plugin_host_free_string(json);
        // The Rust host gives us a JSON document {"plugins":[{...},...]}.
        // We deliberately avoid pulling in a JSON dependency here and
        // instead parse with QJsonDocument which is already available.
        QJsonParseError err{};
        QJsonDocument doc = QJsonDocument::fromJson(raw, &err);
        if (err.error != QJsonParseError::NoError || !doc.isObject()) {
                return;
        }
        const QJsonArray plugins = doc.object().value(QStringLiteral("plugins")).toArray();
        for (const QJsonValue &v : plugins) {
                const QJsonObject obj = v.toObject();
                auto *entry = out.add_plugins();
                entry->set_plugin_name(obj.value(QStringLiteral("plugin_name")).toString().toStdString());
                entry->set_version(obj.value(QStringLiteral("version")).toString().toStdString());
                entry->set_plugin_slot(static_cast< uint32_t >(
                        obj.value(QStringLiteral("plugin_slot")).toInt(0)));
                entry->set_info_json(obj.value(QStringLiteral("info_json")).toString().toStdString());
        }
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

        // Plugins provide fully qualified keys (e.g. "plugin.fancy-live-doc.enabled")
        // so we look them up verbatim in the server configuration table.
        // For the .ini fallback we try the raw key first (snake_case) and
        // then a camelCase variant to also match Mumble's traditional
        // camelCase naming convention.  Operators may use either form.
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

int PluginHostManager::sendPluginMessageTrampoline(void *userData, uint32_t /*serverId*/,
                                                   const char *pluginName, const char *payloadType,
                                                   const uint8_t *payload, size_t payloadLen,
                                                   const uint32_t *targetSessions, size_t targetLen,
                                                   bool channelIdPresent, uint32_t channelId) {
        auto *self = static_cast< PluginHostManager * >(userData);
        if (!self || !self->m_server) {
                return -1;
        }
        QReadLocker rl(&self->m_server->qrwlVoiceThread);

        MumbleProto::PluginMessage msg;
        msg.set_plugin_name(pluginName ? pluginName : "");
        msg.set_payload_type(payloadType ? payloadType : "");
        msg.set_sender_session(0); // server-originated
        if (payload && payloadLen > 0) {
                msg.set_payload(payload, payloadLen);
        }
        if (channelIdPresent) {
                msg.set_channel_id(channelId);
        }

        QVector< uint32_t > recipients;
        if (targetSessions && targetLen > 0) {
                recipients.reserve(static_cast< int >(targetLen));
                for (size_t i = 0; i < targetLen; ++i) {
                        recipients.append(targetSessions[i]);
                        msg.add_target_sessions(targetSessions[i]);
                }
        } else if (channelIdPresent) {
                ::Channel *chan = self->m_server->qhChannels.value(channelId);
                if (chan) {
                        for (::User *u : chan->qlUsers) {
                                recipients.append(static_cast< uint32_t >(u->uiSession));
                        }
                }
        }
        if (recipients.isEmpty()) {
                return 0; // nothing to deliver, treat as success
        }
        for (uint32_t session : recipients) {
                ServerUser *target = self->m_server->qhUsers.value(session);
                if (!target) {
                        continue;
                }
                self->m_server->sendMessage(target, msg);
        }
        return 0;
}

// ---------------------------------------------------------------
// Plugin admin
// ---------------------------------------------------------------

namespace {
// Adopt a NUL-terminated string returned by the Rust FFI into a
// QByteArray and free the original allocation.  Returns an empty
// QByteArray for NULL.
QByteArray adoptFfiString(char *ptr) {
        if (!ptr) {
                return {};
        }
        QByteArray out(ptr);
        plugin_host_free_string(ptr);
        return out;
}
} // namespace

QByteArray PluginHostManager::listPluginsJson() const {
        if (!m_handle) {
                return QByteArray("{\"plugins\":[]}");
        }
        return adoptFfiString(plugin_host_list_plugins(m_handle));
}

QByteArray PluginHostManager::setPluginEnabled(const QString &pluginName, bool enabled) {
        if (!m_handle) {
                return QByteArray("{\"ok\":false,\"error\":\"plugin host not loaded\"}");
        }
        const QByteArray nameUtf8 = pluginName.toUtf8();
        return adoptFfiString(
                plugin_host_set_plugin_enabled(m_handle, nameUtf8.constData(), enabled));
}

QByteArray PluginHostManager::installPlugin(const QString &marketplaceId, const QString &version,
                                            const QString &manifestUrl,
                                            const QString &expectedSha256) {
        if (!m_handle) {
                return QByteArray("{\"ok\":false,\"error\":\"plugin host not loaded\"}");
        }
        const QByteArray idUtf8       = marketplaceId.toUtf8();
        const QByteArray verUtf8      = version.toUtf8();
        const QByteArray urlUtf8      = manifestUrl.toUtf8();
        const QByteArray shaUtf8      = expectedSha256.toUtf8();
        const char *shaPtr            = expectedSha256.isEmpty() ? nullptr : shaUtf8.constData();
        const char *verPtr            = version.isEmpty() ? nullptr : verUtf8.constData();
        return adoptFfiString(plugin_host_install_plugin(m_handle, idUtf8.constData(), verPtr,
                                                         urlUtf8.constData(), shaPtr));
}

QByteArray PluginHostManager::uninstallPlugin(const QString &pluginName) {
        if (!m_handle) {
                return QByteArray("{\"ok\":false,\"error\":\"plugin host not loaded\"}");
        }
        const QByteArray nameUtf8 = pluginName.toUtf8();
        return adoptFfiString(plugin_host_uninstall_plugin(m_handle, nameUtf8.constData()));
}

int PluginHostManager::setConfigTrampoline(void *userData, const char *key, const char *value) {
        auto *self = static_cast< PluginHostManager * >(userData);
        if (!self || !self->m_server || !key) {
                return -1;
        }
        const std::string keyStr(key);
        const std::string valueStr(value ? value : "");
        self->m_server->m_dbWrapper.setConfiguration(
                static_cast< unsigned int >(self->m_server->iServerNum), keyStr, valueStr);
        if (Meta::mp && Meta::mp->qsSettings) {
                Meta::mp->qsSettings->setValue(QString::fromStdString(keyStr),
                                               QString::fromStdString(valueStr));
        }
        return 0;
}

int PluginHostManager::deleteConfigPrefixTrampoline(void *userData, const char *prefix) {
        auto *self = static_cast< PluginHostManager * >(userData);
        if (!self || !self->m_server || !prefix) {
                return -1;
        }
        const std::string prefixStr(prefix);
        const auto serverId = static_cast< unsigned int >(self->m_server->iServerNum);
        const auto all      = self->m_server->m_dbWrapper.getAllConfigurations(serverId);
        for (const auto &entry : all) {
                if (entry.first.rfind(prefixStr, 0) == 0) {
                        self->m_server->m_dbWrapper.clearConfiguration(serverId, entry.first);
                        if (Meta::mp && Meta::mp->qsSettings) {
                                Meta::mp->qsSettings->remove(QString::fromStdString(entry.first));
                        }
                }
        }
        return 0;
}

namespace {
// Allocate a u32 array of length `n` via malloc so the Rust host's
// free_sessions trampoline (which calls std::free) can release it.
// Returns nullptr on allocation failure or when n == 0.
uint32_t *allocSessionArray(size_t n) {
        if (n == 0) {
                return nullptr;
        }
        return static_cast< uint32_t * >(std::malloc(sizeof(uint32_t) * n));
}
} // namespace

uint32_t *PluginHostManager::sessionsInChannelTrampoline(void *userData, uint32_t /*serverId*/,
                                                          uint32_t channelId, size_t *outCount) {
        if (outCount) {
                *outCount = 0;
        }
        auto *self = static_cast< PluginHostManager * >(userData);
        if (!self || !self->m_server || !outCount) {
                return nullptr;
        }
        QReadLocker rl(&self->m_server->qrwlVoiceThread);
        ::Channel *chan = self->m_server->qhChannels.value(channelId);
        if (!chan) {
                return nullptr;
        }
        const auto &members = chan->qlUsers;
        const size_t n      = static_cast< size_t >(members.size());
        if (n == 0) {
                return nullptr;
        }
        uint32_t *buf = allocSessionArray(n);
        if (!buf) {
                return nullptr;
        }
        size_t i = 0;
        for (const ::User *u : members) {
                if (u) {
                        buf[i++] = u->uiSession;
                }
        }
        *outCount = i;
        return buf;
}

uint32_t *PluginHostManager::allSessionsTrampoline(void *userData, uint32_t /*serverId*/,
                                                    size_t *outCount) {
        if (outCount) {
                *outCount = 0;
        }
        auto *self = static_cast< PluginHostManager * >(userData);
        if (!self || !self->m_server || !outCount) {
                return nullptr;
        }
        QReadLocker rl(&self->m_server->qrwlVoiceThread);
        const auto sessions = self->m_server->qhUsers.keys();
        const size_t n      = static_cast< size_t >(sessions.size());
        if (n == 0) {
                return nullptr;
        }
        uint32_t *buf = allocSessionArray(n);
        if (!buf) {
                return nullptr;
        }
        for (size_t i = 0; i < n; ++i) {
                buf[i] = sessions[static_cast< int >(i)];
        }
        *outCount = n;
        return buf;
}

bool PluginHostManager::findSessionByNameTrampoline(void *userData, uint32_t /*serverId*/,
                                                     const char *name, uint32_t *outSession) {
        auto *self = static_cast< PluginHostManager * >(userData);
        if (!self || !self->m_server || !name || !outSession) {
                return false;
        }
        const QString target = QString::fromUtf8(name);
        QReadLocker rl(&self->m_server->qrwlVoiceThread);
        for (auto it = self->m_server->qhUsers.constBegin();
             it != self->m_server->qhUsers.constEnd(); ++it) {
                ServerUser *u = it.value();
                if (u && u->qsName == target) {
                        *outSession = u->uiSession;
                        return true;
                }
        }
        return false;
}

void PluginHostManager::freeSessionsTrampoline(void * /*userData*/, uint32_t *ptr,
                                                size_t /*count*/) {
        if (ptr) {
                std::free(ptr);
        }
}
