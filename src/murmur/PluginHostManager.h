// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#ifndef PLUGIN_HOST_MANAGER_H_
#define PLUGIN_HOST_MANAGER_H_

#include <QByteArray>
#include <QHash>
#include <QObject>
#include <QString>
#include <QVector>

#include <cstdint>
#include <functional>

#include "ServerEventDistributor.h"
#include "mumble_plugin_host.h"

namespace MumbleProto {
class PluginMessage;
class PluginRegistry;
}

class Server;
class User;

/// Owns the Rust plugin-host cdylib and bridges Mumble server events
/// (client connect/disconnect, plugin data) to it. Also implements the
/// `PluginHostCallbacks` callback table the host uses to call back into
/// the server (send PluginDataTransmission, query session/channel state,
/// read configuration).
///
/// One instance per virtual server. Construction loads the cdylib;
/// destruction unloads it. All public methods must be called from the
/// server's main event-loop thread (the cdylib internally hops onto its
/// own runtime thread pool).
class PluginHostManager : public QObject, public EventSubscriber {
	Q_OBJECT
	Q_DISABLE_COPY(PluginHostManager)

public:
	explicit PluginHostManager(Server *server, QObject *parent = nullptr);
	~PluginHostManager() override;

	// ---- EventSubscriber fan-out entry points ----
	// The plugin host consumes the unified connect/disconnect events (it pulls
	// session/name/hash out of the User) and the unified inbound-plugin event.
	void onUserConnected(Server &, const User *user) override;
	void onUserDisconnected(Server &, const User *user) override;
	void onUserStateChanged(Server &, const User *user) override;
	void onPluginMessage(Server &, const PluginInbound &in) override;

        /// Build the PluginRegistry message for the currently loaded
        /// set of plugins.  The server sends this right after ServerSync.
        void fillRegistry(::MumbleProto::PluginRegistry &out) const;

        /// Whether the host loaded successfully.
        bool isLoaded() const { return m_handle != nullptr; }

        // ---- Plugin admin (FancyPluginAdmin wire IDs 146-151) ----

        /// JSON snapshot of every known plugin.  See
        /// `plugin_host_list_plugins` in the generated header for the
        /// payload shape.  Returns an empty string on failure.
        QByteArray listPluginsJson() const;

        /// Toggle a plugin's enabled state.  Returns the FFI's JSON
        /// result envelope ({"ok":true} or {"ok":false,"error":".."}).
        QByteArray setPluginEnabled(const QString &pluginName, bool enabled);

        /// Download and install a plugin from the marketplace.  The
        /// new plugin starts disabled.  Returns the FFI's JSON result
        /// envelope; on success it also carries `plugin_name`.
        /// `expectedSha256` may be empty to skip the caller-side
        /// manifest digest check.
        QByteArray installPlugin(const QString &marketplaceId, const QString &version,
                                 const QString &manifestUrl, const QString &expectedSha256);

        /// Drop a plugin, delete its cdylib, and clear its
        /// `plugin.<name>.*` settings.  Returns the FFI's JSON envelope.
        QByteArray uninstallPlugin(const QString &pluginName);

        // ---- Generic request/response bridge (feature-agnostic) ----

        /// Forward a generic request to `pluginName` as a `PluginMessage`
        /// (`payload_type` + opaque `payload`).  The plugin may later deliver a
        /// typed response through the host's `send_request_response` callback;
        /// register a handler for it with `registerResponseHandler`.  This class
        /// has no knowledge of any specific feature's payloads.
        void sendPluginRequest(const QString &pluginName, const QString &payloadType,
                               uint32_t senderSession, const QByteArray &payload);

        /// Handler invoked when a plugin delivers a response of a given type.
        using RequestResponseHandler =
            std::function< void(uint32_t targetSession, const QString &requestId,
                                const QByteArray &payload) >;

        /// Register (or replace) the handler for `responseType`.  Handlers should
        /// be registered at startup and remain valid for the host's lifetime.
        void registerResponseHandler(const QString &responseType, RequestResponseHandler handler);

private:

        // -- Forwarders to the Rust plugin host (invoked from the overrides above) --
        void onClientConnected(uint32_t session, const QString &username, const QString &certHash, int64_t userId);
        void onClientDisconnected(uint32_t session);
        void onPluginData(uint32_t senderSession, const QString &dataId, const QByteArray &data);
        void onPluginMessage(uint32_t senderSession, const QString &senderName,
                             const ::MumbleProto::PluginMessage &msg);

        // -- C callback trampolines (called from the Rust runtime) --
        static int sendPluginDataTrampoline(void *userData, uint32_t serverId, uint32_t targetSession,
                                            const char *dataId, const uint8_t *data, size_t dataLen);
        static bool isSessionActiveTrampoline(void *userData, uint32_t serverId, uint32_t session);
        static bool userHasChannelAccessTrampoline(void *userData, uint32_t serverId, uint32_t session,
                                                   uint32_t channel);
        static bool hasPermissionTrampoline(void *userData, uint32_t serverId, uint32_t session,
                                            uint32_t channel, uint32_t permissionFlags);
        static bool currentChannelTrampoline(void *userData, uint32_t serverId, uint32_t session,
                                             uint32_t *outChannel);
        static char *getConfigTrampoline(void *userData, const char *key);
        static void freeStringTrampoline(void *userData, char *ptr);
        static int sendPluginMessageTrampoline(void *userData, uint32_t serverId,
                                               const char *pluginName, const char *payloadType,
                                               const uint8_t *payload, size_t payloadLen,
                                               const uint32_t *targetSessions, size_t targetLen,
                                               bool channelIdPresent, uint32_t channelId);
        static int setConfigTrampoline(void *userData, const char *key, const char *value);
        static int deleteConfigPrefixTrampoline(void *userData, const char *prefix);
        static uint32_t *sessionsInChannelTrampoline(void *userData, uint32_t serverId,
                                                     uint32_t channelId, size_t *outCount);
        static uint32_t *allSessionsTrampoline(void *userData, uint32_t serverId,
                                               size_t *outCount);
        static bool findSessionByNameTrampoline(void *userData, uint32_t serverId,
                                                const char *name, uint32_t *outSession);
        static void freeSessionsTrampoline(void *userData, uint32_t *ptr, size_t count);
        static int sendRequestResponseTrampoline(void *userData, uint32_t serverId,
                                                 const char *responseType, const char *requestId,
                                                 uint32_t targetSession, const uint8_t *payload,
                                                 size_t payloadLen);

        Server *m_server;
        PluginHostHandle *m_handle;
        /// Response-type -> handler registry for the generic request/response
        /// bridge.  Populated once at startup (read-only thereafter, so the
        /// callback thread can look up without locking).
        QHash< QString, RequestResponseHandler > m_responseHandlers;
        /// Last registered user_id announced to the host per session, so
        /// onUserStateChanged re-announces a client only when its registration
        /// actually changed (not on every mute/move/comment).
        QHash< uint32_t, int64_t > m_lastUserId;
};

#endif // PLUGIN_HOST_MANAGER_H_
