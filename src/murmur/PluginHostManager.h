// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#ifndef PLUGIN_HOST_MANAGER_H_
#define PLUGIN_HOST_MANAGER_H_

#include <QByteArray>
#include <QObject>
#include <QString>
#include <QVector>

#include <cstdint>

#include "mumble_plugin_host.h"

namespace MumbleProto {
class PluginMessage;
class PluginRegistry;
}

class Server;

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
class PluginHostManager : public QObject {
	Q_OBJECT
	Q_DISABLE_COPY(PluginHostManager)

public:
	explicit PluginHostManager(Server *server, QObject *parent = nullptr);
	~PluginHostManager() override;

	/// Forward a client-connected event to the plugin host.
	void onClientConnected(uint32_t session, const QString &username, const QString &certHash);

	/// Forward a client-disconnected event to the plugin host.
	void onClientDisconnected(uint32_t session);

	/// Forward an inbound PluginDataTransmission to the plugin host.
	void onPluginData(uint32_t senderSession, const QString &dataId, const QByteArray &data);

        /// Forward an inbound generic PluginMessage (wire ID 200) to the
        /// plugin host.  The host dispatches to the single plugin whose
        /// name matches msg.plugin_name(); unknown names are dropped.
        /// `senderName` is stamped server-side from the user's display
        /// name at the time of receipt.
        void onPluginMessage(uint32_t senderSession, const QString &senderName,
                             const ::MumbleProto::PluginMessage &msg);

        /// Build the PluginRegistry message for the currently loaded
        /// set of plugins.  The server sends this right after ServerSync.
        void fillRegistry(::MumbleProto::PluginRegistry &out) const;

        /// Whether the host loaded successfully.
        bool isLoaded() const { return m_handle != nullptr; }

private:
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

        Server *m_server;
        PluginHostHandle *m_handle;
};

#endif // PLUGIN_HOST_MANAGER_H_
