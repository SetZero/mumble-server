// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#ifndef PLUGIN_HOST_MANAGER_H_
#define PLUGIN_HOST_MANAGER_H_

#include <QByteArray>
#include <QObject>
#include <QString>

#include <cstdint>

#include "mumble_plugin_host.h"

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

        /// Forward an inbound FancyLiveDocOpen (wire ID 141) to the plugin host.
        void onFancyLiveDocOpen(uint32_t senderSession, uint32_t channelId,
                                const QString &slug, const QString &title);

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
        static int sendFancyLiveDocInviteTrampoline(void *userData, uint32_t serverId,
                                                    uint32_t targetSession, uint32_t channelId,
                                                    const char *slug, const char *title,
                                                    const char *wsUrl, const char *token);

        Server *m_server;
        PluginHostHandle *m_handle;
};

#endif // PLUGIN_HOST_MANAGER_H_
