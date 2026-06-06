// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#ifndef LINK_PREVIEW_BRIDGE_H_
#define LINK_PREVIEW_BRIDGE_H_

#include <QByteArray>
#include <QString>
#include <QStringList>

#include <cstdint>

class Server;
class PluginHostManager;

/// Link-preview-specific glue over the generic [`PluginHostManager`]
/// request/response bridge.
///
/// Keeps all link-preview knowledge out of the generic plugin host: it forwards
/// a client `FancyLinkPreviewRequest` to the `fancy-link-preview` plugin (as a
/// generic `preview.request` message) and registers a handler for the plugin's
/// `link-preview` response that packs the returned JSON embeds into a
/// `FancyLinkPreviewResponse` and sends it to the requesting user.
///
/// Construct after the `PluginHostManager` exists and destroy before it (so the
/// plugin host stops delivering callbacks before this handler goes away).
class LinkPreviewBridge {
public:
	LinkPreviewBridge(Server *server, PluginHostManager *pluginHost);

	/// Forward a client link-preview request to the plugin.  The response is
	/// delivered asynchronously to `session` once the plugin replies.
	void requestPreviews(uint32_t session, const QStringList &urls, const QString &requestId);

private:
	/// Response handler registered with the plugin host for the
	/// `"link-preview"` response type.  Builds and sends the
	/// `FancyLinkPreviewResponse`.  Runs on the plugin host's callback thread.
	void deliverResponse(uint32_t targetSession, const QString &requestId,
						 const QByteArray &embedsJson);

	Server *m_server;
	PluginHostManager *m_pluginHost;
};

#endif // LINK_PREVIEW_BRIDGE_H_
