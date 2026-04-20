// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#ifndef LINK_PREVIEW_MANAGER_H_
#define LINK_PREVIEW_MANAGER_H_

#include <QDateTime>
#include <QHash>
#include <QJsonObject>
#include <QList>
#include <QMutex>
#include <QNetworkAccessManager>
#include <QObject>
#include <QUrl>

#include <memory>
#include <vector>

class Server;
class LinkPreviewPlugin;

/// Orchestrates link preview fetching via a plugin chain.
///
/// Clients send FancyLinkPreviewRequest; the manager validates the
/// URLs, rate-limits the caller, dispatches each URL to matching
/// plugins (sorted by priority), caches results, and sends a
/// FancyLinkPreviewResponse back to the requesting user.
class LinkPreviewManager : public QObject {
	Q_OBJECT
	Q_DISABLE_COPY(LinkPreviewManager)

public:
	explicit LinkPreviewManager(Server *server, QObject *parent = nullptr);

	/// Process an incoming link preview request from a client.
	void handlePreviewRequest(uint32_t userSession, const QStringList &urls, const QString &requestId);

	/// Register a plugin.  Plugins are sorted by priority (ascending).
	void registerPlugin(std::unique_ptr< LinkPreviewPlugin > plugin);

	static constexpr int MAX_URLS_PER_REQUEST   = 5;
	static constexpr int MAX_CONCURRENT_FETCHES = 20;
	static constexpr int CACHE_TTL_SECS         = 3600;
	static constexpr int MAX_CACHE_ENTRIES      = 2000;
	static constexpr int MAX_REQUESTS_PER_MIN   = 10;

private:
	struct CacheEntry {
		QJsonObject embed;
		qint64 fetchedAtMs;
	};

	struct PendingRequest {
		uint32_t userSession;
		QString requestId;
		int remainingFetches;
		QList< QJsonObject > embeds;
	};

	Server *m_server;
	std::unique_ptr< QNetworkAccessManager > m_networkManager;

	std::vector< std::unique_ptr< LinkPreviewPlugin > > m_plugins;

	QHash< QString, CacheEntry > m_cache;
	QMutex m_cacheMutex;

	QHash< QString, std::shared_ptr< PendingRequest > > m_pendingRequests;
	int m_activeFetches = 0;

	// Per-user sliding-window rate limiting.
	QHash< uint32_t, QList< qint64 > > m_userRequestTimestamps;

	void initDefaultPlugins();

	bool isRateLimited(uint32_t userSession);
	QList< QUrl > validateUrls(const QStringList &urls);

	void fetchUrl(const QUrl &url, std::shared_ptr< PendingRequest > pending);
	void tryPluginChain(const QUrl &url, std::vector< LinkPreviewPlugin * > plugins,
						std::shared_ptr< PendingRequest > pending);

	void onFetchResolved(std::shared_ptr< PendingRequest > pending, const QJsonObject &embed,
						 const QUrl &url);
	void onFetchFailed(std::shared_ptr< PendingRequest > pending);
	void trySendResponse(std::shared_ptr< PendingRequest > pending);

	void sendResponse(uint32_t userSession, const QString &requestId,
					  const QList< QJsonObject > &embeds);
	static void populateProtoEmbed(void *protoEmbed, const QJsonObject &json);
};

#endif // LINK_PREVIEW_MANAGER_H_
