// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#include "LinkPreviewManager.h"

#include "LinkPreviewPlugin.h"
#include "OEmbedPlugin.h"
#include "OpenGraphPlugin.h"
#include "Server.h"

#include "Mumble.pb.h"

#include <QDateTime>
#include <QElapsedTimer>
#include <QThread>
#include <QTimer>

#include <algorithm>

// ---- Construction / default plugin registration ---------------------

LinkPreviewManager::LinkPreviewManager(Server *server, QObject *parent)
	: QObject(parent), m_server(server) {
	m_networkManager = std::make_unique<QNetworkAccessManager>();
	initDefaultPlugins();

	// --- Event-loop heartbeat (diagnostic) ----------------------------
	// Posts a log line every 5s from the thread that owns this object.
	// If the gap between two consecutive heartbeats exceeds ~6s, the
	// event loop of that thread was blocked.  This is the smoking gun
	// for the "setTransferTimeout fires 15-20s late with
	// OperationCanceledError" symptom we see in production: QNAM's
	// transfer-timeout is implemented as a QTimer that can only fire
	// when the event loop actually runs.
	auto *heartbeat = new QTimer(this);
	heartbeat->setInterval(5000);
	heartbeat->setTimerType(Qt::PreciseTimer);
	auto *hbState = new qint64(QDateTime::currentMSecsSinceEpoch());
	connect(heartbeat, &QTimer::timeout, this, [hbState]() {
		qint64 now  = QDateTime::currentMSecsSinceEpoch();
		qint64 diff = now - *hbState;
		*hbState    = now;
		if (diff > 6000) {
			qWarning() << "[LinkPreview][heartbeat] EVENT LOOP STALL"
					   << diff << "ms since previous tick (expected ~5000)"
					   << "thread=" << QThread::currentThread();
		} else {
			qInfo() << "[LinkPreview][heartbeat]" << diff << "ms tick, thread="
					<< QThread::currentThread();
		}
	});
	heartbeat->start();
	qInfo() << "[LinkPreview] manager constructed; thread=" << QThread::currentThread()
			<< "QNAM thread=" << m_networkManager->thread();
}

void LinkPreviewManager::initDefaultPlugins() {
	auto addOEmbed = [this](std::string_view name, std::string_view pattern, std::string_view endpoint) {
		registerPlugin(std::make_unique<OEmbedPlugin>(
			QString::fromUtf8(name.data(), static_cast< qsizetype >(name.size())),
			QString::fromUtf8(pattern.data(), static_cast< qsizetype >(pattern.size())),
			QString::fromUtf8(endpoint.data(), static_cast< qsizetype >(endpoint.size())),
			this));
	};

	addOEmbed("YouTube",
			  R"(https?://(?:www\.)?youtube\.com/(?:watch|shorts/))",
			  "https://www.youtube.com/oembed");
	addOEmbed("YouTube Short",
			  R"(https?://youtu\.be/)",
			  "https://www.youtube.com/oembed");
	addOEmbed("Vimeo",
			  R"(https?://(?:www\.)?vimeo\.com/\d+)",
			  "https://vimeo.com/api/oembed.json");
	addOEmbed("Twitter/X",
			  R"(https?://(?:www\.)?(twitter|x)\.com/.+/status/)",
			  "https://publish.twitter.com/oembed");
	addOEmbed("Spotify",
			  R"(https?://open\.spotify\.com/)",
			  "https://open.spotify.com/oembed");
	addOEmbed("SoundCloud",
			  R"(https?://soundcloud\.com/)",
			  "https://soundcloud.com/oembed");
	addOEmbed("Twitch",
			  R"(https?://(?:www|clips)\.twitch\.tv/)",
			  "https://api.twitch.tv/v5/oembed");
	addOEmbed("TikTok",
			  R"(https?://(?:www\.)?tiktok\.com/)",
			  "https://www.tiktok.com/oembed");
	addOEmbed("Reddit",
			  R"(https?://(?:www\.)?reddit\.com/r/)",
			  "https://www.reddit.com/oembed");
	addOEmbed("Dailymotion",
			  R"(https?://(?:www\.)?dailymotion\.com/video/)",
			  "https://www.dailymotion.com/services/oembed");
	addOEmbed("Dailymotion Short",
			  R"(https?://dai\.ly/)",
			  "https://www.dailymotion.com/services/oembed");

	registerPlugin(std::make_unique<OpenGraphPlugin>(this));
}

void LinkPreviewManager::registerPlugin(std::unique_ptr< LinkPreviewPlugin > plugin) {
	m_plugins.push_back(std::move(plugin));
	std::sort(m_plugins.begin(), m_plugins.end(),
			  [](const auto &a, const auto &b) {
				  return a->priority() < b->priority();
			  });
}

// ---- Per-user rate limiting -----------------------------------------

bool LinkPreviewManager::isRateLimited(uint32_t userSession) {
	qint64 now      = QDateTime::currentMSecsSinceEpoch();
	qint64 windowMs = 60 * 1000LL;

	auto &timestamps = m_userRequestTimestamps[userSession];

	timestamps.erase(std::remove_if(timestamps.begin(), timestamps.end(),
									[now, windowMs](qint64 ts) { return (now - ts) > windowMs; }),
					 timestamps.end());

	if (timestamps.size() >= MAX_REQUESTS_PER_MIN)
		return true;

	timestamps.append(now);
	return false;
}

// ---- URL validation -------------------------------------------------

QList< QUrl > LinkPreviewManager::validateUrls(const QStringList &urls) {
	QList< QUrl > result;
	QSet< QString > seen;
	qsizetype limit = qMin(urls.size(), static_cast< qsizetype >(MAX_URLS_PER_REQUEST));

	for (qsizetype i = 0; i < limit; ++i) {
		QUrl url(urls[i], QUrl::StrictMode);
		if (!url.isValid() || url.host().isEmpty())
			continue;
		if (!LinkPreviewPlugin::isSafeUrl(url))
			continue;

		QString canonical = url.toString(QUrl::RemoveFragment);
		if (seen.contains(canonical))
			continue;
		seen.insert(canonical);
		result.append(url);
	}
	return result;
}

// ---- Request entry point --------------------------------------------

void LinkPreviewManager::handlePreviewRequest(uint32_t userSession, const QStringList &urls,
											  const QString &requestId) {
	qInfo() << "[LinkPreview] request from session" << userSession << "for" << urls.size() << "URLs"
			<< "thread=" << QThread::currentThread()
			<< "ts=" << QDateTime::currentMSecsSinceEpoch();

	if (isRateLimited(userSession)) {
		qWarning() << "[LinkPreview] rate limited session" << userSession;
		sendResponse(userSession, requestId, {});
		return;
	}

	QList< QUrl > validUrls = validateUrls(urls);
	if (validUrls.isEmpty()) {
		qWarning() << "[LinkPreview] no valid URLs after validation";
		sendResponse(userSession, requestId, {});
		return;
	}

	qInfo() << "[LinkPreview] processing" << validUrls.size() << "valid URLs";

	auto pending             = std::make_shared< PendingRequest >();
	pending->userSession     = userSession;
	pending->requestId       = requestId;
	pending->remainingFetches = static_cast< int >(validUrls.size());

	m_pendingRequests.insert(requestId, pending);

	for (const QUrl &url : validUrls) {
		fetchUrl(url, pending);
		qInfo() << "[LinkPreview] fetching URL:" << url.toString();
	}
}

// ---- Per-URL fetch orchestration ------------------------------------

void LinkPreviewManager::fetchUrl(const QUrl &url, std::shared_ptr< PendingRequest > pending) {
	// Check cache.
	{
		QMutexLocker lock(&m_cacheMutex);
		auto cacheIt = m_cache.find(url.toString());
		if (cacheIt != m_cache.end()) {
			qint64 age = QDateTime::currentMSecsSinceEpoch() - cacheIt->fetchedAtMs;
			if (age < CACHE_TTL_SECS * 1000LL) {
				onFetchResolved(pending, cacheIt->embed, url);
				return;
			}
			m_cache.erase(cacheIt);
		}
	}

	if (m_activeFetches >= MAX_CONCURRENT_FETCHES) {
		onFetchFailed(pending);
		return;
	}

	std::vector< LinkPreviewPlugin * > matchingPlugins;
	for (auto &plugin : m_plugins) {
		if (plugin->canHandle(url))
			matchingPlugins.push_back(plugin.get());
	}

	if (matchingPlugins.empty()) {
		onFetchFailed(pending);
		return;
	}

	++m_activeFetches;
	tryPluginChain(url, matchingPlugins, pending);
}

void LinkPreviewManager::tryPluginChain(const QUrl &url, std::vector< LinkPreviewPlugin * > plugins,
										std::shared_ptr< PendingRequest > pending) {
	if (plugins.empty()) {
		--m_activeFetches;
		onFetchFailed(pending);
		return;
	}

	auto *plugin = plugins.front();
	plugins.erase(plugins.begin());
	plugin->fetchPreview(
		url, m_networkManager.get(),
		// Success: cache result and resolve.
		[this, url, pending](const QJsonObject &embed) {
			--m_activeFetches;
			{
				QMutexLocker lock(&m_cacheMutex);
				if (m_cache.size() >= MAX_CACHE_ENTRIES) {
					auto oldest = m_cache.begin();
					for (auto it = m_cache.begin(); it != m_cache.end(); ++it) {
						if (it->fetchedAtMs < oldest->fetchedAtMs)
							oldest = it;
					}
					m_cache.erase(oldest);
				}
				m_cache.insert(url.toString(), { embed, QDateTime::currentMSecsSinceEpoch() });
			}
			onFetchResolved(pending, embed, url);
		},
		// Failure: try next plugin in the chain.
		[this, url, plugins, pending]() mutable { tryPluginChain(url, plugins, pending); });
}

// ---- Fetch completion tracking --------------------------------------

void LinkPreviewManager::onFetchResolved(std::shared_ptr< PendingRequest > pending,
										 const QJsonObject &embed, const QUrl & /*url*/) {
	if (!embed.isEmpty())
		pending->embeds.append(embed);
	--pending->remainingFetches;
	trySendResponse(pending);
}

void LinkPreviewManager::onFetchFailed(std::shared_ptr< PendingRequest > pending) {
	--pending->remainingFetches;
	trySendResponse(pending);
}

void LinkPreviewManager::trySendResponse(std::shared_ptr< PendingRequest > pending) {
	if (pending->remainingFetches > 0)
		return;

	m_pendingRequests.remove(pending->requestId);
	sendResponse(pending->userSession, pending->requestId, pending->embeds);
}

// ---- Build protobuf response and send to client ---------------------

static void populateProtoMedia(MumbleProto::FancyLinkPreviewResponse::Embed::Media *media, const QJsonObject &obj) {
	if (obj.contains("url"))
		media->set_url(obj.value("url").toString().toStdString());
	if (obj.contains("width"))
		media->set_width(obj.value("width").toInt());
	if (obj.contains("height"))
		media->set_height(obj.value("height").toInt());
}

void LinkPreviewManager::populateProtoEmbed(void *rawEmbed, const QJsonObject &json) {
	auto *embed = static_cast< MumbleProto::FancyLinkPreviewResponse::Embed * >(rawEmbed);

	if (json.contains("url"))
		embed->set_url(json.value("url").toString().toStdString());
	if (json.contains("type"))
		embed->set_type(json.value("type").toString().toStdString());
	if (json.contains("title"))
		embed->set_title(json.value("title").toString().toStdString());
	if (json.contains("description"))
		embed->set_description(json.value("description").toString().toStdString());
	if (json.contains("color"))
		embed->set_color(json.value("color").toInt());
	if (json.contains("site_name"))
		embed->set_site_name(json.value("site_name").toString().toStdString());

	QJsonObject thumbnailObj = json.value("thumbnail").toObject();
	if (!thumbnailObj.isEmpty())
		populateProtoMedia(embed->mutable_thumbnail(), thumbnailObj);

	QJsonObject imageObj = json.value("image").toObject();
	if (!imageObj.isEmpty())
		populateProtoMedia(embed->mutable_image(), imageObj);

	QJsonObject videoObj = json.value("video").toObject();
	if (!videoObj.isEmpty())
		populateProtoMedia(embed->mutable_video(), videoObj);

	QJsonObject providerObj = json.value("provider").toObject();
	if (!providerObj.isEmpty()) {
		auto *provider = embed->mutable_provider();
		if (providerObj.contains("name"))
			provider->set_name(providerObj.value("name").toString().toStdString());
		if (providerObj.contains("url"))
			provider->set_url(providerObj.value("url").toString().toStdString());
	}

	QJsonObject authorObj = json.value("author").toObject();
	if (!authorObj.isEmpty()) {
		auto *author = embed->mutable_author();
		if (authorObj.contains("name"))
			author->set_name(authorObj.value("name").toString().toStdString());
		if (authorObj.contains("url"))
			author->set_url(authorObj.value("url").toString().toStdString());
	}
}

void LinkPreviewManager::sendResponse(uint32_t userSession, const QString &requestId,
									  const QList< QJsonObject > &embeds) {
	qInfo() << "[LinkPreview] sending response with" << embeds.size() << "embeds to session" << userSession;

	MumbleProto::FancyLinkPreviewResponse response;
	response.set_request_id(requestId.toStdString());

	for (const QJsonObject &embedJson : embeds) {
		qInfo() << "[LinkPreview] embed fields:" << embedJson.keys();
		if (embedJson.contains(QStringLiteral("thumbnail"))) {
			qInfo() << "[LinkPreview] embed has thumbnail:" 
			        << embedJson.value(QStringLiteral("thumbnail")).toObject();
		}
		if (embedJson.contains(QStringLiteral("image"))) {
			qInfo() << "[LinkPreview] embed has image:" 
			        << embedJson.value(QStringLiteral("image")).toObject();
		}
		populateProtoEmbed(response.add_embeds(), embedJson);
	}

	QMutexLocker qml(&m_server->qmCache);
	ServerUser *u = m_server->qhUsers.value(userSession);
	if (u) {
		m_server->sendMessage(u, response);
		qInfo() << "[LinkPreview] response sent successfully";
	} else {
		qWarning() << "[LinkPreview] user session" << userSession << "no longer exists";
	}
}

