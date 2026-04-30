// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#include "LinkPreviewManager.h"

#include "DirectMediaPlugin.h"
#include "LinkPreviewPlugin.h"
#include "MediaPreviewBuilder.h"
#include "OEmbedPlugin.h"
#include "OpenGraphPlugin.h"
#include "Server.h"

#include "Mumble.pb.h"

#include <QDateTime>
#include <QJsonArray>
#include <QUrl>

#include <algorithm>

// ---- Construction / default plugin registration ---------------------

LinkPreviewManager::LinkPreviewManager(Server *server, QObject *parent)
	: QObject(parent), m_server(server) {
	m_networkManager = std::make_unique<QNetworkAccessManager>();
	initDefaultPlugins();
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
	// Reddit's www.reddit.com serves a JS-only SPA so its OG tags are never
	// present in a plain HTTP fetch.  We supply a URL transform that rewrites
	// any reddit.com URL to old.reddit.com, which still serves SSR HTML with
	// full og: meta tags.  The transform lives here, next to the registration,
	// rather than as a special case inside the manager.
	registerPlugin(std::make_unique< OEmbedPlugin >(
		QStringLiteral("Reddit"),
		QStringLiteral(R"(https?://(?:www\.)?reddit\.com/r/)"),
		QStringLiteral("https://www.reddit.com/oembed"),
		this,
		[](QUrl u) {
			u.setHost(QStringLiteral("old.reddit.com"));
			return u;
		}));
	addOEmbed("Dailymotion",
			  R"(https?://(?:www\.)?dailymotion\.com/video/)",
			  "https://www.dailymotion.com/services/oembed");
	addOEmbed("Dailymotion Short",
			  R"(https?://dai\.ly/)",
			  "https://www.dailymotion.com/services/oembed");

	// Direct media URLs are handled with high priority so the resulting
	// embed already carries the inlined preview bytes.
	registerPlugin(std::make_unique<DirectMediaPlugin>(this));

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
	qInfo() << "[LinkPreview] request from session" << userSession << "for" << urls.size() << "URLs";

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

bool LinkPreviewManager::needsOgEnrichment(const QJsonObject &embed) {
	return embed.value(QStringLiteral("description")).toString().isEmpty()
		&& embed.value(QStringLiteral("summary")).toString().isEmpty();
}

std::optional< std::reference_wrapper< LinkPreviewPlugin > >
LinkPreviewManager::findOpenGraphPlugin() const {
	for (const auto &p : m_plugins) {
		if (dynamic_cast< OpenGraphPlugin * >(p.get()) != nullptr)
			return *p;
	}
	return std::nullopt;
}

std::optional< std::reference_wrapper< LinkPreviewPlugin > >
LinkPreviewManager::findHandlingPlugin(const QUrl &url) const {
	for (const auto &p : m_plugins) {
		if (p->canHandle(url))
			return *p;
	}
	return std::nullopt;
}

void LinkPreviewManager::mergeOgIntoTarget(QJsonObject &target, const QJsonObject &og) {
	const QStringList scalarKeys = {
		QStringLiteral("description"),    QStringLiteral("summary"),
		QStringLiteral("site_name"),      QStringLiteral("canonical_url"),
		QStringLiteral("lang"),           QStringLiteral("published_time"),
		QStringLiteral("modified_time"),  QStringLiteral("reading_time"),
		QStringLiteral("content_type"),   QStringLiteral("favicon"),
	};
	for (const QString &key : scalarKeys) {
		if (target.value(key).toString().isEmpty() && !og.value(key).toString().isEmpty())
			target.insert(key, og.value(key));
	}
	const QStringList objectKeys = {
		QStringLiteral("image"), QStringLiteral("thumbnail"), QStringLiteral("author"),
	};
	for (const QString &key : objectKeys) {
		if (target.value(key).toObject().isEmpty() && !og.value(key).toObject().isEmpty())
			target.insert(key, og.value(key));
	}
	if (target.value(QStringLiteral("keywords")).toArray().isEmpty()
		&& !og.value(QStringLiteral("keywords")).toArray().isEmpty()) {
		target.insert(QStringLiteral("keywords"), og.value(QStringLiteral("keywords")));
	}
}

void LinkPreviewManager::onFetchResolved(std::shared_ptr< PendingRequest > pending,
										 const QJsonObject &embed, const QUrl &url) {
	if (embed.isEmpty()) {
		--pending->remainingFetches;
		trySendResponse(pending);
		return;
	}

	pending->embeds.append(embed);
	const int embedIndex = pending->embeds.size() - 1;

	// If the resolving plugin produced no description, supplement it with an
	// OpenGraph fetch.  The URL used for that fetch may be rewritten by the
	// plugin that originally handled this URL (e.g. Reddit's OEmbedPlugin
	// rewrites www.reddit.com -> old.reddit.com to get proper SSR HTML).
	if (needsOgEnrichment(embed) && url.isValid() && LinkPreviewPlugin::isSafeUrl(url)) {
		if (auto ogOpt = findOpenGraphPlugin()) {
			auto &og = ogOpt->get();
			const auto handlerOpt = findHandlingPlugin(url);
			const QUrl ogUrl = handlerOpt
				? handlerOpt->get().transformUrlForOgFallback(url)
				: url;
			qInfo() << "[LinkPreview] no description for" << url.toString()
					<< "-> running OpenGraph fallback on" << ogUrl.toString();
			auto onMergeDone = [this, embedIndex, pending]() {
				enrichEmbedWithPreviews(embedIndex, pending);
				--pending->remainingFetches;
				trySendResponse(pending);
			};
			og.fetchPreview(
				ogUrl, m_networkManager.get(),
				[this, embedIndex, pending, onMergeDone](const QJsonObject &ogEmbed) {
					if (embedIndex < pending->embeds.size() && !ogEmbed.isEmpty()) {
						QJsonObject merged = pending->embeds[embedIndex];
						mergeOgIntoTarget(merged, ogEmbed);
						pending->embeds[embedIndex] = merged;
					}
					onMergeDone();
				},
				[onMergeDone]() { onMergeDone(); });
			return;
		}
	}

	enrichEmbedWithPreviews(embedIndex, pending);
	--pending->remainingFetches;
	trySendResponse(pending);
}

void LinkPreviewManager::onFetchFailed(std::shared_ptr< PendingRequest > pending) {
	--pending->remainingFetches;
	trySendResponse(pending);
}

void LinkPreviewManager::trySendResponse(std::shared_ptr< PendingRequest > pending) {
	if (pending->remainingFetches > 0 || pending->remainingMediaFetches > 0)
		return;

	m_pendingRequests.remove(pending->requestId);
	sendResponse(pending->userSession, pending->requestId, pending->embeds);
}

// ---- Server-side image preview enrichment ---------------------------

void LinkPreviewManager::enrichEmbedWithPreviews(int embedIndex,
												 std::shared_ptr< PendingRequest > pending) {
	// Each (sub-object key, max-dimension) pair we want to enrich.
	const struct {
		const char *key;
		int maxDim;
	} targets[] = {
		{ "image", MediaPreviewBuilder::DEFAULT_MAX_DIM },
		{ "thumbnail", MediaPreviewBuilder::DEFAULT_MAX_DIM },
		{ "favicon", MediaPreviewBuilder::FAVICON_MAX_DIM },
	};

	for (const auto &t : targets) {
		QJsonObject sub = pending->embeds[embedIndex].value(QLatin1String(t.key)).toObject();
		if (sub.isEmpty())
			continue;
		// If the source plugin already inlined the preview bytes, skip.
		if (sub.contains(QStringLiteral("preview_data_b64")))
			continue;
		const QString urlStr = sub.value(QStringLiteral("url")).toString();
		if (urlStr.isEmpty())
			continue;
		QUrl url(urlStr);
		if (!url.isValid() || !LinkPreviewPlugin::isSafeUrl(url))
			continue;

		++pending->remainingMediaFetches;
		auto *builder = new MediaPreviewBuilder(this);
		const QString key = QLatin1String(t.key);
		builder->fetchAndDownscale(
			url, m_networkManager.get(), t.maxDim, MediaPreviewBuilder::JPEG_QUALITY,
			[this, embedIndex, pending, key, builder](
				const std::optional< MediaPreviewBuilder::Result > &res) {
				builder->deleteLater();
				if (embedIndex < pending->embeds.size()) {
					QJsonObject embed = pending->embeds[embedIndex];
					QJsonObject sub   = embed.value(key).toObject();
					if (res) {
						sub.insert(QStringLiteral("preview_data_b64"),
								   QString::fromLatin1(res->jpeg.toBase64()));
						sub.insert(QStringLiteral("preview_mime"), res->mime);
						sub.insert(QStringLiteral("preview_width"), res->previewWidth);
						sub.insert(QStringLiteral("preview_height"), res->previewHeight);
						sub.insert(QStringLiteral("original_size"),
								   static_cast< qint64 >(res->originalSize));
						if (!sub.contains(QStringLiteral("width")) && res->originalWidth > 0)
							sub.insert(QStringLiteral("width"), res->originalWidth);
						if (!sub.contains(QStringLiteral("height")) && res->originalHeight > 0)
							sub.insert(QStringLiteral("height"), res->originalHeight);
					}
					// Keep the upstream URL even when inlining failed — the
					// frontend's previewSrc() prefers data_url when present, and
					// falls back to url only when allowExternalResources is true,
					// so we don't silently drop content the user expects to see.
					embed.insert(key, sub);
					pending->embeds[embedIndex] = embed;
				}
				--pending->remainingMediaFetches;
				trySendResponse(pending);
			});
	}
}

// ---- Build protobuf response and send to client ---------------------

static void populateProtoMedia(MumbleProto::FancyLinkPreviewResponse::Embed::Media *media, const QJsonObject &obj) {
	if (obj.contains(QStringLiteral("url")))
		media->set_url(obj.value(QStringLiteral("url")).toString().toStdString());
	if (obj.contains(QStringLiteral("width")))
		media->set_width(obj.value(QStringLiteral("width")).toInt());
	if (obj.contains(QStringLiteral("height")))
		media->set_height(obj.value(QStringLiteral("height")).toInt());

	const QString b64 = obj.value(QStringLiteral("preview_data_b64")).toString();
	if (!b64.isEmpty()) {
		QByteArray bytes = QByteArray::fromBase64(b64.toLatin1());
		if (!bytes.isEmpty()) {
			media->set_preview_data(bytes.constData(), static_cast< std::size_t >(bytes.size()));
		}
	}
	if (obj.contains(QStringLiteral("preview_mime")))
		media->set_preview_mime(obj.value(QStringLiteral("preview_mime")).toString().toStdString());
	if (obj.contains(QStringLiteral("preview_width")))
		media->set_preview_width(obj.value(QStringLiteral("preview_width")).toInt());
	if (obj.contains(QStringLiteral("preview_height")))
		media->set_preview_height(obj.value(QStringLiteral("preview_height")).toInt());
	if (obj.contains(QStringLiteral("original_size"))) {
		media->set_original_size(
			static_cast< std::uint32_t >(obj.value(QStringLiteral("original_size")).toDouble()));
	}
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

	// --- Rich extensions ---------------------------------------------

	QJsonObject faviconObj = json.value(QStringLiteral("favicon")).toObject();
	if (!faviconObj.isEmpty())
		populateProtoMedia(embed->mutable_favicon(), faviconObj);

	if (json.contains(QStringLiteral("canonical_url")))
		embed->set_canonical_url(json.value(QStringLiteral("canonical_url")).toString().toStdString());
	if (json.contains(QStringLiteral("lang")))
		embed->set_lang(json.value(QStringLiteral("lang")).toString().toStdString());
	if (json.contains(QStringLiteral("published_time")))
		embed->set_published_time(
			json.value(QStringLiteral("published_time")).toString().toStdString());
	if (json.contains(QStringLiteral("modified_time")))
		embed->set_modified_time(
			json.value(QStringLiteral("modified_time")).toString().toStdString());
	if (json.contains(QStringLiteral("summary")))
		embed->set_summary(json.value(QStringLiteral("summary")).toString().toStdString());
	if (json.contains(QStringLiteral("content_type")))
		embed->set_content_type(
			json.value(QStringLiteral("content_type")).toString().toStdString());
	if (json.contains(QStringLiteral("content_length"))) {
		embed->set_content_length(
			static_cast< std::uint64_t >(json.value(QStringLiteral("content_length")).toDouble()));
	}
	if (json.contains(QStringLiteral("media_duration")))
		embed->set_media_duration(
			json.value(QStringLiteral("media_duration")).toString().toStdString());
	if (json.contains(QStringLiteral("nsfw")))
		embed->set_nsfw(json.value(QStringLiteral("nsfw")).toBool());
	if (json.contains(QStringLiteral("reading_time")))
		embed->set_reading_time(
			json.value(QStringLiteral("reading_time")).toString().toStdString());
	if (json.contains(QStringLiteral("fetched_at")))
		embed->set_fetched_at(json.value(QStringLiteral("fetched_at")).toString().toStdString());

	const QJsonArray keywordsArr = json.value(QStringLiteral("keywords")).toArray();
	for (const QJsonValue &v : keywordsArr) {
		const QString s = v.toString();
		if (!s.isEmpty())
			embed->add_keywords(s.toStdString());
	}

	const QJsonArray fieldsArr = json.value(QStringLiteral("fields")).toArray();
	for (const QJsonValue &v : fieldsArr) {
		const QJsonObject fo = v.toObject();
		if (fo.isEmpty())
			continue;
		auto *protoField = embed->add_fields();
		if (fo.contains(QStringLiteral("name")))
			protoField->set_name(fo.value(QStringLiteral("name")).toString().toStdString());
		if (fo.contains(QStringLiteral("value")))
			protoField->set_value(fo.value(QStringLiteral("value")).toString().toStdString());
		if (fo.contains(QStringLiteral("inline")))
			protoField->set_inline_(fo.value(QStringLiteral("inline")).toBool());
	}
}

void LinkPreviewManager::sendResponse(uint32_t userSession, const QString &requestId,
									  const QList< QJsonObject > &embeds) {
	qInfo() << "[LinkPreview] sending response with" << embeds.size() << "embeds to session" << userSession;

	MumbleProto::FancyLinkPreviewResponse response;
	response.set_request_id(requestId.toStdString());

	for (const QJsonObject &embedJson : embeds) {
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

