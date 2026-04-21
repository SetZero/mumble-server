// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#include "OpenGraphPlugin.h"

#include <QJsonDocument>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QUrlQuery>

OpenGraphPlugin::OpenGraphPlugin(QObject *parent) : LinkPreviewPlugin(parent) {
}

QString OpenGraphPlugin::name() const {
	return QStringLiteral("OpenGraph");
}

bool OpenGraphPlugin::canHandle(const QUrl &url) const {
	return isSafeUrl(url);
}

void OpenGraphPlugin::fetchPreview(const QUrl &url, QNetworkAccessManager *nam,
								   SuccessCallback onSuccess, FailureCallback onFailure) {
	fetchPage(url, nam, std::move(onSuccess), std::move(onFailure), 0);
}

// ---- Page fetching with manual redirect (SSRF-safe) -----------------

void OpenGraphPlugin::fetchPage(const QUrl &url, QNetworkAccessManager *nam,
								SuccessCallback onSuccess, FailureCallback onFailure,
								int redirectCount) {
	if (redirectCount > MAX_REDIRECTS) {
		onFailure();
		return;
	}

	QNetworkRequest request(url);
	request.setHeader(QNetworkRequest::UserAgentHeader,
					  QStringLiteral("Mozilla/5.0 (compatible; FancyMumbleBot/1.0; +http://fancymumble.com/bot)"));
	request.setRawHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
	request.setRawHeader("Accept-Language", "en-US,en;q=0.5");
	request.setTransferTimeout(10000); // Increased to 10 seconds
	request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);

	QNetworkReply *reply = nam->get(request);

	connect(reply, &QNetworkReply::finished, this,
			[this, reply, url, nam, onSuccess, onFailure, redirectCount]() {
				reply->deleteLater();

				int statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
				if (statusCode >= 300 && statusCode < 400) {
					QUrl redirectUrl = reply->header(QNetworkRequest::LocationHeader).toUrl();
					if (redirectUrl.isRelative())
						redirectUrl = url.resolved(redirectUrl);
					if (!isSafeUrl(redirectUrl)) {
						onFailure();
						return;
					}
					fetchPage(redirectUrl, nam, onSuccess, onFailure, redirectCount + 1);
					return;
				}

				if (reply->error() != QNetworkReply::NoError) {
					onFailure();
					return;
				}

				QByteArray data  = reply->read(MAX_RESPONSE_BYTES);
				QJsonObject embed = parseOpenGraphTags(data, url);

				// If OG yielded no title, try oEmbed discovery from <link> tags.
				if (embed.value(QStringLiteral("title")).toString().isEmpty()) {
					QString discoveredEndpoint = discoverOEmbedLink(data);
					if (!discoveredEndpoint.isEmpty()) {
						fetchDiscoveredOEmbed(discoveredEndpoint, url, nam, onSuccess, onFailure);
						return;
					}
				}

				if (embed.isEmpty() || embed.value(QStringLiteral("title")).toString().isEmpty()) {
					onFailure();
					return;
				}

				onSuccess(embed);
			});
}

// ---- HTML <meta> tag parsing ----------------------------------------

void OpenGraphPlugin::parseMetaTags(const QString &content, QHash< QString, QString > &meta) {
	// Matches <meta> with property/name + content in either order.
	QRegularExpression metaRe(
		QString::fromUtf8(
			R"REGEX(<meta\s+[^>]*?(?:(?:property|name)\s*=\s*"([^"]+)"[^>]*?content\s*=\s*"([^"]*?)"|content\s*=\s*"([^"]*?)"[^>]*?(?:property|name)\s*=\s*"([^"]+)"))REGEX"
		),
		QRegularExpression::CaseInsensitiveOption | QRegularExpression::DotMatchesEverythingOption);

	auto it = metaRe.globalMatch(content);
	while (it.hasNext()) {
		QRegularExpressionMatch m = it.next();
		QString prop, val;
		if (!m.captured(1).isEmpty()) {
			prop = m.captured(1).toLower();
			val  = m.captured(2);
		} else {
			prop = m.captured(4).toLower();
			val  = m.captured(3);
		}
		if (!prop.isEmpty() && !val.isEmpty())
			meta.insert(prop, decodeHtmlEntities(val));
	}
}

void OpenGraphPlugin::populateImageAndVideo(QJsonObject &embed,
											const QHash< QString, QString > &meta,
											const QUrl &pageUrl) {
	// Image / thumbnail.
	QString imageUrl = meta.value(QStringLiteral("og:image"),
								  meta.value(QStringLiteral("og:image:url"),
											 meta.value(QStringLiteral("twitter:image"))));
	if (!imageUrl.isEmpty()) {
		QUrl resolved = pageUrl.resolved(QUrl(imageUrl));
		if (isSafeUrl(resolved)) {
			QJsonObject img;
			img.insert(QStringLiteral("url"), resolved.toString());
			QString w = meta.value(QStringLiteral("og:image:width"));
			QString h = meta.value(QStringLiteral("og:image:height"));
			if (!w.isEmpty())
				img.insert(QStringLiteral("width"), w.toInt());
			if (!h.isEmpty())
				img.insert(QStringLiteral("height"), h.toInt());
			embed.insert(QStringLiteral("thumbnail"), img);
		}
	}

	// Video.
	QString videoUrl = meta.value(
		QStringLiteral("og:video"),
		meta.value(QStringLiteral("og:video:url"),
				   meta.value(QStringLiteral("og:video:secure_url"),
							  meta.value(QStringLiteral("twitter:player")))));
	if (!videoUrl.isEmpty()) {
		QUrl resolved = pageUrl.resolved(QUrl(videoUrl));
		if (isSafeUrl(resolved)) {
			QJsonObject vid;
			vid.insert(QStringLiteral("url"), resolved.toString());
			QString w = meta.value(QStringLiteral("og:video:width"),
								   meta.value(QStringLiteral("twitter:player:width")));
			QString h = meta.value(QStringLiteral("og:video:height"),
								   meta.value(QStringLiteral("twitter:player:height")));
			if (!w.isEmpty())
				vid.insert(QStringLiteral("width"), w.toInt());
			if (!h.isEmpty())
				vid.insert(QStringLiteral("height"), h.toInt());
			embed.insert(QStringLiteral("video"), vid);
		}
	}
}

void OpenGraphPlugin::classifyEmbedType(QJsonObject &embed,
										const QHash< QString, QString > &meta) {
	QString ogType     = meta.value(QStringLiteral("og:type"), QStringLiteral("website")).toLower();
	QString twitterCard = meta.value(QStringLiteral("twitter:card"));

	if (embed.contains(QStringLiteral("video"))) {
		embed.insert(QStringLiteral("type"), QStringLiteral("video"));
	} else if (ogType == QLatin1String("article") || ogType == QLatin1String("blog")) {
		embed.insert(QStringLiteral("type"), QStringLiteral("article"));
	} else if (twitterCard == QLatin1String("summary_large_image")
			   || ogType.startsWith(QLatin1String("image"))) {
		embed.insert(QStringLiteral("type"), QStringLiteral("image"));
	} else {
		embed.insert(QStringLiteral("type"), QStringLiteral("link"));
	}
}

QJsonObject OpenGraphPlugin::parseOpenGraphTags(const QByteArray &html, const QUrl &url) {
	QString content = QString::fromUtf8(html.left(65536));

	QHash< QString, QString > meta;
	parseMetaTags(content, meta);

	// Also grab <title>.
	QRegularExpression titleRe(QStringLiteral(R"(<title[^>]*>([^<]+)</title>)"),
							   QRegularExpression::CaseInsensitiveOption);
	auto titleMatch = titleRe.match(content);

	QJsonObject embed;
	embed.insert(QStringLiteral("url"), url.toString());

	QString title = meta.value(QStringLiteral("og:title"),
							   meta.value(QStringLiteral("twitter:title")));
	if (title.isEmpty() && titleMatch.hasMatch())
		title = decodeHtmlEntities(titleMatch.captured(1).trimmed());
	if (!title.isEmpty())
		embed.insert(QStringLiteral("title"), title.left(256));

	QString description = meta.value(
		QStringLiteral("og:description"),
		meta.value(QStringLiteral("twitter:description"), meta.value(QStringLiteral("description"))));
	if (!description.isEmpty())
		embed.insert(QStringLiteral("description"), description.left(4096));

	QString siteName = meta.value(QStringLiteral("og:site_name"));
	if (!siteName.isEmpty()) {
		embed.insert(QStringLiteral("site_name"), siteName);
	} else {
		embed.insert(QStringLiteral("site_name"),
					 url.host().remove(QRegularExpression(QStringLiteral("^www\\."))));
	}

	// Theme color.
	QString themeColor = meta.value(QStringLiteral("theme-color"));
	if (!themeColor.isEmpty()) {
		if (themeColor.startsWith(QLatin1Char('#')))
			themeColor = themeColor.mid(1);
		bool ok      = false;
		int colorInt = themeColor.toInt(&ok, 16);
		if (ok)
			embed.insert(QStringLiteral("color"), colorInt);
	}

	populateImageAndVideo(embed, meta, url);
	classifyEmbedType(embed, meta);

	return embed;
}

// ---- oEmbed discovery from HTML <link> tags -------------------------

QString OpenGraphPlugin::discoverOEmbedLink(const QByteArray &html) {
	QString content = QString::fromUtf8(html.left(65536));

	QRegularExpression linkRe(
		QString::fromUtf8(
			R"REGEX(<link[^>]+type\s*=\s*"application/json\+oembed"[^>]+href\s*=\s*"([^"]+)")REGEX"
		),
		QRegularExpression::CaseInsensitiveOption);
	auto m = linkRe.match(content);
	if (m.hasMatch())
		return decodeHtmlEntities(m.captured(1));

	// Reverse attribute order.
	QRegularExpression linkReReverse(
		QString::fromUtf8(
			R"REGEX(<link[^>]+href\s*=\s*"([^"]+)"[^>]+type\s*=\s*"application/json\+oembed")REGEX"
		),
		QRegularExpression::CaseInsensitiveOption);
	m = linkReReverse.match(content);
	if (m.hasMatch())
		return decodeHtmlEntities(m.captured(1));

	return {};
}

// ---- Fetch a discovered oEmbed endpoint (inline fallback) -----------

void OpenGraphPlugin::fetchDiscoveredOEmbed(const QString &endpoint, const QUrl &originalUrl,
											QNetworkAccessManager *nam, SuccessCallback onSuccess,
											FailureCallback onFailure) {
	QUrl oembedUrl(endpoint);
	if (!isSafeUrl(oembedUrl)) {
		onFailure();
		return;
	}

	QNetworkRequest request(oembedUrl);
	request.setHeader(QNetworkRequest::UserAgentHeader, QStringLiteral("FancyMumbleBot/1.0"));
	request.setTransferTimeout(FETCH_TIMEOUT_MS);

	QNetworkReply *reply = nam->get(request);

	connect(reply, &QNetworkReply::finished, this,
			[reply, originalUrl, onSuccess, onFailure]() {
				reply->deleteLater();

				if (reply->error() != QNetworkReply::NoError
					|| reply->bytesAvailable() > MAX_RESPONSE_BYTES) {
					onFailure();
					return;
				}

				QByteArray data = reply->readAll();
				QJsonParseError parseError;
				QJsonDocument doc = QJsonDocument::fromJson(data, &parseError);
				if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
					onFailure();
					return;
				}

				QJsonObject oembed = doc.object();
				QJsonObject embed;
				embed.insert(QStringLiteral("url"), originalUrl.toString());

				QString title = oembed.value(QStringLiteral("title")).toString();
				if (title.isEmpty()) {
					onFailure();
					return;
				}
				embed.insert(QStringLiteral("title"), title.left(256));

				QString providerName = oembed.value(QStringLiteral("provider_name")).toString();
				if (!providerName.isEmpty())
					embed.insert(QStringLiteral("site_name"), providerName);

				embed.insert(QStringLiteral("type"), QStringLiteral("link"));
				onSuccess(embed);
			});
}
