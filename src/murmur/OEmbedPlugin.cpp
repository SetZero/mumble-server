// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#include "OEmbedPlugin.h"

#include <QJsonDocument>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QUrlQuery>

OEmbedPlugin::OEmbedPlugin(const QString &providerName, const QString &urlPattern,
							 const QString &oembedEndpoint, QObject *parent)
	: LinkPreviewPlugin(parent),
	  m_name(providerName),
	  m_urlPattern(urlPattern, QRegularExpression::CaseInsensitiveOption),
	  m_oembedEndpoint(oembedEndpoint) {
}

QString OEmbedPlugin::name() const {
	return m_name;
}

bool OEmbedPlugin::canHandle(const QUrl &url) const {
	return m_urlPattern.match(url.toString()).hasMatch();
}

void OEmbedPlugin::fetchPreview(const QUrl &url, QNetworkAccessManager *nam,
								SuccessCallback onSuccess, FailureCallback onFailure) {
	QUrl oembedUrl(m_oembedEndpoint);
	QUrlQuery query;
	query.addQueryItem(QStringLiteral("url"), url.toString());
	query.addQueryItem(QStringLiteral("format"), QStringLiteral("json"));
	query.addQueryItem(QStringLiteral("maxwidth"), QStringLiteral("512"));
	query.addQueryItem(QStringLiteral("maxheight"), QStringLiteral("512"));
	oembedUrl.setQuery(query);

	QNetworkRequest request(oembedUrl);
	request.setHeader(QNetworkRequest::UserAgentHeader, QStringLiteral("FancyMumbleBot/1.0"));
	request.setTransferTimeout(FETCH_TIMEOUT_MS);

	QNetworkReply *reply = nam->get(request);

	connect(reply, &QNetworkReply::finished, this, [reply, url, onSuccess, onFailure]() {
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

		QJsonObject embed = oembedToEmbed(doc.object(), url);
		if (embed.isEmpty()) {
			onFailure();
			return;
		}

		onSuccess(embed);
	});
}

// ---- oEmbed response -> normalised embed object ---------------------

QJsonObject OEmbedPlugin::oembedToEmbed(const QJsonObject &oembed, const QUrl &originalUrl) {
	QJsonObject embed;
	embed.insert(QStringLiteral("url"), originalUrl.toString());

	QString title = oembed.value(QStringLiteral("title")).toString();
	if (!title.isEmpty())
		embed.insert(QStringLiteral("title"), title.left(256));

	// Provider.
	QString providerName = oembed.value(QStringLiteral("provider_name")).toString();
	QString providerUrl  = oembed.value(QStringLiteral("provider_url")).toString();
	if (!providerName.isEmpty()) {
		QJsonObject provider;
		provider.insert(QStringLiteral("name"), providerName);
		if (!providerUrl.isEmpty())
			provider.insert(QStringLiteral("url"), providerUrl);
		embed.insert(QStringLiteral("provider"), provider);
		embed.insert(QStringLiteral("site_name"), providerName);
	}

	// Author.
	QString authorName = oembed.value(QStringLiteral("author_name")).toString();
	QString authorUrl  = oembed.value(QStringLiteral("author_url")).toString();
	if (!authorName.isEmpty()) {
		QJsonObject author;
		author.insert(QStringLiteral("name"), authorName);
		if (!authorUrl.isEmpty())
			author.insert(QStringLiteral("url"), authorUrl);
		embed.insert(QStringLiteral("author"), author);
	}

	// Thumbnail.
	QString thumbnailUrl = oembed.value(QStringLiteral("thumbnail_url")).toString();
	if (!thumbnailUrl.isEmpty()) {
		QJsonObject thumb;
		thumb.insert(QStringLiteral("url"), thumbnailUrl);
		int tw = oembed.value(QStringLiteral("thumbnail_width")).toInt();
		int th = oembed.value(QStringLiteral("thumbnail_height")).toInt();
		if (tw > 0)
			thumb.insert(QStringLiteral("width"), tw);
		if (th > 0)
			thumb.insert(QStringLiteral("height"), th);
		embed.insert(QStringLiteral("thumbnail"), thumb);
	}

	// Type classification and video/photo extraction.
	QString type = oembed.value(QStringLiteral("type")).toString().toLower();
	if (type == QLatin1String("video") || type == QLatin1String("rich")) {
		embed.insert(QStringLiteral("type"), QStringLiteral("video"));
		QString html = oembed.value(QStringLiteral("html")).toString();
		if (!html.isEmpty()) {
			QString iframeSrc = extractIframeSrc(html);
			if (!iframeSrc.isEmpty()) {
				QJsonObject vid;
				vid.insert(QStringLiteral("url"), iframeSrc);
				int w = oembed.value(QStringLiteral("width")).toInt();
				int h = oembed.value(QStringLiteral("height")).toInt();
				if (w > 0)
					vid.insert(QStringLiteral("width"), w);
				if (h > 0)
					vid.insert(QStringLiteral("height"), h);
				embed.insert(QStringLiteral("video"), vid);
			}
		}
	} else if (type == QLatin1String("photo")) {
		embed.insert(QStringLiteral("type"), QStringLiteral("image"));
		QString photoUrl = oembed.value(QStringLiteral("url")).toString();
		if (!photoUrl.isEmpty()) {
			QJsonObject img;
			img.insert(QStringLiteral("url"), photoUrl);
			int w = oembed.value(QStringLiteral("width")).toInt();
			int h = oembed.value(QStringLiteral("height")).toInt();
			if (w > 0)
				img.insert(QStringLiteral("width"), w);
			if (h > 0)
				img.insert(QStringLiteral("height"), h);
			embed.insert(QStringLiteral("image"), img);
		}
	} else {
		embed.insert(QStringLiteral("type"), QStringLiteral("link"));
	}

	return embed;
}

QString OEmbedPlugin::extractIframeSrc(const QString &html) {
	QRegularExpression iframeRe(
		QString::fromUtf8(R"REGEX(<iframe[^>]+src\s*=\s*"([^"]+)")REGEX"),
		QRegularExpression::CaseInsensitiveOption);
	auto m = iframeRe.match(html);
	if (m.hasMatch()) {
		QString src = decodeHtmlEntities(m.captured(1));
		QUrl url(src);
		if (url.isValid() && isSafeUrl(url))
			return src;
	}
	return {};
}
