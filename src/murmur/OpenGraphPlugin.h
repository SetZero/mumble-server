// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#ifndef OPEN_GRAPH_PLUGIN_H_
#define OPEN_GRAPH_PLUGIN_H_

#include "LinkPreviewPlugin.h"

#include <QNetworkRequest>

#include <optional>

/// Open Graph / HTML meta tag scraping fallback plugin.
///
/// Handles any HTTP(S) URL by fetching the page and parsing
/// <meta property="og:..."> tags.  If OG parsing yields no title,
/// the plugin also attempts oEmbed discovery via <link> tags.
class OpenGraphPlugin : public LinkPreviewPlugin {
	Q_OBJECT
public:
	explicit OpenGraphPlugin(QObject *parent = nullptr);

	QString name() const override;
	bool canHandle(const QUrl &url) const override;
	int priority() const override { return 1000; }
	void fetchPreview(const QUrl &url, QNetworkAccessManager *nam,
					  SuccessCallback onSuccess, FailureCallback onFailure) override;

private:
	void fetchPage(const QUrl &url, QNetworkAccessManager *nam, SuccessCallback onSuccess,
				   FailureCallback onFailure, int redirectCount);

	static QJsonObject parseOpenGraphTags(const QByteArray &html, const QUrl &url);
	static void parseMetaTags(const QString &content, QHash< QString, QString > &meta);
	static void populateImageAndVideo(QJsonObject &embed, const QHash< QString, QString > &meta,
									  const QUrl &pageUrl);
	static void classifyEmbedType(QJsonObject &embed, const QHash< QString, QString > &meta);
	static QString discoverOEmbedLink(const QByteArray &html);

	// Rich extraction helpers added with the v2 preview rework.
	static QString extractHtmlLang(const QString &content);
	static QString extractCanonical(const QString &content, const QUrl &pageUrl);
	static QString extractFavicon(const QString &content, const QUrl &pageUrl);
	static QString stripTags(const QString &fragment);
	static QString extractMainText(const QString &content);
	static QString summarise(const QString &mainText, int maxChars);
	static QString readingTime(const QString &mainText);
	static void populateExtraFields(QJsonObject &embed,
									const QHash< QString, QString > &meta);

	// Sub-functions of parseOpenGraphTags — each populates one concern.
	static void populateBasicFields(QJsonObject &embed, const QHash< QString, QString > &meta,
									const QString &content, const QUrl &url);
	static void populateAuthorAndMetadata(QJsonObject &embed,
										  const QHash< QString, QString > &meta,
										  const QString &content, const QUrl &url);
	static void populateKeywords(QJsonObject &embed, const QHash< QString, QString > &meta);
	static void populateNsfw(QJsonObject &embed, const QHash< QString, QString > &meta);
	static void populateFaviconField(QJsonObject &embed, const QString &content, const QUrl &url);
	static void populateSummaryAndReadingTime(QJsonObject &embed, const QString &content);

	// Builds the standard HTML-page request (shared by fetchPage and tests).
	static QNetworkRequest buildPageRequest(const QUrl &url);

	// Parses a discovered oEmbed JSON payload. Returns nullopt on malformed
	// input or when the response carries no title.
	static std::optional< QJsonObject > parseDiscoveredOEmbed(const QByteArray &data,
															  const QUrl &originalUrl);

	void fetchDiscoveredOEmbed(const QString &endpoint, const QUrl &originalUrl,
							   QNetworkAccessManager *nam, SuccessCallback onSuccess,
							   FailureCallback onFailure);
};

#endif // OPEN_GRAPH_PLUGIN_H_
