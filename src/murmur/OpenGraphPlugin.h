// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#ifndef OPEN_GRAPH_PLUGIN_H_
#define OPEN_GRAPH_PLUGIN_H_

#include "LinkPreviewPlugin.h"

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

	void fetchDiscoveredOEmbed(const QString &endpoint, const QUrl &originalUrl,
							   QNetworkAccessManager *nam, SuccessCallback onSuccess,
							   FailureCallback onFailure);
};

#endif // OPEN_GRAPH_PLUGIN_H_
