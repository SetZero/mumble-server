// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#ifndef OEMBED_PLUGIN_H_
#define OEMBED_PLUGIN_H_

#include "LinkPreviewPlugin.h"

#include <QRegularExpression>

/// oEmbed-based link preview plugin.
///
/// Each instance is configured with a URL pattern and an oEmbed JSON
/// endpoint.  Multiple instances can be registered for different
/// providers (YouTube, Vimeo, Spotify, ...).
class OEmbedPlugin : public LinkPreviewPlugin {
	Q_OBJECT
public:
	OEmbedPlugin(const QString &providerName, const QString &urlPattern,
				 const QString &oembedEndpoint, QObject *parent = nullptr);

	QString name() const override;
	bool canHandle(const QUrl &url) const override;
	int priority() const override { return 10; }
	void fetchPreview(const QUrl &url, QNetworkAccessManager *nam,
					  SuccessCallback onSuccess, FailureCallback onFailure) override;

private:
	QString m_name;
	QRegularExpression m_urlPattern;
	QString m_oembedEndpoint;

	static QJsonObject oembedToEmbed(const QJsonObject &oembed, const QUrl &originalUrl);
	static QString extractIframeSrc(const QString &html);
};

#endif // OEMBED_PLUGIN_H_
