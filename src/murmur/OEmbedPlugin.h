// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#ifndef OEMBED_PLUGIN_H_
#define OEMBED_PLUGIN_H_

#include "LinkPreviewPlugin.h"

#include <QRegularExpression>

#include <functional>

/// oEmbed-based link preview plugin.
///
/// Each instance is configured with a URL pattern and an oEmbed JSON
/// endpoint.  Multiple instances can be registered for different
/// providers (YouTube, Vimeo, Spotify, ...).
///
/// An optional @p ogUrlTransform functor may be supplied to rewrite the
/// URL before any secondary OpenGraph fallback fetch.  This allows
/// provider-specific quirks (e.g. redirecting reddit.com to old.reddit.com
/// for proper SSR HTML) to live entirely inside the plugin registration
/// site rather than accumulating as if-else chains in the manager.
class OEmbedPlugin : public LinkPreviewPlugin {
	Q_OBJECT
public:
	using UrlTransform = std::function< QUrl(const QUrl &) >;

	OEmbedPlugin(const QString &providerName, const QString &urlPattern,
				 const QString &oembedEndpoint, QObject *parent = nullptr,
				 UrlTransform ogUrlTransform = {});

	QString name() const override;
	bool canHandle(const QUrl &url) const override;
	int priority() const override { return 10; }
	void fetchPreview(const QUrl &url, QNetworkAccessManager *nam,
					  SuccessCallback onSuccess, FailureCallback onFailure) override;
	QUrl transformUrlForOgFallback(const QUrl &url) const override;

private:
	QString m_name;
	QRegularExpression m_urlPattern;
	QString m_oembedEndpoint;
	UrlTransform m_ogUrlTransform;

	static QJsonObject oembedToEmbed(const QJsonObject &oembed, const QUrl &originalUrl);
	static QString extractIframeSrc(const QString &html);
};

#endif // OEMBED_PLUGIN_H_
