// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#ifndef LINK_PREVIEW_PLUGIN_H_
#define LINK_PREVIEW_PLUGIN_H_

#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QObject>
#include <QUrl>

#include <functional>

/// Abstract interface for link preview provider plugins.
///
/// Each plugin declares which URLs it can handle via canHandle() and
/// fetches metadata via fetchPreview().  The LinkPreviewManager
/// dispatches URLs to matching plugins sorted by priority (lower value
/// = higher priority).
class LinkPreviewPlugin : public QObject {
	Q_OBJECT
public:
	using SuccessCallback = std::function< void(const QJsonObject &embed) >;
	using FailureCallback = std::function< void() >;

	explicit LinkPreviewPlugin(QObject *parent = nullptr) : QObject(parent) {}
	~LinkPreviewPlugin() override = default;

	virtual QString name() const                                          = 0;
	virtual bool canHandle(const QUrl &url) const                         = 0;
	virtual int priority() const { return 100; }
	virtual void fetchPreview(const QUrl &url, QNetworkAccessManager *nam,
							  SuccessCallback onSuccess, FailureCallback onFailure) = 0;

        /// Return the URL that should be used for a secondary OpenGraph
        /// fallback fetch when the primary plugin produced no description.
        ///
        /// Plugins that serve broken / JS-rendered HTML on their canonical
        /// URL (e.g. Reddit) override this to supply an alternative URL
        /// (e.g. old.reddit.com) that returns proper SSR HTML with og: tags.
        /// The default implementation is the identity function.
        virtual QUrl transformUrlForOgFallback(const QUrl &url) const { return url; }

	static constexpr int MAX_REDIRECTS      = 5;
	// 20 s gives slow upstreams (YouTube/Spotify oembed, Cloudflare-fronted
	// pages on cold connections) enough time to respond; 10 s was too tight
	// and routinely tripped on first-hit fetches from servers without warm
	// DNS/TLS caches.
	static constexpr int FETCH_TIMEOUT_MS   = 20000;
	static constexpr int MAX_RESPONSE_BYTES = 1024 * 1024;

	/// Returns false for non-HTTP(S) schemes and private/loopback addresses
	/// (SSRF protection).
	static bool isSafeUrl(const QUrl &url);

	/// Returns true when @p host resolves to a private or loopback range.
	static bool isPrivateAddress(const QString &host);

	/// Replaces common HTML entities (&amp; &lt; &gt; &quot; &#39; &apos;)
	/// with their plain-text equivalents.
	static QString decodeHtmlEntities(const QString &input);
};

#endif // LINK_PREVIEW_PLUGIN_H_
