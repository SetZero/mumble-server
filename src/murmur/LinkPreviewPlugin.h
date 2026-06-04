// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#ifndef LINK_PREVIEW_PLUGIN_H_
#define LINK_PREVIEW_PLUGIN_H_

#include <QHostAddress>
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

	/// Cheap, synchronous SSRF pre-filter: returns false for non-HTTP(S)
	/// schemes, empty hosts, literal private/loopback/link-local addresses
	/// (in any encoding) and obviously-internal host names.
	///
	/// This does NOT resolve DNS, so a public host name that resolves to an
	/// internal address still passes here.  Any code that is about to issue a
	/// network request to a user-influenced URL MUST gate it through
	/// resolveAndCheck() instead, which validates the *resolved* addresses.
	static bool isSafeUrl(const QUrl &url);

	/// Returns true when @p host (a literal IP or host name) is known to be
	/// private/loopback/internal without performing DNS resolution.
	static bool isPrivateAddress(const QString &host);

	/// Returns true when @p addr falls in a loopback, link-local, private,
	/// CGNAT, multicast, broadcast or otherwise non-public range.  IPv4-mapped
	/// IPv6 addresses are normalised to IPv4 first so encodings such as
	/// `::ffff:127.0.0.1` are classified by their embedded IPv4 address.
	static bool isBlockedIp(const QHostAddress &addr);

	/// Authoritative, asynchronous SSRF gate.  Applies isSafeUrl(), then (for
	/// host names) resolves the host and rejects the URL if *any* resolved
	/// address is blocked by isBlockedIp().  Exactly one of @p onSafe /
	/// @p onUnsafe is invoked.  @p ctx scopes the async DNS callback's
	/// lifetime.  Every fetch of a user-influenced URL — including each
	/// redirect hop — must pass through this gate before the request is issued.
	static void resolveAndCheck(const QUrl &url, QObject *ctx,
								std::function< void() > onSafe,
								std::function< void() > onUnsafe);

	/// Replaces common HTML entities (&amp; &lt; &gt; &quot; &#39; &apos;)
	/// with their plain-text equivalents.
	static QString decodeHtmlEntities(const QString &input);
};

#endif // LINK_PREVIEW_PLUGIN_H_
