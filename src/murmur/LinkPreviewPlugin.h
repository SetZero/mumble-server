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

	// Shared security / utility helpers available to all plugins.
	static bool isSafeUrl(const QUrl &url);
	static bool isPrivateAddress(const QString &host);
	static QString decodeHtmlEntities(const QString &input);

	static constexpr int MAX_REDIRECTS      = 5;
	static constexpr int FETCH_TIMEOUT_MS   = 10000; // Increased to 10 seconds
	static constexpr int MAX_RESPONSE_BYTES = 1024 * 1024;
};

#endif // LINK_PREVIEW_PLUGIN_H_
