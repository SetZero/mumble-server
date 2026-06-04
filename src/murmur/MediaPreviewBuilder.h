// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#ifndef MEDIA_PREVIEW_BUILDER_H_
#define MEDIA_PREVIEW_BUILDER_H_

#include <QByteArray>
#include <QNetworkAccessManager>
#include <QObject>
#include <QUrl>

#include <functional>
#include <optional>

/// Fetches a remote image, downscales it server-side and re-encodes
/// it as JPEG so the client can render a preview without ever
/// contacting the origin host (which would leak the user's IP).
///
/// All work is asynchronous; the caller receives the result via the
/// provided callback.  Failures are reported as `std::nullopt` so that
/// callers can degrade gracefully (the preview just falls back to a
/// thumbnail-less embed).
class MediaPreviewBuilder : public QObject {
	Q_OBJECT
public:
	struct Result {
		QByteArray jpeg;
		int previewWidth     = 0;
		int previewHeight    = 0;
		int originalWidth    = 0;
		int originalHeight   = 0;
		quint64 originalSize = 0;
		QString mime;
		QString contentType;
	};

	using Callback = std::function< void(const std::optional< Result > &) >;

	/// Hard upper bound on the source bytes downloaded per preview.  Larger
	/// images are rejected to prevent memory blow-up.
	static constexpr qint64 MAX_SOURCE_BYTES = 10 * 1024 * 1024;
	/// Default longest-side pixel size for hero/thumbnail previews.
	static constexpr int DEFAULT_MAX_DIM = 320;
	/// Favicon previews stay tiny so we can inline dozens cheaply.
	static constexpr int FAVICON_MAX_DIM = 64;
	/// JPEG encoder quality (0-100).
	static constexpr int JPEG_QUALITY = 78;
	/// Per-preview transfer timeout.
	static constexpr int FETCH_TIMEOUT_MS = 15000;

	explicit MediaPreviewBuilder(QObject *parent = nullptr) : QObject(parent) {}

	/// Asynchronously fetch `url`, downscale it to fit within
	/// `maxDim` x `maxDim` and JPEG-re-encode at `quality`.  Calls
	/// `cb` on the calling thread when done.
	void fetchAndDownscale(const QUrl &url, QNetworkAccessManager *nam, int maxDim, int quality,
						   Callback cb);

	/// Build a Result from already-downloaded bytes (e.g. when the
	/// owning plugin already has the image in hand).  Returns nullopt
	/// if decoding fails.
	static std::optional< Result > buildFromBytes(const QByteArray &source, int maxDim, int quality,
												  const QString &contentType);

private:
	/// Issues the actual network request once the SSRF gate has confirmed the
	/// URL's resolved addresses are all public.
	void issueFetch(const QUrl &url, QNetworkAccessManager *nam, int maxDim, int quality,
					Callback cb);
};

#endif // MEDIA_PREVIEW_BUILDER_H_
