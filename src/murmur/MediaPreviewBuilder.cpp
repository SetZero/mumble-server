// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#include "MediaPreviewBuilder.h"

#include "LinkPreviewPlugin.h"

#include <QBuffer>
#include <QImage>
#include <QImageReader>
#include <QImageWriter>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QtDebug>

namespace {

QImage decode(const QByteArray &source, QString &mimeOut) {
	QBuffer buffer;
	buffer.setData(source);
	if (!buffer.open(QIODevice::ReadOnly))
		return {};

	QImageReader reader(&buffer);
	// Cap the decoder to avoid decompression bombs.
	reader.setAllocationLimit(64); // MiB
	reader.setAutoTransform(true);
	QImage img = reader.read();
	if (img.isNull())
		return {};

	const QByteArray fmt = reader.format().toLower();
	if (fmt == "png")
		mimeOut = QStringLiteral("image/png");
	else if (fmt == "jpeg" || fmt == "jpg")
		mimeOut = QStringLiteral("image/jpeg");
	else if (fmt == "webp")
		mimeOut = QStringLiteral("image/webp");
	else if (fmt == "gif")
		mimeOut = QStringLiteral("image/gif");
	else if (fmt == "bmp")
		mimeOut = QStringLiteral("image/bmp");
	else
		mimeOut = QStringLiteral("application/octet-stream");
	return img;
}

QByteArray encodeJpeg(const QImage &img, int quality) {
	QByteArray out;
	QBuffer buffer(&out);
	if (!buffer.open(QIODevice::WriteOnly))
		return {};
	QImageWriter writer(&buffer, "JPEG");
	writer.setQuality(quality);
	// Re-encode through an opaque RGB image so JPEG (which has no alpha)
	// produces predictable, smaller output.
	QImage rgb = img.hasAlphaChannel() ? img.convertToFormat(QImage::Format_RGB32) : img;
	if (!writer.write(rgb))
		return {};
	return out;
}

} // namespace

std::optional< MediaPreviewBuilder::Result >
MediaPreviewBuilder::buildFromBytes(const QByteArray &source, int maxDim, int quality,
									const QString &contentType) {
	if (source.isEmpty())
		return std::nullopt;

	QString detectedMime;
	QImage img = decode(source, detectedMime);
	if (img.isNull())
		return std::nullopt;

	const int origW = img.width();
	const int origH = img.height();
	if (origW <= 0 || origH <= 0)
		return std::nullopt;

	QImage scaled = img;
	if (origW > maxDim || origH > maxDim) {
		scaled = img.scaled(maxDim, maxDim, Qt::KeepAspectRatio, Qt::SmoothTransformation);
	}

	QByteArray jpeg = encodeJpeg(scaled, quality);
	if (jpeg.isEmpty())
		return std::nullopt;

	Result r;
	r.jpeg           = jpeg;
	r.previewWidth   = scaled.width();
	r.previewHeight  = scaled.height();
	r.originalWidth  = origW;
	r.originalHeight = origH;
	r.originalSize   = static_cast< quint64 >(source.size());
	r.mime           = QStringLiteral("image/jpeg");
	r.contentType    = contentType.isEmpty() ? detectedMime : contentType;
	return r;
}

void MediaPreviewBuilder::fetchAndDownscale(const QUrl &url, QNetworkAccessManager *nam, int maxDim,
											int quality, Callback cb) {
	if (!url.isValid() || !LinkPreviewPlugin::isSafeUrl(url)) {
		cb(std::nullopt);
		return;
	}

	QNetworkRequest request(url);
	request.setHeader(QNetworkRequest::UserAgentHeader,
					  QStringLiteral("Mozilla/5.0 (compatible; FancyMumbleBot/1.0)"));
	request.setRawHeader("Accept", "image/*");
	request.setTransferTimeout(FETCH_TIMEOUT_MS);
	request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
						 QNetworkRequest::ManualRedirectPolicy);
	request.setAttribute(QNetworkRequest::Http2AllowedAttribute, false);
	request.setMaximumRedirectsAllowed(0);

	QNetworkReply *reply = nam->get(request);

	// Streaming size guard: if the server announces a bigger payload
	// than we are willing to ingest, abort straight away.
	connect(reply, &QNetworkReply::metaDataChanged, reply, [reply]() {
		const QVariant lenHeader = reply->header(QNetworkRequest::ContentLengthHeader);
		bool ok          = false;
		const qint64 len = lenHeader.toLongLong(&ok);
		if (ok && len > MAX_SOURCE_BYTES) {
			reply->abort();
		}
	});
	connect(reply, &QNetworkReply::downloadProgress, reply, [reply](qint64 received, qint64) {
		if (received > MAX_SOURCE_BYTES)
			reply->abort();
	});

	connect(reply, &QNetworkReply::finished, this, [reply, maxDim, quality, cb, nam, url]() {
		reply->deleteLater();

		const int statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
		// Manual single-hop redirect for SSRF-safety.
		if (statusCode >= 300 && statusCode < 400) {
			QUrl redir = reply->header(QNetworkRequest::LocationHeader).toUrl();
			if (redir.isRelative())
				redir = url.resolved(redir);
			if (LinkPreviewPlugin::isSafeUrl(redir)) {
				// Single hop only; rebuild with the new URL.
				auto *self = qobject_cast< MediaPreviewBuilder * >(reply->parent());
				if (self) {
					self->fetchAndDownscale(redir, nam, maxDim, quality, cb);
				} else {
					cb(std::nullopt);
				}
			} else {
				cb(std::nullopt);
			}
			return;
		}

		if (reply->error() != QNetworkReply::NoError) {
			cb(std::nullopt);
			return;
		}

		QByteArray data = reply->read(MAX_SOURCE_BYTES);
		QString contentType =
			reply->header(QNetworkRequest::ContentTypeHeader).toString().split(';').value(0).trimmed();

		auto result = buildFromBytes(data, maxDim, quality, contentType);
		cb(result);
	});

	// Reparent so the redirect helper above can locate `this`.
	reply->setParent(this);
}
