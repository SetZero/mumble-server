// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#include "DirectMediaPlugin.h"

#include "MediaPreviewBuilder.h"

#include <QFileInfo>
#include <QJsonArray>
#include <QJsonObject>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QtDebug>

DirectMediaPlugin::DirectMediaPlugin(QObject *parent) : LinkPreviewPlugin(parent) {
}

DirectMediaPlugin::Kind DirectMediaPlugin::classify(const QUrl &url) {
	const QString path = url.path().toLower();
	if (path.endsWith(QLatin1String(".png")) || path.endsWith(QLatin1String(".jpg"))
		|| path.endsWith(QLatin1String(".jpeg")) || path.endsWith(QLatin1String(".webp"))
		|| path.endsWith(QLatin1String(".bmp")) || path.endsWith(QLatin1String(".avif"))
		|| path.endsWith(QLatin1String(".jxl")))
		return Kind::Image;
	if (path.endsWith(QLatin1String(".gif")))
		return Kind::Gif;
	if (path.endsWith(QLatin1String(".mp4")) || path.endsWith(QLatin1String(".webm"))
		|| path.endsWith(QLatin1String(".mov")) || path.endsWith(QLatin1String(".mkv"))
		|| path.endsWith(QLatin1String(".m4v")))
		return Kind::Video;
	if (path.endsWith(QLatin1String(".mp3")) || path.endsWith(QLatin1String(".ogg"))
		|| path.endsWith(QLatin1String(".oga")) || path.endsWith(QLatin1String(".wav"))
		|| path.endsWith(QLatin1String(".flac")) || path.endsWith(QLatin1String(".m4a"))
		|| path.endsWith(QLatin1String(".opus")))
		return Kind::Audio;
	if (path.endsWith(QLatin1String(".pdf")) || path.endsWith(QLatin1String(".zip"))
		|| path.endsWith(QLatin1String(".tar")) || path.endsWith(QLatin1String(".7z"))
		|| path.endsWith(QLatin1String(".gz")) || path.endsWith(QLatin1String(".xz"))
		|| path.endsWith(QLatin1String(".rar")) || path.endsWith(QLatin1String(".doc"))
		|| path.endsWith(QLatin1String(".docx")) || path.endsWith(QLatin1String(".xls"))
		|| path.endsWith(QLatin1String(".xlsx")) || path.endsWith(QLatin1String(".ppt"))
		|| path.endsWith(QLatin1String(".pptx")) || path.endsWith(QLatin1String(".odt"))
		|| path.endsWith(QLatin1String(".epub")))
		return Kind::Document;
	return Kind::Unknown;
}

bool DirectMediaPlugin::canHandle(const QUrl &url) const {
	if (!isSafeUrl(url))
		return false;
	return classify(url) != Kind::Unknown;
}

QString DirectMediaPlugin::filenameOf(const QUrl &url) {
	return QFileInfo(url.path()).fileName();
}

QString DirectMediaPlugin::humanFileSize(quint64 bytes) {
	constexpr double KB = 1024.0;
	constexpr double MB = 1024.0 * 1024.0;
	constexpr double GB = 1024.0 * 1024.0 * 1024.0;
	if (bytes >= static_cast< quint64 >(GB))
		return QStringLiteral("%1 GiB").arg(bytes / GB, 0, 'f', 2);
	if (bytes >= static_cast< quint64 >(MB))
		return QStringLiteral("%1 MiB").arg(bytes / MB, 0, 'f', 2);
	if (bytes >= static_cast< quint64 >(KB))
		return QStringLiteral("%1 KiB").arg(bytes / KB, 0, 'f', 1);
	return QStringLiteral("%1 B").arg(bytes);
}

void DirectMediaPlugin::fetchPreview(const QUrl &url, QNetworkAccessManager *nam,
									 SuccessCallback onSuccess, FailureCallback onFailure) {
	const Kind kind = classify(url);
	if (kind == Kind::Image || kind == Kind::Gif) {
		fetchImage(url, nam, std::move(onSuccess), std::move(onFailure));
	} else {
		describeOnly(url, kind, nam, std::move(onSuccess), std::move(onFailure));
	}
}

void DirectMediaPlugin::fetchImage(const QUrl &url, QNetworkAccessManager *nam,
								   SuccessCallback onSuccess, FailureCallback onFailure) {
	auto *builder = new MediaPreviewBuilder(this);
	const Kind kind = classify(url);
	builder->fetchAndDownscale(
		url, nam, MediaPreviewBuilder::DEFAULT_MAX_DIM, MediaPreviewBuilder::JPEG_QUALITY,
		[url, kind, onSuccess, onFailure, builder](const std::optional< MediaPreviewBuilder::Result > &res) {
			builder->deleteLater();
			if (!res) {
				onFailure();
				return;
			}

			QJsonObject embed;
			embed.insert(QStringLiteral("url"), url.toString());
			embed.insert(QStringLiteral("type"),
						 kind == Kind::Gif ? QStringLiteral("gifv") : QStringLiteral("image"));
			embed.insert(QStringLiteral("title"), filenameOf(url));
			embed.insert(QStringLiteral("site_name"), url.host());
			if (!res->contentType.isEmpty())
				embed.insert(QStringLiteral("content_type"), res->contentType);
			embed.insert(QStringLiteral("content_length"),
						 static_cast< qint64 >(res->originalSize));

			QJsonObject image;
			image.insert(QStringLiteral("url"), url.toString());
			image.insert(QStringLiteral("width"), res->originalWidth);
			image.insert(QStringLiteral("height"), res->originalHeight);
			image.insert(QStringLiteral("preview_data_b64"),
						 QString::fromLatin1(res->jpeg.toBase64()));
			image.insert(QStringLiteral("preview_mime"), res->mime);
			image.insert(QStringLiteral("preview_width"), res->previewWidth);
			image.insert(QStringLiteral("preview_height"), res->previewHeight);
			image.insert(QStringLiteral("original_size"),
						 static_cast< qint64 >(res->originalSize));
			embed.insert(QStringLiteral("image"), image);

			QJsonObject fields;
			QJsonArray fieldArr;
			QJsonObject f1;
			f1.insert(QStringLiteral("name"), QStringLiteral("Resolution"));
			f1.insert(QStringLiteral("value"),
					  QStringLiteral("%1 \u00d7 %2").arg(res->originalWidth).arg(res->originalHeight));
			f1.insert(QStringLiteral("inline"), true);
			fieldArr.append(f1);

			QJsonObject f2;
			f2.insert(QStringLiteral("name"), QStringLiteral("Size"));
			f2.insert(QStringLiteral("value"), humanFileSize(res->originalSize));
			f2.insert(QStringLiteral("inline"), true);
			fieldArr.append(f2);

			if (!res->contentType.isEmpty()) {
				QJsonObject f3;
				f3.insert(QStringLiteral("name"), QStringLiteral("Type"));
				f3.insert(QStringLiteral("value"), res->contentType);
				f3.insert(QStringLiteral("inline"), true);
				fieldArr.append(f3);
			}
			embed.insert(QStringLiteral("fields"), fieldArr);

			onSuccess(embed);
		});
}

void DirectMediaPlugin::describeOnly(const QUrl &url, Kind kind, QNetworkAccessManager *nam,
									 SuccessCallback onSuccess, FailureCallback onFailure) {
	// HEAD-only fetch to learn Content-Type / Content-Length without
	// downloading the full media.
	QNetworkRequest req(url);
	req.setHeader(QNetworkRequest::UserAgentHeader,
				  QStringLiteral("Mozilla/5.0 (compatible; FancyMumbleBot/1.0)"));
	req.setTransferTimeout(FETCH_TIMEOUT_MS);
	req.setAttribute(QNetworkRequest::Http2AllowedAttribute, false);
	req.setMaximumRedirectsAllowed(3);

	QNetworkReply *reply = nam->head(req);

	connect(reply, &QNetworkReply::finished, this,
			[reply, url, kind, onSuccess, onFailure]() {
				reply->deleteLater();

				QString contentType = reply->header(QNetworkRequest::ContentTypeHeader)
										  .toString()
										  .split(';')
										  .value(0)
										  .trimmed();
				bool sizeOk         = false;
				qint64 contentLen   = reply->header(QNetworkRequest::ContentLengthHeader)
										.toLongLong(&sizeOk);

				if (reply->error() != QNetworkReply::NoError && contentType.isEmpty()) {
					// Best-effort fallback: still emit a minimal embed so the
					// client can render something useful (filename + kind).
				}

				QJsonObject embed;
				embed.insert(QStringLiteral("url"), url.toString());
				embed.insert(QStringLiteral("title"), filenameOf(url));
				embed.insert(QStringLiteral("site_name"), url.host());
				switch (kind) {
					case Kind::Video:
						embed.insert(QStringLiteral("type"), QStringLiteral("video"));
						break;
					case Kind::Audio:
						embed.insert(QStringLiteral("type"), QStringLiteral("audio"));
						break;
					case Kind::Document:
						embed.insert(QStringLiteral("type"), QStringLiteral("file"));
						break;
					default:
						embed.insert(QStringLiteral("type"), QStringLiteral("link"));
				}

				if (!contentType.isEmpty())
					embed.insert(QStringLiteral("content_type"), contentType);
				if (sizeOk && contentLen > 0)
					embed.insert(QStringLiteral("content_length"), contentLen);

				QJsonArray fieldArr;
				if (!contentType.isEmpty()) {
					QJsonObject f;
					f.insert(QStringLiteral("name"), QStringLiteral("Type"));
					f.insert(QStringLiteral("value"), contentType);
					f.insert(QStringLiteral("inline"), true);
					fieldArr.append(f);
				}
				if (sizeOk && contentLen > 0) {
					QJsonObject f;
					f.insert(QStringLiteral("name"), QStringLiteral("Size"));
					f.insert(QStringLiteral("value"), humanFileSize(static_cast< quint64 >(contentLen)));
					f.insert(QStringLiteral("inline"), true);
					fieldArr.append(f);
				}
				if (!fieldArr.isEmpty())
					embed.insert(QStringLiteral("fields"), fieldArr);

				onSuccess(embed);
			});

	Q_UNUSED(onFailure);
	Q_UNUSED(nam);
}
