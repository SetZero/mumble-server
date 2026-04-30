// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#ifndef DIRECT_MEDIA_PLUGIN_H_
#define DIRECT_MEDIA_PLUGIN_H_

#include "LinkPreviewPlugin.h"

/// Handles URLs that point directly at media files (.png, .jpg,
/// .mp4, .mp3, .pdf, ...).
///
/// For images we download the bytes and inline a server-side
/// downscaled JPEG so the client never has to contact the origin.
/// For non-image media (audio/video/PDF) we still build a useful
/// embed with type, size and filename info.
class DirectMediaPlugin : public LinkPreviewPlugin {
	Q_OBJECT
public:
	explicit DirectMediaPlugin(QObject *parent = nullptr);

	QString name() const override { return QStringLiteral("DirectMedia"); }
	bool canHandle(const QUrl &url) const override;
	int priority() const override { return 5; }

	void fetchPreview(const QUrl &url, QNetworkAccessManager *nam, SuccessCallback onSuccess,
					  FailureCallback onFailure) override;

private:
	enum class Kind { Image, Gif, Video, Audio, Document, Unknown };
	static Kind classify(const QUrl &url);
	static QString humanFileSize(quint64 bytes);
	static QString filenameOf(const QUrl &url);

	void fetchImage(const QUrl &url, QNetworkAccessManager *nam, SuccessCallback onSuccess,
					FailureCallback onFailure);
	void describeOnly(const QUrl &url, Kind kind, QNetworkAccessManager *nam,
					  SuccessCallback onSuccess, FailureCallback onFailure);
};

#endif // DIRECT_MEDIA_PLUGIN_H_
