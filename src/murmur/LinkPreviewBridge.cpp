// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#include "LinkPreviewBridge.h"

#include "PluginHostManager.h"
#include "Server.h"
#include "ServerUser.h"

#include "Mumble.pb.h"

#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonParseError>
#include <QtCore/QJsonValue>
#include <QtCore/QReadLocker>

// Identifiers shared with the `fancy-link-preview` Rust plugin.
namespace {
const QString kPluginName   = QStringLiteral("fancy-link-preview");
const QString kRequestType  = QStringLiteral("preview.request");
const QString kResponseType = QStringLiteral("link-preview");

// ---- JSON embed -> protobuf packing --------------------------------------
// The embed JSON keys map 1:1 onto FancyLinkPreviewResponse.Embed; this packing
// is unchanged from the former in-process LinkPreviewManager implementation.

void populateProtoMedia(MumbleProto::FancyLinkPreviewResponse::Embed::Media *media,
						const QJsonObject &obj) {
	if (obj.contains(QStringLiteral("url")))
		media->set_url(obj.value(QStringLiteral("url")).toString().toStdString());
	if (obj.contains(QStringLiteral("width")))
		media->set_width(obj.value(QStringLiteral("width")).toInt());
	if (obj.contains(QStringLiteral("height")))
		media->set_height(obj.value(QStringLiteral("height")).toInt());

	const QString b64 = obj.value(QStringLiteral("preview_data_b64")).toString();
	if (!b64.isEmpty()) {
		QByteArray bytes = QByteArray::fromBase64(b64.toLatin1());
		if (!bytes.isEmpty()) {
			media->set_preview_data(bytes.constData(), static_cast< std::size_t >(bytes.size()));
		}
	}
	if (obj.contains(QStringLiteral("preview_mime")))
		media->set_preview_mime(obj.value(QStringLiteral("preview_mime")).toString().toStdString());
	if (obj.contains(QStringLiteral("preview_width")))
		media->set_preview_width(obj.value(QStringLiteral("preview_width")).toInt());
	if (obj.contains(QStringLiteral("preview_height")))
		media->set_preview_height(obj.value(QStringLiteral("preview_height")).toInt());
	if (obj.contains(QStringLiteral("original_size"))) {
		media->set_original_size(
			static_cast< std::uint32_t >(obj.value(QStringLiteral("original_size")).toDouble()));
	}
}

void populateProtoEmbed(MumbleProto::FancyLinkPreviewResponse::Embed *embed,
						const QJsonObject &json) {
	if (json.contains(QStringLiteral("url")))
		embed->set_url(json.value(QStringLiteral("url")).toString().toStdString());
	if (json.contains(QStringLiteral("type")))
		embed->set_type(json.value(QStringLiteral("type")).toString().toStdString());
	if (json.contains(QStringLiteral("title")))
		embed->set_title(json.value(QStringLiteral("title")).toString().toStdString());
	if (json.contains(QStringLiteral("description")))
		embed->set_description(json.value(QStringLiteral("description")).toString().toStdString());
	if (json.contains(QStringLiteral("color")))
		embed->set_color(json.value(QStringLiteral("color")).toInt());
	if (json.contains(QStringLiteral("site_name")))
		embed->set_site_name(json.value(QStringLiteral("site_name")).toString().toStdString());

	const QJsonObject thumbnailObj = json.value(QStringLiteral("thumbnail")).toObject();
	if (!thumbnailObj.isEmpty())
		populateProtoMedia(embed->mutable_thumbnail(), thumbnailObj);
	const QJsonObject imageObj = json.value(QStringLiteral("image")).toObject();
	if (!imageObj.isEmpty())
		populateProtoMedia(embed->mutable_image(), imageObj);
	const QJsonObject videoObj = json.value(QStringLiteral("video")).toObject();
	if (!videoObj.isEmpty())
		populateProtoMedia(embed->mutable_video(), videoObj);

	const QJsonObject providerObj = json.value(QStringLiteral("provider")).toObject();
	if (!providerObj.isEmpty()) {
		auto *provider = embed->mutable_provider();
		if (providerObj.contains(QStringLiteral("name")))
			provider->set_name(providerObj.value(QStringLiteral("name")).toString().toStdString());
		if (providerObj.contains(QStringLiteral("url")))
			provider->set_url(providerObj.value(QStringLiteral("url")).toString().toStdString());
	}

	const QJsonObject authorObj = json.value(QStringLiteral("author")).toObject();
	if (!authorObj.isEmpty()) {
		auto *author = embed->mutable_author();
		if (authorObj.contains(QStringLiteral("name")))
			author->set_name(authorObj.value(QStringLiteral("name")).toString().toStdString());
		if (authorObj.contains(QStringLiteral("url")))
			author->set_url(authorObj.value(QStringLiteral("url")).toString().toStdString());
	}

	const QJsonObject faviconObj = json.value(QStringLiteral("favicon")).toObject();
	if (!faviconObj.isEmpty())
		populateProtoMedia(embed->mutable_favicon(), faviconObj);

	if (json.contains(QStringLiteral("canonical_url")))
		embed->set_canonical_url(json.value(QStringLiteral("canonical_url")).toString().toStdString());
	if (json.contains(QStringLiteral("lang")))
		embed->set_lang(json.value(QStringLiteral("lang")).toString().toStdString());
	if (json.contains(QStringLiteral("published_time")))
		embed->set_published_time(json.value(QStringLiteral("published_time")).toString().toStdString());
	if (json.contains(QStringLiteral("modified_time")))
		embed->set_modified_time(json.value(QStringLiteral("modified_time")).toString().toStdString());
	if (json.contains(QStringLiteral("summary")))
		embed->set_summary(json.value(QStringLiteral("summary")).toString().toStdString());
	if (json.contains(QStringLiteral("content_type")))
		embed->set_content_type(json.value(QStringLiteral("content_type")).toString().toStdString());
	if (json.contains(QStringLiteral("content_length")))
		embed->set_content_length(
			static_cast< std::uint64_t >(json.value(QStringLiteral("content_length")).toDouble()));
	if (json.contains(QStringLiteral("media_duration")))
		embed->set_media_duration(json.value(QStringLiteral("media_duration")).toString().toStdString());
	if (json.contains(QStringLiteral("nsfw")))
		embed->set_nsfw(json.value(QStringLiteral("nsfw")).toBool());
	if (json.contains(QStringLiteral("reading_time")))
		embed->set_reading_time(json.value(QStringLiteral("reading_time")).toString().toStdString());
	if (json.contains(QStringLiteral("fetched_at")))
		embed->set_fetched_at(json.value(QStringLiteral("fetched_at")).toString().toStdString());

	const QJsonArray keywordsArr = json.value(QStringLiteral("keywords")).toArray();
	for (const QJsonValue &v : keywordsArr) {
		const QString s = v.toString();
		if (!s.isEmpty())
			embed->add_keywords(s.toStdString());
	}

	const QJsonArray fieldsArr = json.value(QStringLiteral("fields")).toArray();
	for (const QJsonValue &v : fieldsArr) {
		const QJsonObject fo = v.toObject();
		if (fo.isEmpty())
			continue;
		auto *protoField = embed->add_fields();
		if (fo.contains(QStringLiteral("name")))
			protoField->set_name(fo.value(QStringLiteral("name")).toString().toStdString());
		if (fo.contains(QStringLiteral("value")))
			protoField->set_value(fo.value(QStringLiteral("value")).toString().toStdString());
		if (fo.contains(QStringLiteral("inline")))
			protoField->set_inline_(fo.value(QStringLiteral("inline")).toBool());
	}
}

} // namespace

LinkPreviewBridge::LinkPreviewBridge(Server *server, PluginHostManager *pluginHost)
	: m_server(server), m_pluginHost(pluginHost) {
	m_pluginHost->registerResponseHandler(
		kResponseType,
		[this](uint32_t targetSession, const QString &requestId, const QByteArray &payload) {
			deliverResponse(targetSession, requestId, payload);
		});
}

void LinkPreviewBridge::requestPreviews(uint32_t session, const QStringList &urls,
										const QString &requestId) {
	QJsonArray urlArr;
	for (const QString &u : urls) {
		urlArr.append(u);
	}
	QJsonObject req;
	req.insert(QStringLiteral("request_id"), requestId);
	req.insert(QStringLiteral("urls"), urlArr);
	const QByteArray payload = QJsonDocument(req).toJson(QJsonDocument::Compact);

	m_pluginHost->sendPluginRequest(kPluginName, kRequestType, session, payload);
}

void LinkPreviewBridge::deliverResponse(uint32_t targetSession, const QString &requestId,
										const QByteArray &embedsJson) {
	QJsonParseError err{};
	const QJsonDocument doc = QJsonDocument::fromJson(embedsJson, &err);
	if (err.error != QJsonParseError::NoError || !doc.isObject()) {
		return;
	}
	const QJsonArray embeds = doc.object().value(QStringLiteral("embeds")).toArray();

	MumbleProto::FancyLinkPreviewResponse response;
	response.set_request_id(requestId.toStdString());
	for (const QJsonValue &v : embeds) {
		const QJsonObject embedJson = v.toObject();
		if (!embedJson.isEmpty()) {
			populateProtoEmbed(response.add_embeds(), embedJson);
		}
	}

	QReadLocker rl(&m_server->qrwlVoiceThread);
	ServerUser *target = m_server->qhUsers.value(targetSession);
	if (target) {
		m_server->sendMessage(target, response);
	}
}
