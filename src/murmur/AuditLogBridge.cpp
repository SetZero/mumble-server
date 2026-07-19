// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#include "AuditLogBridge.h"

#include "ACL.h"
#include "Channel.h"
#include "PluginHostManager.h"
#include "Server.h"
#include "ServerUser.h"
#include "Version.h"

#include "Mumble.pb.h"

#include <QtCore/QDateTime>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonParseError>
#include <QtCore/QJsonValue>
#include <QtCore/QMutexLocker>
#include <QtCore/QReadLocker>

// Identifiers shared with the `mumble-audit` Rust plugin (audit/src/lib.rs).
// NB: prefixed kAudit* (not the generic kPluginName other bridges use) so
// the unity build does not collide anonymous-namespace symbols across
// translation units.
namespace {
const QString kAuditPluginName       = QStringLiteral("fancy-audit");
const QString kAuditQueryType        = QStringLiteral("audit.query");
const QString kAuditVerifyType       = QStringLiteral("audit.verify");
const QString kAuditIngestType       = QStringLiteral("audit.ingest");
const QString kAuditConfigGetType    = QStringLiteral("audit.config.get");
const QString kAuditConfigSetType    = QStringLiteral("audit.config.set");
const QString kAuditResultType       = QStringLiteral("audit.result");
const QString kAuditVerifyResultType = QStringLiteral("audit.verify.result");
const QString kAuditConfigType       = QStringLiteral("audit.config");

/// The server-side page-size cap (docs/audit-log.md section 5).
constexpr uint32_t kAuditMaxLimit     = 200;
constexpr uint32_t kAuditDefaultLimit = 50;

QJsonObject identityJson(const ServerUser *u) {
	QJsonObject obj;
	if (!u) {
		return obj;
	}
	if (u->iId >= 0) {
		obj.insert(QStringLiteral("user_id"), static_cast< qint64 >(u->iId));
	}
	if (!u->qsHash.isEmpty()) {
		obj.insert(QStringLiteral("hash"), u->qsHash);
	}
	obj.insert(QStringLiteral("name"), u->qsName);
	return obj;
}

void entryFromJson(const QJsonObject &obj, MumbleProto::AuditEntry *out) {
	out->set_id(static_cast< uint64_t >(obj.value(QStringLiteral("id")).toDouble()));
	out->set_ts(static_cast< uint64_t >(obj.value(QStringLiteral("ts_ms")).toDouble()));
	out->set_source(obj.value(QStringLiteral("source")).toString().toStdString());
	out->set_category(obj.value(QStringLiteral("category")).toString().toStdString());
	out->set_severity(obj.value(QStringLiteral("severity")).toString().toStdString());

	const QJsonObject actor = obj.value(QStringLiteral("actor")).toObject();
	if (actor.contains(QStringLiteral("user_id")) && !actor.value(QStringLiteral("user_id")).isNull()) {
		out->set_actor_user_id(static_cast< uint32_t >(actor.value(QStringLiteral("user_id")).toDouble()));
	}
	if (!actor.value(QStringLiteral("name")).toString().isEmpty()) {
		out->set_actor_name(actor.value(QStringLiteral("name")).toString().toStdString());
	}
	const QJsonObject target = obj.value(QStringLiteral("target")).toObject();
	if (target.contains(QStringLiteral("user_id")) && !target.value(QStringLiteral("user_id")).isNull()) {
		out->set_target_user_id(static_cast< uint32_t >(target.value(QStringLiteral("user_id")).toDouble()));
	}
	if (!target.value(QStringLiteral("name")).toString().isEmpty()) {
		out->set_target_name(target.value(QStringLiteral("name")).toString().toStdString());
	}

	if (obj.contains(QStringLiteral("channel_id")) && !obj.value(QStringLiteral("channel_id")).isNull()) {
		out->set_channel_id(static_cast< uint32_t >(obj.value(QStringLiteral("channel_id")).toDouble()));
	}
	const QString reason = obj.value(QStringLiteral("reason")).toString();
	if (!reason.isEmpty()) {
		out->set_reason(reason.toStdString());
	}
	const QJsonValue detail = obj.value(QStringLiteral("detail_json"));
	if (detail.isString() && !detail.toString().isEmpty()) {
		out->set_detail_json(detail.toString().toStdString());
	}
	if (obj.contains(QStringLiteral("relates_to")) && !obj.value(QStringLiteral("relates_to")).isNull()) {
		out->set_relates_to(static_cast< uint64_t >(obj.value(QStringLiteral("relates_to")).toDouble()));
	}
	const QByteArray hashHex = obj.value(QStringLiteral("entry_hash")).toString().toLatin1();
	const QByteArray hash    = QByteArray::fromHex(hashHex);
	if (!hash.isEmpty()) {
		out->set_entry_hash(hash.constData(), static_cast< std::size_t >(hash.size()));
	}
}

} // namespace

AuditLogBridge::AuditLogBridge(Server *server, PluginHostManager *pluginHost)
	: m_server(server), m_pluginHost(pluginHost) {
	m_pluginHost->registerResponseHandler(
		kAuditResultType, [this](uint32_t targetSession, const QString &requestId, const QByteArray &payload) {
			deliverResult(targetSession, requestId, payload);
		});
	m_pluginHost->registerResponseHandler(
		kAuditVerifyResultType,
		[this](uint32_t targetSession, const QString &requestId, const QByteArray &payload) {
			deliverVerifyResult(targetSession, requestId, payload);
		});
	m_pluginHost->registerResponseHandler(
		kAuditConfigType, [this](uint32_t targetSession, const QString &requestId, const QByteArray &payload) {
			deliverConfig(targetSession, requestId, payload);
		});
}

void AuditLogBridge::handleQuery(ServerUser *u, const MumbleProto::FancyAuditQuery &msg) {
	const QString requestId = QString::fromStdString(msg.query_id());

	// Advanced SQL mode is not available through this bridge (the sandbox
	// self-test seam is not wired); reject rather than silently ignore.
	if (msg.has_sql() && !msg.sql().empty()) {
		MumbleProto::FancyAuditResponse response;
		response.set_query_id(msg.query_id());
		response.set_error("advanced SQL mode is not available on this server");
		m_server->sendMessage(u, response);
		return;
	}

	if (msg.has_verify_chain() && msg.verify_chain()) {
		QJsonObject req;
		req.insert(QStringLiteral("request_id"), requestId);
		m_pluginHost->sendPluginRequest(kAuditPluginName, kAuditVerifyType, u->uiSession,
										QJsonDocument(req).toJson(QJsonDocument::Compact));
		return;
	}

	uint32_t limit = msg.has_limit() && msg.limit() > 0 ? msg.limit() : kAuditDefaultLimit;
	if (limit > kAuditMaxLimit) {
		limit = kAuditMaxLimit;
	}

	QJsonObject req;
	req.insert(QStringLiteral("request_id"), requestId);
	if (msg.categories_size() > 0) {
		QJsonArray categories;
		for (int i = 0; i < msg.categories_size(); ++i) {
			categories.append(QString::fromStdString(msg.categories(i)));
		}
		req.insert(QStringLiteral("categories"), categories);
	}
	if (msg.has_source()) {
		req.insert(QStringLiteral("source"), QString::fromStdString(msg.source()));
	}
	if (msg.has_actor_user_id()) {
		req.insert(QStringLiteral("actor_user_id"), static_cast< qint64 >(msg.actor_user_id()));
	}
	if (msg.has_target_user_id()) {
		req.insert(QStringLiteral("target_user_id"), static_cast< qint64 >(msg.target_user_id()));
	}
	if (msg.has_channel_id()) {
		req.insert(QStringLiteral("channel_id"), static_cast< qint64 >(msg.channel_id()));
	}
	if (msg.has_text() && !msg.text().empty()) {
		req.insert(QStringLiteral("text"), QString::fromStdString(msg.text()));
	}
	if (msg.has_since_ms()) {
		req.insert(QStringLiteral("since_ms"), static_cast< qint64 >(msg.since_ms()));
	}
	if (msg.has_until_ms()) {
		req.insert(QStringLiteral("until_ms"), static_cast< qint64 >(msg.until_ms()));
	}
	if (msg.has_before_id()) {
		req.insert(QStringLiteral("before_id"), static_cast< qint64 >(msg.before_id()));
	}
	req.insert(QStringLiteral("limit"), static_cast< qint64 >(limit));

	{
		QMutexLocker lock(&m_pendingMutex);
		m_pendingLimits.insert(requestId, limit);
	}
	m_pluginHost->sendPluginRequest(kAuditPluginName, kAuditQueryType, u->uiSession,
									QJsonDocument(req).toJson(QJsonDocument::Compact));
}

void AuditLogBridge::handleConfigUpdate(ServerUser *u, const MumbleProto::FancyAuditConfigUpdate &msg) {
	QJsonArray settings;
	for (int i = 0; i < msg.settings_size(); ++i) {
		const MumbleProto::Setting &s = msg.settings(i);
		QJsonObject row;
		row.insert(QStringLiteral("key"), QString::fromStdString(s.key()));
		row.insert(QStringLiteral("value"), QString::fromStdString(s.value()));
		settings.append(row);
	}
	QJsonObject req;
	req.insert(QStringLiteral("request_id"), QString());
	req.insert(QStringLiteral("settings"), settings);
	m_pluginHost->sendPluginRequest(kAuditPluginName, kAuditConfigSetType, u->uiSession,
									QJsonDocument(req).toJson(QJsonDocument::Compact));
}

void AuditLogBridge::pushConfig(ServerUser *u) {
	if (!u || u->sState != ServerUser::Authenticated) {
		return;
	}
	// The Audit tab is gated at fancy 0.4.2 client-side; older clients drop
	// the unknown message anyway, so only the permission gate is hard.
	if (!u->m_FancyVersion.has_value()
		|| u->m_FancyVersion.value() < Version::fromComponents(0, 4, 2)) {
		return;
	}
	Channel *root = m_server->qhChannels.value(0);
	if (!root || !u->hasPermission(root, ChanACL::Write)) {
		return;
	}
	QJsonObject req;
	req.insert(QStringLiteral("request_id"), QString());
	m_pluginHost->sendPluginRequest(kAuditPluginName, kAuditConfigGetType, u->uiSession,
									QJsonDocument(req).toJson(QJsonDocument::Compact));
}

void AuditLogBridge::emitEvent(const QString &kind, const ServerUser *actor, const ServerUser *target,
							   int64_t channelId, const QJsonObject &detail) {
	const qint64 now = QDateTime::currentMSecsSinceEpoch();

	QJsonObject event;
	event.insert(QStringLiteral("kind"), kind);
	event.insert(QStringLiteral("ts_ms"), now);
	if (actor) {
		event.insert(QStringLiteral("actor"), identityJson(actor));
	}
	if (target) {
		event.insert(QStringLiteral("target"), identityJson(target));
	}
	if (channelId >= 0) {
		event.insert(QStringLiteral("channel_id"), static_cast< qint64 >(channelId));
	}
	if (!detail.isEmpty()) {
		event.insert(QStringLiteral("detail_json"),
					 QString::fromUtf8(QJsonDocument(detail).toJson(QJsonDocument::Compact)));
	}

	// Offsets are the plugin's idempotency key and must stay unique across
	// server restarts: derive from the wall clock with a same-millisecond
	// tie-breaker rather than an in-process counter.
	const uint64_t seq    = m_eventSeq.fetch_add(1, std::memory_order_relaxed) % 1000;
	const uint64_t offset = static_cast< uint64_t >(now) * 1000 + seq;

	QJsonObject envelope;
	envelope.insert(QStringLiteral("offset"), static_cast< qint64 >(offset));
	envelope.insert(QStringLiteral("event"), event);

	// sender_session 0 marks the message as core-originated; the plugin drops
	// `audit.ingest` from any real session (anti-forgery).
	m_pluginHost->sendPluginRequest(kAuditPluginName, kAuditIngestType, 0,
									QJsonDocument(envelope).toJson(QJsonDocument::Compact));
}

uint32_t AuditLogBridge::takePendingLimit(const QString &requestId) {
	QMutexLocker lock(&m_pendingMutex);
	return m_pendingLimits.take(requestId);
}

void AuditLogBridge::deliverResult(uint32_t targetSession, const QString &requestId,
								   const QByteArray &json) {
	QJsonParseError err{};
	const QJsonDocument doc = QJsonDocument::fromJson(json, &err);
	if (err.error != QJsonParseError::NoError || !doc.isArray()) {
		return;
	}
	const QJsonArray entries = doc.array();
	const uint32_t limit     = takePendingLimit(requestId);

	MumbleProto::FancyAuditResponse response;
	response.set_query_id(requestId.toStdString());
	uint64_t minId  = 0;
	bool haveMinId  = false;
	for (const QJsonValue &v : entries) {
		const QJsonObject obj = v.toObject();
		if (obj.isEmpty()) {
			continue;
		}
		entryFromJson(obj, response.add_entries());
		const auto id = static_cast< uint64_t >(obj.value(QStringLiteral("id")).toDouble());
		if (!haveMinId || id < minId) {
			minId     = id;
			haveMinId = true;
		}
	}
	response.set_has_more(limit > 0 && static_cast< uint32_t >(entries.size()) >= limit);
	if (haveMinId) {
		response.set_next_before_id(minId);
	}

	QReadLocker rl(&m_server->qrwlVoiceThread);
	ServerUser *target = m_server->qhUsers.value(targetSession);
	if (target) {
		m_server->sendMessage(target, response);
	}
}

void AuditLogBridge::deliverVerifyResult(uint32_t targetSession, const QString &requestId,
										 const QByteArray &json) {
	QJsonParseError err{};
	const QJsonDocument doc = QJsonDocument::fromJson(json, &err);
	if (err.error != QJsonParseError::NoError || !doc.isObject()) {
		return;
	}
	const QJsonObject obj = doc.object();

	MumbleProto::FancyAuditResponse response;
	response.set_query_id(requestId.toStdString());
	if (obj.contains(QStringLiteral("error"))) {
		response.set_chain_ok(false);
		response.set_chain_error(obj.value(QStringLiteral("error")).toString().toStdString());
	} else if (obj.value(QStringLiteral("intact")).toBool()) {
		response.set_chain_ok(true);
		response.set_chain_height(
			static_cast< uint64_t >(obj.value(QStringLiteral("checked")).toDouble()));
	} else {
		response.set_chain_ok(false);
		response.set_chain_height(
			static_cast< uint64_t >(obj.value(QStringLiteral("index")).toDouble()));
		response.set_chain_error(obj.value(QStringLiteral("description")).toString().toStdString());
	}

	QReadLocker rl(&m_server->qrwlVoiceThread);
	ServerUser *target = m_server->qhUsers.value(targetSession);
	if (target) {
		m_server->sendMessage(target, response);
	}
}

void AuditLogBridge::deliverConfig(uint32_t targetSession, const QString & /*requestId*/,
								   const QByteArray &json) {
	QJsonParseError err{};
	const QJsonDocument doc = QJsonDocument::fromJson(json, &err);
	if (err.error != QJsonParseError::NoError || !doc.isObject()) {
		return;
	}
	const QJsonObject obj = doc.object();

	MumbleProto::FancyAuditConfig config;
	const QJsonArray settings = obj.value(QStringLiteral("settings")).toArray();
	for (const QJsonValue &v : settings) {
		const QJsonObject row = v.toObject();
		if (row.isEmpty()) {
			continue;
		}
		MumbleProto::Setting *setting = config.add_settings();
		setting->set_key(row.value(QStringLiteral("key")).toString().toStdString());
		setting->set_type(row.value(QStringLiteral("type")).toString().toStdString());
		setting->set_group(row.value(QStringLiteral("group")).toString().toStdString());
		setting->set_label(row.value(QStringLiteral("label")).toString().toStdString());
		setting->set_value(row.value(QStringLiteral("value")).toString().toStdString());
		const QString help = row.value(QStringLiteral("help")).toString();
		if (!help.isEmpty()) {
			setting->set_help(help.toStdString());
		}
	}
	config.set_revision(static_cast< uint64_t >(obj.value(QStringLiteral("revision")).toDouble()));
	config.set_advanced_sql_available(obj.value(QStringLiteral("advanced_sql_available")).toBool());
	config.set_chain_height(
		static_cast< uint64_t >(obj.value(QStringLiteral("chain_height")).toDouble()));

	QReadLocker rl(&m_server->qrwlVoiceThread);
	ServerUser *target = m_server->qhUsers.value(targetSession);
	if (target) {
		m_server->sendMessage(target, config);
	}
}
