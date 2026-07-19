// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#ifndef AUDIT_LOG_BRIDGE_H_
#define AUDIT_LOG_BRIDGE_H_

#include <QByteArray>
#include <QHash>
#include <QJsonObject>
#include <QMutex>
#include <QString>

#include <atomic>
#include <cstdint>

class Server;
class ServerUser;
class PluginHostManager;

namespace MumbleProto {
class FancyAuditQuery;
class FancyAuditConfigUpdate;
}

/// Audit-log-specific glue over the generic [`PluginHostManager`]
/// request/response bridge (docs/audit-log.md section 5, mirroring
/// `LinkPreviewBridge`).
///
/// Three translations:
///  - `FancyAuditQuery` (wire 166) -> plugin `audit.query` / `audit.verify`;
///    the plugin's `audit.result` / `audit.verify.result` replies are packed
///    into a `FancyAuditResponse` (167) for the requesting session.
///  - `FancyAuditConfigUpdate` (171) -> plugin `audit.config.set`; the
///    `audit.config` snapshot reply becomes a `FancyAuditConfig` (170).
///    `pushConfig` requests the same snapshot post-ServerSync.
///  - `emitEvent` publishes one server-authoritative moderation event to the
///    plugin's ingest pipeline (`audit.ingest`, sender_session 0 = core).
///
/// Construct after the `PluginHostManager` exists and destroy before it.
class AuditLogBridge {
public:
	AuditLogBridge(Server *server, PluginHostManager *pluginHost);

	/// Forward an authorized client audit query (or chain-verify request) to
	/// the plugin. The caller has already enforced ViewAudit (Write on root).
	void handleQuery(ServerUser *u, const MumbleProto::FancyAuditQuery &msg);

	/// Forward an authorized config update to the plugin; the accepted
	/// snapshot is delivered back to the same session.
	void handleConfigUpdate(ServerUser *u, const MumbleProto::FancyAuditConfigUpdate &msg);

	/// Push the audit config snapshot to `u` if they hold ViewAudit and speak
	/// fancy >= 0.4.2 (called after ServerSync, mirroring
	/// `sendFancyServerSettings`).
	void pushConfig(ServerUser *u);

	/// Publish one authoritative moderation event into the plugin's ingest
	/// pipeline. `actor`/`target` may be null; `channelId < 0` means "no
	/// channel". `detail` is the category-specific structured payload.
	void emitEvent(const QString &kind, const ServerUser *actor, const ServerUser *target,
				   int64_t channelId, const QJsonObject &detail);

private:
	/// `audit.result` handler: entries JSON -> FancyAuditResponse.
	void deliverResult(uint32_t targetSession, const QString &requestId, const QByteArray &json);
	/// `audit.verify.result` handler: outcome JSON -> FancyAuditResponse
	/// carrying only the chain_* fields.
	void deliverVerifyResult(uint32_t targetSession, const QString &requestId,
							 const QByteArray &json);
	/// `audit.config` handler: snapshot JSON -> FancyAuditConfig.
	void deliverConfig(uint32_t targetSession, const QString &requestId, const QByteArray &json);

	/// Take (and forget) the limit remembered for `requestId`.
	uint32_t takePendingLimit(const QString &requestId);

	Server *m_server;
	PluginHostManager *m_pluginHost;

	/// request_id -> requested page size, so the response can set `has_more`.
	QMutex m_pendingMutex;
	QHash< QString, uint32_t > m_pendingLimits;

	/// Tie-breaker for ingest offsets minted in the same millisecond.
	std::atomic< uint64_t > m_eventSeq{ 0 };
};

#endif // AUDIT_LOG_BRIDGE_H_
