// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "PushNotificationDispatcher.h"

#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QFileInfo>

namespace push {

PushNotificationDispatcher::PushNotificationDispatcher() = default;

PushNotificationDispatcher::~PushNotificationDispatcher() {
	shutdown();
}

bool PushNotificationDispatcher::init(const PushConfig &config) {
	m_config = config;

	if (!config.enabled) {
		qWarning("push: disabled in configuration");
		return false;
	}

	// Determine library path
	QString libPath = config.modulePath;

	if (libPath.isEmpty()) {
		// Look next to the server binary
		QDir appDir(QCoreApplication::applicationDirPath());
#ifdef Q_OS_WIN
		libPath = appDir.filePath("mumble_push_fcm.dll");
#else
		libPath = appDir.filePath("libmumble_push_fcm.so");
#endif
	}

	if (!QFileInfo::exists(libPath)) {
		qWarning("push: module not found at %s - push notifications disabled",
		         qUtf8Printable(libPath));
		return false;
	}

	// Load the shared library
	m_lib = std::make_unique< QLibrary >(libPath);

	if (!m_lib->load()) {
		qWarning("push: failed to load module %s: %s",
		         qUtf8Printable(libPath),
		         qUtf8Printable(m_lib->errorString()));
		m_lib.reset();
		return false;
	}

	qWarning("push: loaded module from %s", qUtf8Printable(libPath));

	if (!resolveSymbols()) {
		qWarning("push: failed to resolve required symbols from module");
		m_lib->unload();
		m_lib.reset();
		return false;
	}

	// Check API version
	int version = m_sym.apiVersion();
	if (version != MUMBLE_PUSH_API_VERSION) {
		qWarning("push: module API version mismatch (got %d, expected %d)",
		         version, MUMBLE_PUSH_API_VERSION);
		m_lib->unload();
		m_lib.reset();
		return false;
	}

	// Initialise the module
	int rc = m_sym.init(config.credentialsPath.toUtf8().constData(),
	                    config.projectId.toUtf8().constData());
	if (rc != MUMBLE_PUSH_OK) {
		const char *err = m_sym.lastError ? m_sym.lastError() : nullptr;
		qWarning("push: module init failed (rc=%d): %s", rc, err ? err : "unknown");
		m_lib->unload();
		m_lib.reset();
		return false;
	}

	m_initialised = true;
	qWarning("push: module initialised successfully (project=%s, topic_prefix=%s)",
	         qUtf8Printable(config.projectId),
	         config.topicPrefix.isEmpty() ? "(none)" : qUtf8Printable(config.topicPrefix));

	return true;
}

bool PushNotificationDispatcher::isAvailable() const {
	return m_initialised;
}

bool PushNotificationDispatcher::resolveSymbols() {
	if (!m_lib || !m_lib->isLoaded()) return false;

	auto resolve = [this](const char *name) -> QFunctionPointer {
		QFunctionPointer fn = m_lib->resolve(name);
		if (!fn) {
			qWarning("push: symbol '%s' not found in module", name);
		}
		return fn;
	};

	auto fnInit       = reinterpret_cast< int (*)(const char *, const char *) >(resolve("mumble_push_init"));
	auto fnVersion    = reinterpret_cast< int (*)() >(resolve("mumble_push_api_version"));
	auto fnSend       = reinterpret_cast< int (*)(const MumblePushNotification *) >(resolve("mumble_push_send"));
	auto fnSendBatch  = reinterpret_cast< int (*)(const MumblePushNotification *, const char *const *, size_t) >(resolve("mumble_push_send_batch"));
	auto fnShutdown   = reinterpret_cast< void (*)() >(resolve("mumble_push_shutdown"));
	auto fnLastError  = reinterpret_cast< const char *(*)() >(resolve("mumble_push_last_error"));

	// init, api_version, send, and shutdown are mandatory
	if (!fnInit || !fnVersion || !fnSend || !fnShutdown) {
		return false;
	}

	m_sym.init       = fnInit;
	m_sym.apiVersion = fnVersion;
	m_sym.send       = fnSend;
	m_sym.sendBatch  = fnSendBatch;  // optional
	m_sym.shutdown   = fnShutdown;
	m_sym.lastError  = fnLastError;  // optional

	return true;
}

void PushNotificationDispatcher::notifyTopic(const std::string &topic,
                                             const std::string &title,
                                             const std::string &body,
                                             MumblePushCategory category,
                                             MumblePushPriority priority,
                                             uint32_t serverId,
                                             uint32_t channelId,
                                             const std::string &dataJson) {
	if (!m_initialised) return;

	// FCM topic tokens use "/topics/<name>" as the device_token field
	std::string topicToken = "/topics/" + topic;

	MumblePushNotification notif{};
	notif.device_token = topicToken.c_str();
	notif.title        = title.c_str();
	notif.body         = body.c_str();
	notif.category     = category;
	notif.priority     = priority;
	notif.server_id    = serverId;
	notif.channel_id   = channelId;
	notif.data_json    = dataJson.empty() ? nullptr : dataJson.c_str();

	int rc = m_sym.send(&notif);
	if (rc != MUMBLE_PUSH_OK) {
		const char *err = m_sym.lastError ? m_sym.lastError() : nullptr;
		qWarning("push: send to topic '%s' failed (rc=%d): %s",
		         topic.c_str(), rc, err ? err : "unknown");
	}
}

void PushNotificationDispatcher::notifyChannel(uint32_t serverId, uint32_t channelId,
                                               const std::string &title,
                                               const std::string &body,
                                               MumblePushCategory category,
                                               MumblePushPriority priority,
                                               const std::string &dataJson) {
	if (!m_initialised) return;

	std::string topic;
	if (!m_config.topicPrefix.isEmpty()) {
		topic = m_config.topicPrefix.toStdString() + "_server"
		        + std::to_string(serverId) + "_channel"
		        + std::to_string(channelId);
	} else {
		topic = "mumble_server" + std::to_string(serverId) + "_channel"
		        + std::to_string(channelId);
	}

	notifyTopic(topic, title, body, category, priority, serverId, channelId, dataJson);
}

void PushNotificationDispatcher::shutdown() {
	if (m_initialised && m_sym.shutdown) {
		m_sym.shutdown();
		qWarning("push: module shut down");
	}
	m_initialised = false;

	if (m_lib && m_lib->isLoaded()) {
		m_lib->unload();
	}
	m_lib.reset();
	m_sym = {};
}

std::string PushNotificationDispatcher::lastError() const {
	if (!m_initialised || !m_sym.lastError) return {};
	const char *err = m_sym.lastError();
	return err ? std::string(err) : std::string();
}

} // namespace push
