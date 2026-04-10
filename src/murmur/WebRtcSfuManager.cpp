// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "WebRtcSfuManager.h"

#include <QCoreApplication>
#include <QDir>

#include <tracy/Tracy.hpp>

// FFI event type values (must match Rust SfuFfiEventType).
static constexpr int kSfuEventSdpAnswer    = 0;
static constexpr int kSfuEventSessionEnded = 1;

WebRtcSfuManager::WebRtcSfuManager(QObject *parent) : QObject(parent) {
}

WebRtcSfuManager::~WebRtcSfuManager() {
	shutdown();
}

bool WebRtcSfuManager::init(const WebRtcSfuConfig &config) {
	ZoneScoped;

	if (!config.enabled)
		return false;

	// Determine library path.
	QString libPath = config.modulePath;
	if (libPath.isEmpty()) {
		QDir appDir(QCoreApplication::applicationDirPath());
#ifdef Q_OS_WIN
		libPath = appDir.filePath(QStringLiteral("webrtc_sfu.dll"));
#elif defined(Q_OS_MAC)
		libPath = appDir.filePath(QStringLiteral("libwebrtc_sfu.dylib"));
#else
		libPath = appDir.filePath(QStringLiteral("libwebrtc_sfu.so"));
#endif
	}

	m_lib = std::make_unique< QLibrary >(libPath);
	if (!m_lib->load()) {
		qWarning("WebRtcSfuManager: failed to load SFU library at '%s': %s",
		         qPrintable(libPath), qPrintable(m_lib->errorString()));
		m_lib.reset();
		return false;
	}

	if (!resolveSymbols()) {
		qWarning("WebRtcSfuManager: failed to resolve SFU symbols");
		m_lib->unload();
		m_lib.reset();
		return false;
	}

	// Build FFI config.
	QByteArray ipBytes = config.publicIp.toUtf8();

	// Use a stack struct matching the FFI layout.
	struct FfiConfig {
		uint16_t udp_port;
		const char *public_ip;
	};

	FfiConfig ffiConfig;
	ffiConfig.udp_port  = config.udpPort;
	ffiConfig.public_ip = ipBytes.constData();

	m_handle = m_sym.init(reinterpret_cast< const SfuFfiConfig * >(&ffiConfig));
	if (!m_handle) {
		qWarning("WebRtcSfuManager: sfu_init() returned NULL");
		m_lib->unload();
		m_lib.reset();
		return false;
	}

	// Start polling for events from the Rust runtime.
	m_pollTimer = new QTimer(this);
	m_pollTimer->setInterval(5); // 5 ms poll interval
	connect(m_pollTimer, &QTimer::timeout, this, &WebRtcSfuManager::pollEvents);
	m_pollTimer->start();

	qInfo("WebRtcSfuManager: SFU initialised (UDP port %u, public IP %s)",
	      config.udpPort, qPrintable(config.publicIp));

	return true;
}

bool WebRtcSfuManager::isAvailable() const {
	return m_handle != nullptr;
}

void WebRtcSfuManager::createSession(uint32_t broadcasterSession) {
	if (!m_handle) return;
	m_sym.createSession(m_handle, broadcasterSession);
}

void WebRtcSfuManager::broadcasterOffer(uint32_t broadcasterSession, const QString &sdp) {
	if (!m_handle) return;
	QByteArray utf8 = sdp.toUtf8();
	m_sym.broadcasterOffer(m_handle, broadcasterSession, utf8.constData());
}

void WebRtcSfuManager::viewerOffer(uint32_t broadcasterSession, uint32_t viewerSession,
                                   const QString &sdp) {
	if (!m_handle) return;
	QByteArray utf8 = sdp.toUtf8();
	m_sym.viewerOffer(m_handle, broadcasterSession, viewerSession, utf8.constData());
}

void WebRtcSfuManager::addIceCandidate(uint32_t broadcasterSession, uint32_t clientSession,
                                       const QString &candidateJson) {
	if (!m_handle) return;
	QByteArray utf8 = candidateJson.toUtf8();
	m_sym.addIceCandidate(m_handle, broadcasterSession, clientSession, utf8.constData());
}

void WebRtcSfuManager::destroySession(uint32_t broadcasterSession) {
	if (!m_handle) return;
	m_sym.destroySession(m_handle, broadcasterSession);
}

void WebRtcSfuManager::shutdown() {
	if (m_pollTimer) {
		m_pollTimer->stop();
		delete m_pollTimer;
		m_pollTimer = nullptr;
	}

	if (m_handle && m_sym.shutdown) {
		m_sym.shutdown(m_handle);
		m_handle = nullptr;
	}

	if (m_lib) {
		m_lib->unload();
		m_lib.reset();
	}
}

void WebRtcSfuManager::pollEvents() {
	if (!m_handle) return;

	// Drain all queued events.
	while (true) {
		SfuFfiEvent *event = m_sym.pollEvent(m_handle);
		if (!event) break;

		// Read fields through a matching POD struct.
		struct EventPod {
			int event_type;
			uint32_t session_id;
			uint32_t broadcaster_session;
			char *payload;
		};

		auto *pod = reinterpret_cast< EventPod * >(event);

		if (pod->event_type == kSfuEventSdpAnswer && pod->payload) {
			emit sdpAnswerReady(pod->session_id, pod->broadcaster_session,
			                    QString::fromUtf8(pod->payload));
		} else if (pod->event_type == kSfuEventSessionEnded) {
			emit sessionEnded(pod->session_id);
		}

		m_sym.freeEvent(event);
	}
}

bool WebRtcSfuManager::resolveSymbols() {
	if (!m_lib) return false;

	auto resolve = [this](const char *name) -> QFunctionPointer {
		QFunctionPointer fn = m_lib->resolve(name);
		if (!fn) {
			qWarning("WebRtcSfuManager: missing symbol '%s'", name);
		}
		return fn;
	};

	auto fnInit = resolve("sfu_init");
	auto fnCreate = resolve("sfu_create_session");
	auto fnBrOffer = resolve("sfu_broadcaster_offer");
	auto fnVwOffer = resolve("sfu_viewer_offer");
	auto fnIce = resolve("sfu_add_ice_candidate");
	auto fnPoll = resolve("sfu_poll_event");
	auto fnFree = resolve("sfu_free_event");
	auto fnDestroy = resolve("sfu_destroy_session");
	auto fnShutdown = resolve("sfu_shutdown");

	if (!fnInit || !fnCreate || !fnBrOffer || !fnVwOffer || !fnIce
	    || !fnPoll || !fnFree || !fnDestroy || !fnShutdown) {
		return false;
	}

	m_sym.init = reinterpret_cast< SfuHandle *(*)(const SfuFfiConfig *) >(fnInit);
	m_sym.createSession = reinterpret_cast< void (*)(SfuHandle *, uint32_t) >(fnCreate);
	m_sym.broadcasterOffer =
		reinterpret_cast< void (*)(SfuHandle *, uint32_t, const char *) >(fnBrOffer);
	m_sym.viewerOffer =
		reinterpret_cast< void (*)(SfuHandle *, uint32_t, uint32_t, const char *) >(fnVwOffer);
	m_sym.addIceCandidate =
		reinterpret_cast< void (*)(SfuHandle *, uint32_t, uint32_t, const char *) >(fnIce);
	m_sym.pollEvent = reinterpret_cast< SfuFfiEvent *(*)(SfuHandle *) >(fnPoll);
	m_sym.freeEvent = reinterpret_cast< void (*)(SfuFfiEvent *) >(fnFree);
	m_sym.destroySession = reinterpret_cast< void (*)(SfuHandle *, uint32_t) >(fnDestroy);
	m_sym.shutdown  = reinterpret_cast< void (*)(SfuHandle *) >(fnShutdown);

	return true;
}
