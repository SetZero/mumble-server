// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_MURMUR_WEBRTCSFUMANAGER_H_
#define MUMBLE_MURMUR_WEBRTCSFUMANAGER_H_

#include <QLibrary>
#include <QTimer>
#include <QString>

#include <functional>
#include <memory>
#include <cstdint>

struct SfuHandle;
struct SfuFfiConfig;
struct SfuFfiEvent;

/// Configuration for the WebRTC SFU module.
struct WebRtcSfuConfig {
	/// Master switch: if false, SFU is not loaded and WebRTC signals are
	/// relayed as before (pure client-to-client P2P).
	bool enabled = false;

	/// Filesystem path to the webrtc_sfu shared library.
	/// When empty, the server tries to find it next to the binary.
	QString modulePath;

	/// UDP port for WebRTC media (0 = OS-assigned).
	uint16_t udpPort = 0;

	/// Public IP address that clients can reach.
	/// Embedded into SDP answers as the server's ICE candidate.
	QString publicIp = QStringLiteral("0.0.0.0");
};

/// Thin C++ wrapper around the Rust webrtc-sfu shared library.
/// Loads the library at runtime via QLibrary.  If the library is not
/// available, all methods silently no-op (the server falls back to
/// pure relay mode).
class WebRtcSfuManager : public QObject {
	Q_OBJECT
public:
	explicit WebRtcSfuManager(QObject *parent = nullptr);
	~WebRtcSfuManager() override;

	WebRtcSfuManager(const WebRtcSfuManager &)            = delete;
	WebRtcSfuManager &operator=(const WebRtcSfuManager &) = delete;

	/// Load the Rust SFU library and initialise the runtime.
	bool init(const WebRtcSfuConfig &config);

	/// Whether the SFU was loaded and initialised successfully.
	bool isAvailable() const;

	/// Create a broadcast session (called when START signal arrives).
	void createSession(uint32_t broadcasterSession);

	/// Handle a broadcaster's SDP offer.
	void broadcasterOffer(uint32_t broadcasterSession, const QString &sdp);

	/// Handle a viewer's SDP offer.
	void viewerOffer(uint32_t broadcasterSession, uint32_t viewerSession,
	                 const QString &sdp);

	/// Forward an ICE candidate from a client.
	void addIceCandidate(uint32_t broadcasterSession, uint32_t clientSession,
	                     const QString &candidateJson);

	/// Destroy a broadcast session (called on STOP or disconnect).
	void destroySession(uint32_t broadcasterSession);

	/// Shut down the SFU runtime and unload the library.
	void shutdown();

signals:
	/// Emitted when an SDP answer is ready for a client.
	void sdpAnswerReady(uint32_t targetSession, const QString &sdp);

	/// Emitted when a broadcast session ends.
	void sessionEnded(uint32_t broadcasterSession);

private slots:
	void pollEvents();

private:
	struct Symbols {
		std::function< SfuHandle *(const SfuFfiConfig *) > init;
		std::function< void(SfuHandle *, uint32_t) > createSession;
		std::function< void(SfuHandle *, uint32_t, const char *) > broadcasterOffer;
		std::function< void(SfuHandle *, uint32_t, uint32_t, const char *) > viewerOffer;
		std::function< void(SfuHandle *, uint32_t, uint32_t, const char *) > addIceCandidate;
		std::function< SfuFfiEvent *(SfuHandle *) > pollEvent;
		std::function< void(SfuFfiEvent *) > freeEvent;
		std::function< void(SfuHandle *, uint32_t) > destroySession;
		std::function< void(SfuHandle *) > shutdown;
	};

	bool resolveSymbols();

	std::unique_ptr< QLibrary > m_lib;
	Symbols m_sym{};
	SfuHandle *m_handle = nullptr;
	QTimer *m_pollTimer = nullptr;
};

#endif // MUMBLE_MURMUR_WEBRTCSFUMANAGER_H_
