// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_MURMUR_SERVER_H_
#define MUMBLE_MURMUR_SERVER_H_

#include <QtCore/QtGlobal>

#ifdef Q_OS_WIN
#	include "win.h"
#endif

#include "ACL.h"
#include "AclSubsystem.h"
#include "AudioReceiverBuffer.h"
#include "Ban.h"
#include "ChannelListenerManager.h"
#include "ChannelVisibility.h"
#include "DBWrapper.h"
#include "HostAddress.h"
#include "pchat/PersistentChatManager.h"
#include "pchat/ServerBridge.h"
#include "pchat/TokenBucketRateLimiter.h"
#include "push/PushNotificationDispatcher.h"
#include "WebRtcSfuManager.h"
#include "ServerEventDistributor.h"

class PluginHostManager;
class LinkPreviewBridge;
#include "Mumble.pb.h"
#include "MumbleProtocol.h"
#include "QtUtils.h"
#include "Timer.h"
#include "User.h"
#include "Version.h"
#include "VolumeAdjustment.h"
#include "database/ConnectionParameter.h"

#include <QtCore/QEvent>
#include <QtCore/QMutex>
#include <QtCore/QQueue>
#include <QtCore/QReadWriteLock>
#include <QtCore/QRegularExpression>
#include <QtCore/QSocketNotifier>
#include <QtCore/QStringList>
#include <QtCore/QThread>
#include <QtCore/QTimer>
#include <QtCore/QUrl>
#include <QtNetwork/QSslCertificate>
#include <QtNetwork/QSslKey>
#include <QtNetwork/QSslSocket>
#include <QtNetwork/QTcpServer>
#if defined(USE_QSSLDIFFIEHELLMANPARAMETERS)
#	include <QtNetwork/QSslDiffieHellmanParameters>
#endif

#ifdef Q_OS_WIN
#	include <winsock2.h>
#endif

#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

class Zeroconf;
class Channel;
class PacketDataStream;
class ServerUser;
class User;
class QNetworkAccessManager;

struct TextMessage {
	QList< unsigned int > qlSessions;
	QList< unsigned int > qlChannels;
	QList< unsigned int > qlTrees;
	QString qsText;
};

/// A registered push notification target.
/// Stored per certificate hash so that push still works after the
/// user disconnects (the FCM token remains valid).
struct PushRegistration {
	/// FCM device token obtained from the client.
	std::string fcmToken;
	/// Channels the user had TextMessage permission for at registration time.
	std::set< uint32_t > allowedChannels;
	/// Channels the user explicitly muted notifications for (client preference).
	std::set< uint32_t > mutedChannels;
};

/// Live push subscription for a connected client session.
/// The server routes TextMessages to subscribed sessions for channels
/// they are not currently in, as long as the channel is in allowedChannels
/// and not in mutedChannels.
struct LivePushSubscription {
	/// Channels the user has SubscribePush permission for.
	std::set< uint32_t > allowedChannels;
	/// Channels the user explicitly excluded from live delivery.
	std::set< uint32_t > mutedChannels;
};

class SslServer : public QTcpServer {
private:
	Q_OBJECT
	Q_DISABLE_COPY(SslServer)
protected:
	QList< QSslSocket * > qlSockets;
	void incomingConnection(qintptr) Q_DECL_OVERRIDE;

public:
	QSslSocket *nextPendingSSLConnection();
	SslServer(QObject *parent = nullptr);
};

#define EXEC_QEVENT (QEvent::User + 959)

class ExecEvent : public QEvent {
	Q_DISABLE_COPY(ExecEvent)

protected:
	std::function< void() > func;

public:
	ExecEvent(std::function< void() >);
	void execute();
};

class Server : public QThread {
private:
	Q_OBJECT
	Q_DISABLE_COPY(Server)

	friend class PluginHostManager;
	friend class LinkPreviewBridge;

protected:
	bool bRunning;

	QNetworkAccessManager *qnamNetwork;

#ifdef USE_ZEROCONF
	Zeroconf *zeroconf;
#endif
	void startThread();
	void stopThread();

	void customEvent(QEvent *evt);
	// Former ServerParams
public:
	QList< QHostAddress > qlBind;
	unsigned short usPort;
	int iTimeout;
	int iMaxBandwidth;
	unsigned int iMaxUsers;
	unsigned int iMaxUsersPerChannel;
	unsigned int iDefaultChan;
	bool bRememberChan;
	int iRememberChanDuration;
	int iMaxTextMessageLength;
	int iMaxImageMessageLength;
	int iOpusThreshold;
	bool bAllowHTML;
	QString qsPassword;
	QString qsWelcomeText;
	QString qsWelcomeTextFile;
	bool bCertRequired;
	bool bForceExternalAuth;
	/// Whether registered users may enrol / use a TOTP second factor
	/// (self-service account settings). Runtime-toggleable via the
	/// `allowaccounttotp` server setting; enforcement in msgAuthenticate
	/// is skipped while disabled.
	bool bAllowAccountTotp;
	unsigned int m_botCount = 0;

	QString qsRegName;
	QString qsRegPassword;
	QString qsRegHost;
	QString qsRegLocation;
	QUrl qurlRegWeb;
	/// Optional override for the Fancy Mumble REST API base URL
	/// advertised to clients in `ServerConfig::fancy_rest_api_url`.
	/// Used when the HTTP interface is behind a reverse proxy or
	/// ingress and therefore not reachable at the same hostname as
	/// the Mumble TCP port.
	QString qsFancyRestApiUrl;
	bool bBonjour;
	bool bAllowPing;
	bool allowRecording;
	unsigned int rollingStatsWindow;

	QRegularExpression qrUserName;
	QRegularExpression qrChannelName;

	unsigned int iMessageLimit;
	unsigned int iMessageBurst;

	unsigned int iPluginMessageLimit;
	unsigned int iPluginMessageBurst;

	bool broadcastListenerVolumeAdjustments;

	Version::full_t m_suggestVersion;

	std::optional< bool > m_suggestPositional;
	std::optional< bool > m_suggestPushToTalk;

	bool bUsingMetaCert;
	QSslCertificate qscCert;
	QSslKey qskKey;

	/// qlIntermediates contains the certificates
	/// from this virtual server's certificate PEM
	// bundle that do not match the virtual server's
	// private key.
	///
	/// Simply put: it contains any certificates
	/// that aren't the main certificate, or "leaf"
	/// certificate.
	QList< QSslCertificate > qlIntermediates;
#if defined(USE_QSSLDIFFIEHELLMANPARAMETERS)
	QSslDiffieHellmanParameters qsdhpDHParams;
#endif

	Timer tUptime;

	bool bValid;

	ChannelListenerManager m_channelListenerManager;


	Mumble::Protocol::UDPDecoder< Mumble::Protocol::Role::Server > m_udpDecoder;
	Mumble::Protocol::UDPDecoder< Mumble::Protocol::Role::Server > m_tcpTunnelDecoder;
	Mumble::Protocol::UDPPingEncoder< Mumble::Protocol::Role::Server > m_udpPingEncoder;
	Mumble::Protocol::UDPAudioEncoder< Mumble::Protocol::Role::Server > m_udpAudioEncoder;
	Mumble::Protocol::UDPAudioEncoder< Mumble::Protocol::Role::Server > m_tcpAudioEncoder;

	std::span< const Mumble::Protocol::byte >
		handlePing(const Mumble::Protocol::UDPDecoder< Mumble::Protocol::Role::Server > &decoder,
				   Mumble::Protocol::UDPPingEncoder< Mumble::Protocol::Role::Server > &encoder, bool expectExtended);

	void readParams();

	int iCodecAlpha;
	int iCodecBeta;
	bool bPreferAlpha;
	bool bOpus;
	void recheckCodecVersions(ServerUser *connectingUser = 0);

#ifdef USE_ZEROCONF
	void initZeroconf();
	void removeZeroconf();
#endif
	// Registration, implementation in Register.cpp
	QTimer qtTick;
	void initRegister();

	WhisperTargetCache createWhisperTargetCacheFor(ServerUser &speaker, const WhisperTarget &target);

private:
	int iChannelNestingLimit;
	int iChannelCountLimit;

	AudioReceiverBuffer m_udpAudioReceivers;
	AudioReceiverBuffer m_tcpAudioReceivers;

public slots:
	void regSslError(const QList< QSslError > &);
	void finished();
	void update();

	// Certificate stuff, implemented partially in Cert.cpp
public:
	static bool isKeyForCert(const QSslKey &key, const QSslCertificate &cert);
	/// Attempt to load a private key in PEM format from |buf|.
	/// If |passphrase| is non-empty, it will be used for decrypting the private key in |buf|.
	/// If a valid RSA, DSA or EC key is found, it is returned.
	/// If no valid private key is found, a null QSslKey is returned.
	static QSslKey privateKeyFromPEM(const QByteArray &buf, const QByteArray &pass = QByteArray());
	void initializeCert();
	const QString getDigest() const;

public slots:
	void newClient();
	void connectionClosed(QAbstractSocket::SocketError, const QString &);
	void sslError(const QList< QSslError > &);
	void message(Mumble::Protocol::TCPMessageType, const QByteArray &, ServerUser *cCon = nullptr);
	void checkTimeout();
	void tcpTransmitData(QByteArray, unsigned int);
	void doSync(unsigned int);
	void encrypted();
	void udpActivated(int);
signals:
	void reqSync(unsigned int);
	void tcpTransmit(QByteArray, unsigned int id);

public:
	unsigned int iServerNum;
	QQueue< unsigned int > qqIds;
	QList< SslServer * > qlServer;
	QTimer *qtTimeout;

#ifdef Q_OS_UNIX
	int aiNotify[2];
	QList< int > qlUdpSocket;
#else
	HANDLE hNotify;
	QList< SOCKET > qlUdpSocket;
#endif
	QList< QSocketNotifier * > qlUdpNotifier;

	/// This lock provides synchronization between the
	/// main thread (where control channel messages and
	/// RPC happens), and the Server's voice thread.
	///
	/// These are the only two threads in Murmur that
	/// access a Server's data.
	///
	/// The easiest way to understand the locking strategy
	/// and synchronization between the main thread and the
	/// Server's voice thread is by using the concept of
	/// ownership.
	///
	/// A thread owning an object means that it is the only
	/// thread that is allowed to write to that object. To
	/// make changes to it.
	///
	/// Most data in the Server class is owned by the main
	/// thread. That means that the main thread is the only
	/// thread that writes/updates those structures.
	///
	/// When processing incoming voice data (and re-
	/// broadcasting) that voice data), the Server's voice
	/// thread needs to access various parts of Server's data,
	/// such as qhUsers, qhChannels, User->cChannel, etc.
	/// However, these are owned by the main thread.
	///
	/// To ensure correct synchronization between the two
	/// threads, the contract for using qrwlVoiceThread is
	/// as follows:
	///
	///  - When the Server's voice thread needs to read data
	///    owned by the main thread, it must hold a read lock
	///    on qrwlVoiceThread.
	///
	///  - The Server's voice thread does not write to any data
	///    that is owned by the main thread.
	///
	///  - When the main thread needs to write to data owned by
	///    itself that is accessed by the voice thread, it must
	///    hold a write lock on qrwlVoiceThread.
	///
	///  - When the main thread needs to read data that is owned
	///    by itself, it DOES NOT hold a lock on qrwlVoiceThread.
	///    That is because ownership of data guarantees that no
	///    other thread can write to that data.
	QReadWriteLock qrwlVoiceThread;
	QHash< unsigned int, ServerUser * > qhUsers;
	QHash< QPair< HostAddress, quint16 >, ServerUser * > qhPeerUsers;
	QHash< HostAddress, QSet< ServerUser * > > qhHostUsers;
	QHash< unsigned int, Channel * > qhChannels;

	QHash< int, QString > qhUserNameCache;
	QHash< Mumble::QtUtils::CaseInsensitiveQString, int > qhUserIDCache;

	std::vector< Ban > m_bans;

	DBWrapper m_dbWrapper;

	std::unique_ptr< pchat::ServerBridge > m_pchatBridge;
	std::unique_ptr< pchat::TokenBucketRateLimiter > m_pchatRateLimiter;
	std::unique_ptr< pchat::PersistentChatManager > m_pchatManager;
	pchat::PersistentChatManager::Config m_pchatConfig;

	std::unique_ptr< push::PushNotificationDispatcher > m_pushDispatcher;

	std::unique_ptr< WebRtcSfuManager > m_sfuManager;

	/// Central event registry/dispatcher. Distributors (the internal plugin
	/// host, ZeroC Ice, future gRPC, …) register here and the Server fans every
	/// control-plane event out to all of them. Declared before m_pluginHost so
	/// the host (a subscriber) is destroyed while the distributor is still alive.
	ServerEventDistributor m_events{ *this };

	/// Owns the ACL permission cache, its lock and the channel-visibility policy.
	/// Replaces the former public qmCache / acCache / m_channelVisibility members
	/// that callers reached into directly.
	AclSubsystem m_aclCache;

	/// Single-shot timer for the channel-expiry reaper. Fires on the main event
	/// loop (same thread as channel mutations -> no locking needed), armed to the
	/// earliest channel deadline so the server sleeps between expiries.
	QTimer m_channelExpiryTimer;
	/// Fired by m_channelExpiryTimer: reap channels whose deadline has passed
	/// (recomputing sliding deadlines lazily), then re-arm to the next one.
	void onChannelExpiryTimer();

	// Link-preview glue over the generic plugin host.  Declared before
	// m_pluginHost so the host (whose plugin runtime delivers the responses this
	// bridge handles) is destroyed first, while this bridge is still alive.
	std::unique_ptr< LinkPreviewBridge > m_linkPreviewBridge;

	std::unique_ptr< PluginHostManager > m_pluginHost;


	QHash< QString, PushRegistration > m_pushRegistrations;

	/// Live push subscriptions keyed by session ID.
	/// Removed automatically when the user disconnects.
	QHash< uint32_t, LivePushSubscription > m_livePushSubscriptions;

	/// Read receipt watermarks: channel_id -> (cert_hash -> watermark).
	/// Tracks the last read message_id per user per channel.
	struct ReadWatermark {
		std::string lastMessageId;
		uint64_t timestamp = 0;
	};
	QHash< uint32_t, QHash< QString, ReadWatermark > > m_readWatermarks;
	void handleReadReceipt(ServerUser *uSource, MumbleProto::FancyReadReceipt &msg);

	/// Maps message_id to the session that originally sent it.
	/// Used to validate edit ownership (only the original sender can edit).
	QHash< QString, uint32_t > m_messageOwners;

	/// Latest broadcast onboarding config. Empty by default; set via
	/// `FancyOnboardingConfigUpdate` from a Write-permitted user on the
	/// root channel. Sent to every Fancy 0.3.1+ client after ServerSync.
	MumbleProto::FancyOnboardingConfig m_onboardingConfig;
	/// Per-cert-hash onboarding responses. Looked up on
	/// `FancyOnboardingResponseQuery` and used to apply the
	/// answer-mapped ACL group memberships when the response is
	/// updated.
	QHash< QString, MumbleProto::FancyOnboardingResponse > m_onboardingResponses;

	/// Monotonic revision for the editable server-settings snapshot, bumped
	/// each time an admin applies a change so clients can drop stale
	/// broadcasts.
	uint64_t m_serverSettingsRevision = 0;

	/// Build and send the editable server-settings snapshot (core + plugin
	/// settings) to `u`.  No-op unless `u` has Write on the root channel and
	/// reports a Fancy version new enough to understand it.
	void sendFancyServerSettings(ServerUser *u);

	/// Build and send the self-service account snapshot (registration state,
	/// auth mode, email, 2FA) for `u`'s own account to `u`.
	void sendFancyAccountSettings(ServerUser *u);

	/// Send a FancyAccountAck for `action` to `u`.  `error` empty = success.
	void sendFancyAccountAck(ServerUser *u, unsigned int action, const QString &error = QString());

	void addListener(QHash< ServerUser *, VolumeAdjustment > &listeners, ServerUser &user, const Channel &channel);
	void processMsg(ServerUser *u, Mumble::Protocol::AudioData audioData, AudioReceiverBuffer &buffer,
					Mumble::Protocol::UDPAudioEncoder< Mumble::Protocol::Role::Server > &encoder);
	void sendMessage(ServerUser &u, const unsigned char *data, int len, QByteArray &cache, bool force = false);
	void run();

	bool validateChannelName(const QString &name);
	bool validateUserName(const QString &name);

	bool checkDecrypt(ServerUser *u, const unsigned char *encrypted, unsigned char *plain, unsigned int cryptlen);

	// Permission / channel-visibility checks live on ServerUser
	// (user->hasPermission(c, perm) / user->canSee(c) / user->effectivePermissions(c)),
	// grouped on the object the question is about. Those delegate to the
	// AclSubsystem reached through this accessor (no Server internals exposed).
	AclSubsystem &aclCache() { return m_aclCache; }

	/// Re-arm the single-shot channel-expiry timer to the earliest upcoming
	/// channel deadline ("sleep until next" reaper). Cheap; call after any change
	/// that can affect a channel's expiry (create / edit / remove).
	void rescheduleChannelExpiry();
	void sendClientPermission(ServerUser *u, Channel *c, bool explicitlyRequested = false);
	void flushClientPermissionCache(ServerUser *u, MumbleProto::PermissionQuery &mpqq);
	void clearACLCache(User *p = nullptr);
	void clearWhisperTargetCache();

	void sendProtoAll(const ::google::protobuf::Message &msg, Mumble::Protocol::TCPMessageType type,
					  Version::full_t version, Version::CompareMode mode);
	void sendProtoExcept(ServerUser *, const ::google::protobuf::Message &msg, Mumble::Protocol::TCPMessageType type,
						 Version::full_t version, Version::CompareMode mode);
	void sendProtoMessage(ServerUser *, const ::google::protobuf::Message &msg, Mumble::Protocol::TCPMessageType type);
	/// Like sendProtoAll, but only to users who may see channel @p c (visibility
	/// policy). Used for any message that concerns a (possibly hidden) channel.
	void sendProtoToChannelObservers(Channel *c, const ::google::protobuf::Message &msg,
									 Mumble::Protocol::TCPMessageType type, Version::full_t version,
									 Version::CompareMode mode);
	/// As sendProtoToChannelObservers, but skips @p except (the acting user).
	void sendProtoToChannelObserversExcept(ServerUser *except, Channel *c, const ::google::protobuf::Message &msg,
										   Mumble::Protocol::TCPMessageType type, Version::full_t version,
										   Version::CompareMode mode);

	// sendAll sends a protobuf message to all users on the server whose version is either bigger than v or
	// lower than ~v. If v == 0 the message is sent to everyone.
#define PROCESS_MUMBLE_TCP_MESSAGE(name, value)                                                        \
	void sendAll(const MumbleProto::name &msg, Version::full_t v = Version::UNKNOWN,                   \
				 Version::CompareMode mode = Version::CompareMode::AtLeast) {                          \
		sendProtoAll(msg, Mumble::Protocol::TCPMessageType::name, v, mode);                            \
	}                                                                                                  \
	void sendExcept(ServerUser *u, const MumbleProto::name &msg, Version::full_t v = Version::UNKNOWN, \
					Version::CompareMode mode = Version::CompareMode::AtLeast) {                       \
		sendProtoExcept(u, msg, Mumble::Protocol::TCPMessageType::name, v, mode);                      \
	}                                                                                                  \
	void sendMessage(ServerUser *u, const MumbleProto::name &msg) {                                    \
		sendProtoMessage(u, msg, Mumble::Protocol::TCPMessageType::name);                              \
	}                                                                                                  \
	/* Broadcast only to users who may see channel c (hidden-channel aware). */                       \
	void sendToObservers(Channel *c, const MumbleProto::name &msg, Version::full_t v = Version::UNKNOWN, \
						 Version::CompareMode mode = Version::CompareMode::AtLeast) {                  \
		sendProtoToChannelObservers(c, msg, Mumble::Protocol::TCPMessageType::name, v, mode);          \
	}                                                                                                  \
	/* As sendToObservers, but excludes the acting user u. */                                          \
	void sendToObserversExcept(ServerUser *u, Channel *c, const MumbleProto::name &msg,               \
							   Version::full_t v = Version::UNKNOWN,                                    \
							   Version::CompareMode mode = Version::CompareMode::AtLeast) {            \
		sendProtoToChannelObserversExcept(u, c, msg, Mumble::Protocol::TCPMessageType::name, v, mode); \
	}

	MUMBLE_ALL_TCP_MESSAGES
#undef PROCESS_MUMBLE_TCP_MESSAGE

	static void hashAssign(QString &destination, QByteArray &hash, const QString &str);
	static void hashAssign(QByteArray &destination, QByteArray &hash, const QByteArray &source);
	bool isTextAllowed(QString &str, bool &changed);

	void setLiveConf(const QString &key, const QString &value);

	QString addressToString(const QHostAddress &, unsigned short port);

	void log(const QString &) const;
	void log(ServerUser *u, const QString &) const;

	// Push notification helpers (impl in Messages.cpp)
	void dispatchPushNotifications(ServerUser *sender, const std::set< uint32_t > &targetChannels,
								   const std::string &title, const std::string &body);
	void handlePushRegistration(ServerUser *sender, const MumbleProto::FancyPushRegister &msg);
	void handlePushChannelUpdate(ServerUser *sender, const MumbleProto::FancyPushUpdate &msg);
	void computeAllowedPushChannels(ServerUser *user, std::set< uint32_t > &out);
	void handleLivePushSubscribe(ServerUser *sender, const MumbleProto::FancySubscribePush &msg);

	void removeChannel(unsigned int id);
	void removeChannel(Channel *c, Channel *dest = nullptr);
	void userEnterChannel(User *u, Channel *c, MumbleProto::UserState &mpus);
	bool unregisterUser(int id);

	Server(unsigned int snum, const ::mumble::db::ConnectionParameter &connectionParam, QObject *parent = nullptr);
	~Server();

	bool canNest(Channel *newParent, Channel *channel = nullptr) const;

	/// @return UserID of authenticated user, -1 for authentication failures, -2 for unknown user (fallthrough),
	///         -3 for authentication failures where the data could (temporarily) not be verified.
	int authenticate(QString &name, const QString &password, int sessionId = 0, const QStringList &emails = {},
					 const QString &certhash = {}, bool bStrongCert = false,
					 const QList< QSslCertificate > &certs = {});
	bool setTexture(ServerUser &user, const QByteArray &texture);
	bool storeTexture(const ServerUserInfo &userInfo, const QByteArray &texture);
	void loadTexture(ServerUser &user);
	QByteArray getTexture(int userID);
	bool setComment(ServerUser &user, const QString &comment);
	void loadComment(ServerUser &user);

	void addChannelListener(const ServerUser &user, const Channel &channel);
	void setChannelListenerVolume(const ServerUser &user, const Channel &channel, float volume);
	void disableChannelListener(const ServerUser &user, const Channel &channel);
	void deleteChannelListener(const ServerUser &user, const Channel &channel);
	bool channelListenerExists(const ServerUser &user, const Channel &channel);

	QString getRegisteredUserName(int userID);
	int getRegisteredUserID(const QString &name);

	bool registerUser(ServerUser &user);
	int registerUser(const ServerUserInfo &userInfo);

	bool setUserProperties(int userID, QMap< int, QString > properties);
	QMap< int, QString > getUserProperties(int userID);

	Channel *createNewChannel(Channel *parent, const QString &name, bool temporary = false, int position = 0,
							  unsigned int maxUser = 0);

	/// Generic, content-agnostic channel provisioning for the plugin host bridge
	/// (the private-rooms primitive, exposed programmatically). These run on the
	/// server's own thread - off-thread callers marshal via QMetaObject::invokeMethod.
	///
	/// Create a sub-channel under `parentId` (or return an existing same-named
	/// child) with standard channel properties: `hidden`, persistent-chat
	/// `pchatProtocol` (0 = none), auto-`expiryMode`/`expiryDuration` (0 = none),
	/// and `inviteeUserIds` which - when non-empty - make it a private channel
	/// (deny @all see/enter/traverse, allow each invitee). When
	/// `registeredCanManage` is true it becomes a shared container the `auth`
	/// (registered-users) group may see, traverse and create sub-channels in,
	/// hidden from guests (deny @all SeeChannel). Returns the channel id, or 0
	/// on failure. The server ascribes no domain meaning to any of this.
	/// Create a channel on behalf of a plugin. When @p detached is true the
	/// channel is parentless (like the root) and marked ChannelAttribute::Detached:
	/// it never appears in the channel tree and is only ever sent to Fancy clients
	/// (@p parentId is then ignored). Otherwise it is created under @p parentId.
	unsigned int createChannelForPlugin(unsigned int parentId, const QString &name, bool hidden,
										bool registeredCanManage, bool detached, uint32_t pchatProtocol,
										uint32_t expiryMode, uint32_t expiryDuration,
										const QVector< unsigned int > &inviteeUserIds);
	/// Grant a registered user SeeChannel|Enter|Traverse on an existing private
	/// channel (admission to an invitee-gated room). Returns true on success.
	bool grantChannelAccess(unsigned int channelId, unsigned int userId);
	/// Inverse of grantChannelAccess: drop the user's per-user allow ACLs on the
	/// channel, move their sessions out if inside, and tell them the channel is
	/// gone (a user who cannot see a room should not keep it in their list).
	/// Idempotent; returns true unless the channel does not exist.
	bool revokeChannelAccess(unsigned int channelId, unsigned int userId);

	void linkChannels(Channel &first, Channel &second);
	void unlinkChannels(Channel &first, Channel &second);

	std::vector< UserInfo > getAllRegisteredUserProperties(QString nameSubstring = "");

	/// Access the central event registry/dispatcher. Distributors register
	/// here via events().registerSubscriber(...) or events().subscribe()....
	ServerEventDistributor &events() { return m_events; }

	// RPC functions. Implementation in RPC.cpp
	void connectAuthenticator(QObject *p);
	void disconnectAuthenticator(QObject *p);
	void setTempGroups(int userid, int sessionId, Channel *cChannel, const QStringList &groups);
	void clearTempGroups(User *user, Channel *cChannel = nullptr, bool recurse = true);
	void startListeningToChannel(ServerUser *user, Channel *cChannel);
	void stopListeningToChannel(ServerUser *user, Channel *cChannel);
	void setListenerVolumeAdjustment(ServerUser *user, const Channel *cChannel,
									 const VolumeAdjustment &volumeAdjustment);
	void sendWelcomeMessageTo(ServerUser *user);

	/// @returns Whether the given ID is a valid user ID. That is, whether the given ID corresponds to a registered
	/// user on this server.
	bool isValidUserID(int userID);
signals:
	void registerUserSig(int &, const QMap< int, QString > &);
	void unregisterUserSig(int &, int);
	void getRegisteredUsersSig(const QString &, QMap< int, QString > &);
	void getRegistrationSig(int &, int, QMap< int, QString > &);
	void authenticateSig(int &, QString &, int, const QList< QSslCertificate > &, const QString &, bool,
						 const QString &);
	void setInfoSig(int &, int, const QMap< int, QString > &);
	void setTextureSig(int &, int, const QByteArray &);
	void idToNameSig(QString &, int);
	void nameToIdSig(int &, const QString &);
	void idToTextureSig(QByteArray &, int);

	void textMessageFilterSig(int &, const User *, MumbleProto::TextMessage &);

public:
	void setUserState(User *p, Channel *parent, bool mute, bool deaf, bool suppressed, bool prioritySpeaker,
					  const QString &name = QString(), const QString &comment = QString());

	bool setChannelState(Channel *c, Channel *parent, const QString &qsName, const QSet< Channel * > &links,
						 const QString &desc = QString(), const int position = 0);

	void sendTextMessage(Channel *cChannel, ServerUser *pUser, bool tree, const QString &text);

	/// Returns true if a channel is full. If a user is provided, false will always
	/// be returned if the user has write permission in the channel.
	bool isChannelFull(Channel *c, ServerUser *u = 0);

	// Implementation in Messages.cpp
#define PROCESS_MUMBLE_TCP_MESSAGE(name, value) void msg##name(ServerUser *, MumbleProto::name &);
	MUMBLE_ALL_TCP_MESSAGES
#undef PROCESS_MUMBLE_TCP_MESSAGE
};

#endif
