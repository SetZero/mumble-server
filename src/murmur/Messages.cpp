// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "ACL.h"
#include "Channel.h"
#include "ChannelListenerManager.h"
#include "ClientType.h"
#include "Connection.h"
#include "Group.h"
#include "Meta.h"
#include "MumbleConstants.h"
#include "ProtoUtils.h"
#include "QtUtils.h"
#include "Server.h"
#include "PluginHostManager.h"
#include "ServerUser.h"
#include "User.h"
#include "Version.h"
#include "crypto/CryptState.h"

#include "murmur/database/UserProperty.h"

#include <algorithm>
#include <cassert>
#include <set>
#include <unordered_map>
#include <chrono>

#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonArray>
#include <QtCore/QStack>
#include <QtCore/QTimeZone>
#include <QtCore/QtEndian>
#include <QUuid>

#include <tracy/Tracy.hpp>

#define RATELIMIT(user)                   \
	if (user->leakyBucket.ratelimit(1)) { \
		return;                           \
	}

#define MSG_SETUP(st)            \
	if (uSource->sState != st) { \
		return;                  \
	}                            \
	uSource->bwr.resetIdleSeconds()

#define MSG_SETUP_NO_UNIDLE(st) \
	if (uSource->sState != st)  \
	return

#define VICTIM_SETUP                                   \
	ServerUser *pDstServerUser = uSource;              \
	if (msg.has_session())                             \
		pDstServerUser = qhUsers.value(msg.session()); \
	if (!pDstServerUser)                               \
		return;                                        \
	Q_UNUSED(pDstServerUser)

#define PERM_DENIED(who, where, what)                                                                                \
	{                                                                                                                \
		MumbleProto::PermissionDenied mppd;                                                                          \
		mppd.set_permission(static_cast< unsigned int >(what));                                                      \
		mppd.set_channel_id(where->iId);                                                                             \
		mppd.set_session(who->uiSession);                                                                            \
		mppd.set_type(MumbleProto::PermissionDenied_DenyType_Permission);                                            \
		sendMessage(uSource, mppd);                                                                                  \
		log(uSource,                                                                                                 \
			QString("%1 not allowed to %2 in %3").arg(who->qsName).arg(ChanACL::permName(what)).arg(where->qsName)); \
	}

#define PERM_DENIED_TYPE(type)                                        \
	{                                                                 \
		MumbleProto::PermissionDenied mppd;                           \
		mppd.set_type(MumbleProto::PermissionDenied_DenyType_##type); \
		sendMessage(uSource, mppd);                                   \
	}

#define PERM_DENIED_FALLBACK(type, version, text)                     \
	{                                                                 \
		MumbleProto::PermissionDenied mppd;                           \
		mppd.set_type(MumbleProto::PermissionDenied_DenyType_##type); \
		if (uSource->m_version < version)                             \
			mppd.set_reason(u8(text));                                \
		sendMessage(uSource, mppd);                                   \
	}

#define PERM_DENIED_HASH(user)                                                    \
	{                                                                             \
		MumbleProto::PermissionDenied mppd;                                       \
		mppd.set_type(MumbleProto::PermissionDenied_DenyType_MissingCertificate); \
		if (user)                                                                 \
			mppd.set_session(user->uiSession);                                    \
		sendMessage(uSource, mppd);                                               \
	}

/// A helper class for managing temporary access tokens.
/// It will add the tokens in the comstructor and remove them again in the destructor effectively
/// turning the tokens into a scope-based property.
class TemporaryAccessTokenHelper {
protected:
	ServerUser *affectedUser;
	QStringList qslTemporaryTokens;
	Server *server;

public:
	TemporaryAccessTokenHelper(ServerUser *affectedUser, const QStringList &tokens, Server *server)
		: affectedUser(affectedUser), qslTemporaryTokens(tokens), server(server) {
		// Add the temporary tokens
		QMutableStringListIterator it(this->qslTemporaryTokens);

		{
			QMutexLocker qml(&server->qmCache);

			while (it.hasNext()) {
				QString &token = it.next();

				// If tokens are treated case-insensitively, transform all temp. tokens to lowercase first
				if (Group::accessTokenCaseSensitivity == Qt::CaseInsensitive) {
					token = token.toLower();
				}

				if (!this->affectedUser->qslAccessTokens.contains(token, Group::accessTokenCaseSensitivity)) {
					// Add token
					this->affectedUser->qslAccessTokens << token;
				} else {
					// It appears, as if the user already has this token set -> it's not a temporary one or a duplicate
					it.remove();
				}
			}
		}

		if (!this->qslTemporaryTokens.isEmpty()) {
			// Clear the cache in order for tokens to take effect
			server->clearACLCache(this->affectedUser);
		}
	}

	~TemporaryAccessTokenHelper() {
		if (!this->qslTemporaryTokens.isEmpty()) {
			{
				QMutexLocker qml(&server->qmCache);

				// remove the temporary tokens
				for (const QString &token : this->qslTemporaryTokens) {
					this->affectedUser->qslAccessTokens.removeOne(token);
				}
			}

			// Clear cache to actually get rid of the temporary tokens
			server->clearACLCache(this->affectedUser);
		}
	}
};

/// Checks whether the given channel has restrictions affecting the ENTER privilege
///
/// @param c A pointer to the Channel that should be checked
/// @return Whether the provided channel has an ACL denying ENTER
bool isChannelEnterRestricted(Channel *c) {
	// A channel is enter restricted if there's an ACL denying enter privileges
	for (ChanACL *acl : c->qlACL) {
		if (acl->pDeny & ChanACL::Enter) {
			return true;
		}
	}

	return false;
}

void Server::msgAuthenticate(ServerUser *uSource, MumbleProto::Authenticate &msg) {
	ZoneScoped;

	if (uSource->sState == ServerUser::Authenticated && (msg.tokens_size() > 0 || !uSource->qslAccessTokens.empty())) {
		// Process a change in access tokens for already authenticated users
		QStringList qsl;

		for (int i = 0; i < msg.tokens_size(); ++i) {
			qsl << u8(msg.tokens(i));
		}

		{
			QMutexLocker qml(&qmCache);
			uSource->qslAccessTokens = qsl;
		}

		clearACLCache(uSource);

		// Send back updated enter states of all channels
		MumbleProto::ChannelState mpcs;

		for (Channel *chan : qhChannels) {
			mpcs.set_channel_id(static_cast< unsigned int >(chan->iId));
			mpcs.set_can_enter(hasPermission(uSource, chan, ChanACL::Enter));
			// As no ACLs have changed, we don't need to update the is_access_restricted message field

			sendMessage(uSource, mpcs);
		}
	}
	MSG_SETUP(ServerUser::Connected);

	// As the first thing, assign a session ID to this client. Given that the client initiated
	// the authentication procedure we can be sure that this is not just a random TCP connection.
	// Thus it is about time we assign the ID to this client in order to be able to reference it
	// in the following.
	{
		QWriteLocker wl(&qrwlVoiceThread);
		uSource->uiSession = qqIds.dequeue();
		qhUsers.insert(uSource->uiSession, uSource);
		qhHostUsers[uSource->haAddress].insert(uSource);
	}

	Channel *root = qhChannels.value(0);
	Channel *c;

	uSource->qsName = u8(msg.username()).trimmed();

	bool ok     = false;
	bool nameok = validateUserName(uSource->qsName);
	QString pw  = u8(msg.password());

	// Fetch ID and stored username.
	// This function needs to support the fact that sessions may go away.
	int id = authenticate(uSource->qsName, pw, static_cast< int >(uSource->uiSession), uSource->qslEmail,
						  uSource->qsHash, uSource->bVerified, uSource->peerCertificateChain());

	uSource->iId = id >= 0 ? id : -1;

	QString reason;
	MumbleProto::Reject_RejectType rtType = MumbleProto::Reject_RejectType_None;

	if (id == -2 && !nameok) {
		reason = "Invalid username";
		rtType = MumbleProto::Reject_RejectType_InvalidUsername;
	} else if (id == -1) {
		reason = "Wrong certificate or password for existing user";
		rtType = MumbleProto::Reject_RejectType_WrongUserPW;
	} else if (id == -2 && !qsPassword.isEmpty() && qsPassword != pw) {
		reason = "Invalid server password";
		rtType = MumbleProto::Reject_RejectType_WrongServerPW;
	} else if (id == -3) {
		reason = "Your account information can not be verified currently. Please try again later";
		rtType = MumbleProto::Reject_RejectType_AuthenticatorFail;
	} else {
		ok = true;
	}

	ServerUser *uOld = nullptr;
	for (ServerUser *u : qhUsers) {
		if (u == uSource)
			continue;
		if (((u->iId >= 0) && (u->iId == uSource->iId)) || (u->qsName.toLower() == uSource->qsName.toLower())) {
			uOld = u;
			break;
		}
	}

	// Allow reuse of name from same IP
	if (ok && uOld && (uSource->iId == -1)) {
		if ((uOld->peerAddress() != uSource->peerAddress())
			&& (uSource->qsHash.isEmpty() || (uSource->qsHash != uOld->qsHash))) {
			reason = "Username already in use";
			rtType = MumbleProto::Reject_RejectType_UsernameInUse;
			ok     = false;
		}
	}

	if ((id != 0) && (static_cast< unsigned int >(qhUsers.count()) > iMaxUsers)) {
		reason = QString::fromLatin1("Server is full (max %1 users)").arg(iMaxUsers);
		rtType = MumbleProto::Reject_RejectType_ServerFull;
		ok     = false;
	}

	if ((id != 0) && (uSource->qsHash.isEmpty() && bCertRequired)) {
		reason = QString::fromLatin1("A certificate is required to connect to this server");
		rtType = MumbleProto::Reject_RejectType_NoCertificate;
		ok     = false;
	}

	if (ok) {
		if (msg.tokens_size() > 0) {
			// Set the access tokens for the newly connected user
			QStringList qsl;

			for (int i = 0; i < msg.tokens_size(); ++i) {
				qsl << u8(msg.tokens(i));
			}

			{
				QMutexLocker qml(&qmCache);
				uSource->qslAccessTokens = qsl;
			}
		}

		// Clear cache as the "auth" ACL depends on the user id
		// and any cached ACL won't have taken that into account yet
		// Also, if we set access tokens above, we have to reset
		// the ACL cache anyway.
		clearACLCache(uSource);
	}

	Channel *lc = nullptr;
	if (uSource->iId >= 0 && Meta::mp->bRememberChan) {
		unsigned int lastChannelID = m_dbWrapper.getLastChannelID(iServerNum, static_cast< unsigned int >(uSource->iId),
																  static_cast< unsigned int >(iRememberChanDuration),
																  tUptime.elapsed< std::chrono::seconds >());
		lc                         = qhChannels.value(lastChannelID);
	}

	if (!lc || !hasPermission(uSource, lc, ChanACL::Enter) || isChannelFull(lc, uSource)) {
		lc = qhChannels.value(iDefaultChan);
		if (!lc || !hasPermission(uSource, lc, ChanACL::Enter) || isChannelFull(lc, uSource)) {
			lc = root;
			if (isChannelFull(lc, uSource)) {
				reason = QString::fromLatin1("Server channels are full");
				rtType = MumbleProto::Reject_RejectType_ServerFull;
				ok     = false;
			}
		}
	}

	if (!ok) {
		log(uSource, QString("Rejected connection from %1: %2")
						 .arg(addressToString(uSource->peerAddress(), uSource->peerPort()), reason));
		MumbleProto::Reject mpr;
		mpr.set_reason(u8(reason));
		mpr.set_type(rtType);
		sendMessage(uSource, mpr);
		uSource->disconnectSocket();
		return;
	}

	startThread();

	// Kick ghost
	if (uOld) {
		log(uSource, "Disconnecting ghost");
		MumbleProto::UserRemove mpur;
		mpur.set_session(uOld->uiSession);
		mpur.set_reason("You connected to the server from another device");
		sendMessage(uOld, mpur);
		uOld->forceFlush();
		uOld->disconnectSocket(true);
	}

	// Setup UDP encryption
	{
		QMutexLocker l(&uSource->qmCrypt);

		uSource->csCrypt->genKey();

		MumbleProto::CryptSetup mpcrypt;
		mpcrypt.set_key(uSource->csCrypt->getRawKey());
		mpcrypt.set_server_nonce(uSource->csCrypt->getEncryptIV());
		mpcrypt.set_client_nonce(uSource->csCrypt->getDecryptIV());
		sendMessage(uSource, mpcrypt);
	}

	bool fake_celt_support = false;
	if (msg.celt_versions_size() > 0) {
		for (int i = 0; i < msg.celt_versions_size(); ++i)
			uSource->qlCodecs.append(msg.celt_versions(i));
	} else {
		uSource->qlCodecs.append(static_cast< qint32 >(0x8000000b));
		fake_celt_support = true;
	}
	uSource->bOpus = msg.opus();
	recheckCodecVersions(uSource);

	MumbleProto::CodecVersion mpcv;
	mpcv.set_alpha(iCodecAlpha);
	mpcv.set_beta(iCodecBeta);
	mpcv.set_prefer_alpha(bPreferAlpha);
	mpcv.set_opus(bOpus);
	sendMessage(uSource, mpcv);

	if (!bOpus && uSource->bOpus && fake_celt_support) {
		sendTextMessage(
			nullptr, uSource, false,
			QLatin1String("<strong>WARNING:</strong> Your client doesn't support the CELT codec, you won't be able to "
						  "talk to or hear most clients. Please make sure your client was built with CELT support."));
	}

	// Transmit channel tree
	QQueue< Channel * > q;
	QSet< Channel * > chans;
	q << root;
	MumbleProto::ChannelState mpcs;

	while (!q.isEmpty()) {
		c = q.dequeue();
		chans.insert(c);

		mpcs.Clear();

		mpcs.set_channel_id(c->iId);
		if (c->cParent)
			mpcs.set_parent(c->cParent->iId);
		if (c->iId == 0)
			mpcs.set_name(u8(qsRegName.isEmpty() ? QLatin1String("Root") : qsRegName));
		else
			mpcs.set_name(u8(c->qsName));

		mpcs.set_position(c->iPosition);

		if ((uSource->m_version >= Version::fromComponents(1, 2, 2)) && !c->qbaDescHash.isEmpty())
			mpcs.set_description_hash(blob(c->qbaDescHash));
		else if (!c->qsDesc.isEmpty())
			mpcs.set_description(u8(c->qsDesc));

		mpcs.set_max_users(c->uiMaxUsers);

		if (c->isPersistentChat()) {
			mpcs.set_pchat_protocol(
				static_cast< MumbleProto::PchatProtocol >(c->uiPChatProtocol));
			mpcs.set_pchat_max_history(c->uiPChatMaxHistory);
			mpcs.set_pchat_retention_days(c->uiPChatRetentionDays);
			for (const auto &kc : c->qslPChatKeyCustodians)
				mpcs.add_pchat_key_custodians(u8(kc));
			qWarning("pchat: sending channel tree for channelId=%d pchat_protocol=%u to session=%u",
				   c->iId, c->uiPChatProtocol, uSource->uiSession);
		}

		// Include info about enter restrictions of this channel
		mpcs.set_is_enter_restricted(isChannelEnterRestricted(c));
		mpcs.set_can_enter(hasPermission(uSource, c, ChanACL::Enter));

		sendMessage(uSource, mpcs);

		for (Channel *chan : c->qlChannels) {
			q.enqueue(chan);
		}
	}

	// Transmit links
	for (Channel *chan : chans) {
		if (chan->qhLinks.count() > 0) {
			mpcs.Clear();
			mpcs.set_channel_id(chan->iId);

			for (Channel *l : chan->qhLinks.keys()) {
				mpcs.add_links(l->iId);
			}
			sendMessage(uSource, mpcs);
		}
	}

	if (uSource->iId >= 0) {
		m_dbWrapper.loadChannelListenersOf(iServerNum, *uSource, m_channelListenerManager);
	}

	// Transmit user profile
	MumbleProto::UserState mpus;

	userEnterChannel(uSource, lc, mpus);

	{
		QWriteLocker wl(&qrwlVoiceThread);
		uSource->sState = ServerUser::Authenticated;
	}

	mpus.set_session(uSource->uiSession);
	mpus.set_name(u8(uSource->qsName));
	if (uSource->iId >= 0) {
		mpus.set_user_id(static_cast< unsigned int >(uSource->iId));

		loadTexture(*uSource);

		if (!uSource->qbaTextureHash.isEmpty()) {
			mpus.set_texture_hash(blob(uSource->qbaTextureHash));
		} else if (!uSource->qbaTexture.isEmpty()) {
			mpus.set_texture(blob(uSource->qbaTexture));
		}

		loadComment(*uSource);

		if (!uSource->qbaCommentHash.isEmpty()) {
			mpus.set_comment_hash(blob(uSource->qbaCommentHash));
		} else if (!uSource->qsComment.isEmpty()) {
			mpus.set_comment(u8(uSource->qsComment));
		}
	}
	if (!uSource->qsHash.isEmpty())
		mpus.set_hash(u8(uSource->qsHash));

	if (uSource->m_FancyVersion.has_value())
		mpus.add_client_features(MumbleProto::UserState::FEATURE_PCHAT_E2EE);

	mpus.set_channel_id(uSource->cChannel->iId);

	sendAll(mpus, Version::fromComponents(1, 2, 2), Version::CompareMode::AtLeast);

	if ((uSource->qbaTexture.length() >= 4)
		&& (qFromBigEndian< unsigned int >(reinterpret_cast< const unsigned char * >(uSource->qbaTexture.constData()))
			== 600 * 60 * 4))
		mpus.set_texture(blob(uSource->qbaTexture));
	if (!uSource->qsComment.isEmpty())
		mpus.set_comment(u8(uSource->qsComment));
	sendAll(mpus, Version::fromComponents(1, 2, 2), Version::CompareMode::LessThan);

	// Transmit other users profiles
	for (ServerUser *u : qhUsers) {
		if (u->sState != ServerUser::Authenticated)
			continue;

		if (u == uSource)
			continue;

		mpus.Clear();
		mpus.set_session(u->uiSession);
		mpus.set_name(u8(u->qsName));
		if (u->iId >= 0)
			mpus.set_user_id(static_cast< unsigned int >(u->iId));
		if (uSource->m_version >= Version::fromComponents(1, 2, 2)) {
			if (!u->qbaTextureHash.isEmpty())
				mpus.set_texture_hash(blob(u->qbaTextureHash));
			else if (!u->qbaTexture.isEmpty())
				mpus.set_texture(blob(u->qbaTexture));
		} else if ((uSource->qbaTexture.length() >= 4)
				   && (qFromBigEndian< unsigned int >(
						   reinterpret_cast< const unsigned char * >(uSource->qbaTexture.constData()))
					   == 600 * 60 * 4)) {
			mpus.set_texture(blob(u->qbaTexture));
		}
		if (u->cChannel->iId != 0)
			mpus.set_channel_id(u->cChannel->iId);
		if (u->bDeaf)
			mpus.set_deaf(true);
		else if (u->bMute)
			mpus.set_mute(true);
		if (u->bSuppress)
			mpus.set_suppress(true);
		if (u->bPrioritySpeaker)
			mpus.set_priority_speaker(true);
		if (u->bRecording)
			mpus.set_recording(true);
		if (u->bSelfDeaf)
			mpus.set_self_deaf(true);
		else if (u->bSelfMute)
			mpus.set_self_mute(true);
		if ((uSource->m_version >= Version::fromComponents(1, 2, 2)) && !u->qbaCommentHash.isEmpty())
			mpus.set_comment_hash(blob(u->qbaCommentHash));
		else if (!u->qsComment.isEmpty())
			mpus.set_comment(u8(u->qsComment));
		if (!u->qsHash.isEmpty())
			mpus.set_hash(u8(u->qsHash));

		if (u->m_FancyVersion.has_value())
			mpus.add_client_features(MumbleProto::UserState::FEATURE_PCHAT_E2EE);

		for (unsigned int channelID : m_channelListenerManager.getListenedChannelsForUser(u->uiSession)) {
			mpus.add_listening_channel_add(channelID);

			if (broadcastListenerVolumeAdjustments) {
				VolumeAdjustment volume = m_channelListenerManager.getListenerVolumeAdjustment(u->uiSession, channelID);
				MumbleProto::UserState::VolumeAdjustment *adjustment = mpus.add_listening_volume_adjustment();
				adjustment->set_listening_channel(channelID);
				adjustment->set_volume_adjustment(volume.factor);
			}
		}

		sendMessage(uSource, mpus);
	}

	// Send synchronisation packet
	MumbleProto::ServerSync mpss;
	mpss.set_session(uSource->uiSession);
	if (!qsWelcomeText.isEmpty())
		mpss.set_welcome_text(u8(qsWelcomeText));
	mpss.set_max_bandwidth(static_cast< unsigned int >(iMaxBandwidth));

	if (uSource->iId == 0) {
		mpss.set_permissions(ChanACL::All);
	} else {
		QMutexLocker qml(&qmCache);
		ChanACL::hasPermission(uSource, root, ChanACL::Enter, &acCache);
		mpss.set_permissions(acCache.value(uSource)->value(root));
	}

	sendMessage(uSource, mpss);

	// Transmit user's listeners - this has to be done AFTER the server-sync message has been sent to uSource as the
	// client may require its own session ID for processing the listeners properly.
	mpus.Clear();
	mpus.set_session(uSource->uiSession);
	for (unsigned int channelID : m_channelListenerManager.getListenedChannelsForUser(uSource->uiSession)) {
		mpus.add_listening_channel_add(channelID);
	}

	// If we are not intending to broadcast the volume adjustments to everyone, we have to send the message to all but
	// uSource without the volume adjustments. Then append the adjustments, but only send them to uSource. If we are in
	// fact broadcasting, just append the adjustments and send to everyone.
	if (!broadcastListenerVolumeAdjustments && mpus.listening_channel_add_size() > 0) {
		sendExcept(uSource, mpus, Version::fromComponents(1, 2, 2), Version::CompareMode::AtLeast);
	}

	std::unordered_map< unsigned int, VolumeAdjustment > volumeAdjustments =
		m_channelListenerManager.getAllListenerVolumeAdjustments(uSource->uiSession);
	for (auto it = volumeAdjustments.begin(); it != volumeAdjustments.end(); ++it) {
		MumbleProto::UserState::VolumeAdjustment *adjustment = mpus.add_listening_volume_adjustment();
		adjustment->set_listening_channel(it->first);
		adjustment->set_volume_adjustment(it->second.factor);
	}

	if (mpus.listening_channel_add_size() > 0 || mpus.listening_volume_adjustment_size() > 0) {
		if (!broadcastListenerVolumeAdjustments) {
			if (uSource->m_version >= Version::fromComponents(1, 2, 2)) {
				sendMessage(uSource, mpus);
			}
		} else {
			sendAll(mpus, Version::fromComponents(1, 2, 2), Version::CompareMode::AtLeast);
		}
	}

	MumbleProto::ServerConfig mpsc;
	mpsc.set_allow_html(bAllowHTML);
	mpsc.set_message_length(static_cast< unsigned int >(iMaxTextMessageLength));
	mpsc.set_image_message_length(static_cast< unsigned int >(iMaxImageMessageLength));
	mpsc.set_max_users(static_cast< unsigned int >(iMaxUsers));
	mpsc.set_recording_allowed(allowRecording);
	if (m_sfuManager && m_sfuManager->isAvailable()) {
		mpsc.set_webrtc_sfu_available(true);
	}
	if (!qsFancyRestApiUrl.isEmpty()) {
		mpsc.set_fancy_rest_api_url(qsFancyRestApiUrl.toStdString());
	}
	sendMessage(uSource, mpsc);

	MumbleProto::SuggestConfig mpsug;
	if (m_suggestVersion != Version::UNKNOWN) {
		MumbleProto::setSuggestedVersion(mpsug, m_suggestVersion);
	}
	if (m_suggestPositional)
		mpsug.set_positional(m_suggestPositional.value());
	if (m_suggestPushToTalk)
		mpsug.set_push_to_talk(m_suggestPushToTalk.value());
#if GOOGLE_PROTOBUF_VERSION >= 3004000
	if (mpsug.ByteSizeLong() > 0) {
#else
	// ByteSize() has been deprecated as of protobuf v3.4
	if (mpsug.ByteSize() > 0) {
#endif
		sendMessage(uSource, mpsug);
	}

	if (uSource->m_version < Version::fromComponents(1, 4, 0) && Meta::mp->iMaxListenersPerChannel != 0
		&& Meta::mp->iMaxListenerProxiesPerUser != 0) {
		// The server has the ChannelListener feature enabled but the client that connects doesn't have version 1.4.0 or
		// newer meaning that this client doesn't know what ChannelListeners are. Thus we'll send that user a
		// text-message informing about this.
		MumbleProto::TextMessage mptm;

		if (Meta::mp->bAllowHTML) {
			mptm.set_message("<b>[WARNING]</b>: This server has the <b>ChannelListener</b> feature enabled but your "
							 "client version does not support it. "
							 "This means that users <b>might be listening to what you are saying in your channel "
							 "without you noticing!</b> "
							 "You can solve this issue by upgrading to Mumble 1.4.0 or newer.");
		} else {
			mptm.set_message(
				"[WARNING]: This server has the ChannelListener feature enabled but your client version does not "
				"support it. "
				"This means that users might be listening to what you are saying in your channel without you noticing! "
				"You can solve this issue by upgrading to Mumble 1.4.0 or newer.");
		}

		sendMessage(uSource, mptm);
	}

	switch (msg.client_type()) {
		case static_cast< int >(ClientType::BOT):
			uSource->m_clientType = ClientType::BOT;
			m_botCount++;
			break;
		case static_cast< int >(ClientType::REGULAR):
			// No-op (also applies to unknown values of msg.client_type())
			// (The default client type is regular anyway, so we don't need to change anything here)
			break;
	}

	// Send the active onboarding config to Fancy 0.3.1+ clients so the
	// onboarding modal can render immediately after connect without an
	// extra round-trip.
	if (uSource->m_FancyVersion.has_value()
		&& uSource->m_FancyVersion.value() >= Version::fromComponents(0, 3, 1)
		&& m_onboardingConfig.has_enabled()) {
		sendMessage(uSource, m_onboardingConfig);
	}

	log(uSource, "Authenticated");

	emit userConnected(uSource);

	if (m_pluginHost) {
		m_pluginHost->onClientConnected(uSource->uiSession, uSource->qsName, uSource->qsHash);
	}
}

void Server::msgBanList(ServerUser *uSource, MumbleProto::BanList &msg) {
	ZoneScoped;

	MSG_SETUP(ServerUser::Authenticated);

	if (!hasPermission(uSource, qhChannels.value(0), ChanACL::Ban)) {
		PERM_DENIED(uSource, qhChannels.value(0), ChanACL::Ban);
		return;
	}

	std::set< Ban > previousBans;

	if (msg.query()) {
		msg.clear_query();
		msg.clear_bans();
		for (const Ban &b : m_bans) {
			MumbleProto::BanList_BanEntry *be = msg.add_bans();
			be->set_address(b.haAddress.toStdString());
			be->set_mask(static_cast< unsigned int >(b.iMask));
			be->set_name(u8(b.qsUsername));
			be->set_hash(u8(b.qsHash));
			be->set_reason(u8(b.qsReason));
			be->set_start(u8(b.qdtStart.toString(Qt::ISODate)));
			be->set_duration(b.iDuration);
		}
		sendMessage(uSource, msg);
	} else {
		previousBans = std::set< Ban >(m_bans.begin(), m_bans.end());
		std::set< QString > uniqueBans;

		m_bans.clear();
		for (int i = 0; i < msg.bans_size(); ++i) {
			const MumbleProto::BanList_BanEntry &be = msg.bans(i);

			Ban b;
			b.haAddress  = be.address();
			b.iMask      = static_cast< int >(be.mask());
			b.qsUsername = u8(be.name());
			b.qsHash     = u8(be.hash());
			b.qsReason   = u8(be.reason());
			if (be.has_start()) {
				b.qdtStart = QDateTime::fromString(u8(be.start()), Qt::ISODate);
#if QT_VERSION >= QT_VERSION_CHECK(6, 5, 0)
				b.qdtStart.setTimeZone(QTimeZone::UTC);
#else
				b.qdtStart.setTimeSpec(Qt::UTC);
#endif
			} else {
				b.qdtStart = QDateTime::currentDateTime().toUTC();
			}

			b.iDuration = be.duration();

			QString repr = b.toKey();

			// server-side de-duplication
			if (uniqueBans.contains(repr)) {
				continue;
			}

			if (b.isValid()) {
				m_bans.push_back(std::move(b));
				uniqueBans.insert(repr);
			}
		}
		// m_bans needs to be sorted in order for it to be used in the set_difference functions below
		std::sort(m_bans.begin(), m_bans.end());

		std::vector< Ban > removed, added;
		std::set_difference(previousBans.begin(), previousBans.end(), m_bans.begin(), m_bans.end(),
							std::back_inserter(removed));
		std::set_difference(m_bans.begin(), m_bans.end(), previousBans.begin(), previousBans.end(),
							std::back_inserter(added));

		for (const Ban &b : removed) {
			log(uSource, QString("Removed ban: %1").arg(b.toString()));
		}

		for (const Ban &b : added) {
			log(uSource, QString("New ban: %1").arg(b.toString()));
		}

		m_dbWrapper.saveBans(iServerNum, m_bans);
		log(uSource, "Updated banlist");
	}
}

void Server::msgReject(ServerUser *, MumbleProto::Reject &) {
}

void Server::msgServerSync(ServerUser *, MumbleProto::ServerSync &) {
}

void Server::msgPermissionDenied(ServerUser *, MumbleProto::PermissionDenied &) {
}

void Server::msgUDPTunnel(ServerUser *, MumbleProto::UDPTunnel &) {
	// This code should be unreachable
	assert(false);
	qWarning("Messages: Reached theoretically unreachable function msgUDPTunnel");
}

void Server::msgUserState(ServerUser *uSource, MumbleProto::UserState &msg) {
	ZoneScoped;

	MSG_SETUP(ServerUser::Authenticated);
	VICTIM_SETUP;

	Channel *root = qhChannels.value(0);

	/*
		First check all permissions involved
	*/
	if ((pDstServerUser->iId == 0) && (uSource->iId != 0)) {
		// Don't allow any action on the SuperUser except initiated directly by the SuperUser himself/herself
		PERM_DENIED_TYPE(SuperUser);
		return;
	}

	msg.set_session(pDstServerUser->uiSession);
	msg.set_actor(uSource->uiSession);

	if (msg.has_name()) {
		PERM_DENIED_TYPE(UserName);
		return;
	}

	if (uSource == pDstServerUser) {
		RATELIMIT(uSource);
	}

	// Handle potential temporary access tokens
	QStringList temporaryAccessTokens;
	for (int i = 0; i < msg.temporary_access_tokens_size(); i++) {
		temporaryAccessTokens << u8(msg.temporary_access_tokens(i));
	}
	TemporaryAccessTokenHelper tempTokenHelper(uSource, temporaryAccessTokens, this);

	if (msg.has_channel_id()) {
		Channel *c = qhChannels.value(msg.channel_id());
		if (!c || (c == pDstServerUser->cChannel))
			return;

		if ((uSource != pDstServerUser) && (!hasPermission(uSource, pDstServerUser->cChannel, ChanACL::Move))) {
			PERM_DENIED(uSource, pDstServerUser->cChannel, ChanACL::Move);
			return;
		}

		if (!hasPermission(uSource, c, ChanACL::Move) && !hasPermission(pDstServerUser, c, ChanACL::Enter)) {
			PERM_DENIED(pDstServerUser, c, ChanACL::Enter);
			return;
		}
		if (isChannelFull(c, uSource)) {
			PERM_DENIED_FALLBACK(ChannelFull, Version::fromComponents(1, 2, 1), QLatin1String("Channel is full"));
			return;
		}
	}

	QList< Channel * > listeningChannelsAdd;
	int passedChannelListener = 0;
	// Check permission for each channel
	for (int i = 0; i < msg.listening_channel_add_size(); i++) {
		Channel *c = qhChannels.value(msg.listening_channel_add(i));

		if (!c) {
			continue;
		}

		if (!hasPermission(pDstServerUser, c, ChanACL::Listen)) {
			PERM_DENIED(pDstServerUser, c, ChanACL::Listen);
			continue;
		}

		if (Meta::mp->iMaxListenersPerChannel >= 0
			&& Meta::mp->iMaxListenersPerChannel - m_channelListenerManager.getListenerCountForChannel(c->iId) - 1
				   < 0) {
			// A limit for the amount of listener proxies per channel is set and it has been reached already
			PERM_DENIED_FALLBACK(ChannelListenerLimit, Version::fromComponents(1, 4, 0),
								 QLatin1String("No more listeners allowed in this channel"));
			continue;
		}

		if (Meta::mp->iMaxListenerProxiesPerUser >= 0
			&& Meta::mp->iMaxListenerProxiesPerUser
					   - m_channelListenerManager.getListenedChannelCountForUser(uSource->uiSession)
					   - passedChannelListener - 1
				   < 0) {
			// A limit for the amount of listener proxies per user is set and it has been reached already
			PERM_DENIED_FALLBACK(UserListenerLimit, Version::fromComponents(1, 4, 0),
								 QLatin1String("No more listeners allowed in this channel"));
			continue;
		}

		passedChannelListener++;

		listeningChannelsAdd << c;
	}

	if (msg.has_mute() || msg.has_deaf() || msg.has_suppress() || msg.has_priority_speaker()) {
		if (pDstServerUser->iId == 0) {
			PERM_DENIED_TYPE(SuperUser);
			return;
		}
		if (!hasPermission(uSource, pDstServerUser->cChannel, ChanACL::MuteDeafen) || msg.suppress()) {
			PERM_DENIED(uSource, pDstServerUser->cChannel, ChanACL::MuteDeafen);
			return;
		}
	}

	if (msg.has_mute() || msg.has_deaf() || msg.has_suppress()) {
		if (pDstServerUser->cChannel->bTemporary) {
			// If the destination user is inside a temporary channel,
			// the source user needs to have the MuteDeafen ACL in the first
			// non-temporary parent channel.

			Channel *c = pDstServerUser->cChannel;
			while (c && c->bTemporary) {
				c = c->cParent;
			}

			if (!c || !hasPermission(uSource, c, ChanACL::MuteDeafen)) {
				PERM_DENIED_TYPE(TemporaryChannel);
				return;
			}
		}
	}

	QString comment;

	if (msg.has_comment()) {
		bool changed = false;
		comment      = u8(msg.comment());
		if (uSource != pDstServerUser) {
			if (!hasPermission(uSource, root, ChanACL::ResetUserContent)) {
				PERM_DENIED(uSource, root, ChanACL::ResetUserContent);
				return;
			}
			if (comment.length() > 0) {
				PERM_DENIED_TYPE(TextTooLong);
				return;
			}
		}


		if (!isTextAllowed(comment, changed)) {
			PERM_DENIED_TYPE(TextTooLong);
			return;
		}
		if (changed)
			msg.set_comment(u8(comment));
	}

	if (msg.has_texture()) {
		if (iMaxImageMessageLength > 0
			&& (msg.texture().length() > static_cast< unsigned int >(iMaxImageMessageLength))) {
			PERM_DENIED_TYPE(TextTooLong);
			return;
		}
		if (uSource != pDstServerUser) {
			if (!hasPermission(uSource, root, ChanACL::ResetUserContent)) {
				PERM_DENIED(uSource, root, ChanACL::ResetUserContent);
				return;
			}
			if (msg.texture().length() > 0) {
				PERM_DENIED_TYPE(TextTooLong);
				return;
			}
		}
	}


	if (msg.has_user_id()) {
		ChanACL::Perm p = (uSource == pDstServerUser) ? ChanACL::SelfRegister : ChanACL::Register;
		if ((pDstServerUser->iId >= 0) || !hasPermission(uSource, root, p)) {
			PERM_DENIED(uSource, root, p);
			return;
		}
		if (pDstServerUser->qsHash.isEmpty()) {
			PERM_DENIED_HASH(pDstServerUser);
			return;
		}
	}

	// Prevent self-targeting state changes from being applied to others
	if ((pDstServerUser != uSource)
		&& (msg.has_self_deaf() || msg.has_self_mute() || msg.has_plugin_context() || msg.has_plugin_identity()
			|| msg.has_recording() || msg.listening_channel_add_size() > 0
			|| msg.listening_channel_remove_size() > 0)) {
		return;
	}

	/*
		-------------------- Permission checks done. Now act --------------------
	*/
	bool bBroadcast = false;

	if (msg.has_texture()) {
		QByteArray qba = blob(msg.texture());
		if (pDstServerUser->iId >= 0) {
			// For registered users store the texture we just received in the database
			if (!setTexture(*pDstServerUser, qba)) {
				return;
			}
		} else {
			// For unregistered users or SuperUser only get the hash
			hashAssign(pDstServerUser->qbaTexture, pDstServerUser->qbaTextureHash, qba);
		}

		// The texture will be sent out later in this function
		bBroadcast = true;
	}

	// Writing to bSelfMute, bSelfDeaf and ssContext
	// requires holding a write lock on qrwlVoiceThread.
	{
		QWriteLocker wl(&qrwlVoiceThread);

		if (msg.has_self_deaf()) {
			pDstServerUser->bSelfDeaf = msg.self_deaf();
			if (pDstServerUser->bSelfDeaf)
				msg.set_self_mute(true);
			bBroadcast = true;
		}

		if (msg.has_self_mute()) {
			pDstServerUser->bSelfMute = msg.self_mute();
			if (!pDstServerUser->bSelfMute) {
				msg.set_self_deaf(false);
				pDstServerUser->bSelfDeaf = false;
			}
			bBroadcast = true;
		}

		if (msg.has_plugin_context()) {
			pDstServerUser->ssContext = msg.plugin_context();

			// Make sure to clear this from the packet so we don't broadcast it
			msg.clear_plugin_context();
		}
	}

	if (msg.has_plugin_identity()) {
		pDstServerUser->qsIdentity = u8(msg.plugin_identity());
		// Make sure to clear this from the packet so we don't broadcast it
		msg.clear_plugin_identity();
	}

	if (!comment.isNull()) {
		setComment(*uSource, comment);

		bBroadcast = true;
	}



	if (msg.has_mute() || msg.has_deaf() || msg.has_suppress() || msg.has_priority_speaker()) {
		// Writing to bDeaf, bMute and bSuppress requires
		// holding a write lock on qrwlVoiceThread.
		QWriteLocker wl(&qrwlVoiceThread);

		if (msg.has_deaf()) {
			pDstServerUser->bDeaf = msg.deaf();
			if (pDstServerUser->bDeaf)
				msg.set_mute(true);
		}
		if (msg.has_mute()) {
			pDstServerUser->bMute = msg.mute();
			if (!pDstServerUser->bMute) {
				msg.set_deaf(false);
				pDstServerUser->bDeaf = false;
			}
		}
		if (msg.has_suppress())
			pDstServerUser->bSuppress = msg.suppress();

		if (msg.has_priority_speaker())
			pDstServerUser->bPrioritySpeaker = msg.priority_speaker();

		log(uSource, QString("Changed speak-state of %1 (%2 %3 %4 %5)")
						 .arg(QString(*pDstServerUser), QString::number(pDstServerUser->bMute),
							  QString::number(pDstServerUser->bDeaf), QString::number(pDstServerUser->bSuppress),
							  QString::number(pDstServerUser->bPrioritySpeaker)));

		bBroadcast = true;
	}

	if (msg.has_recording() && (pDstServerUser->bRecording != msg.recording())) {
		assert(uSource == pDstServerUser);

		pDstServerUser->bRecording = msg.recording();

		MumbleProto::TextMessage mptm;
		mptm.add_tree_id(0);
		if (pDstServerUser->bRecording) {
			if (!allowRecording) {
				// User tried to start recording even though this server forbids it
				// -> Kick user
				MumbleProto::UserRemove mpur;
				mpur.set_session(uSource->uiSession);
				mpur.set_reason("Recording is not allowed on this server");
				sendMessage(uSource, mpur);
				uSource->forceFlush();
				uSource->disconnectSocket(true);

				// We just kicked this user, so there is no point in further processing his/her message
				return;
			} else {
				mptm.set_message(u8(QString(QLatin1String("User '%1' started recording")).arg(pDstServerUser->qsName)));
			}
		} else {
			mptm.set_message(u8(QString(QLatin1String("User '%1' stopped recording")).arg(pDstServerUser->qsName)));
		}

		sendAll(mptm, Version::fromComponents(1, 2, 3), Version::CompareMode::LessThan);

		bBroadcast = true;
	}

	if (msg.has_channel_id()) {
		Channel *c = qhChannels.value(msg.channel_id());

		userEnterChannel(pDstServerUser, c, msg);
		log(uSource, QString("Moved %1 to %2").arg(QString(*pDstServerUser), QString(*c)));
		bBroadcast = true;
	}

	// Handle channel listening
	// Note that it is important to handle the listening channels after channel-joins
	std::set< unsigned int > additionalVolumeAdjustedChannels;
	for (Channel *c : listeningChannelsAdd) {
		addChannelListener(*pDstServerUser, *c);

		log(QString::fromLatin1("\"%1\" is now listening to channel \"%2\"")
				.arg(QString(*pDstServerUser))
				.arg(QString(*c)));

		float volumeFactor =
			m_channelListenerManager.getListenerVolumeAdjustment(pDstServerUser->uiSession, c->iId).factor;

		if (volumeFactor != 1.0f) {
			additionalVolumeAdjustedChannels.insert(c->iId);
		}
	}
	for (int i = 0; i < msg.listening_volume_adjustment_size(); i++) {
		const MumbleProto::UserState::VolumeAdjustment &adjustment = msg.listening_volume_adjustment(i);

		const Channel *channel = qhChannels.value(adjustment.listening_channel());

		if (channel) {
			setChannelListenerVolume(*pDstServerUser, *channel, adjustment.volume_adjustment());

			// If the message contains a new volume adjustment for this channel anyway, we don't have to
			// add this adjustment again
			additionalVolumeAdjustedChannels.erase(channel->iId);
		} else {
			log(uSource, QString::fromLatin1("Invalid channel ID \"%1\" in volume adjustment")
							 .arg(adjustment.listening_channel()));
		}
	}
	for (int i = 0; i < msg.listening_channel_remove_size(); i++) {
		Channel *c = qhChannels.value(msg.listening_channel_remove(i));

		if (c) {
			disableChannelListener(*pDstServerUser, *c);

			log(QString::fromLatin1("\"%1\" is no longer listening to \"%2\"")
					.arg(QString(*pDstServerUser))
					.arg(QString(*c)));

			// If the channel is no longer listened to anyway, we don't need to broadcast its volume adjustment
			additionalVolumeAdjustedChannels.erase(c->iId);
		}
	}
	// For the channels that are listened to and for which no explicit volume adjustment is part of the message yet,
	// but which had a volume adjustment != 1 (restored from the DB), we ensure that this adjustment is broadcast
	// as if it was part of the message all along.
	for (unsigned int channelID : additionalVolumeAdjustedChannels) {
		const Channel *channel = qhChannels.value(channelID);

		if (channel) {
			const float factor =
				m_channelListenerManager.getListenerVolumeAdjustment(pDstServerUser->uiSession, channelID).factor;

			MumbleProto::UserState::VolumeAdjustment *adjustment = msg.add_listening_volume_adjustment();
			adjustment->set_listening_channel(channel->iId);
			adjustment->set_volume_adjustment(factor);
		}
	}

	bool listenerVolumeChanged = msg.listening_volume_adjustment_size() > 0;
	bool listenerChanged       = !listeningChannelsAdd.isEmpty() || msg.listening_channel_remove_size() > 0;

	bool broadcastingBecauseOfVolumeChange = !bBroadcast && listenerVolumeChanged;
	bBroadcast                             = bBroadcast || listenerChanged || listenerVolumeChanged;

	if (listenerChanged || listenerVolumeChanged) {
		// As whisper targets also contain information about ChannelListeners and
		// their associated volume adjustment, we have to clear the target cache
		clearWhisperTargetCache();
	}


	bool bDstAclChanged = false;
	if (msg.has_user_id()) {
		// Handle user (Self-)Registration
		if (registerUser(*pDstServerUser)) {
			assert(pDstServerUser->iId >= 0);
			msg.set_user_id(static_cast< unsigned int >(pDstServerUser->iId));
			bDstAclChanged = true;
		} else {
			// Registration failed
			msg.clear_user_id();
		}

		bBroadcast = true;
	}

	if (bBroadcast) {
		// Texture handling for clients < 1.2.2.
		// Send the texture data in the message.
		if (msg.has_texture() && (pDstServerUser->qbaTexture.length() >= 4)
			&& (qFromBigEndian< unsigned int >(
					reinterpret_cast< const unsigned char * >(pDstServerUser->qbaTexture.constData()))
				!= 600 * 60 * 4)) {
			// This is a new style texture, don't send it because the client doesn't handle it correctly / crashes.
			msg.clear_texture();
			sendAll(msg, Version::fromComponents(1, 2, 2), Version::CompareMode::LessThan);
			msg.set_texture(blob(pDstServerUser->qbaTexture));
		} else {
			// This is an old style texture, empty texture or there was no texture in this packet,
			// send the message unchanged.
			sendAll(msg, Version::fromComponents(1, 2, 2), Version::CompareMode::LessThan);
		}

		// Texture / comment handling for clients >= 1.2.2.
		// Send only a hash of the texture / comment text. The client will request the actual data if necessary.
		if (msg.has_texture() && !pDstServerUser->qbaTextureHash.isEmpty()) {
			msg.clear_texture();
			msg.set_texture_hash(blob(pDstServerUser->qbaTextureHash));
		}
		if (msg.has_comment() && !pDstServerUser->qbaCommentHash.isEmpty()) {
			msg.clear_comment();
			msg.set_comment_hash(blob(pDstServerUser->qbaCommentHash));
		}

		if (uSource->m_version >= Version::fromComponents(1, 2, 2)) {
			sendMessage(uSource, msg);
		}
		if (!broadcastListenerVolumeAdjustments) {
			// Don't broadcast the volume adjustments to everyone
			msg.clear_listening_volume_adjustment();
		}

		if (broadcastListenerVolumeAdjustments || !broadcastingBecauseOfVolumeChange) {
			sendExcept(uSource, msg, Version::fromComponents(1, 2, 2), Version::CompareMode::AtLeast);
		}

		if (bDstAclChanged) {
			clearACLCache(pDstServerUser);
		} else if (listenerChanged || listenerVolumeChanged) {
			// We only have to do this if the ACLs didn't change as
			// clearACLCache calls clearWhisperTargetChache anyways
			clearWhisperTargetCache();
		}
	}

	emit userStateChanged(pDstServerUser);
}

void Server::msgUserRemove(ServerUser *uSource, MumbleProto::UserRemove &msg) {
	ZoneScoped;

	MSG_SETUP(ServerUser::Authenticated);
	VICTIM_SETUP;

	msg.set_actor(uSource->uiSession);

	bool ban = msg.has_ban() && msg.ban();

	Channel *c                   = qhChannels.value(0);
	QFlags< ChanACL::Perm > perm = ban ? ChanACL::Ban : (ChanACL::Ban | ChanACL::Kick);

	if ((pDstServerUser->iId == 0) || !hasPermission(uSource, c, perm)) {
		PERM_DENIED(uSource, c, perm);
		return;
	}

	if (ban) {
		// Before Mumble 1.6, a ban meant certificate and IP ban. This is the fallback.
		// Starting with Mumble 1.6, an admin must specify which method to use.
		bool banCertificate = !msg.has_ban_certificate() || msg.ban_certificate();
		bool banIP          = !msg.has_ban_ip() || msg.ban_ip();

		// User might not even have a certificate
		banCertificate &= !pDstServerUser->qsHash.isEmpty();

		if (!banIP && !banCertificate) {
			// No ban method specified
			return;
		}

		Ban b;
		if (banIP) {
			b.haAddress = pDstServerUser->haAddress;
			b.iMask     = 128;
		}
		if (banCertificate) {
			b.qsHash = pDstServerUser->qsHash;
		}
		b.qsReason   = u8(msg.reason());
		b.qsUsername = pDstServerUser->qsName;
		b.qdtStart   = QDateTime::currentDateTime().toUTC();
		b.iDuration  = 0;

		m_bans.push_back(std::move(b));
		m_dbWrapper.saveBans(iServerNum, m_bans);
	}

	sendAll(msg);
	if (ban)
		log(uSource, QString("Kickbanned %1 (%2)").arg(QString(*pDstServerUser), u8(msg.reason())));
	else
		log(uSource, QString("Kicked %1 (%2)").arg(QString(*pDstServerUser), u8(msg.reason())));
	pDstServerUser->disconnectSocket();
}

void Server::msgChannelState(ServerUser *uSource, MumbleProto::ChannelState &msg) {
	ZoneScoped;

	MSG_SETUP(ServerUser::Authenticated);

	Channel *c = nullptr;
	Channel *p = nullptr;

	// If this message relates to an existing channel check if the id is really valid
	if (msg.has_channel_id()) {
		c = qhChannels.value(msg.channel_id());
		if (!c)
			return;
	} else {
		RATELIMIT(uSource);
	}

	// Check if the parent exists
	if (msg.has_parent()) {
		p = qhChannels.value(msg.parent());
		if (!p)
			return;
	}

	msg.clear_links();

	QString qsName;
	QString qsDesc;
	if (msg.has_description()) {
		qsDesc       = u8(msg.description());
		bool changed = false;
		if (!isTextAllowed(qsDesc, changed)) {
			PERM_DENIED_TYPE(TextTooLong);
			return;
		}
		if (changed)
			msg.set_description(u8(qsDesc));
	}

	if (msg.has_name()) {
		// If we are sent a channel name this means we want to create this channel so
		// check if the name is valid and not already in use.
		qsName = u8(msg.name());

		if (!validateChannelName(qsName)) {
			PERM_DENIED_TYPE(ChannelName);
			return;
		}

		if (qsName.length() == 0) {
			PERM_DENIED_TYPE(ChannelName);
			return;
		}

		if (p || (c && c->iId != 0)) {
			Channel *cp = p ? p : c->cParent;
			for (Channel *sibling : cp->qlChannels) {
				if (sibling->qsName == qsName) {
					PERM_DENIED_TYPE(ChannelName);
					return;
				}
			}
		}
	}

	if (p) {
		// Having a parent channel given means we either want to create
		// a channel in or move a channel into this parent.

		if (!canNest(p, c)) {
			PERM_DENIED_FALLBACK(NestingLimit, Version::fromComponents(1, 2, 4),
								 QLatin1String("Channel nesting limit reached"));
			return;
		}
	}

	if (!c) {
		// If we don't have a channel handle up to now we want to create a new channel
		// so check if the user has enough rights and we got everything we need.
		if (!p || qsName.isNull())
			return;

		if (iChannelCountLimit != 0 && qhChannels.count() >= iChannelCountLimit) {
			PERM_DENIED_FALLBACK(ChannelCountLimit, Version::fromComponents(1, 3, 0),
								 QLatin1String("Channel count limit reached"));
			return;
		}

		ChanACL::Perm perm = msg.temporary() ? ChanACL::MakeTempChannel : ChanACL::MakeChannel;
		if (!hasPermission(uSource, p, perm)) {
			PERM_DENIED(uSource, p, perm);
			return;
		}

		if ((uSource->iId < 0) && uSource->qsHash.isEmpty()) {
			PERM_DENIED_HASH(uSource);
			return;
		}

		if (p->bTemporary) {
			PERM_DENIED_TYPE(TemporaryChannel);
			return;
		}

		c = createNewChannel(p, qsName, msg.temporary(), msg.position(), msg.max_users());
		hashAssign(c->qsDesc, c->qbaDescHash, qsDesc);

		if (msg.has_pchat_protocol()) {
			c->uiPChatProtocol = static_cast< uint32_t >(msg.pchat_protocol());
		}
		if (msg.has_pchat_max_history()) {
			c->uiPChatMaxHistory = msg.pchat_max_history();
		}
		if (msg.has_pchat_retention_days()) {
			c->uiPChatRetentionDays = msg.pchat_retention_days();
		}
		if (msg.pchat_key_custodians_size() > 0) {
			c->qslPChatKeyCustodians.clear();
			for (int i = 0; i < msg.pchat_key_custodians_size(); ++i)
				c->qslPChatKeyCustodians << u8(msg.pchat_key_custodians(i));
		}

		if (uSource->iId >= 0) {
			Group *g = new Group(c, "admin");
			g->qsAdd << uSource->iId;
		}

		if (!hasPermission(uSource, c, ChanACL::Write)) {
			ChanACL *a    = new ChanACL(c);
			a->bApplyHere = true;
			a->bApplySubs = false;
			if (uSource->iId >= 0)
				a->iUserId = uSource->iId;
			else
				a->qsGroup = QLatin1Char('$') + uSource->qsHash;
			a->pDeny  = ChanACL::None;
			a->pAllow = ChanACL::Write | ChanACL::Traverse;

			clearACLCache();
		}

		if (!c->bTemporary) {
			m_dbWrapper.updateChannelData(iServerNum, *c);
		}

		msg.set_channel_id(c->iId);
		log(uSource, QString("Added channel %1 under %2").arg(QString(*c), QString(*p)));
		emit channelCreated(c);

		if (c->isPersistentChat() && m_pchatManager) {
			m_pchatManager->onPersistentChannelCreated(
				static_cast< unsigned int >(c->iId), uSource->uiSession);
		}

		sendAll(msg, Version::fromComponents(1, 2, 2), Version::CompareMode::LessThan);
		if (!c->qbaDescHash.isEmpty()) {
			msg.clear_description();
			msg.set_description_hash(blob(c->qbaDescHash));
		}
		sendAll(msg, Version::fromComponents(1, 2, 2), Version::CompareMode::AtLeast);

		if (c->bTemporary) {
			// If a temporary channel has been created move the creator right in there
			MumbleProto::UserState mpus;
			mpus.set_session(uSource->uiSession);
			mpus.set_channel_id(c->iId);
			userEnterChannel(uSource, c, mpus);
			sendAll(mpus);
			emit userStateChanged(uSource);
		}
	} else {
		// The message is related to an existing channel c so check if the user is allowed to modify it
		// and perform the modifications
		if (!qsName.isNull()) {
			if (!hasPermission(uSource, c, ChanACL::Write) || (c->iId == 0)) {
				PERM_DENIED(uSource, c, ChanACL::Write);
				return;
			}
		}
		if (!qsDesc.isNull()) {
			if (!hasPermission(uSource, c, ChanACL::Write)) {
				PERM_DENIED(uSource, c, ChanACL::Write);
				return;
			}
		}
		if (msg.has_position()) {
			if (!hasPermission(uSource, c, ChanACL::Write)) {
				PERM_DENIED(uSource, c, ChanACL::Write);
				return;
			}
		}
		if (p) {
			// If we received a parent channel check if it differs from the old one and is not
			// Temporary. If that is the case check if the user has enough rights and if the
			// channel name is not used in the target location. Abort otherwise.
			if (p == c->cParent)
				return;

			Channel *ip = p;
			while (ip) {
				if (ip == c)
					return;
				ip = ip->cParent;
			}

			if (p->bTemporary) {
				PERM_DENIED_TYPE(TemporaryChannel);
				return;
			}

			if (!hasPermission(uSource, c, ChanACL::Write)) {
				PERM_DENIED(uSource, c, ChanACL::Write);
				return;
			}

			QFlags< ChanACL::Perm > parentMakePermission =
				c->bTemporary ? ChanACL::MakeTempChannel : ChanACL::MakeChannel;
			if (!hasPermission(uSource, p, parentMakePermission)) {
				PERM_DENIED(uSource, p, parentMakePermission);
				return;
			}

			QString name = qsName.isNull() ? c->qsName : qsName;

			for (Channel *sibling : p->qlChannels) {
				if (sibling->qsName == name) {
					PERM_DENIED_TYPE(ChannelName);
					return;
				}
			}
		}
		QList< Channel * > qlAdd;
		QList< Channel * > qlRemove;

		if (msg.links_add_size() || msg.links_remove_size()) {
			if (!hasPermission(uSource, c, ChanACL::LinkChannel)) {
				PERM_DENIED(uSource, c, ChanACL::LinkChannel);
				return;
			}
			if (msg.links_remove_size()) {
				for (int i = 0; i < msg.links_remove_size(); ++i) {
					unsigned int link = msg.links_remove(i);
					Channel *l        = qhChannels.value(link);
					if (!l) {
						return;
					}
					qlRemove << l;
				}
			}
			if (msg.links_add_size()) {
				for (int i = 0; i < msg.links_add_size(); ++i) {
					unsigned int link = msg.links_add(i);
					Channel *l        = qhChannels.value(link);
					if (!l) {
						return;
					}
					if (!hasPermission(uSource, l, ChanACL::LinkChannel)) {
						PERM_DENIED(uSource, l, ChanACL::LinkChannel);
						return;
					}
					qlAdd << l;
				}
			}
		}

		if (msg.has_max_users()) {
			if (!hasPermission(uSource, c, ChanACL::Write)) {
				PERM_DENIED(uSource, c, ChanACL::Write);
				return;
			}
		}

		if (msg.has_pchat_protocol() || msg.has_pchat_max_history() || msg.has_pchat_retention_days()
			|| msg.pchat_key_custodians_size() > 0) {
			if (!hasPermission(uSource, c, ChanACL::Write)) {
				PERM_DENIED(uSource, c, ChanACL::Write);
				return;
			}
		}

		// All permission checks done -- the update is good.

		if (p) {
			log(uSource, QString("Moved channel %1 from %2 to %3").arg(QString(*c), QString(*c->cParent), QString(*p)));

			{
				QWriteLocker wl(&qrwlVoiceThread);
				c->cParent->removeChannel(c);
				p->addChannel(c);
			}
		}
		if (!qsName.isNull()) {
			log(uSource, QString("Renamed channel %1 to %2").arg(QString(*c), QString(qsName)));
			c->qsName = qsName;
		}
		if (!qsDesc.isNull())
			hashAssign(c->qsDesc, c->qbaDescHash, qsDesc);

		if (msg.has_position())
			c->iPosition = msg.position();

		for (Channel *l : qlAdd) {
			linkChannels(*c, *l);
		}

		for (Channel *l : qlRemove) {
			unlinkChannels(*c, *l);
		}

		if (msg.has_max_users())
			c->uiMaxUsers = msg.max_users();

		if (msg.has_pchat_protocol()) {
			c->uiPChatProtocol = static_cast< uint32_t >(msg.pchat_protocol());
			log(uSource, QString("pchat: set channel %1 pchat_protocol=%2").arg(c->iId).arg(c->uiPChatProtocol));
		}
		if (msg.has_pchat_max_history()) {
			c->uiPChatMaxHistory = msg.pchat_max_history();
			log(uSource, QString("pchat: set channel %1 pchat_max_history=%2").arg(c->iId).arg(c->uiPChatMaxHistory));
		}
		if (msg.has_pchat_retention_days()) {
			c->uiPChatRetentionDays = msg.pchat_retention_days();
			log(uSource, QString("pchat: set channel %1 pchat_retention_days=%2").arg(c->iId).arg(c->uiPChatRetentionDays));
		}
		if (msg.pchat_key_custodians_size() > 0) {
			c->qslPChatKeyCustodians.clear();
			for (int i = 0; i < msg.pchat_key_custodians_size(); ++i)
				c->qslPChatKeyCustodians << u8(msg.pchat_key_custodians(i));
			log(uSource, QString("pchat: set channel %1 key_custodians count=%2").arg(c->iId).arg(c->qslPChatKeyCustodians.size()));
		}

		if (!c->bTemporary) {
			m_dbWrapper.updateChannelData(iServerNum, *c);
		}
		emit channelStateChanged(c);

		sendAll(msg, Version::fromComponents(1, 2, 2), Version::CompareMode::LessThan);
		if (msg.has_description() && !c->qbaDescHash.isEmpty()) {
			msg.clear_description();
			msg.set_description_hash(blob(c->qbaDescHash));
		}
		sendAll(msg, Version::fromComponents(1, 2, 2), Version::CompareMode::AtLeast);
	}
}

void Server::msgChannelRemove(ServerUser *uSource, MumbleProto::ChannelRemove &msg) {
	ZoneScoped;

	MSG_SETUP(ServerUser::Authenticated);

	Channel *c = qhChannels.value(msg.channel_id());
	if (!c)
		return;

	if (!hasPermission(uSource, c, ChanACL::Write) || (c->iId == 0)) {
		PERM_DENIED(uSource, c, ChanACL::Write);
		return;
	}

	log(uSource, QString("Removed channel %1").arg(*c));

	removeChannel(c);
}

void Server::msgTextMessage(ServerUser *uSource, MumbleProto::TextMessage &msg) {
	ZoneScoped;

	MSG_SETUP(ServerUser::Authenticated);
	QMutexLocker qml(&qmCache);

	// For signal userTextMessage (RPC consumers)
	TextMessage tm;

	// List of users to route the message to
	QSet< ServerUser * > users;
	// List of channels used if dest is a tree of channels
	QQueue< Channel * > q;

	RATELIMIT(uSource);

	int res = 0;
	emit textMessageFilterSig(res, uSource, msg);
	switch (res) {
		// Accept
		case 0:
			// No-op.
			break;
		// Reject
		case 1:
			PERM_DENIED(uSource, uSource->cChannel, ChanACL::TextMessage);
			return;
		// Drop
		case 2:
			return;
	}

	QString text = u8(msg.message());
	bool changed = false;

	if (!isTextAllowed(text, changed)) {
		PERM_DENIED_TYPE(TextTooLong);
		return;
	}
	if (text.isEmpty()) {
		return;
	}
	if (changed) {
		msg.set_message(u8(text));
	}

	tm.qsText = text;

	{ // Happy easter
		char m[29] = { 0117, 0160, 0145, 0156, 040,  0164, 0150, 0145, 040, 0160, 0157, 0144, 040, 0142, 0141,
					   0171, 040,  0144, 0157, 0157, 0162, 0163, 054,  040, 0110, 0101, 0114, 056, 0 };
		if (msg.channel_id_size() == 1 && msg.channel_id(0) == 0 && msg.message() == m) {
			PERM_DENIED_TYPE(H9K);
			return;
		}
	}

	msg.set_actor(uSource->uiSession);

	// Preserve client-provided message_id (Fancy Mumble extension) when present;
	// generate a server-side UUID only for legacy clients that omit it.
	if (!msg.has_message_id() || msg.message_id().empty()) {
		QUuid uuid = QUuid::createUuid();
		QString strUuid = uuid.toString();
		msg.set_message_id(u8(strUuid));
	}

	// Preserve client-provided timestamp when present; generate one otherwise.
	if (!msg.has_timestamp()) {
		auto now = std::chrono::system_clock::now();
		auto epoch = now.time_since_epoch();
		auto value = std::chrono::duration_cast<std::chrono::milliseconds>(epoch);
		long long timestamp = value.count();
		msg.set_timestamp(static_cast<uint64_t>(timestamp));
	}


	// Edit validation: if edit_id is set, verify the sender owns the original
	// message.  Only the original author may edit their own messages.
	if (msg.has_edit_id() && !msg.edit_id().empty()) {
		QString editId = u8(msg.edit_id());
		auto it = m_messageOwners.find(editId);
		if (it == m_messageOwners.end()) {
			// Unknown message_id - cannot verify ownership, reject.
			log(uSource, QString("Edit rejected: unknown message_id %1").arg(editId));
			PERM_DENIED_TYPE(Text);
			return;
		}
		if (it.value() != uSource->uiSession) {
			// Sender is not the original author - reject.
			log(uSource, QString("Edit rejected: session %1 is not the owner of message %2 (owner: %3)")
					.arg(uSource->uiSession).arg(editId).arg(it.value()));
			PERM_DENIED_TYPE(Text);
			return;
		}
	}

	// Track message_id -> sender session for edit ownership validation.
	if (msg.has_message_id() && !msg.message_id().empty()) {
		m_messageOwners.insert(u8(msg.message_id()), uSource->uiSession);
	}



	// Send the message to all users that are in (= have joined) OR are
	// "listening" to channels to which the message has been directed to
	for (int i = 0; i < msg.channel_id_size(); ++i) {
		unsigned int id = msg.channel_id(i);

		Channel *c = qhChannels.value(id);
		if (!c) {
			return;
		}

		if (!ChanACL::hasPermission(uSource, c, ChanACL::TextMessage, &acCache)) {
			PERM_DENIED(uSource, c, ChanACL::TextMessage);
			return;
		}

		if (c->isPersistentChat() && m_pchatManager
			&& !m_pchatManager->isSessionVerified(id, uSource->uiSession)) {
			PERM_DENIED(uSource, c, ChanACL::TextMessage);
			return;
		}

		// Users directly in that channel
		for (User *p : c->qlUsers) {
			users.insert(static_cast< ServerUser * >(p));
		}

		// Users only listening in that channel
		for (unsigned int session : m_channelListenerManager.getListenersForChannel(c->iId)) {
			ServerUser *currentUser = qhUsers.value(session);
			if (currentUser) {
				users.insert(currentUser);
			}
		}

		tm.qlChannels.append(id);
	}

	// If the message is sent to trees of channels, find all affected channels
	// and append them to q
	for (int i = 0; i < msg.tree_id_size(); ++i) {
		unsigned int id = msg.tree_id(i);

		Channel *c = qhChannels.value(id);
		if (!c) {
			return;
		}

		if (!ChanACL::hasPermission(uSource, c, ChanACL::TextMessage, &acCache)) {
			PERM_DENIED(uSource, c, ChanACL::TextMessage);
			return;
		}

		if (c->isPersistentChat() && m_pchatManager
			&& !m_pchatManager->isSessionVerified(id, uSource->uiSession)) {
			PERM_DENIED(uSource, c, ChanACL::TextMessage);
			return;
		}

		q.enqueue(c);

		tm.qlTrees.append(id);
	}

	// Go through all channels in q and append all users in those channels
	// to the list of recipients
	// Sub-channels are enqued so they are also checked by a later loop-iteration
	while (!q.isEmpty()) {
		Channel *c = q.dequeue();
		if (ChanACL::hasPermission(uSource, c, ChanACL::TextMessage, &acCache)
			&& !(c->isPersistentChat() && m_pchatManager
				 && !m_pchatManager->isSessionVerified(static_cast< unsigned int >(c->iId),
													   uSource->uiSession))) {
			for (Channel *sub : c->qlChannels) {
				q.enqueue(sub);
			}
			// Users directly in that channel
			for (User *p : c->qlUsers) {
				users.insert(static_cast< ServerUser * >(p));
			}
			// Users only listening in that channel
			for (unsigned int session : m_channelListenerManager.getListenersForChannel(c->iId)) {
				ServerUser *currentUser = qhUsers.value(session);
				if (currentUser) {
					users.insert(currentUser);
				}
			}
		}
	}

	// Go through all users the message is sent to directly
	for (int i = 0; i < msg.session_size(); ++i) {
		unsigned int session = msg.session(i);
		ServerUser *u        = qhUsers.value(session);
		if (u) {
			if (!ChanACL::hasPermission(uSource, u->cChannel, ChanACL::TextMessage, &acCache)) {
				PERM_DENIED(uSource, u->cChannel, ChanACL::TextMessage);
				return;
			}
			users.insert(u);
		}

		tm.qlSessions.append(session);
	}

	// Remove the message sender from the list of users to send the message to
	users.remove(uSource);

	// Route to live push subscribers: connected users who registered via
	// FancySubscribePush and have SubscribePush permission for a target
	// channel but are not already in the recipients set.
	for (auto it = m_livePushSubscriptions.constBegin(); it != m_livePushSubscriptions.constEnd(); ++it) {
		uint32_t session = it.key();
		const LivePushSubscription &sub = it.value();

		ServerUser *subscriber = qhUsers.value(session);
		if (!subscriber || subscriber == uSource || users.contains(subscriber))
			continue;

		bool subscribed = false;
		for (int i = 0; !subscribed && i < msg.channel_id_size(); ++i) {
			uint32_t channelId = msg.channel_id(i);
			if (sub.allowedChannels.count(channelId)
				&& !sub.mutedChannels.count(channelId)) {
				subscribed = true;
			}
		}
		for (int i = 0; !subscribed && i < msg.tree_id_size(); ++i) {
			uint32_t channelId = msg.tree_id(i);
			if (sub.allowedChannels.count(channelId)
				&& !sub.mutedChannels.count(channelId)) {
				subscribed = true;
			}
		}
		if (subscribed) {
			users.insert(subscriber);
		}
	}

	// Actually send the original message to the affected users
	for (ServerUser *u : users) {
		sendMessage(u, msg);
	}

	// Emit the signal for RPC consumers
	emit userTextMessage(uSource, tm);

	// Collect target channel IDs from the message.
	std::set< uint32_t > targetChannels;
	std::copy(msg.channel_id().begin(), msg.channel_id().end(),
          std::inserter(targetChannels, targetChannels.end()));
	std::copy(msg.tree_id().begin(), msg.tree_id().end(),
		  std::inserter(targetChannels, targetChannels.end()));

	const std::string title = uSource->qsName.toStdString();
	const std::string body  = u8(msg.message()).left(200).toStdString();

	dispatchPushNotifications(uSource, targetChannels, title, body);
}

void Server::dispatchPushNotifications(ServerUser *sender, const std::set< uint32_t > &targetChannels,
									   const std::string &title, const std::string &body) {
	if (!m_pushDispatcher || !m_pushDispatcher->isAvailable()) {
		log(sender, QString("push: dispatcher not available"));
		return;
	}
	if (m_pushRegistrations.isEmpty()) {
		log(sender, QString("push: no registrations"));
		return;
	}

	log(sender, QString("push: %1 registrations, %2 target channels")
			.arg(m_pushRegistrations.size())
			.arg(targetChannels.size()));

	if (targetChannels.empty()) {
		log(sender, QString("push: no target channels, skipping"));
		return;
	}

	QSet< QString > connectedHashes;
	for (auto *u : qhUsers) {
		if (!u->qsHash.isEmpty()) {
			connectedHashes.insert(u->qsHash);
		}
	}

	for (const auto &[certHash, reg] : std::as_const(m_pushRegistrations).asKeyValueRange()) {
		if (certHash == sender->qsHash) {
			log(sender, QString("push: skip %1 (sender)").arg(certHash.left(8) + "..."));
			continue;
		}

		if (connectedHashes.contains(certHash)) {
			log(sender, QString("push: skip %1 (connected)").arg(certHash.left(8) + "..."));
			continue;
		}

		for (uint32_t channelId : targetChannels) {
			if (reg.allowedChannels.find(channelId) == reg.allowedChannels.end()) {
				log(sender, QString("push: skip %1 channel %2 (no permission, allowed=%3)")
						.arg(certHash.left(8) + "...")
						.arg(channelId)
						.arg(reg.allowedChannels.size()));
				continue;
			}

			if (reg.mutedChannels.find(channelId) != reg.mutedChannels.end()) {
				log(sender, QString("push: skip %1 channel %2 (muted)")
						.arg(certHash.left(8) + "...")
						.arg(channelId));
				continue;
			}

			m_pushDispatcher->notifyUser(
				reg.fcmToken, title, body,
				MUMBLE_PUSH_CAT_TEXT_MESSAGE, MUMBLE_PUSH_PRIORITY_NORMAL,
				iServerNum, channelId);
			log(sender, QString("push: sending to %1 for channel %2")
					.arg(certHash.left(8) + "...")
					.arg(channelId));
		}
	}
}

/// Helper function to log the groups of the given channel.
///
/// @param server A pointer to the server object the provided channel lives on
/// @param c A pointer to the channel the groups should be logged for
/// @param prefix An optional QString that is being printed before the groups
void logGroups(Server *server, const Channel *c, QString prefix = QString()) {
	if (!prefix.isEmpty()) {
		server->log(prefix);
	}

	if (c->qhGroups.isEmpty()) {
		server->log(QString::fromLatin1("Channel %1 (%2) has no groups set").arg(c->qsName).arg(c->iId));
		return;
	} else {
		server->log(QString::fromLatin1("%1Listing groups specified for channel \"%2\" (%3)...")
						.arg(prefix.isEmpty() ? QLatin1String("") : QLatin1String("\t"))
						.arg(c->qsName)
						.arg(c->iId));
	}

	for (Group *currentGroup : c->qhGroups) {
		QString memberList;
		for (int m : currentGroup->members()) {
			memberList += QString::fromLatin1("\"%1\"").arg(server->getRegisteredUserName(m));
			memberList += ", ";
		}

		if (currentGroup->members().size() > 0) {
			memberList.remove(memberList.length() - 2, 2);
			server->log(QString::fromLatin1("%1Group: \"%2\" contains following users: %3")
							.arg(prefix.isEmpty() ? QLatin1String("\t") : QLatin1String("\t\t"))
							.arg(currentGroup->qsName)
							.arg(memberList));
		} else {
			server->log(QString::fromLatin1("%1Group \"%2\" doesn't contain any users")
							.arg(prefix.isEmpty() ? QLatin1String("\t") : QLatin1String("\t\t"))
							.arg(currentGroup->qsName));
		}
	}
}

/// Helper function to log the ACLs of the given channel.
///
/// @param server A pointer to the server object the provided channel lives on
/// @param c A pointer to the channel the ACLs should be logged for
/// @param prefix An optional QString that is being printed before the ACLs
void logACLs(Server *server, const Channel *c, QString prefix = QString()) {
	if (!prefix.isEmpty()) {
		server->log(prefix);
	}

	for (const ChanACL *a : c->qlACL) {
		server->log(QString::fromLatin1("%1%2")
						.arg(prefix.isEmpty() ? QLatin1String("") : QLatin1String("\t"))
						.arg(static_cast< QString >(*a)));
	}
}


void Server::msgACL(ServerUser *uSource, MumbleProto::ACL &msg) {
	ZoneScoped;

	MSG_SETUP(ServerUser::Authenticated);

	Channel *c = qhChannels.value(msg.channel_id());
	if (!c)
		return;

	// For changing channel properties (the 'Write') ACL we allow two things:
	// 1) As per regular ACL propagating mechanism, we check if the user has been
	// granted Write in the channel they try to edit
	// 2) We allow all users who have been granted 'Write' on the root channel
	// to be able to edit _all_ channels, independent of actual propagated ACLs
	// This is done to prevent users who have permission to create (temporary)
	// channels being able to "lock-out" admins by denying them 'Write' in their
	// channel effectively becoming ungovernable.
	if (!hasPermission(uSource, c, ChanACL::Write) && !hasPermission(uSource, qhChannels.value(0), ChanACL::Write)) {
		PERM_DENIED(uSource, c, ChanACL::Write);
		return;
	}

	RATELIMIT(uSource);

	if (msg.has_query() && msg.query()) {
		QStack< Channel * > chans;
		Channel *p;

		QSet< unsigned int > qsId;

		msg.clear_groups();
		msg.clear_acls();
		msg.clear_query();
		msg.set_inherit_acls(c->bInheritACL);

		p = c;
		while (p) {
			chans.push(p);
			if ((p == c) || p->bInheritACL)
				p = p->cParent;
			else
				p = nullptr;
		}

		while (!chans.isEmpty()) {
			p = chans.pop();
			for (ChanACL *acl : p->qlACL) {
				if ((p == c) || (acl->bApplySubs)) {
					MumbleProto::ACL_ChanACL *mpacl = msg.add_acls();

					mpacl->set_inherited(p != c);
					mpacl->set_apply_here(acl->bApplyHere);
					mpacl->set_apply_subs(acl->bApplySubs);
					if (acl->iUserId >= 0) {
						mpacl->set_user_id(static_cast< unsigned int >(acl->iUserId));
						qsId.insert(static_cast< unsigned int >(acl->iUserId));
					} else
						mpacl->set_group(u8(acl->qsGroup));
					mpacl->set_grant(acl->pAllow);
					mpacl->set_deny(acl->pDeny);
				}
			}
		}

		p                        = c->cParent;
		QSet< QString > allnames = Group::groupNames(c);
		for (const QString &name : allnames) {
			Group *g  = c->qhGroups.value(name);
			Group *pg = p ? Group::getGroup(p, name) : nullptr;

			MumbleProto::ACL_ChanGroup *group = msg.add_groups();
			group->set_name(u8(name));
			group->set_inherit(g ? g->bInherit : true);
			group->set_inheritable(g ? g->bInheritable : true);
			group->set_inherited(pg && pg->bInheritable);
			if (g) {
				for (int id : g->qsAdd) {
					qsId.insert(static_cast< unsigned int >(id));
					group->add_add(static_cast< unsigned int >(id));
				}
				for (int id : g->qsRemove) {
					qsId.insert(static_cast< unsigned int >(id));
					group->add_remove(static_cast< unsigned int >(id));
				}
			}
			if (pg) {
				for (int id : pg->members()) {
					qsId.insert(static_cast< unsigned int >(id));
					group->add_inherited_members(static_cast< unsigned int >(id));
				}
			}

			// FancyMumble role customization fields. Only attach values that are actually set on this group
			// (effective inheritance happens server-side; we always send the local group's data).
			if (g) {
				if (!g->qsColor.isEmpty()) {
					group->set_color(u8(g->qsColor));
				}
				if (!g->qbaIcon.isEmpty()) {
					group->set_icon(g->qbaIcon.constData(), static_cast< std::size_t >(g->qbaIcon.size()));
				}
				if (!g->qsStylePreset.isEmpty()) {
					group->set_style_preset(u8(g->qsStylePreset));
				}
				for (auto it = g->qhMetadata.constBegin(); it != g->qhMetadata.constEnd(); ++it) {
					MumbleProto::ACL_ChanGroup_KeyValue *kv = group->add_metadata();
					kv->set_key(u8(it.key()));
					kv->set_value(u8(it.value()));
				}
			}
		}

		sendMessage(uSource, msg);

		MumbleProto::QueryUsers mpqu;
		for (unsigned int id : qsId) {
			QString uname = getRegisteredUserName(static_cast< int >(id));
			if (!uname.isEmpty()) {
				mpqu.add_ids(id);
				mpqu.add_names(u8(uname));
			}
		}
		if (mpqu.ids_size())
			sendMessage(uSource, mpqu);
	} else {
		{
			QWriteLocker wl(&qrwlVoiceThread);

			QHash< QString, QSet< int > > hOldTemp;

			if (Meta::mp->bLogGroupChanges || Meta::mp->bLogACLChanges) {
				log(uSource, QString::fromLatin1("Updating ACL in channel %1").arg(*c));
			}

			if (Meta::mp->bLogGroupChanges) {
				logGroups(this, c, QLatin1String("These are the groups before applying the change:"));
			}

			for (Group *g : c->qhGroups) {
				hOldTemp.insert(g->qsName, g->qsTemporary);
				delete g;
			}

			if (Meta::mp->bLogACLChanges) {
				logACLs(this, c, QLatin1String("These are the ACLs before applying the changed:"));
			}

			// Clear old ACLs
			for (ChanACL *a : c->qlACL) {
				delete a;
			}

			c->qhGroups.clear();
			c->qlACL.clear();

			c->bInheritACL = msg.inherit_acls();

			// Add new groups
			for (int i = 0; i < msg.groups_size(); ++i) {
				const MumbleProto::ACL_ChanGroup &group = msg.groups(i);
				Group *g                                = new Group(c, u8(group.name()));
				g->bInherit                             = group.inherit();
				g->bInheritable                         = group.inheritable();
				for (int j = 0; j < group.add_size(); ++j)
					if (!getRegisteredUserName(static_cast< int >(group.add(j))).isEmpty())
						g->qsAdd << static_cast< int >(group.add(j));
				for (int j = 0; j < group.remove_size(); ++j)
					if (!getRegisteredUserName(static_cast< int >(group.remove(j))).isEmpty())
						g->qsRemove << static_cast< int >(group.remove(j));

				// FancyMumble role customization fields.
				g->qsColor = group.has_color() ? u8(group.color()) : QString();
				if (group.has_icon()) {
					const std::string &iconBytes = group.icon();
					if (iMaxImageMessageLength > 0
						&& iconBytes.size() > static_cast< std::size_t >(iMaxImageMessageLength)) {
						// Reject the icon when it exceeds the configurable
						// `imagemessagelength` server limit.  Leaves any
						// previously stored icon untouched.
						log(uSource,
							QString("Rejected role icon for group '%1' (%2 bytes > limit %3)")
								.arg(g->qsName)
								.arg(iconBytes.size())
								.arg(iMaxImageMessageLength));
					} else {
						g->qbaIcon = QByteArray(iconBytes.data(), static_cast< int >(iconBytes.size()));
					}
				} else {
					g->qbaIcon.clear();
				}
				g->qsStylePreset = group.has_style_preset() ? u8(group.style_preset()) : QString();
				g->qhMetadata.clear();
				for (int j = 0; j < group.metadata_size(); ++j) {
					const MumbleProto::ACL_ChanGroup_KeyValue &kv = group.metadata(j);
					g->qhMetadata.insert(u8(kv.key()), kv.has_value() ? u8(kv.value()) : QString());
				}

				g->qsTemporary = hOldTemp.value(g->qsName);
			}

			if (Meta::mp->bLogGroupChanges) {
				logGroups(this, c, QLatin1String("And these are the new groups:"));
			}

			// Add new ACLs
			for (int i = 0; i < msg.acls_size(); ++i) {
				const MumbleProto::ACL_ChanACL &mpacl = msg.acls(i);
				if (mpacl.has_user_id() && getRegisteredUserName(static_cast< int >(mpacl.user_id())).isEmpty())
					continue;

				ChanACL *a    = new ChanACL(c);
				a->bApplyHere = mpacl.apply_here();
				a->bApplySubs = mpacl.apply_subs();
				if (mpacl.has_user_id())
					a->iUserId = static_cast< int >(mpacl.user_id());
				else
					a->qsGroup = u8(mpacl.group());
				a->pDeny  = static_cast< ChanACL::Permissions >(mpacl.deny()) & ChanACL::All;
				a->pAllow = static_cast< ChanACL::Permissions >(mpacl.grant()) & ChanACL::All;
			}

			if (Meta::mp->bLogACLChanges) {
				logACLs(this, c, QLatin1String("And these are the new ACLs:"));
			}
		}

		clearACLCache();

		if (!hasPermission(uSource, c, ChanACL::Write) && ((uSource->iId >= 0) || !uSource->qsHash.isEmpty())) {
			{
				QWriteLocker wl(&qrwlVoiceThread);

				ChanACL *a    = new ChanACL(c);
				a->bApplyHere = true;
				a->bApplySubs = false;
				if (uSource->iId >= 0)
					a->iUserId = uSource->iId;
				else
					a->qsGroup = QLatin1Char('$') + uSource->qsHash;
				a->iUserId = uSource->iId;
				a->pDeny   = ChanACL::None;
				a->pAllow  = ChanACL::Write | ChanACL::Traverse;
			}

			clearACLCache();
		}


		if (!c->bTemporary) {
			m_dbWrapper.updateChannelData(iServerNum, *c);
		}
		log(uSource, QString("Updated ACL in channel %1").arg(*c));

		// Send refreshed enter states of this channel to all clients
		MumbleProto::ChannelState mpcs;
		mpcs.set_channel_id(c->iId);

		for (ServerUser *user : qhUsers) {
			mpcs.set_is_enter_restricted(isChannelEnterRestricted(c));
			mpcs.set_can_enter(hasPermission(user, c, ChanACL::Enter));

			sendMessage(user, mpcs);
		}
	}
}

void Server::msgQueryUsers(ServerUser *uSource, MumbleProto::QueryUsers &msg) {
	ZoneScoped;

	MSG_SETUP(ServerUser::Authenticated);

	// User needs Write permission on at least one channel in the tree
	bool hasWritePermission = false;
	for (Channel *chan : qhChannels) {
		if (hasPermission(uSource, chan, ChanACL::Write)) {
			hasWritePermission = true;
			break;
		}
	}

	if (!hasWritePermission) {
		return;
	}

	MumbleProto::QueryUsers reply;

	for (int i = 0; i < msg.ids_size(); ++i) {
		unsigned int id     = msg.ids(i);
		const QString &name = getRegisteredUserName(static_cast< int >(id));
		if (!name.isEmpty()) {
			reply.add_ids(id);
			reply.add_names(u8(name));
		}
	}

	for (int i = 0; i < msg.names_size(); ++i) {
		QString name = u8(msg.names(i));
		int id       = getRegisteredUserID(name);
		if (id >= 0) {
			name = getRegisteredUserName(id);
			reply.add_ids(static_cast< unsigned int >(id));
			reply.add_names(u8(name));
		}
	}

	sendMessage(uSource, reply);
}

void Server::msgPing(ServerUser *uSource, MumbleProto::Ping &msg) {
	ZoneScoped;

	MSG_SETUP_NO_UNIDLE(ServerUser::Authenticated);

	QMutexLocker l(&uSource->qmCrypt);

	uSource->csCrypt->m_statsRemote.good   = msg.good();
	uSource->csCrypt->m_statsRemote.late   = msg.late();
	uSource->csCrypt->m_statsRemote.lost   = msg.lost();
	uSource->csCrypt->m_statsRemote.resync = msg.resync();

	uSource->dUDPPingAvg  = msg.udp_ping_avg();
	uSource->dUDPPingVar  = msg.udp_ping_var();
	uSource->uiUDPPackets = msg.udp_packets();
	uSource->dTCPPingAvg  = msg.tcp_ping_avg();
	uSource->dTCPPingVar  = msg.tcp_ping_var();
	uSource->uiTCPPackets = msg.tcp_packets();

	quint64 ts = msg.timestamp();

	msg.Clear();
	msg.set_timestamp(ts);
	msg.set_good(uSource->csCrypt->m_statsLocal.good);
	msg.set_late(uSource->csCrypt->m_statsLocal.late);
	msg.set_lost(uSource->csCrypt->m_statsLocal.lost);
	msg.set_resync(uSource->csCrypt->m_statsLocal.resync);

	sendMessage(uSource, msg);
}

void Server::msgCryptSetup(ServerUser *uSource, MumbleProto::CryptSetup &msg) {
	ZoneScoped;

	MSG_SETUP_NO_UNIDLE(ServerUser::Authenticated);

	QMutexLocker l(&uSource->qmCrypt);

	if (!msg.has_client_nonce()) {
		log(uSource, "Requested crypt-nonce resync");
		msg.set_server_nonce(uSource->csCrypt->getEncryptIV());
		sendMessage(uSource, msg);
	} else {
		const std::string &str = msg.client_nonce();
		uSource->csCrypt->m_statsLocal.resync++;
		if (!uSource->csCrypt->setDecryptIV(str)) {
			qWarning("Messages: Cipher resync failed: Invalid nonce from the client!");
		}
	}
}

void Server::msgContextActionModify(ServerUser *, MumbleProto::ContextActionModify &) {
}

void Server::msgContextAction(ServerUser *uSource, MumbleProto::ContextAction &msg) {
	ZoneScoped;

	MSG_SETUP(ServerUser::Authenticated);

	unsigned int session = msg.has_session() ? msg.session() : 0;
	int id               = msg.has_channel_id() ? static_cast< int >(msg.channel_id()) : -1;

	if (session && !qhUsers.contains(session))
		return;
	if ((id >= 0) && !qhChannels.contains(static_cast< unsigned int >(id)))
		return;
	emit contextAction(uSource, u8(msg.action()), session, id);
}

/// @param str The std::string to convert
/// @param maxSize The maximum allowed size for this string
/// @returns The given std::string converted to a QString, if its size is less
///  	than or equal to the given maxSize. If it is bigger, "[[Invalid]]"
///  	is returned.
QString convertWithSizeRestriction(const std::string &str, size_t maxSize) {
	if (str.size() > maxSize) {
		return QLatin1String("[[Invalid]]");
	}

	return QString::fromStdString(str);
}

void Server::msgVersion(ServerUser *uSource, MumbleProto::Version &msg) {
	ZoneScoped;

	RATELIMIT(uSource);

	uSource->m_version = MumbleProto::getVersion(msg);
	if (msg.has_release()) {
		uSource->qsRelease = convertWithSizeRestriction(msg.release(), 100);
	}
	if (msg.has_os()) {
		uSource->qsOS = convertWithSizeRestriction(msg.os(), 40);

		if (msg.has_os_version()) {
			uSource->qsOSVersion = convertWithSizeRestriction(msg.os_version(), 60);
		}
	}

	if(msg.has_fancy_version()) {
		uSource->m_FancyVersion.emplace(static_cast<::Version::full_t >(msg.fancy_version()));
	}

	auto versionString = uSource->m_FancyVersion ? Version::toString(*(uSource->m_FancyVersion)) : "n/a";

	log(uSource, QString(R"({"event": "ClientVersion", "payload": {"version": "%1", "os": "%2", "os_version": "%3", "release": "%4", "fancy_version": "%5"}})")
					 .arg(Version::toString(uSource->m_version))
					 .arg(uSource->qsOS)
					 .arg(uSource->qsOSVersion)
					 .arg(uSource->qsRelease)
					 .arg(versionString));
}

void Server::msgUserList(ServerUser *uSource, MumbleProto::UserList &msg) {
	ZoneScoped;

	MSG_SETUP(ServerUser::Authenticated);

	// The register permission is required on the root channel to be allowed to
	// view the registered users.
	if (!hasPermission(uSource, qhChannels.value(0), ChanACL::Register)) {
		PERM_DENIED(uSource, qhChannels.value(0), ChanACL::Register);
		return;
	}

	if (msg.users_size() == 0) {
		// Query mode.
		std::vector< UserInfo > users = getAllRegisteredUserProperties();
		for (const UserInfo &info : users) {
			// Skip the SuperUser
			if (info.user_id > 0 && static_cast< unsigned int >(info.user_id) != Mumble::SUPERUSER_ID) {
				::MumbleProto::UserList_User *user = msg.add_users();
				user->set_user_id(static_cast< unsigned int >(info.user_id));
				user->set_name(u8(info.name));
				if (info.last_channel) {
					user->set_last_channel(static_cast< unsigned int >(info.last_channel.value()));
				}
				user->set_last_seen(u8(info.last_active.toString(Qt::ISODate)));
				if (!info.texture.empty()) {
					user->set_texture(info.texture.data(), info.texture.size());
				}
				if (!info.comment_hash.isEmpty()) {
					if (!info.comment.isEmpty()) {
						// Short comment: include inline.
						user->set_comment(u8(info.comment));
					} else {
						// Long comment: send SHA-1 hash; client must request blob.
						user->set_comment_hash(info.comment_hash.constData(),
							static_cast< size_t >(info.comment_hash.size()));
					}
				}
			}
		}
		sendMessage(uSource, msg);
	} else {
		// Update mode
		for (int i = 0; i < msg.users_size(); ++i) {
			const MumbleProto::UserList_User &user = msg.users(i);

			unsigned int id = user.user_id();
			if (id == 0)
				continue;

			if (!user.has_name()) {
				log(uSource, QString::fromLatin1("Unregistered user %1").arg(id));
				unregisterUser(static_cast< int >(id));
			} else {
				const QString &name = u8(user.name()).trimmed();
				if (validateUserName(name)) {
					log(uSource, QString::fromLatin1("Renamed user %1 to '%2'").arg(QString::number(id), name));

					QMap< int, QString > info;
					info.insert(static_cast< int >(::mumble::server::db::UserProperty::Name), name);
					setUserProperties(static_cast< int >(id), info);

					MumbleProto::UserState mpus;
					for (ServerUser *serverUser : qhUsers) {
						if (serverUser->iId == static_cast< int >(id)) {
							serverUser->qsName = name;
							mpus.set_session(serverUser->uiSession);
							break;
						}
					}
					if (mpus.has_session()) {
						mpus.set_actor(uSource->uiSession);
						mpus.set_name(u8(name));
						sendAll(mpus);
					}
				} else {
					MumbleProto::PermissionDenied mppd;
					mppd.set_type(MumbleProto::PermissionDenied_DenyType_UserName);
					if (uSource->m_version < Version::fromComponents(1, 2, 1))
						mppd.set_reason(u8(QString::fromLatin1("%1 is not a valid username").arg(name)));
					else
						mppd.set_name(u8(name));
					sendMessage(uSource, mppd);
				}
			}
		}
	}
}

void Server::msgVoiceTarget(ServerUser *uSource, MumbleProto::VoiceTarget &msg) {
	ZoneScoped;

	MSG_SETUP_NO_UNIDLE(ServerUser::Authenticated);

	int target = static_cast< int >(msg.id());
	if ((target < 1) || (target >= 0x1f))
		return;

	QWriteLocker lock(&qrwlVoiceThread);

	uSource->qmTargetCache.remove(target);

	int count = msg.targets_size();
	if (count == 0) {
		uSource->qmTargets.remove(target);
	} else {
		WhisperTarget wt;
		for (int i = 0; i < count; ++i) {
			const MumbleProto::VoiceTarget_Target &t = msg.targets(i);
			for (int j = 0; j < t.session_size(); ++j) {
				unsigned int s = t.session(j);
				if (qhUsers.contains(s)) {
					wt.sessions.push_back(s);
				}
			}
			if (t.has_channel_id()) {
				unsigned int id = t.channel_id();
				if (qhChannels.contains(id)) {
					WhisperTarget::Channel wtc;
					wtc.id              = id;
					wtc.includeChildren = t.children();
					wtc.includeLinks    = t.links();
					if (t.has_group()) {
						wtc.targetGroup = u8(t.group());
					}

					wt.channels.push_back(wtc);
				}
			}
		}
		if (wt.sessions.empty() && wt.channels.empty()) {
			uSource->qmTargets.remove(target);
		} else {
			uSource->qmTargets.insert(target, std::move(wt));
		}
	}
}

void Server::msgPermissionQuery(ServerUser *uSource, MumbleProto::PermissionQuery &msg) {
	ZoneScoped;

	MSG_SETUP_NO_UNIDLE(ServerUser::Authenticated);

	Channel *c = qhChannels.value(msg.channel_id());
	if (!c)
		return;

	sendClientPermission(uSource, c, true);
}

void Server::msgCodecVersion(ServerUser *, MumbleProto::CodecVersion &) {
}

void Server::msgUserStats(ServerUser *uSource, MumbleProto::UserStats &msg) {
	ZoneScoped;

	MSG_SETUP_NO_UNIDLE(ServerUser::Authenticated);
	VICTIM_SETUP;
	const BandwidthRecord &bwr            = pDstServerUser->bwr;
	const QList< QSslCertificate > &certs = pDstServerUser->peerCertificateChain();

	bool extend = (uSource == pDstServerUser) || hasPermission(uSource, qhChannels.value(0), ChanACL::Ban);

	if (!extend && !hasPermission(uSource, pDstServerUser->cChannel, ChanACL::Enter)) {
		PERM_DENIED(uSource, pDstServerUser->cChannel, ChanACL::Enter);
		return;
	}

	bool details = extend;
	bool local   = extend || (pDstServerUser->cChannel == uSource->cChannel);

	if (msg.stats_only())
		details = false;

	msg.Clear();
	msg.set_session(pDstServerUser->uiSession);

	if (details) {
		for (const QSslCertificate &cert : certs) {
			const QByteArray &der = cert.toDer();
			msg.add_certificates(blob(der));
		}
		msg.set_strong_certificate(pDstServerUser->bVerified);
	}

	if (local) {
		MumbleProto::UserStats_Stats *mpusss;

		QMutexLocker l(&pDstServerUser->qmCrypt);

		mpusss = msg.mutable_from_client();
		mpusss->set_good(pDstServerUser->csCrypt->m_statsLocal.good);
		mpusss->set_late(pDstServerUser->csCrypt->m_statsLocal.late);
		mpusss->set_lost(pDstServerUser->csCrypt->m_statsLocal.lost);
		mpusss->set_resync(pDstServerUser->csCrypt->m_statsLocal.resync);

		mpusss = msg.mutable_from_server();
		mpusss->set_good(pDstServerUser->csCrypt->m_statsRemote.good);
		mpusss->set_late(pDstServerUser->csCrypt->m_statsRemote.late);
		mpusss->set_lost(pDstServerUser->csCrypt->m_statsRemote.lost);
		mpusss->set_resync(pDstServerUser->csCrypt->m_statsRemote.resync);

		bool outsideInitialWindow =
			static_cast< unsigned int >(bwr.onlineSeconds()) > pDstServerUser->csCrypt->m_rollingWindow.count();

		MumbleProto::UserStats_RollingStats *mpussrs = msg.mutable_rolling_stats();

		mpusss = mpussrs->mutable_from_client();
		if (outsideInitialWindow) {
			mpusss->set_good(pDstServerUser->csCrypt->m_statsLocalRolling.good);
			mpusss->set_late(pDstServerUser->csCrypt->m_statsLocalRolling.late);
			mpusss->set_lost(pDstServerUser->csCrypt->m_statsLocalRolling.lost);
			mpusss->set_resync(pDstServerUser->csCrypt->m_statsLocalRolling.resync);
		} else {
			mpusss->CopyFrom(*msg.mutable_from_client());
		}

		mpusss = mpussrs->mutable_from_server();
		if (outsideInitialWindow) {
			mpusss->set_good(pDstServerUser->csCrypt->m_statsRemoteRolling.good);
			mpusss->set_late(pDstServerUser->csCrypt->m_statsRemoteRolling.late);
			mpusss->set_lost(pDstServerUser->csCrypt->m_statsRemoteRolling.lost);
			mpusss->set_resync(pDstServerUser->csCrypt->m_statsRemoteRolling.resync);
		} else {
			mpusss->CopyFrom(*msg.mutable_from_server());
		}

		mpussrs->set_time_window(pDstServerUser->csCrypt->m_rollingWindow.count());
	}

	msg.set_udp_packets(pDstServerUser->uiUDPPackets);
	msg.set_tcp_packets(pDstServerUser->uiTCPPackets);
	msg.set_udp_ping_avg(pDstServerUser->dUDPPingAvg);
	msg.set_udp_ping_var(pDstServerUser->dUDPPingVar);
	msg.set_tcp_ping_avg(pDstServerUser->dTCPPingAvg);
	msg.set_tcp_ping_var(pDstServerUser->dTCPPingVar);

	if (details) {
		MumbleProto::Version *mpv;

		mpv = msg.mutable_version();
		if (pDstServerUser->m_version != Version::UNKNOWN) {
			MumbleProto::setVersion(*mpv, pDstServerUser->m_version);
		}
		if (!pDstServerUser->qsRelease.isEmpty()) {
			mpv->set_release(u8(pDstServerUser->qsRelease));
		}
		if (!pDstServerUser->qsOS.isEmpty()) {
			mpv->set_os(u8(pDstServerUser->qsOS));
			if (!pDstServerUser->qsOSVersion.isEmpty())
				mpv->set_os_version(u8(pDstServerUser->qsOSVersion));
		}

		for (int v : pDstServerUser->qlCodecs) {
			msg.add_celt_versions(v);
		}
		msg.set_opus(pDstServerUser->bOpus);

		msg.set_address(pDstServerUser->haAddress.toStdString());
	}

	if (local)
		msg.set_bandwidth(static_cast< unsigned int >(bwr.bandwidth()));
	msg.set_onlinesecs(static_cast< unsigned int >(bwr.onlineSeconds()));
	if (local)
		msg.set_idlesecs(static_cast< unsigned int >(bwr.idleSeconds()));

	sendMessage(uSource, msg);
}

void Server::msgRequestBlob(ServerUser *uSource, MumbleProto::RequestBlob &msg) {
	ZoneScoped;

	MSG_SETUP_NO_UNIDLE(ServerUser::Authenticated);

	int ntextures     = msg.session_texture_size();
	int ncomments     = msg.session_comment_size();
	int ndescriptions = msg.channel_description_size();

	if (ndescriptions) {
		MumbleProto::ChannelState mpcs;
		for (int i = 0; i < ndescriptions; ++i) {
			unsigned int id = msg.channel_description(i);
			Channel *c      = qhChannels.value(id);
			if (c && !c->qsDesc.isEmpty()) {
				mpcs.set_channel_id(id);
				mpcs.set_description(u8(c->qsDesc));
				sendMessage(uSource, mpcs);
			}
		}
	}
	if (ntextures || ncomments) {
		MumbleProto::UserState mpus;
		for (int i = 0; i < ntextures; ++i) {
			unsigned int session = msg.session_texture(i);
			ServerUser *su       = qhUsers.value(session);
			if (su && !su->qbaTexture.isEmpty()) {
				mpus.set_session(session);
				mpus.set_texture(blob(su->qbaTexture));
				sendMessage(uSource, mpus);
			}
		}
		if (ntextures)
			mpus.clear_texture();
		for (int i = 0; i < ncomments; ++i) {
			unsigned int session = msg.session_comment(i);
			ServerUser *su       = qhUsers.value(session);
			if (su && !su->qsComment.isEmpty()) {
				mpus.set_session(session);
				mpus.set_comment(u8(su->qsComment));
				sendMessage(uSource, mpus);
			}
		}
	}

	// Registered user comment blobs (for offline users).
	for (int i = 0; i < msg.user_id_comment_size(); ++i) {
		unsigned int uid = msg.user_id_comment(i);
		if (uid == 0 || uid == Mumble::SUPERUSER_ID)
			continue;
		QMap< int, QString > details = m_dbWrapper.getRegisteredUserDetails(iServerNum, uid);
		QString comment =
			details.value(static_cast< int >(::mumble::server::db::UserProperty::Comment));
		if (!comment.isEmpty()) {
			MumbleProto::UserList blobreply;
			MumbleProto::UserList_User *entry = blobreply.add_users();
			entry->set_user_id(uid);
			entry->set_comment(u8(comment));
			sendMessage(uSource, blobreply);
		}
	}
}

void Server::msgServerConfig(ServerUser *, MumbleProto::ServerConfig &) {
}

void Server::msgSuggestConfig(ServerUser *, MumbleProto::SuggestConfig &) {
}

void Server::msgPluginDataTransmission(ServerUser *sender, MumbleProto::PluginDataTransmission &msg) {
	ZoneScoped;

	// A client's plugin has sent us a message that we shall delegate to its receivers

	if (sender->m_pluginMessageBucket.ratelimit(1)) {
		qWarning("Dropping plugin message sent from \"%s\" (%d)", qUtf8Printable(sender->qsName), sender->uiSession);
		return;
	}

	if (!msg.has_data() || !msg.has_dataid()) {
		// Messages without data and/or without a data ID can't be used by the clients. Thus we don't even have to send
		// them
		return;
	}

	// Always set the sender's session and don't rely on it being set correctly (would
	// allow spoofing the sender's session)
	msg.set_sendersession(sender->uiSession);

	if (msg.data().size() > Mumble::Plugins::PluginMessage::MAX_DATA_LENGTH) {
		qWarning("Dropping plugin message sent from \"%s\" (%d) - data too large", qUtf8Printable(sender->qsName),
				 sender->uiSession);
		return;
	}
	if (msg.dataid().size() > Mumble::Plugins::PluginMessage::MAX_DATA_ID_LENGTH) {
		qWarning("Dropping plugin message sent from \"%s\" (%d) - data ID too long", qUtf8Printable(sender->qsName),
				 sender->uiSession);
		return;
	}

	// Copy needed data from message in order to be able to remove info about receivers from the message as this doesn't
	// matter for the client
	size_t receiverAmount = static_cast< std::size_t >(msg.receiversessions_size());
	const ::google::protobuf::RepeatedField<::google::protobuf::uint32 > receiverSessions = msg.receiversessions();

	msg.clear_receiversessions();

	QSet< uint32_t > uniqueReceivers;
	uniqueReceivers.reserve(receiverSessions.size());

	for (int i = 0; static_cast< size_t >(i) < receiverAmount; i++) {
		uint32_t userSession = receiverSessions.Get(i);

		if (!uniqueReceivers.contains(userSession)) {
			uniqueReceivers.insert(userSession);
		} else {
			// Duplicate entry -> ignore
			continue;
		}

		ServerUser *receiver = qhUsers.value(receiverSessions.Get(i));

		if (receiver) {
			// We can simply redirect the message we have received to the clients
			sendMessage(receiver, msg);
		}
	}

	// Also expose the message to server-side Rust plugins (e.g. file-server
	// auth tickets). The plugin host runs out-of-band and never blocks the
	// client-to-client delivery above.
	if (m_pluginHost) {
		m_pluginHost->onPluginData(
			sender->uiSession, QString::fromStdString(msg.dataid()),
			QByteArray(msg.data().data(), static_cast< int >(msg.data().size())));
	}
}

// ---------------------------------------------------------------------------
// Push notification registration helpers
// ---------------------------------------------------------------------------

void Server::computeAllowedPushChannels(ServerUser *user, std::set< uint32_t > &out) {
	out.clear();
	for (auto it = qhChannels.constBegin(); it != qhChannels.constEnd(); ++it) {
		Channel *c = it.value();
		if (ChanACL::hasPermission(user, c, ChanACL::SubscribePush, &acCache)) {
			out.insert(static_cast< uint32_t >(c->iId));
		}
	}
}

void Server::handlePushRegistration(ServerUser *sender,
                                    const MumbleProto::FancyPushRegister &msg) {
	if (sender->qsHash.isEmpty()) {
		log(sender, QString("push-register: ignored (no certificate hash)"));
		return;
	}

	QString token = QString::fromStdString(msg.token());
	if (token.isEmpty()) {
		log(sender, QString("push-register: missing 'token'"));
		return;
	}

	PushRegistration reg;
	reg.fcmToken = token.toStdString();

	// Compute which channels the user has TextMessage permission for.
	computeAllowedPushChannels(sender, reg.allowedChannels);

	// Apply any muted list from the payload.
	for (int i = 0; i < msg.muted_channels_size(); ++i) {
		reg.mutedChannels.insert(msg.muted_channels(i));
	}

	m_pushRegistrations[sender->qsHash] = reg;

	log(sender, QString("push-register: stored token (len=%1) allowed=%2 muted=%3")
	        .arg(token.size())
	        .arg(reg.allowedChannels.size())
	        .arg(reg.mutedChannels.size()));
}

void Server::handlePushChannelUpdate(ServerUser *sender,
                                     const MumbleProto::FancyPushUpdate &msg) {
	if (sender->qsHash.isEmpty()) return;

	auto it = m_pushRegistrations.find(sender->qsHash);
	if (it == m_pushRegistrations.end()) {
		log(sender, QString("push-update: no registration found, ignoring"));
		return;
	}

	it->mutedChannels.clear();
	for (int i = 0; i < msg.muted_channels_size(); ++i) {
		it->mutedChannels.insert(msg.muted_channels(i));
	}

	// Also refresh allowed channels while the user is connected.
	computeAllowedPushChannels(sender, it->allowedChannels);

	log(sender, QString("push-update: muted=%1 allowed=%2")
	        .arg(it->mutedChannels.size())
	        .arg(it->allowedChannels.size()));
}

void Server::msgFancyPushRegister(ServerUser *uSource, MumbleProto::FancyPushRegister &msg) {
	MSG_SETUP(ServerUser::Authenticated);
	handlePushRegistration(uSource, msg);
}

void Server::msgFancyPushUpdate(ServerUser *uSource, MumbleProto::FancyPushUpdate &msg) {
	MSG_SETUP(ServerUser::Authenticated);
	handlePushChannelUpdate(uSource, msg);
}

void Server::msgFancyCustomReactionsConfig(ServerUser *, MumbleProto::FancyCustomReactionsConfig &) {
	// Server -> Client only; ignore if received from client.
}

void Server::handleLivePushSubscribe(ServerUser *sender,
                                     const MumbleProto::FancySubscribePush &msg) {
	LivePushSubscription sub;
	computeAllowedPushChannels(sender, sub.allowedChannels);

	for (int i = 0; i < msg.muted_channels_size(); ++i) {
		sub.mutedChannels.insert(msg.muted_channels(i));
	}

	m_livePushSubscriptions[sender->uiSession] = sub;

	log(sender, QString("live-push-subscribe: allowed=%1 muted=%2")
	        .arg(sub.allowedChannels.size())
	        .arg(sub.mutedChannels.size()));
}

void Server::msgFancySubscribePush(ServerUser *uSource, MumbleProto::FancySubscribePush &msg) {
	MSG_SETUP(ServerUser::Authenticated);
	handleLivePushSubscribe(uSource, msg);
}

void Server::msgPchatMessage(ServerUser *uSource, MumbleProto::PchatMessage &msg) {
	MSG_SETUP(ServerUser::Authenticated);

	if (m_pchatManager) {
		m_pchatManager->handlePchatMessage(uSource->uiSession, msg);
	}
}

void Server::msgPchatFetch(ServerUser *uSource, MumbleProto::PchatFetch &msg) {
	MSG_SETUP(ServerUser::Authenticated);

	if (m_pchatManager) {
		m_pchatManager->handlePchatFetch(uSource->uiSession, msg);
	}
}

// Server -> Client only; ignore if received from client
void Server::msgPchatFetchResponse(ServerUser *, MumbleProto::PchatFetchResponse &) {
}

// Server -> Client only; ignore if received from client
void Server::msgPchatMessageDeliver(ServerUser *, MumbleProto::PchatMessageDeliver &) {
}

void Server::msgPchatKeyAnnounce(ServerUser *uSource, MumbleProto::PchatKeyAnnounce &msg) {
	MSG_SETUP(ServerUser::Authenticated);

	if (m_pchatManager) {
		m_pchatManager->handlePchatKeyAnnounce(uSource->uiSession, msg);
	}
}

void Server::msgPchatKeyExchange(ServerUser *uSource, MumbleProto::PchatKeyExchange &msg) {
	MSG_SETUP(ServerUser::Authenticated);

	if (m_pchatManager) {
		m_pchatManager->handlePchatKeyExchange(uSource->uiSession, msg);
	}
}

// Server -> Client only; ignore if received from client
void Server::msgPchatKeyRequest(ServerUser *, MumbleProto::PchatKeyRequest &) {
}

// PchatAck is primarily Server -> Client, but clients also send it
// to acknowledge offline queue drains.
void Server::msgPchatAck(ServerUser *uSource, MumbleProto::PchatAck &msg) {
	MSG_SETUP(ServerUser::Authenticated);
	if (m_pchatManager) {
		m_pchatManager->handlePchatAck(uSource->uiSession, msg);
	}
}

void Server::msgPchatEpochCountersig(ServerUser *uSource, MumbleProto::PchatEpochCountersig &msg) {
	MSG_SETUP(ServerUser::Authenticated);

	if (m_pchatManager) {
		m_pchatManager->handlePchatEpochCountersig(uSource->uiSession, msg);
	}
}

void Server::msgPchatKeyHolderReport(ServerUser *uSource, MumbleProto::PchatKeyHolderReport &msg) {
	MSG_SETUP(ServerUser::Authenticated);

	if (m_pchatManager) {
		m_pchatManager->handlePchatKeyHolderReport(uSource->uiSession, msg);
	}
}

void Server::msgPchatKeyHoldersQuery(ServerUser *uSource, MumbleProto::PchatKeyHoldersQuery &msg) {
	MSG_SETUP(ServerUser::Authenticated);

	if (m_pchatManager) {
		m_pchatManager->handlePchatKeyHoldersQuery(uSource->uiSession, msg);
	}
}

// Server -> Client only; ignore if received from client
void Server::msgPchatKeyHoldersList(ServerUser *, MumbleProto::PchatKeyHoldersList &) {
}

// Server sends PchatKeyChallenge; ignore if received from client
void Server::msgPchatKeyChallenge(ServerUser *, MumbleProto::PchatKeyChallenge &) {
}

void Server::msgPchatKeyChallengeResponse(ServerUser *uSource, MumbleProto::PchatKeyChallengeResponse &msg) {
	MSG_SETUP(ServerUser::Authenticated);

	if (m_pchatManager) {
		m_pchatManager->handlePchatKeyChallengeResponse(uSource->uiSession, msg);
	}
}


void Server::msgPchatDeleteMessages(ServerUser *uSource, MumbleProto::PchatDeleteMessages &msg) {
	MSG_SETUP(ServerUser::Authenticated);

	if (!msg.has_channel_id()) {
		return;
	}

	Channel *c = qhChannels.value(msg.channel_id());
	if (!c) {
		return;
	}

	if (!hasPermission(uSource, c, ChanACL::DeleteMessage)) {
		PERM_DENIED(uSource, c, ChanACL::DeleteMessage);
		return;
	}

	if (m_pchatManager) {
		m_pchatManager->handlePchatDeleteMessages(uSource->uiSession, msg);
	}
}

// Server -> Client only; ignore if received from client
void Server::msgPchatKeyChallengeResult(ServerUser *, MumbleProto::PchatKeyChallengeResult &) {
}

// Server -> Client only; ignore if received from client
void Server::msgPchatOfflineQueueDrain(ServerUser *, MumbleProto::PchatOfflineQueueDrain &) {
}

void Server::msgPchatReaction(ServerUser *uSource, MumbleProto::PchatReaction &msg) {
	MSG_SETUP(ServerUser::Authenticated);

	if (m_pchatManager) {
		m_pchatManager->handlePchatReaction(uSource->uiSession, msg);
	}
}

// Server -> Client only; ignore if received from client
void Server::msgPchatReactionDeliver(ServerUser *, MumbleProto::PchatReactionDeliver &) {
}

// Server -> Client only; ignore if received from client
void Server::msgPchatReactionFetchResponse(ServerUser *, MumbleProto::PchatReactionFetchResponse &) {
}

void Server::msgPchatSenderKeyDistribution(ServerUser *uSource, MumbleProto::PchatSenderKeyDistribution &msg) {
	MSG_SETUP(ServerUser::Authenticated);

	if (m_pchatManager) {
		m_pchatManager->handlePchatSenderKeyDistribution(uSource->uiSession, msg);
	}
}

void Server::msgPchatPin(ServerUser *uSource, MumbleProto::PchatPin &msg) {
	MSG_SETUP(ServerUser::Authenticated);

	if (m_pchatManager) {
		m_pchatManager->handlePchatPin(uSource->uiSession, msg);
	}
}

// Server -> Client only; ignore if received from client
void Server::msgPchatPinDeliver(ServerUser *, MumbleProto::PchatPinDeliver &) {
}

// Server -> Client only; ignore if received from client
void Server::msgPchatPinFetchResponse(ServerUser *, MumbleProto::PchatPinFetchResponse &) {
}


// ---------------------------------------------------------------------------
// WebRtcSignal relay (Fancy Mumble screen sharing)
// ---------------------------------------------------------------------------

void Server::msgWebRtcSignal(ServerUser *uSource, MumbleProto::WebRtcSignal &msg) {
	ZoneScoped;

	MSG_SETUP(ServerUser::Authenticated);

	RATELIMIT(uSource);

	// The sender must have TextMessage permission in their channel to
	// broadcast screen-sharing signals.
	Channel *c = uSource->cChannel;
	if (!c)
		return;

	if (!ChanACL::hasPermission(uSource, c, ChanACL::TextMessage, &acCache)) {
		PERM_DENIED(uSource, c, ChanACL::TextMessage);
		return;
	}

	// Stamp the sender session (never trust client-supplied value).
	msg.set_sender_session(uSource->uiSession);

	auto sigType = msg.signal_type();

	// If the SFU is available, intercept SDP/ICE signals.
	if (m_sfuManager && m_sfuManager->isAvailable()) {
		switch (sigType) {
			case MumbleProto::WebRtcSignal::START: {
				// Create the SFU session and relay START to the channel.
				m_sfuManager->createSession(uSource->uiSession);
				for (User *p : c->qlUsers) {
					if (p == uSource) continue;
					sendMessage(static_cast< ServerUser * >(p), msg);
				}
				return;
			}
			case MumbleProto::WebRtcSignal::STOP: {
				// Destroy the SFU session and relay STOP to the channel.
				m_sfuManager->destroySession(uSource->uiSession);
				for (User *p : c->qlUsers) {
					if (p == uSource) continue;
					sendMessage(static_cast< ServerUser * >(p), msg);
				}
				return;
			}
			case MumbleProto::WebRtcSignal::SDP_OFFER: {
				uint32_t target = msg.target_session();
				QString sdp = QString::fromStdString(msg.payload());

				if (target == 0) {
					// Broadcaster sending offer to server SFU.
					m_sfuManager->broadcasterOffer(uSource->uiSession, sdp);
				} else {
					// Viewer sending offer - target is the broadcaster session.
					m_sfuManager->viewerOffer(target, uSource->uiSession, sdp);
				}
				return;
			}
			case MumbleProto::WebRtcSignal::ICE_CANDIDATE: {
				uint32_t target = msg.target_session();
				QString json = QString::fromStdString(msg.payload());

				// Determine which broadcast session this ICE candidate belongs to.
				// target=0 means from broadcaster, otherwise target is the broadcaster.
				uint32_t broadcasterSession = (target == 0) ? uSource->uiSession : target;
				m_sfuManager->addIceCandidate(broadcasterSession, uSource->uiSession, json);
				return;
			}
			case MumbleProto::WebRtcSignal::SDP_ANSWER: {
				// Clients should not send SDP_ANSWER when SFU is active
				// (only the server sends answers). Ignore silently.
				return;
			}
		}
	}

	// Fallback: pure relay mode (no SFU loaded).
	uint32_t target = msg.target_session();

	if (target == 0) {
		// Broadcast to all users in the sender's channel (except self).
		for (User *p : c->qlUsers) {
			if (p == uSource) continue;
			sendMessage(static_cast< ServerUser * >(p), msg);
		}
	} else {
		// Directed relay to a single target (must be in the same channel).
		ServerUser *pDst = qhUsers.value(target);
		if (pDst && pDst->cChannel == c) {
			sendMessage(pDst, msg);
		}
	}
}

void Server::msgFancyReadReceipt(ServerUser *uSource, MumbleProto::FancyReadReceipt &msg) {
	MSG_SETUP(ServerUser::Authenticated);
	handleReadReceipt(uSource, msg);
}

// Server -> Client only; ignore if received from client
void Server::msgFancyReadReceiptDeliver(ServerUser *, MumbleProto::FancyReadReceiptDeliver &) {
}

void Server::handleReadReceipt(ServerUser *uSource, MumbleProto::FancyReadReceipt &msg) {
	if (!msg.has_channel_id()) {
		return;
	}

	const auto channelId = msg.channel_id();
	Channel *c = qhChannels.value(channelId);
	if (!c) {
		return;
	}

	const QString certHash = uSource->qsHash;
	if (certHash.isEmpty()) {
		return;
	}

	// Query mode: return current watermarks for this channel without updating.
	if (msg.has_query() && msg.query()) {
		MumbleProto::FancyReadReceiptDeliver deliver;
		deliver.set_channel_id(channelId);

		const auto &channelWatermarks = m_readWatermarks.value(channelId);
		const bool hasQueryMsgId = msg.has_query_message_id();
		const auto &queryMsgId = hasQueryMsgId ? msg.query_message_id() : std::string{};

		if (hasQueryMsgId) {
			deliver.set_query_message_id(queryMsgId);
		}

		for (auto it = channelWatermarks.constBegin(); it != channelWatermarks.constEnd(); ++it) {
			// If querying for a specific message, only include users whose
			// watermark is >= that message. Since message_ids are UUIDs
			// (not ordered), we store them all and let the client filter.
			// For simplicity, include all watermarks and let the client
			// determine which ones have read the queried message by comparing
			// message timestamps or message ordering.
			auto *rs = deliver.add_read_states();
			rs->set_cert_hash(it.key().toStdString());
			rs->set_last_read_message_id(it.value().lastMessageId);
			rs->set_timestamp(it.value().timestamp);

			// Fill display name from connected user if available.
			for (ServerUser *u : qhUsers) {
				if (u->qsHash == it.key() && u->sState == ServerUser::Authenticated) {
					rs->set_name(u->qsName.toStdString());
					break;
				}
			}
		}

		sendMessage(uSource, deliver);
		return;
	}

	// Update mode: store watermark and broadcast.
	if (!msg.has_last_read_message_id() || msg.last_read_message_id().empty()) {
		return;
	}

	auto now = static_cast< uint64_t >(
		std::chrono::duration_cast< std::chrono::milliseconds >(
			std::chrono::system_clock::now().time_since_epoch())
			.count());

	ReadWatermark wm;
	wm.lastMessageId = msg.last_read_message_id();
	wm.timestamp = msg.has_timestamp() ? msg.timestamp() : now;

	m_readWatermarks[channelId][certHash] = wm;

	// Broadcast the update to all Fancy clients in the channel.
	MumbleProto::FancyReadReceiptDeliver deliver;
	deliver.set_channel_id(channelId);

	auto *rs = deliver.add_read_states();
	rs->set_cert_hash(certHash.toStdString());
	rs->set_name(uSource->qsName.toStdString());
	rs->set_last_read_message_id(wm.lastMessageId);
	rs->set_timestamp(wm.timestamp);

	for (User *p : c->qlUsers) {
		auto *su = static_cast< ServerUser * >(p);
		if (su->sState == ServerUser::Authenticated
			&& su->m_FancyVersion.has_value()
			&& su->m_FancyVersion.value() >= Version::fromComponents(0, 2, 0)) {
			sendMessage(su, deliver);
		}
	}
}

// -- Typing indicator (ID 131) --------------------------------------------

void Server::msgFancyTypingIndicator(ServerUser *uSource, MumbleProto::FancyTypingIndicator &msg) {
	MSG_SETUP(ServerUser::Authenticated);
	RATELIMIT(uSource);

	if (!msg.has_channel_id()) {
		return;
	}

	const auto channelId = msg.channel_id();
	Channel *c = qhChannels.value(channelId);
	if (!c) {
		return;
	}

	// Fill in the sender's session so recipients know who is typing.
	msg.set_actor(uSource->uiSession);

	// Broadcast to all Fancy clients in the channel except the sender.
	for (User *p : c->qlUsers) {
		auto *su = static_cast< ServerUser * >(p);
		if (su->uiSession == uSource->uiSession) {
			continue;
		}
		if (su->sState != ServerUser::Authenticated) {
			continue;
		}
		if (!su->m_FancyVersion.has_value()
			|| su->m_FancyVersion.value() < Version::fromComponents(0, 2, 0)) {
			continue;
		}
		sendMessage(su, msg);
	}
}

// ---------------------------------------------------------------------------
// Fancy Mumble: link preview request/response (IDs 132-133)
// ---------------------------------------------------------------------------

void Server::msgFancyLinkPreviewRequest(ServerUser *uSource, MumbleProto::FancyLinkPreviewRequest &msg) {
	MSG_SETUP(ServerUser::Authenticated);
	RATELIMIT(uSource);

	if (!m_linkPreviewManager)
		return;

	QStringList urls;
	urls.reserve(msg.urls_size());
	for (const auto &url : msg.urls()) {
		urls.append(QString::fromStdString(url));
	}

	QString requestId = QString::fromStdString(msg.request_id());

	m_linkPreviewManager->handlePreviewRequest(uSource->uiSession, urls, requestId);
}

void Server::msgFancyLinkPreviewResponse(ServerUser *, MumbleProto::FancyLinkPreviewResponse &) {
	// Server-to-client only; silently drop if received from a client.
}

// ---------------------------------------------------------------------------
// Fancy Mumble: watch-together (ID 134)
// ---------------------------------------------------------------------------

void Server::msgFancyWatchSync(ServerUser *uSource, MumbleProto::FancyWatchSync &msg) {
	MSG_SETUP(ServerUser::Authenticated);
	RATELIMIT(uSource);

	// Determine the channel to broadcast in.  For Start events the
	// channel is carried in the event payload; for all other event
	// kinds we relay within the sender's current channel.
	Channel *c = nullptr;
	if (msg.has_start() && msg.start().has_channel_id()) {
		c = qhChannels.value(msg.start().channel_id());
	} else {
		c = uSource->cChannel;
	}
	if (!c) {
		return;
	}

	// Fill in the sender's session so recipients know who emitted the event.
	msg.set_actor(uSource->uiSession);

	// Broadcast to all Fancy >= 0.2.15 clients in the channel except the sender.
	const auto minVersion = Version::fromComponents(0, 2, 15);
	for (User *p : c->qlUsers) {
		auto *su = static_cast< ServerUser * >(p);
		if (su->uiSession == uSource->uiSession) {
			continue;
		}
		if (su->sState != ServerUser::Authenticated) {
			continue;
		}
		if (!su->m_FancyVersion.has_value() || su->m_FancyVersion.value() < minVersion) {
			continue;
		}
		sendMessage(su, msg);
	}
}

// ---------------------------------------------------------------------------
// Fancy Mumble: screen-drawing overlay (ID 135)
// ---------------------------------------------------------------------------

void Server::msgFancyDrawStroke(ServerUser *uSource, MumbleProto::FancyDrawStroke &msg) {
	MSG_SETUP(ServerUser::Authenticated);

	// Drawing strokes are emitted as a high-frequency burst (multiple
	// packets per second while the user drags the pointer). The default
	// general-purpose leaky bucket (1 msg/s sustained, 5 burst) drops
	// most of them silently and produces broken strokes on receivers.
	// They are conceptually identical to plugin-data relay messages, so
	// we use the same higher-rate bucket here (4 msg/s, 15 burst by
	// default; tunable via `pluginmessagelimit` / `pluginmessageburst`).
	if (uSource->m_pluginMessageBucket.ratelimit(1)) {
		qWarning("Dropping draw stroke from \"%s\" (%d)", qUtf8Printable(uSource->qsName), uSource->uiSession);
		return;
	}

	if (!msg.has_channel_id()) {
		return;
	}

	const auto channelId = msg.channel_id();
	Channel *c = qhChannels.value(channelId);
	if (!c) {
		return;
	}

	// Stamp the sender's session so the receiver can attribute the stroke.
	msg.set_sender_session(uSource->uiSession);

	// Broadcast to every Fancy client in the channel except the sender.
	for (User *p : c->qlUsers) {
		auto *su = static_cast< ServerUser * >(p);
		if (su->uiSession == uSource->uiSession) {
			continue;
		}
		if (su->sState != ServerUser::Authenticated) {
			continue;
		}
		if (!su->m_FancyVersion.has_value()
			|| su->m_FancyVersion.value() < Version::fromComponents(0, 2, 0)) {
			continue;
		}
		sendMessage(su, msg);
	}
}


// ---------------------------------------------------------------------------
// Fancy Mumble: onboarding workflow (IDs 136-140) - introduced in 0.3.1
// ---------------------------------------------------------------------------

void Server::msgFancyOnboardingConfig(ServerUser *, MumbleProto::FancyOnboardingConfig &) {
	// Server -> Client only; ignore inbound.
}

void Server::msgFancyOnboardingConfigUpdate(ServerUser *uSource,
											MumbleProto::FancyOnboardingConfigUpdate &msg) {
	MSG_SETUP(ServerUser::Authenticated);
	RATELIMIT(uSource);

	Channel *root = qhChannels.value(0);
	if (!root) {
		return;
	}
	// Only users with Write permission on the root channel can edit
	// the onboarding flow (mirrors how server-wide config edits are
	// authorised elsewhere).
	if (!hasPermission(uSource, root, ChanACL::Write)) {
		PERM_DENIED(uSource, root, ChanACL::Write);
		return;
	}

	if (!msg.has_config()) {
		return;
	}

	MumbleProto::FancyOnboardingConfig config = msg.config();
	// Server-side metadata stamping; clients leave these empty.
	const uint64_t prevRevision = m_onboardingConfig.has_revision() ? m_onboardingConfig.revision() : 0;
	config.set_revision(prevRevision + 1);
	config.set_updated_by(uSource->qsHash.toStdString());
	config.set_updated_at(static_cast< uint64_t >(QDateTime::currentMSecsSinceEpoch()));

	m_onboardingConfig = config;

	// Broadcast to every Fancy 0.3.1+ client.
	const Version::full_t minVersion = Version::fromComponents(0, 3, 1);
	for (ServerUser *u : qhUsers) {
		if (u->sState != ServerUser::Authenticated) {
			continue;
		}
		if (!u->m_FancyVersion.has_value() || u->m_FancyVersion.value() < minVersion) {
			continue;
		}
		sendMessage(u, m_onboardingConfig);
	}

	log(uSource, QString("onboarding config updated (revision %1, %2 questions)")
					 .arg(m_onboardingConfig.revision())
					 .arg(m_onboardingConfig.questions_size()));
}

void Server::msgFancyOnboardingResponse(ServerUser *uSource,
										MumbleProto::FancyOnboardingResponse &msg) {
	MSG_SETUP(ServerUser::Authenticated);
	RATELIMIT(uSource);

	if (uSource->qsHash.isEmpty()) {
		// Without a TLS certificate hash we cannot key the response
		// stably across reconnects.
		return;
	}

	// Stamp the sender's identity & timestamp; clients leave these empty.
	msg.set_user_hash(uSource->qsHash.toStdString());
	msg.set_submitted_at(static_cast< uint64_t >(QDateTime::currentMSecsSinceEpoch()));

	m_onboardingResponses[uSource->qsHash] = msg;

	log(uSource, QString("onboarding response stored (%1 selections, revision %2)")
					 .arg(msg.selections_size())
					 .arg(msg.has_config_revision() ? msg.config_revision() : 0));
}

void Server::msgFancyOnboardingResponseQuery(ServerUser *uSource,
											 MumbleProto::FancyOnboardingResponseQuery &) {
	MSG_SETUP(ServerUser::Authenticated);
	RATELIMIT(uSource);

	MumbleProto::FancyOnboardingResponseDeliver reply;
	if (!uSource->qsHash.isEmpty() && m_onboardingResponses.contains(uSource->qsHash)) {
		*reply.mutable_response() = m_onboardingResponses.value(uSource->qsHash);
	}
	sendMessage(uSource, reply);
}

void Server::msgFancyOnboardingResponseDeliver(ServerUser *,
											   MumbleProto::FancyOnboardingResponseDeliver &) {
	// Server -> Client only; ignore inbound.
}


#undef RATELIMIT
#undef MSG_SETUP
#undef MSG_SETUP_NO_UNIDLE
#undef VICTIM_SETUP
#undef PERM_DENIED
#undef PERM_DENIED_TYPE
#undef PERM_DENIED_FALLBACK
#undef PERM_DENIED_HASH
