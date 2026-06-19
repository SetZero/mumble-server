// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_CHANNEL_H_
#define MUMBLE_CHANNEL_H_

#include <QtCore/QHash>
#include <QtCore/QList>
#include <QtCore/QObject>
#include <QtCore/QReadWriteLock>
#include <QtCore/QSet>
#include <QtCore/QString>
#include <QtCore/QStringList>

#include <bitset>
#include <cstddef>
#include <cstdint>

#ifdef MUMBLE
#	include <atomic>
#	include "ChannelFilterMode.h"
#endif

class User;
class Group;
class ChanACL;

class ClientUser;

/// Boolean channel attributes, stored in a Channel as a fixed-width bit set so
/// new attributes can be added without growing the class. Indices are stable
/// (the bit position is part of the on-the-wire/on-disk meaning where relevant)
/// - always append new attributes, never reorder or reuse a removed slot.
enum class ChannelAttribute : std::size_t {
	/// Channel is temporary (auto-removed when the last user leaves).
	Temporary = 0,
	/// Channel is hidden (only users with SeeChannel are told it exists).
	Hidden = 1,
	/// Channel inherits its parent's ACLs (the default for a new channel).
	InheritACL = 2,
	/// Channel is detached: it has no parent (like the root), never appears in
	/// any channel tree, and is only ever sent to Fancy clients. Used for
	/// meeting rooms. A detached channel is implicitly hidden from the tree, but
	/// unlike Hidden it is not nested anywhere.
	Detached = 3,
};

class Channel : public QObject {
private:
	Q_OBJECT
	Q_DISABLE_COPY(Channel)
private:
	QSet< Channel * > qsUnseen;
	/// Boolean attributes (temporary, hidden, inherit-ACL, ...). 64 bits for now;
	/// widen the bitset if more than 64 attributes are ever needed.
	std::bitset< 64 > m_attributes;

public:
	unsigned int iId;
	int iPosition;
	Channel *cParent;
	QString qsName;
	QString qsDesc;
	QByteArray qbaDescHash;
	QList< Channel * > qlChannels;
	QList< User * > qlUsers;
	QHash< QString, Group * > qhGroups;
	QList< ChanACL * > qlACL;

#ifdef MUMBLE
	/// A flag indicating whether this channel has enter restrictions (ACL denying ENTER) in place
	std::atomic< bool > hasEnterRestrictions;
	/// A flag indicating whether the local user is currently able to enter this channel. In theory this should
	/// represent the correct access state (apart from the time it takes to synchronize ACL changes from the server
	/// to the client), but in the end, it's the server who decides whether the user can enter. This flag is only
	/// meant for UI purposes and should not be used influence actual behaviour.
	std::atomic< bool > localUserCanEnter;
#endif

	QSet< Channel * > qsPermLinks;
	QHash< Channel *, int > qhLinks;

	/// Maximum number of users allowed in the channel. If this
	/// value is zero, the maximum number of users allowed in the
	/// channel is given by the server's "usersperchannel"
	/// setting.
	unsigned int uiMaxUsers;

	/// Persistent chat protocol: 0=NONE, 1=FANCY_V1_POST_JOIN, 2=FANCY_V1_FULL_ARCHIVE, 3=SERVER_MANAGED.
	uint32_t uiPChatProtocol = 0;
	/// Maximum number of stored persistent chat messages (0=unlimited).
	uint32_t uiPChatMaxHistory = 0;
	/// Auto-delete persistent chat messages after N days (0=forever).
	uint32_t uiPChatRetentionDays = 0;
	/// TLS certificate hashes of persistent chat key custodians.
	QStringList qslPChatKeyCustodians;

	/// Channel expiry mode: 0 = none, 1 = absolute (createdAt + duration),
	/// 2 = sliding (lastActivity + duration). Drives the ChannelReaper.
	uint32_t uiExpiryMode = 0;
	/// Expiry lifetime / idle window in seconds (0 = none).
	uint32_t uiExpiryDuration = 0;
	/// Channel creation time (unix seconds); anchor for absolute expiry.
	uint32_t uiCreatedAt = 0;
	/// Last activity (unix seconds); runtime, drives sliding expiry. Seeded from
	/// createdAt on load and bumped on join/leave.
	int64_t iLastActivity = 0;

	bool isPersistentChat() const { return uiPChatProtocol > 0; }
	bool hasExpiry() const { return uiExpiryMode != 0 && uiExpiryDuration > 0; }

	// -- Boolean channel attributes (bit set; see ChannelAttribute) -------------

	/// Whether attribute @p a is set on this channel.
	bool hasAttribute(ChannelAttribute a) const {
		return m_attributes.test(static_cast< std::size_t >(a));
	}
	/// Set attribute @p a.
	void setAttribute(ChannelAttribute a) { m_attributes.set(static_cast< std::size_t >(a)); }
	/// Set or clear attribute @p a according to @p on (convenience for direct
	/// assignment from a bool).
	void setAttribute(ChannelAttribute a, bool on) {
		m_attributes.set(static_cast< std::size_t >(a), on);
	}
	/// Clear attribute @p a.
	void clearAttribute(ChannelAttribute a) { m_attributes.reset(static_cast< std::size_t >(a)); }

	Channel(unsigned int id, const QString &name, QObject *p = nullptr);
	~Channel();

#ifdef MUMBLE
	unsigned int uiPermissions;

	ChannelFilterMode m_filterMode;

	void setFilterMode(ChannelFilterMode filterMode);
	void clearFilterMode();
	bool isFiltered() const;

	static QHash< unsigned int, Channel * > c_qhChannels;
	static QReadWriteLock c_qrwlChannels;

	static Channel *get(unsigned int);
	static Channel *add(unsigned int, const QString &);
	static void remove(Channel *);

	void addClientUser(ClientUser *p);
#endif
	static bool lessThan(const Channel *, const Channel *);

	size_t getLevel() const;
	size_t getDepth() const;
	QString getPath() const;

	void addChannel(Channel *c);
	void removeChannel(Channel *c);
	void addUser(User *p);
	void removeUser(User *p);

	bool isLinked(Channel *c) const;
	void link(Channel *c);
	void unlink(Channel *c = nullptr);


	QSet< Channel * > allLinks();
	QSet< Channel * > allChildren();

	operator QString() const;

signals:
	/// Signal emitted whenever a user enters a channel.
	///
	/// @param newChannel A pointer to the Channel the user has just entered
	/// @param prevChannel A pointer to the Channel the user is coming from or nullptr if
	/// 	there is no such channel.
	/// @param user A pointer to the User that has triggered this signal
	void channelEntered(const Channel *newChannel, const Channel *prevChannel, const User *user);
	/// Signal emitted whenever a user leaves a channel.
	///
	/// @param channel A pointer to the Channel the user has left
	/// @param user A pointer to the User that has triggered this signal
	void channelExited(const Channel *channel, const User *user);
};

#endif
