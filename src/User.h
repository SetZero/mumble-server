// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_USER_H_
#define MUMBLE_USER_H_

#include <QtCore/QByteArray>
#include <QtCore/QDateTime>
#include <QtCore/QList>
#include <QtCore/QString>

#include <cstdint>
#include <optional>
#include <vector>

class Channel;

class User {
private:
	Q_DISABLE_COPY(User)

public:
	unsigned int uiSession;
	int iId;
	QString qsName;
	QString qsComment;
	QByteArray qbaCommentHash;
	QString qsHash;
	bool bMute, bDeaf, bSuppress;
	bool bSelfMute, bSelfDeaf;
	bool bPrioritySpeaker;
	bool bRecording;
	Channel *cChannel;
	QByteArray qbaTexture;
	QByteArray qbaTextureHash;

	User();
	virtual ~User(){};

	static bool lessThan(const User *, const User *);
};

// for last seen
struct UserInfo {
	int user_id;
	QString name;
	std::optional< int > last_channel;
	QDateTime last_active;
	std::vector< std::uint8_t > texture;
	// SHA-1 of the comment when len >= 128; full UTF-8 bytes when len < 128.
	// Empty means no comment.
	QByteArray comment_hash;
	// Full comment text, populated only in blob responses.
	QString comment;

	UserInfo() : user_id(-1) {}
	UserInfo(int id, QString uname) : user_id(id), name(uname) {}
};

#endif
