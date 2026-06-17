// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_MURMUR_CHANNELVISIBILITY_H_
#define MUMBLE_MURMUR_CHANNELVISIBILITY_H_

#include "ACL.h"
#include "Channel.h"

class ServerUser;

/// Decides whether a user may *see* a channel - i.e. be told that the channel
/// exists in the channel tree, and see the users inside it. This is the single
/// source of truth for channel visibility; every broadcast/enumeration path
/// consults it. Kept behind an interface so the rule can be swapped or unit
/// tested in isolation (Dependency Inversion).
class IChannelVisibilityPolicy {
public:
	virtual ~IChannelVisibilityPolicy() = default;

	/// @param user The user the channel list is being tailored for.
	/// @param channel The channel whose visibility is in question.
	/// @param cache Optional ACL cache to reuse for permission lookups (may be null).
	/// @returns true if @p user is allowed to see @p channel.
	virtual bool canSee(ServerUser &user, Channel &channel, ChanACL::ACLCache *cache) const = 0;
};

/// Default policy: every channel is visible unless it is flagged hidden, in which
/// case the user must hold the SeeChannel permission on it. Non-hidden channels
/// are always visible, so existing servers behave exactly as before.
class AclChannelVisibilityPolicy : public IChannelVisibilityPolicy {
public:
	bool canSee(ServerUser &user, Channel &channel, ChanACL::ACLCache *cache) const override {
		if (!channel.hasAttribute(ChannelAttribute::Hidden)) {
			return true;
		}
		return ChanACL::hasPermission(&user, &channel, ChanACL::SeeChannel, cache);
	}
};

#endif // MUMBLE_MURMUR_CHANNELVISIBILITY_H_
