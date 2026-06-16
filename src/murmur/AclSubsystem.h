// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_MURMUR_ACLSUBSYSTEM_H_
#define MUMBLE_MURMUR_ACLSUBSYSTEM_H_

#include "ACL.h"
#include "ChannelVisibility.h"

#include <QtCore/QMutex>

#include <concepts>
#include <memory>

class User;

/// A callable that answers a permission/visibility question when given locked
/// access to the ACL memo cache and the channel-visibility policy. Used to
/// constrain AclSubsystem::evaluate so only such queries can run under the lock.
template< typename Fn >
concept AclQuery = std::invocable< Fn, ChanACL::ACLCache &, IChannelVisibilityPolicy & >;

/// Synchronised owner of the access-control *state* that used to live as public
/// members of the Server "god" class: the per-(user, channel) permission memo
/// cache, the mutex serialising it, and the channel-visibility policy.
///
/// It deliberately does NOT answer "can this user do X" - that question belongs
/// to ServerUser (`user.hasPermission(c)`, `user.canSee(c)`). This class only
/// lends its cache + policy, under lock, to whoever evaluates: see evaluate().
/// That keeps the permission *meaning* on the user while the shared, lockable
/// *storage* has a single owner (no public cache, no ServerUser `friend`).
///
/// Threading: evaluate() and the clear* methods lock #m_mutex internally, so a
/// caller must NOT already hold mutex() when calling them. mutex() is exposed
/// only to serialise edits to ACL *inputs* (a channel's ACL list, a user's
/// access tokens) against concurrent evaluation; no evaluation happens inside
/// those critical sections, so there is no re-entrant locking.
class AclSubsystem {
public:
	/// @param policy Channel-visibility policy to use; defaults to the standard
	///        ACL-based policy when none is injected (kept for testability/DIP).
	explicit AclSubsystem(std::unique_ptr< IChannelVisibilityPolicy > policy = nullptr);

	/// Run @p query under the ACL lock with access to the memo cache and the
	/// visibility policy, returning its result. This is the seam ServerUser uses
	/// to evaluate a permission/visibility question: the question itself is posed
	/// by ServerUser; this class only provides synchronised access to the state
	/// it owns.
	auto evaluate(AclQuery auto &&query) {
		QMutexLocker qml(&m_mutex);
		return query(m_cache, *m_visibility);
	}

	/// Drop @p user's memoised permissions (after their ACL inputs changed).
	void clearUser(User &user);
	/// Drop the entire memo cache (after a global ACL change).
	void clearAll();

	/// The lock guarding ACL evaluation. Acquire it only to serialise edits to
	/// ACL *inputs* (channel ACL lists, access tokens) against evaluation; never
	/// call evaluate()/clear*() while holding it.
	QMutex &mutex() { return m_mutex; }

private:
	QMutex m_mutex;
	ChanACL::ACLCache m_cache;
	std::unique_ptr< IChannelVisibilityPolicy > m_visibility;
};

#endif // MUMBLE_MURMUR_ACLSUBSYSTEM_H_
