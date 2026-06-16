// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "AclSubsystem.h"

#include "User.h"

AclSubsystem::AclSubsystem(std::unique_ptr< IChannelVisibilityPolicy > policy)
	: m_visibility(policy ? std::move(policy) : std::make_unique< AclChannelVisibilityPolicy >()) {
}

void AclSubsystem::clearUser(User &user) {
	QMutexLocker qml(&m_mutex);
	delete m_cache.take(&user);
}

void AclSubsystem::clearAll() {
	QMutexLocker qml(&m_mutex);
	for (ChanACL::ChanCache *h : m_cache) {
		delete h;
	}
	m_cache.clear();
}
