// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "ServerEventDistributor.h"

#include <algorithm>

namespace {

/// Adapter that turns a set of staged std::function callbacks into an
/// EventSubscriber. Only the events whose closure was set do anything; the
/// rest fall through to the no-op base implementation.
class BuilderSubscriber : public EventSubscriber {
public:
	std::function< void(Server &, const User *) > userConnected, userDisconnected, userStateChanged;
	std::function< void(Server &, const User *, const TextMessage &) > userTextMessage;
	std::function< void(Server &, const Channel *) > channelCreated, channelRemoved, channelStateChanged;
	std::function< void(Server &, const User *, const QString &, unsigned int, int) > contextAction;
	std::function< void(Server &, const PluginInbound &) > pluginMessage;

	void onUserConnected(Server &s, const User *u) override {
		if (userConnected) {
			userConnected(s, u);
		}
	}
	void onUserDisconnected(Server &s, const User *u) override {
		if (userDisconnected) {
			userDisconnected(s, u);
		}
	}
	void onUserStateChanged(Server &s, const User *u) override {
		if (userStateChanged) {
			userStateChanged(s, u);
		}
	}
	void onUserTextMessage(Server &s, const User *u, const TextMessage &m) override {
		if (userTextMessage) {
			userTextMessage(s, u, m);
		}
	}
	void onChannelCreated(Server &s, const Channel *c) override {
		if (channelCreated) {
			channelCreated(s, c);
		}
	}
	void onChannelRemoved(Server &s, const Channel *c) override {
		if (channelRemoved) {
			channelRemoved(s, c);
		}
	}
	void onChannelStateChanged(Server &s, const Channel *c) override {
		if (channelStateChanged) {
			channelStateChanged(s, c);
		}
	}
	void onContextAction(Server &s, const User *u, const QString &action, unsigned int session, int channel) override {
		if (contextAction) {
			contextAction(s, u, action, session, channel);
		}
	}
	void onPluginMessage(Server &s, const PluginInbound &in) override {
		if (pluginMessage) {
			pluginMessage(s, in);
		}
	}
};

/// Meta-level counterpart of BuilderSubscriber.
class MetaBuilderSubscriber : public MetaEventSubscriber {
public:
	std::function< void(Server &) > started, stopped;

	void onServerStarted(Server &s) override {
		if (started) {
			started(s);
		}
	}
	void onServerStopped(Server &s) override {
		if (stopped) {
			stopped(s);
		}
	}
};

} // namespace

// ---------------------------------------------------------------------------
// ServerEventDistributor
// ---------------------------------------------------------------------------

void ServerEventDistributor::registerSubscriber(EventSubscriber *subscriber) {
	if (!subscriber) {
		return;
	}
	QMutexLocker locker(&m_mutex);
	if (std::find(m_subscribers.begin(), m_subscribers.end(), subscriber) != m_subscribers.end()) {
		return;
	}
	m_subscribers.push_back(subscriber);
}

void ServerEventDistributor::unregisterSubscriber(EventSubscriber *subscriber) {
	QMutexLocker locker(&m_mutex);
	m_subscribers.erase(std::remove(m_subscribers.begin(), m_subscribers.end(), subscriber), m_subscribers.end());
	m_owned.erase(std::remove_if(m_owned.begin(), m_owned.end(),
								 [subscriber](const std::unique_ptr< EventSubscriber > &owned) {
									 return owned.get() == subscriber;
								 }),
				  m_owned.end());
}

EventSubscriber *ServerEventDistributor::adopt(std::unique_ptr< EventSubscriber > subscriber) {
	QMutexLocker locker(&m_mutex);
	EventSubscriber *raw = subscriber.get();
	m_owned.push_back(std::move(subscriber));
	m_subscribers.push_back(raw);
	return raw;
}

ServerEventDistributor::Builder ServerEventDistributor::subscribe() {
	return Builder(*this);
}

EventSubscription ServerEventDistributor::Builder::build() {
	auto subscriber                 = std::make_unique< BuilderSubscriber >();
	subscriber->userConnected       = std::move(m_userConnected);
	subscriber->userDisconnected    = std::move(m_userDisconnected);
	subscriber->userStateChanged    = std::move(m_userStateChanged);
	subscriber->userTextMessage     = std::move(m_userTextMessage);
	subscriber->channelCreated      = std::move(m_channelCreated);
	subscriber->channelRemoved      = std::move(m_channelRemoved);
	subscriber->channelStateChanged = std::move(m_channelStateChanged);
	subscriber->contextAction       = std::move(m_contextAction);
	subscriber->pluginMessage       = std::move(m_pluginMessage);

	EventSubscriber *raw = m_owner.adopt(std::move(subscriber));
	return EventSubscription(&m_owner, raw);
}

void EventSubscription::reset() {
	if (m_owner && m_sub) {
		m_owner->unregisterSubscriber(m_sub);
	}
	m_owner = nullptr;
	m_sub   = nullptr;
}

// ---------------------------------------------------------------------------
// MetaEventDistributor
// ---------------------------------------------------------------------------

void MetaEventDistributor::registerSubscriber(MetaEventSubscriber *subscriber) {
	if (!subscriber) {
		return;
	}
	if (std::find(m_subscribers.begin(), m_subscribers.end(), subscriber) != m_subscribers.end()) {
		return;
	}
	m_subscribers.push_back(subscriber);
}

void MetaEventDistributor::unregisterSubscriber(MetaEventSubscriber *subscriber) {
	m_subscribers.erase(std::remove(m_subscribers.begin(), m_subscribers.end(), subscriber), m_subscribers.end());
	m_owned.erase(std::remove_if(m_owned.begin(), m_owned.end(),
								 [subscriber](const std::unique_ptr< MetaEventSubscriber > &owned) {
									 return owned.get() == subscriber;
								 }),
				  m_owned.end());
}

MetaEventSubscriber *MetaEventDistributor::adopt(std::unique_ptr< MetaEventSubscriber > subscriber) {
	MetaEventSubscriber *raw = subscriber.get();
	m_owned.push_back(std::move(subscriber));
	registerSubscriber(raw);
	return raw;
}

MetaEventDistributor::Builder MetaEventDistributor::subscribe() {
	return Builder(*this);
}

MetaEventSubscription MetaEventDistributor::Builder::build() {
	auto subscriber     = std::make_unique< MetaBuilderSubscriber >();
	subscriber->started = std::move(m_started);
	subscriber->stopped = std::move(m_stopped);

	MetaEventSubscriber *raw = m_owner.adopt(std::move(subscriber));
	return MetaEventSubscription(&m_owner, raw);
}

void MetaEventSubscription::reset() {
	if (m_owner && m_sub) {
		m_owner->unregisterSubscriber(m_sub);
	}
	m_owner = nullptr;
	m_sub   = nullptr;
}
