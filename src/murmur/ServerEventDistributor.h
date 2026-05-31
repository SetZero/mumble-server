// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_MURMUR_SERVEREVENTDISTRIBUTOR_H_
#define MUMBLE_MURMUR_SERVEREVENTDISTRIBUTOR_H_

#include <QtCore/QByteArray>
#include <QtCore/QMutex>
#include <QtCore/QString>

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

class Server;
class User;
class Channel;
struct TextMessage;

namespace MumbleProto {
class PluginMessage;
}

/// Unified inbound plugin payload. Folds the two distinct wire messages a
/// client can address to a server-side plugin (PluginDataTransmission and the
/// generic PluginMessage, wire ID 200) into a single event so distributors
/// have one hook to subscribe to.
struct PluginInbound {
	enum class Kind { DataTransmission, Message };

	Kind kind;
	uint32_t senderSession = 0;

	// Valid when kind == Kind::DataTransmission:
	QString dataId;
	QByteArray data;

	// Valid when kind == Kind::Message:
	QString senderName;
	const ::MumbleProto::PluginMessage *message = nullptr;
};

/// Uniform sink for per-virtual-server control-plane events.
///
/// Every handler is a no-op by default, so a distributor overrides only the
/// events it cares about ("not everything subscribes to everything"). Every
/// call carries the originating Server explicitly, which removes the previous
/// reliance on qobject_cast<Server*>(sender()).
///
/// Handlers are invoked synchronously on the originating Server's thread. The
/// User*/Channel*/TextMessage&/PluginInbound& arguments are valid only for the
/// duration of the call: a subscriber that needs another thread must snapshot
/// what it needs and hop itself (e.g. via ExecEvent/postEvent).
class EventSubscriber {
public:
	virtual ~EventSubscriber() = default;

	// The broadcast server events. onUserConnected/onUserDisconnected also
	// cover what used to be the plugin-host-specific client connect/disconnect
	// events (extract session/name/hash from the User).
	virtual void onUserConnected(Server &, const User *) {}
	virtual void onUserDisconnected(Server &, const User *) {}
	virtual void onUserStateChanged(Server &, const User *) {}
	virtual void onUserTextMessage(Server &, const User *, const TextMessage &) {}
	virtual void onChannelCreated(Server &, const Channel *) {}
	virtual void onChannelRemoved(Server &, const Channel *) {}
	virtual void onChannelStateChanged(Server &, const Channel *) {}
	virtual void onContextAction(Server &, const User *, const QString & /* action */, unsigned int /* session */,
								 int /* channel */) {}

	// Inbound traffic addressed to a server-side plugin (data + message unified).
	virtual void onPluginMessage(Server &, const PluginInbound &) {}
};

/// Uniform sink for meta/global lifecycle events.
class MetaEventSubscriber {
public:
	virtual ~MetaEventSubscriber() = default;

	virtual void onServerStarted(Server &) {}
	virtual void onServerStopped(Server &) {}
};

class ServerEventDistributor;

/// Move-only RAII handle returned by the builder. Unregisters (and destroys)
/// the builder-created subscriber when it goes out of scope.
class EventSubscription {
public:
	EventSubscription() = default;
	EventSubscription(ServerEventDistributor *owner, EventSubscriber *sub) : m_owner(owner), m_sub(sub) {}
	EventSubscription(const EventSubscription &) = delete;
	EventSubscription &operator=(const EventSubscription &) = delete;
	EventSubscription(EventSubscription &&other) noexcept : m_owner(other.m_owner), m_sub(other.m_sub) {
		other.m_owner = nullptr;
		other.m_sub   = nullptr;
	}
	EventSubscription &operator=(EventSubscription &&other) noexcept {
		if (this != &other) {
			reset();
			m_owner       = other.m_owner;
			m_sub         = other.m_sub;
			other.m_owner = nullptr;
			other.m_sub   = nullptr;
		}
		return *this;
	}
	~EventSubscription() { reset(); }

	void reset();

private:
	ServerEventDistributor *m_owner = nullptr;
	EventSubscriber *m_sub          = nullptr;
};

/// Per-virtual-server event registry and dispatcher (the Subject of the
/// Observer pattern). Owned by Server as a composition member so that Server
/// itself does not grow registry/dispatch responsibilities.
///
/// Two registration paths share a single storage and dispatch loop:
///  - Interface: implement EventSubscriber and registerSubscriber(this).
///  - Builder:   subscribe().onX(...).build() for lightweight lambda opt-in;
///               build() produces an owned adapter that *is* an EventSubscriber.
class ServerEventDistributor {
public:
	explicit ServerEventDistributor(Server &owner) : m_owner(owner) {}
	ServerEventDistributor(const ServerEventDistributor &) = delete;
	ServerEventDistributor &operator=(const ServerEventDistributor &) = delete;

	// --- Path A: interface ---
	void registerSubscriber(EventSubscriber *subscriber);
	void unregisterSubscriber(EventSubscriber *subscriber);

	// --- Path B: builder ---
	class Builder;
	Builder subscribe();

	// --- Dispatch entry points (called by the Server core) ---
	// Near-zero cost when nothing is registered: a single empty()-check branch.
	void userConnected(const User *u) { dispatch(&EventSubscriber::onUserConnected, u); }
	void userDisconnected(const User *u) { dispatch(&EventSubscriber::onUserDisconnected, u); }
	void userStateChanged(const User *u) { dispatch(&EventSubscriber::onUserStateChanged, u); }
	void userTextMessage(const User *u, const TextMessage &m) { dispatch(&EventSubscriber::onUserTextMessage, u, m); }
	void channelCreated(const Channel *c) { dispatch(&EventSubscriber::onChannelCreated, c); }
	void channelRemoved(const Channel *c) { dispatch(&EventSubscriber::onChannelRemoved, c); }
	void channelStateChanged(const Channel *c) { dispatch(&EventSubscriber::onChannelStateChanged, c); }
	void contextAction(const User *u, const QString &action, unsigned int session, int channel) {
		dispatch(&EventSubscriber::onContextAction, u, action, session, channel);
	}
	void pluginMessage(const PluginInbound &in) { dispatch(&EventSubscriber::onPluginMessage, in); }

private:
	/// Adopt ownership of a builder-created subscriber and register it.
	EventSubscriber *adopt(std::unique_ptr< EventSubscriber > subscriber);

	template< typename Method, typename... Args > void dispatch(Method method, Args &&... args) {
		// Dispatch runs on the Server's thread, while registration may happen on
		// another thread (e.g. Ice registers from the meta/main thread in
		// onServerStarted). Snapshot the subscriber list under the lock, then
		// invoke callbacks without holding it (so a callback may freely
		// (un)register, and a slow/throwing callback can't stall registration).
		std::vector< EventSubscriber * > snapshot;
		{
			QMutexLocker locker(&m_mutex);
			if (m_subscribers.empty()) {
				return;
			}
			snapshot = m_subscribers;
		}
		for (EventSubscriber *subscriber : snapshot) {
			try {
				(subscriber->*method)(m_owner, std::forward< Args >(args)...);
			} catch (...) {
				// A misbehaving distributor must not abort the others.
			}
		}
	}

	Server &m_owner;
	QMutex m_mutex;                                             ///< guards m_subscribers / m_owned
	std::vector< EventSubscriber * > m_subscribers;             ///< all active (external + owned)
	std::vector< std::unique_ptr< EventSubscriber > > m_owned;  ///< builder-created adapters
};

/// Fluent builder that stages a std::function per event and, on build(),
/// registers an owned adapter implementing EventSubscriber.
class ServerEventDistributor::Builder {
public:
	Builder &onUserConnected(std::function< void(Server &, const User *) > cb) {
		m_userConnected = std::move(cb);
		return *this;
	}
	Builder &onUserDisconnected(std::function< void(Server &, const User *) > cb) {
		m_userDisconnected = std::move(cb);
		return *this;
	}
	Builder &onUserStateChanged(std::function< void(Server &, const User *) > cb) {
		m_userStateChanged = std::move(cb);
		return *this;
	}
	Builder &onUserTextMessage(std::function< void(Server &, const User *, const TextMessage &) > cb) {
		m_userTextMessage = std::move(cb);
		return *this;
	}
	Builder &onChannelCreated(std::function< void(Server &, const Channel *) > cb) {
		m_channelCreated = std::move(cb);
		return *this;
	}
	Builder &onChannelRemoved(std::function< void(Server &, const Channel *) > cb) {
		m_channelRemoved = std::move(cb);
		return *this;
	}
	Builder &onChannelStateChanged(std::function< void(Server &, const Channel *) > cb) {
		m_channelStateChanged = std::move(cb);
		return *this;
	}
	Builder &onContextAction(std::function< void(Server &, const User *, const QString &, unsigned int, int) > cb) {
		m_contextAction = std::move(cb);
		return *this;
	}
	Builder &onPluginMessage(std::function< void(Server &, const PluginInbound &) > cb) {
		m_pluginMessage = std::move(cb);
		return *this;
	}

	EventSubscription build();

private:
	friend class ServerEventDistributor;
	explicit Builder(ServerEventDistributor &owner) : m_owner(owner) {}

	ServerEventDistributor &m_owner;
	std::function< void(Server &, const User *) > m_userConnected, m_userDisconnected, m_userStateChanged;
	std::function< void(Server &, const User *, const TextMessage &) > m_userTextMessage;
	std::function< void(Server &, const Channel *) > m_channelCreated, m_channelRemoved, m_channelStateChanged;
	std::function< void(Server &, const User *, const QString &, unsigned int, int) > m_contextAction;
	std::function< void(Server &, const PluginInbound &) > m_pluginMessage;
};

class MetaEventDistributor;

/// Move-only RAII handle for a meta-level subscription (builder path).
class MetaEventSubscription {
public:
	MetaEventSubscription() = default;
	MetaEventSubscription(MetaEventDistributor *owner, MetaEventSubscriber *sub) : m_owner(owner), m_sub(sub) {}
	MetaEventSubscription(const MetaEventSubscription &) = delete;
	MetaEventSubscription &operator=(const MetaEventSubscription &) = delete;
	MetaEventSubscription(MetaEventSubscription &&other) noexcept : m_owner(other.m_owner), m_sub(other.m_sub) {
		other.m_owner = nullptr;
		other.m_sub   = nullptr;
	}
	MetaEventSubscription &operator=(MetaEventSubscription &&other) noexcept {
		if (this != &other) {
			reset();
			m_owner       = other.m_owner;
			m_sub         = other.m_sub;
			other.m_owner = nullptr;
			other.m_sub   = nullptr;
		}
		return *this;
	}
	~MetaEventSubscription() { reset(); }

	void reset();

private:
	MetaEventDistributor *m_owner = nullptr;
	MetaEventSubscriber *m_sub    = nullptr;
};

/// Meta/global counterpart of ServerEventDistributor, owned by Meta.
class MetaEventDistributor {
public:
	MetaEventDistributor()                                       = default;
	MetaEventDistributor(const MetaEventDistributor &)            = delete;
	MetaEventDistributor &operator=(const MetaEventDistributor &) = delete;

	void registerSubscriber(MetaEventSubscriber *subscriber);
	void unregisterSubscriber(MetaEventSubscriber *subscriber);

	class Builder;
	Builder subscribe();

	void serverStarted(Server &s) { dispatch(&MetaEventSubscriber::onServerStarted, s); }
	void serverStopped(Server &s) { dispatch(&MetaEventSubscriber::onServerStopped, s); }

private:
	/// Adopt ownership of a builder-created subscriber and register it.
	MetaEventSubscriber *adopt(std::unique_ptr< MetaEventSubscriber > subscriber);

	template< typename Method > void dispatch(Method method, Server &s) {
		if (m_subscribers.empty()) {
			return;
		}
		for (MetaEventSubscriber *subscriber : m_subscribers) {
			try {
				(subscriber->*method)(s);
			} catch (...) {
				// A misbehaving distributor must not abort the others.
			}
		}
	}

	std::vector< MetaEventSubscriber * > m_subscribers;
	std::vector< std::unique_ptr< MetaEventSubscriber > > m_owned;
};

class MetaEventDistributor::Builder {
public:
	Builder &onServerStarted(std::function< void(Server &) > cb) {
		m_started = std::move(cb);
		return *this;
	}
	Builder &onServerStopped(std::function< void(Server &) > cb) {
		m_stopped = std::move(cb);
		return *this;
	}

	MetaEventSubscription build();

private:
	friend class MetaEventDistributor;
	explicit Builder(MetaEventDistributor &owner) : m_owner(owner) {}

	MetaEventDistributor &m_owner;
	std::function< void(Server &) > m_started, m_stopped;
};

#endif // MUMBLE_MURMUR_SERVEREVENTDISTRIBUTOR_H_
