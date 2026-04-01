// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_MURMUR_PUSH_PUSHNOTIFICATIONDISPATCHER_H_
#define MUMBLE_MURMUR_PUSH_PUSHNOTIFICATIONDISPATCHER_H_

#include "fcm/mumble_push_api.h"

#include <QString>
#include <QLibrary>

#include <functional>
#include <memory>
#include <string>

namespace push {

/// Configuration read from the server INI file.
struct PushConfig {
	/// Master switch: if false nothing is loaded or sent.
	bool enabled = false;

	/// Filesystem path to the push module shared library
	/// (e.g. "/usr/lib/mumble/libmumble_push_fcm.so").
	/// When empty, the server attempts to find the library
	/// next to the server binary.
	QString modulePath;

	/// Path to the provider credentials file (e.g. FCM service-account JSON).
	QString credentialsPath;

	/// Provider project identifier (e.g. Firebase project ID).
	QString projectId;

	/// FCM topic prefix. Notifications are sent to topic
	/// "<topicPrefix>_server<N>_channel<C>" unless empty.
	/// When set, no per-device tokens are needed.
	QString topicPrefix;

	/// Send notifications for text messages.
	bool notifyTextMessage = true;

	/// Send notifications for reactions.
	bool notifyReaction = false;

	/// Send notifications for user join/leave.
	bool notifyUserJoin = false;
};

/// Thin wrapper around the dynamically-loaded push module.
/// If the module is not available the dispatcher silently no-ops.
class PushNotificationDispatcher {
public:
	PushNotificationDispatcher();
	~PushNotificationDispatcher();

	PushNotificationDispatcher(const PushNotificationDispatcher &)            = delete;
	PushNotificationDispatcher &operator=(const PushNotificationDispatcher &) = delete;

	/// Try to load the push module at the given path and initialise it
	/// with the provided credentials. Returns true on success.
	bool init(const PushConfig &config);

	/// Whether the module was loaded and initialised successfully.
	bool isAvailable() const;

	/// Send a notification to a specific FCM topic.
	/// Topic string should be the full topic name (e.g. "mumble_server1_channel5").
	void notifyTopic(const std::string &topic, const std::string &title,
	                 const std::string &body, MumblePushCategory category,
	                 MumblePushPriority priority, uint32_t serverId,
	                 uint32_t channelId, const std::string &dataJson = {});

	/// Convenience: notify the default topic for a given server + channel.
	void notifyChannel(uint32_t serverId, uint32_t channelId,
	                   const std::string &title, const std::string &body,
	                   MumblePushCategory category,
	                   MumblePushPriority priority = MUMBLE_PUSH_PRIORITY_NORMAL,
	                   const std::string &dataJson = {});

	/// Shut down the module and unload the library.
	void shutdown();

	/// Return the last error from the module, or empty string.
	std::string lastError() const;

private:
	struct ModuleSymbols {
		std::function< int(const char *, const char *) > init;
		std::function< int() > apiVersion;
		std::function< int(const MumblePushNotification *) > send;
		std::function< int(const MumblePushNotification *, const char *const *, size_t) > sendBatch;
		std::function< void() > shutdown;
		std::function< const char *() > lastError;
	};

	bool resolveSymbols();

	std::unique_ptr< QLibrary > m_lib;
	ModuleSymbols m_sym{};
	bool m_initialised = false;
	PushConfig m_config;
};

} // namespace push

#endif // MUMBLE_MURMUR_PUSH_PUSHNOTIFICATIONDISPATCHER_H_
