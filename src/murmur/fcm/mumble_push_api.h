// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

// Mumble Push Notification Module API
//
// This header defines the stable C ABI that any push notification provider
// (FCM, APNs, etc.) must implement as a shared library (.so / .dll).
// The Mumble server loads the library at startup via dlopen/LoadLibrary
// and resolves these symbols. If the library is absent or loading fails
// the server continues without push support.
//
// All strings are UTF-8, null-terminated. The caller owns all pointer
// arguments, the module must copy any data it needs to keep.

#ifndef MUMBLE_PUSH_API_H_
#define MUMBLE_PUSH_API_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#	ifdef MUMBLE_PUSH_BUILD_DLL
#		define MUMBLE_PUSH_EXPORT __declspec(dllexport)
#	else
#		define MUMBLE_PUSH_EXPORT __declspec(dllimport)
#	endif
#else
#	define MUMBLE_PUSH_EXPORT __attribute__((visibility("default")))
#endif

// Module API version. Bumped on breaking changes.
#define MUMBLE_PUSH_API_VERSION 1

// Return codes
#define MUMBLE_PUSH_OK            0
#define MUMBLE_PUSH_ERR_INIT     -1
#define MUMBLE_PUSH_ERR_SEND     -2
#define MUMBLE_PUSH_ERR_TOKEN    -3
#define MUMBLE_PUSH_ERR_SHUTDOWN -4

// Notification priority levels
typedef enum {
	MUMBLE_PUSH_PRIORITY_NORMAL = 0,
	MUMBLE_PUSH_PRIORITY_HIGH   = 1,
} MumblePushPriority;

// Notification categories (server decides which to send)
typedef enum {
	MUMBLE_PUSH_CAT_TEXT_MESSAGE = 0,
	MUMBLE_PUSH_CAT_MENTION     = 1,
	MUMBLE_PUSH_CAT_REACTION    = 2,
	MUMBLE_PUSH_CAT_CHANNEL     = 3,
} MumblePushCategory;

// Payload passed to mumble_push_send().
typedef struct {
	// Device token / registration ID obtained from the client.
	const char *device_token;

	// Notification title (e.g. channel or sender name). UTF-8.
	const char *title;

	// Notification body (e.g. message preview). UTF-8.
	const char *body;

	// Category of the notification.
	MumblePushCategory category;

	// Priority (normal or high).
	MumblePushPriority priority;

	// Server-assigned ID for the originating server (virtual server number).
	uint32_t server_id;

	// Channel ID where the event occurred.
	uint32_t channel_id;

	// Optional data payload: arbitrary key-value pairs encoded as
	// a JSON object string. May be NULL.
	const char *data_json;
} MumblePushNotification;

// ---------------------------------------------------------------------------
// Functions the module must export
// ---------------------------------------------------------------------------

// Initialise the module. Called once at server startup.
//   credentials_json : path to the FCM service-account JSON key file.
//   project_id       : Firebase project ID (from INI).
// Returns MUMBLE_PUSH_OK on success.
MUMBLE_PUSH_EXPORT int mumble_push_init(const char *credentials_json,
                                        const char *project_id);

// Returns the API version this module was compiled against.
MUMBLE_PUSH_EXPORT int mumble_push_api_version(void);

// Send a push notification. Non-blocking internally (the module should
// queue or use async I/O). Returns MUMBLE_PUSH_OK on success.
MUMBLE_PUSH_EXPORT int mumble_push_send(const MumblePushNotification *notification);

// Send the same notification to multiple device tokens at once.
//   tokens      : array of null-terminated device token strings.
//   token_count : number of elements in the tokens array.
// Returns the number of successfully queued notifications (>= 0),
// or a negative error code.
MUMBLE_PUSH_EXPORT int mumble_push_send_batch(const MumblePushNotification *notification,
                                              const char *const *tokens,
                                              size_t token_count);

// Shut down the module. Release resources, join worker threads.
MUMBLE_PUSH_EXPORT void mumble_push_shutdown(void);

// Return a human-readable description of the last error, or NULL.
MUMBLE_PUSH_EXPORT const char *mumble_push_last_error(void);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // MUMBLE_PUSH_API_H_
