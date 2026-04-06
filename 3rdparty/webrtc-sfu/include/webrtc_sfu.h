/* Copyright The Mumble Developers. All rights reserved.
 * Use of this source code is governed by a BSD-style license
 * that can be found in the LICENSE file at the root of the
 * Mumble source tree or at <https://www.mumble.info/LICENSE>.
 *
 * C header for the webrtc-sfu Rust library.
 * This file mirrors the types and functions exported by ffi.rs.
 */

#ifndef MUMBLE_WEBRTC_SFU_H_
#define MUMBLE_WEBRTC_SFU_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle to the SFU runtime (Rust-side SfuHandle). */
typedef struct SfuHandle SfuHandle;

/* Configuration for sfu_init(). */
typedef struct SfuFfiConfig {
	uint16_t udp_port;       /* UDP port for WebRTC media (0 = OS-assigned). */
	const char *public_ip;   /* Public IP as C string, e.g. "203.0.113.1". */
} SfuFfiConfig;

/* Event types returned by sfu_poll_event(). */
typedef enum SfuFfiEventType {
	SFU_EVENT_SDP_ANSWER    = 0,
	SFU_EVENT_SESSION_ENDED = 1,
} SfuFfiEventType;

/* Event struct returned by sfu_poll_event(). Free with sfu_free_event(). */
typedef struct SfuFfiEvent {
	SfuFfiEventType event_type;
	uint32_t session_id;     /* Target session (SDP answer) or broadcaster (session ended). */
	char *payload;           /* Null-terminated payload, or NULL. */
} SfuFfiEvent;

/* Initialise the SFU runtime. Returns NULL on failure. */
SfuHandle *sfu_init(const SfuFfiConfig *config);

/* Create a new broadcast session for the given broadcaster. */
void sfu_create_session(SfuHandle *handle, uint32_t broadcaster_session);

/* Submit a broadcaster's SDP offer. Answer arrives via sfu_poll_event(). */
void sfu_broadcaster_offer(SfuHandle *handle, uint32_t broadcaster_session, const char *sdp);

/* Submit a viewer's SDP offer. Answer arrives via sfu_poll_event(). */
void sfu_viewer_offer(SfuHandle *handle, uint32_t broadcaster_session,
                      uint32_t viewer_session, const char *sdp);

/* Forward an ICE candidate from a client. */
void sfu_add_ice_candidate(SfuHandle *handle, uint32_t broadcaster_session,
                           uint32_t client_session, const char *candidate_json);

/* Poll for the next event. Returns NULL when the queue is empty.
 * The caller must free the returned event with sfu_free_event(). */
SfuFfiEvent *sfu_poll_event(SfuHandle *handle);

/* Free an event returned by sfu_poll_event(). Accepts NULL safely. */
void sfu_free_event(SfuFfiEvent *event);

/* Destroy a broadcast session, closing all WebRTC connections. */
void sfu_destroy_session(SfuHandle *handle, uint32_t broadcaster_session);

/* Shut down the SFU runtime and free the handle. The pointer is invalid after. */
void sfu_shutdown(SfuHandle *handle);

#ifdef __cplusplus
}
#endif

#endif /* MUMBLE_WEBRTC_SFU_H_ */
