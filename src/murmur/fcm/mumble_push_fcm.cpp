// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

// FCM (Firebase Cloud Messaging) push notification module.
//
// Implements the mumble_push_api.h C ABI so the Mumble server can send
// push notifications via FCM HTTP v1 API.
//
// Build as a shared library: libmumble_push_fcm.so / mumble_push_fcm.dll.
// The server loads it at startup if configured; if absent, push is disabled.

#include "mumble_push_api.h"

#include <Poco/JSON/Object.h>
#include <Poco/JSON/Parser.h>
#include <Poco/JWT/Signer.h>
#include <Poco/JWT/Token.h>
#include <Poco/Net/HTTPSClientSession.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/Net/Context.h>
#include <Poco/StreamCopier.h>
#include <Poco/Timestamp.h>
#include <Poco/URI.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <functional>
#include <mutex>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

namespace {

struct FcmState {
	std::string projectId;
	std::string clientEmail;
	std::string privateKeyPem;

	std::string cachedAccessToken;
	std::chrono::steady_clock::time_point tokenExpiry;
	std::mutex tokenMutex;

	// Worker thread pool for async sends
	std::vector< std::thread > workers;
	std::queue< std::function< void() > > workQueue;
	std::mutex queueMutex;
	std::condition_variable queueCv;
	std::atomic< bool > shutdownFlag{ false };

	std::string lastError;
	std::mutex errorMutex;

	void setError(const std::string &err) {
		std::lock_guard< std::mutex > lock(errorMutex);
		lastError = err;
	}
};

FcmState *g_state = nullptr;

// Static error buffer for errors that occur before g_state is allocated
// (e.g. during init when the credentials file is missing).
std::string g_staticError;
std::mutex g_staticErrorMutex;

void setStaticError(const std::string &err) {
	std::lock_guard< std::mutex > lock(g_staticErrorMutex);
	g_staticError = err;
}

// Number of worker threads for async notification dispatch.
constexpr int WORKER_COUNT = 2;

// FCM access tokens are valid for 1 hour; refresh 5 minutes early.
constexpr auto TOKEN_REFRESH_MARGIN = std::chrono::minutes(5);
constexpr auto TOKEN_LIFETIME       = std::chrono::minutes(55);

// ---------------------------------------------------------------------------
// JWT-based OAuth2 access token (service account)
// ---------------------------------------------------------------------------

bool refreshAccessToken(FcmState &state) {
	try {
		auto now = Poco::Timestamp();
		auto iat = static_cast< int64_t >(now.epochTime());
		auto exp = iat + 3600; // 1 hour

		Poco::JWT::Token jwtToken;
		jwtToken.setType("JWT");
		jwtToken.setIssuer(state.clientEmail);
		jwtToken.setSubject(state.clientEmail);
		jwtToken.setAudience("https://oauth2.googleapis.com/token");
		jwtToken.setIssuedAt(Poco::Timestamp::fromEpochTime(iat));
		jwtToken.setExpiration(Poco::Timestamp::fromEpochTime(exp));
		jwtToken.payload().set("scope", "https://www.googleapis.com/auth/firebase.messaging");

		Poco::JWT::Signer signer(state.privateKeyPem);
		std::string signedJwt = signer.sign(jwtToken, Poco::JWT::Signer::ALGO_RS256);

		// Exchange JWT for access token
		Poco::URI uri("https://oauth2.googleapis.com/token");
		Poco::Net::Context::Ptr ctx = new Poco::Net::Context(
			Poco::Net::Context::TLS_CLIENT_USE, "", "", "",
			Poco::Net::Context::VERIFY_RELAXED, 9, true);
		Poco::Net::HTTPSClientSession session(uri.getHost(), uri.getPort(), ctx);
		session.setTimeout(Poco::Timespan(15, 0));

		std::string body = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=" + signedJwt;

		Poco::Net::HTTPRequest request(Poco::Net::HTTPRequest::HTTP_POST, uri.getPathAndQuery());
		request.setContentType("application/x-www-form-urlencoded");
		request.setContentLength(body.size());
		session.sendRequest(request) << body;

		Poco::Net::HTTPResponse response;
		std::istream &rs = session.receiveResponse(response);
		std::string responseBody;
		Poco::StreamCopier::copyToString(rs, responseBody);

		if (response.getStatus() != Poco::Net::HTTPResponse::HTTP_OK) {
			state.setError("OAuth2 token exchange failed: HTTP " + std::to_string(response.getStatus()));
			return false;
		}

		Poco::JSON::Parser parser;
		auto result  = parser.parse(responseBody).extract< Poco::JSON::Object::Ptr >();
		auto token   = result->getValue< std::string >("access_token");

		std::lock_guard< std::mutex > lock(state.tokenMutex);
		state.cachedAccessToken = token;
		state.tokenExpiry       = std::chrono::steady_clock::now() + TOKEN_LIFETIME;

		return true;

	} catch (const Poco::Exception &ex) {
		state.setError(std::string("Token refresh failed: ") + ex.displayText());
		return false;
	} catch (const std::exception &ex) {
		state.setError(std::string("Token refresh failed: ") + ex.what());
		return false;
	}
}

std::string getAccessToken(FcmState &state) {
	{
		std::lock_guard< std::mutex > lock(state.tokenMutex);
		if (!state.cachedAccessToken.empty()
		    && std::chrono::steady_clock::now() < state.tokenExpiry - TOKEN_REFRESH_MARGIN) {
			return state.cachedAccessToken;
		}
	}
	if (refreshAccessToken(state)) {
		std::lock_guard< std::mutex > lock(state.tokenMutex);
		return state.cachedAccessToken;
	}
	return {};
}

// ---------------------------------------------------------------------------
// FCM HTTP v1 send
// ---------------------------------------------------------------------------

int sendNotification(FcmState &state, const MumblePushNotification &notif) {
	std::string token = getAccessToken(state);
	if (token.empty()) {
		return MUMBLE_PUSH_ERR_SEND;
	}

	try {
		// Build FCM v1 payload
		Poco::JSON::Object::Ptr message  = new Poco::JSON::Object;
		Poco::JSON::Object::Ptr wrapper  = new Poco::JSON::Object;
		Poco::JSON::Object::Ptr notifObj = new Poco::JSON::Object;

		notifObj->set("title", std::string(notif.title ? notif.title : ""));
		notifObj->set("body", std::string(notif.body ? notif.body : ""));

		message->set("token", std::string(notif.device_token));
		message->set("notification", notifObj);

		// Data payload
		Poco::JSON::Object::Ptr dataObj = new Poco::JSON::Object;
		dataObj->set("server_id", std::to_string(notif.server_id));
		dataObj->set("channel_id", std::to_string(notif.channel_id));
		dataObj->set("category", std::to_string(static_cast< int >(notif.category)));

		if (notif.data_json) {
			dataObj->set("extra", std::string(notif.data_json));
		}
		message->set("data", dataObj);

		// Android-specific: high priority for mentions
		if (notif.priority == MUMBLE_PUSH_PRIORITY_HIGH) {
			Poco::JSON::Object::Ptr android = new Poco::JSON::Object;
			android->set("priority", "high");
			message->set("android", android);
		}

		wrapper->set("message", message);

		std::ostringstream bodyStream;
		wrapper->stringify(bodyStream);
		std::string bodyStr = bodyStream.str();

		// Send to FCM
		std::string path = "/v1/projects/" + state.projectId + "/messages:send";
		Poco::Net::Context::Ptr ctx = new Poco::Net::Context(
			Poco::Net::Context::TLS_CLIENT_USE, "", "", "",
			Poco::Net::Context::VERIFY_RELAXED, 9, true);
		Poco::Net::HTTPSClientSession session("fcm.googleapis.com", 443, ctx);
		session.setTimeout(Poco::Timespan(15, 0));

		Poco::Net::HTTPRequest request(Poco::Net::HTTPRequest::HTTP_POST, path);
		request.setContentType("application/json");
		request.setContentLength(bodyStr.size());
		request.set("Authorization", "Bearer " + token);
		session.sendRequest(request) << bodyStr;

		Poco::Net::HTTPResponse response;
		std::istream &rs = session.receiveResponse(response);
		std::string responseBody;
		Poco::StreamCopier::copyToString(rs, responseBody);

		if (response.getStatus() != Poco::Net::HTTPResponse::HTTP_OK) {
			state.setError("FCM send failed: HTTP " + std::to_string(response.getStatus()) + " " + responseBody);
			return MUMBLE_PUSH_ERR_SEND;
		}

		return MUMBLE_PUSH_OK;

	} catch (const Poco::Exception &ex) {
		state.setError(std::string("FCM send exception: ") + ex.displayText());
		return MUMBLE_PUSH_ERR_SEND;
	} catch (const std::exception &ex) {
		state.setError(std::string("FCM send exception: ") + ex.what());
		return MUMBLE_PUSH_ERR_SEND;
	}
}

// Worker thread function
void workerLoop(FcmState &state) {
	while (true) {
		std::function< void() > task;
		{
			std::unique_lock< std::mutex > lock(state.queueMutex);
			state.queueCv.wait(lock, [&] { return state.shutdownFlag.load() || !state.workQueue.empty(); });
			if (state.shutdownFlag.load() && state.workQueue.empty()) {
				return;
			}
			task = std::move(state.workQueue.front());
			state.workQueue.pop();
		}
		task();
	}
}

void enqueueWork(FcmState &state, std::function< void() > task) {
	{
		std::lock_guard< std::mutex > lock(state.queueMutex);
		state.workQueue.push(std::move(task));
	}
	state.queueCv.notify_one();
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Public API implementation
// ---------------------------------------------------------------------------

extern "C" {

MUMBLE_PUSH_EXPORT int mumble_push_api_version(void) {
	return MUMBLE_PUSH_API_VERSION;
}

MUMBLE_PUSH_EXPORT int mumble_push_init(const char *credentials_path, const char *project_id) {
	if (g_state) {
		return MUMBLE_PUSH_OK; // Already initialised
	}

	if (!credentials_path || !project_id) {
		setStaticError("mumble_push_init: credentials_path or project_id is NULL");
		return MUMBLE_PUSH_ERR_INIT;
	}

	// Read service account JSON
	std::ifstream file(credentials_path);
	if (!file.is_open()) {
		setStaticError(std::string("mumble_push_init: cannot open credentials file: ") + credentials_path);
		return MUMBLE_PUSH_ERR_INIT;
	}
	std::string jsonContent((std::istreambuf_iterator< char >(file)),
	                         std::istreambuf_iterator< char >());

	try {
		Poco::JSON::Parser parser;
		auto obj = parser.parse(jsonContent).extract< Poco::JSON::Object::Ptr >();

		auto state        = new FcmState();
		state->projectId  = std::string(project_id);

		if (obj->has("client_email")) {
			state->clientEmail = obj->getValue< std::string >("client_email");
		}
		if (obj->has("private_key")) {
			state->privateKeyPem = obj->getValue< std::string >("private_key");
		}

		if (state->clientEmail.empty() || state->privateKeyPem.empty()) {
			setStaticError("mumble_push_init: credentials JSON missing 'client_email' or 'private_key'");
			delete state;
			return MUMBLE_PUSH_ERR_INIT;
		}

		// Start worker threads
		state->shutdownFlag = false;
		for (int i = 0; i < WORKER_COUNT; ++i) {
			state->workers.emplace_back(workerLoop, std::ref(*state));
		}

		g_state = state;
		return MUMBLE_PUSH_OK;

	} catch (const Poco::Exception &ex) {
		setStaticError(std::string("mumble_push_init: JSON parse error: ") + ex.displayText());
		return MUMBLE_PUSH_ERR_INIT;
	} catch (const std::exception &ex) {
		setStaticError(std::string("mumble_push_init: JSON parse error: ") + ex.what());
		return MUMBLE_PUSH_ERR_INIT;
	}
}

MUMBLE_PUSH_EXPORT int mumble_push_send(const MumblePushNotification *notification) {
	if (!g_state || !notification || !notification->device_token) {
		return MUMBLE_PUSH_ERR_SEND;
	}

	// Copy notification data for async dispatch
	MumblePushNotification copy = *notification;
	std::string tokenCopy(notification->device_token);
	std::string titleCopy(notification->title ? notification->title : "");
	std::string bodyCopy(notification->body ? notification->body : "");
	std::string dataCopy(notification->data_json ? notification->data_json : "");

	enqueueWork(*g_state, [copy, tokenCopy, titleCopy, bodyCopy, dataCopy]() mutable {
		copy.device_token = tokenCopy.c_str();
		copy.title        = titleCopy.c_str();
		copy.body         = bodyCopy.c_str();
		copy.data_json    = dataCopy.empty() ? nullptr : dataCopy.c_str();
		sendNotification(*g_state, copy);
	});

	return MUMBLE_PUSH_OK;
}

MUMBLE_PUSH_EXPORT int mumble_push_send_batch(const MumblePushNotification *notification,
                                              const char *const *tokens,
                                              size_t token_count) {
	if (!g_state || !notification || !tokens) {
		return MUMBLE_PUSH_ERR_SEND;
	}

	int queued = 0;

	// Copy shared notification fields once
	std::string titleCopy(notification->title ? notification->title : "");
	std::string bodyCopy(notification->body ? notification->body : "");
	std::string dataCopy(notification->data_json ? notification->data_json : "");
	MumblePushNotification baseCopy = *notification;

	for (size_t i = 0; i < token_count; ++i) {
		if (!tokens[i]) continue;

		std::string tokenCopy(tokens[i]);

		enqueueWork(*g_state, [baseCopy, tokenCopy, titleCopy, bodyCopy, dataCopy]() mutable {
			baseCopy.device_token = tokenCopy.c_str();
			baseCopy.title        = titleCopy.c_str();
			baseCopy.body         = bodyCopy.c_str();
			baseCopy.data_json    = dataCopy.empty() ? nullptr : dataCopy.c_str();
			sendNotification(*g_state, baseCopy);
		});
		++queued;
	}

	return queued;
}

MUMBLE_PUSH_EXPORT void mumble_push_shutdown(void) {
	if (!g_state) return;

	g_state->shutdownFlag = true;
	g_state->queueCv.notify_all();

	for (auto &t : g_state->workers) {
		if (t.joinable()) {
			t.join();
		}
	}

	delete g_state;
	g_state = nullptr;
}

MUMBLE_PUSH_EXPORT const char *mumble_push_last_error(void) {
	if (g_state) {
		std::lock_guard< std::mutex > lock(g_state->errorMutex);
		if (!g_state->lastError.empty()) return g_state->lastError.c_str();
	}
	// Fall back to static error (set during init before g_state exists)
	std::lock_guard< std::mutex > lock(g_staticErrorMutex);
	if (!g_staticError.empty()) return g_staticError.c_str();
	return nullptr;
}

} // extern "C"
