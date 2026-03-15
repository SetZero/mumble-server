// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_MURMUR_PCHAT_TOKENBUCKETRATELIMITER_H_
#define MUMBLE_MURMUR_PCHAT_TOKENBUCKETRATELIMITER_H_

#include "IRateLimiter.h"

#include <chrono>
#include <mutex>
#include <unordered_map>

namespace pchat {

/// Simple token-bucket rate limiter implementation.
class TokenBucketRateLimiter : public IRateLimiter {
public:
	/// Define a rate limit for a named operation.
	/// @param operation  Operation name (e.g. "fetch", "msg").
	/// @param maxTokens  Maximum burst size.
	/// @param refillPerSecond  Tokens refilled per second.
	void defineLimit(const std::string &operation, uint32_t maxTokens, double refillPerSecond);

	bool allow(const std::string &key, const std::string &operation) override;
	void reset(const std::string &key) override;

private:
	struct Bucket {
		double tokens;
		std::chrono::steady_clock::time_point lastRefill;
	};

	struct OperationConfig {
		uint32_t maxTokens      = 10;
		double refillPerSecond   = 1.0;
	};

	std::mutex m_mutex;
	std::unordered_map< std::string, OperationConfig > m_configs;
	// key: "operation:session_key"
	std::unordered_map< std::string, Bucket > m_buckets;

	std::string bucketKey(const std::string &key, const std::string &operation) const;
};

} // namespace pchat

#endif // MUMBLE_MURMUR_PCHAT_TOKENBUCKETRATELIMITER_H_
