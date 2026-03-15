// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_MURMUR_PCHAT_IRATELIMITER_H_
#define MUMBLE_MURMUR_PCHAT_IRATELIMITER_H_

#include <cstdint>
#include <string>

namespace pchat {

/// Abstract rate limiter interface for persistent chat operations.
class IRateLimiter {
public:
	virtual ~IRateLimiter() = default;

	/// Check if an operation should be rate-limited.
	/// @param key       Identifier (e.g. session ID or cert hash).
	/// @param operation Operation name (e.g. "fetch", "msg", "key-announce").
	/// @return true if the operation is allowed, false if rate-limited.
	virtual bool allow(const std::string &key, const std::string &operation) = 0;

	/// Reset rate limit state for a key (e.g. on disconnect).
	virtual void reset(const std::string &key) = 0;
};

} // namespace pchat

#endif // MUMBLE_MURMUR_PCHAT_IRATELIMITER_H_
