// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "TokenBucketRateLimiter.h"

namespace pchat {

void TokenBucketRateLimiter::defineLimit(const std::string &operation, uint32_t maxTokens, double refillPerSecond) {
	std::lock_guard< std::mutex > lock(m_mutex);
	m_configs[operation] = { maxTokens, refillPerSecond };
}

bool TokenBucketRateLimiter::allow(const std::string &key, const std::string &operation) {
	std::lock_guard< std::mutex > lock(m_mutex);

	auto configIt = m_configs.find(operation);
	if (configIt == m_configs.end()) {
		// No limit defined for this operation - allow
		return true;
	}

	const auto &cfg = configIt->second;
	auto bk         = bucketKey(key, operation);
	auto now        = std::chrono::steady_clock::now();

	auto it = m_buckets.find(bk);
	if (it == m_buckets.end()) {
		// First request - create bucket with maxTokens - 1
		m_buckets[bk] = { static_cast< double >(cfg.maxTokens) - 1.0, now };
		return true;
	}

	auto &bucket   = it->second;
	double elapsed = std::chrono::duration< double >(now - bucket.lastRefill).count();
	bucket.tokens  = std::min(static_cast< double >(cfg.maxTokens), bucket.tokens + elapsed * cfg.refillPerSecond);
	bucket.lastRefill = now;

	if (bucket.tokens >= 1.0) {
		bucket.tokens -= 1.0;
		return true;
	}

	return false;
}

void TokenBucketRateLimiter::reset(const std::string &key) {
	std::lock_guard< std::mutex > lock(m_mutex);
	// Remove all buckets that start with this key
	for (auto it = m_buckets.begin(); it != m_buckets.end();) {
		if (it->first.find(key + ":") == 0) {
			it = m_buckets.erase(it);
		} else {
			++it;
		}
	}
}

std::string TokenBucketRateLimiter::bucketKey(const std::string &key, const std::string &operation) const {
	return key + ":" + operation;
}

} // namespace pchat
