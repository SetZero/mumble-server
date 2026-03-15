// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_SERVER_DATABASE_PCHATPENDINGKEYREQUESTS_TABLE_H_
#define MUMBLE_SERVER_DATABASE_PCHATPENDINGKEYREQUESTS_TABLE_H_

#include "database/Backend.h"
#include "database/Table.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace soci {
class session;
}

namespace mumble {
namespace server {
	namespace db {

		class ServerTable;

		struct PChatPendingKeyRequest {
			unsigned int serverID = 0;
			std::string requestId;
			unsigned int channelId = 0;
			std::string mode; // "POST_JOIN" or "FULL_ARCHIVE"
			std::string requesterHash;
			std::string requesterPublic; // X25519 public key (32 bytes)
			int relayCap    = 7;
			int relaysSent  = 0;
			long long createdAt    = 0;
			long long fulfilledAt  = 0; // 0 means NULL / not fulfilled
			std::string fulfilledBy;
		};

		class PChatPendingKeyRequestsTable : public ::mumble::db::Table {
		public:
			static constexpr const char *NAME = "pchat_pending_key_requests";

			struct column {
				column()                                         = delete;
				static constexpr const char *server_id           = "server_id";
				static constexpr const char *request_id          = "request_id";
				static constexpr const char *channel_id          = "channel_id";
				static constexpr const char *mode                = "mode";
				static constexpr const char *requester_hash      = "requester_hash";
				static constexpr const char *requester_public    = "requester_public";
				static constexpr const char *relay_cap           = "relay_cap";
				static constexpr const char *relays_sent         = "relays_sent";
				static constexpr const char *created_at          = "created_at";
				static constexpr const char *fulfilled_at        = "fulfilled_at";
				static constexpr const char *fulfilled_by        = "fulfilled_by";
			};

			PChatPendingKeyRequestsTable(soci::session &sql, ::mumble::db::Backend backend,
										 const ServerTable &serverTable);
			~PChatPendingKeyRequestsTable() = default;

			bool createRequest(const PChatPendingKeyRequest &request);

			/// Record a relay response. Returns true if relay was accepted, false if cap reached or duplicate sender.
			bool recordRelay(unsigned int serverID, const std::string &requestId, const std::string &senderHash);

			bool isRequestFulfilled(unsigned int serverID, const std::string &requestId);

			std::vector< PChatPendingKeyRequest > getPendingRequests(unsigned int serverID,
																	 unsigned int channelId);

			unsigned int countForChannel(unsigned int serverID, unsigned int channelId);

			unsigned int countForUser(unsigned int serverID, const std::string &requesterHash);

			/// FIFO eviction: evict the oldest pending request from the requester with the most slots.
			void evictOldest(unsigned int serverID, unsigned int channelId);

			unsigned int cleanupExpired(unsigned int serverID, int maxAgeDays);

			unsigned int cleanupFulfilled(unsigned int serverID, int maxAgeHours);

			void migrate(unsigned int fromSchemaVersion, unsigned int toSchemaVersion) override;
		};

	} // namespace db
} // namespace server
} // namespace mumble

#endif // MUMBLE_SERVER_DATABASE_PCHATPENDINGKEYREQUESTS_TABLE_H_
