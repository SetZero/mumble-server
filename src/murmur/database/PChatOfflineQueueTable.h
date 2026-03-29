// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_SERVER_DATABASE_PCHATOFFLINEQUEUETABLE_H_
#define MUMBLE_SERVER_DATABASE_PCHATOFFLINEQUEUETABLE_H_

#include "database/Backend.h"
#include "database/Table.h"

#include <cstdint>
#include <string>
#include <vector>

namespace soci {
class session;
}

namespace mumble {
namespace server {
	namespace db {

		class ServerTable;

		struct PChatOfflineQueueEntry {
			unsigned int serverID  = 0;
			std::string certHash;
			unsigned int channelId = 0;
			std::string messageId;
			std::string senderHash;
			long long timestamp    = 0;
			std::string envelope;
			long long createdAt    = 0;
		};

		class PChatOfflineQueueTable : public ::mumble::db::Table {
		public:
			static constexpr const char *NAME = "pchat_offline_queue";

			struct column {
				column()                                   = delete;
				static constexpr const char *server_id     = "server_id";
				static constexpr const char *cert_hash     = "cert_hash";
				static constexpr const char *channel_id    = "channel_id";
				static constexpr const char *message_id    = "message_id";
				static constexpr const char *sender_hash   = "sender_hash";
				static constexpr const char *timestamp     = "timestamp";
				static constexpr const char *envelope      = "envelope";
				static constexpr const char *created_at    = "created_at";
			};

			PChatOfflineQueueTable(soci::session &sql, ::mumble::db::Backend backend,
								   const ServerTable &serverTable);
			~PChatOfflineQueueTable() = default;

			/// Enqueue a message for an offline recipient.
			void enqueue(const PChatOfflineQueueEntry &entry);

			/// Fetch all queued messages for a (server, cert_hash, channel) ordered by timestamp ASC.
			std::vector< PChatOfflineQueueEntry > fetchQueue(unsigned int serverID, const std::string &certHash,
															 unsigned int channelId);

			/// Delete specific messages by their IDs for a recipient.
			void deleteByIds(unsigned int serverID, const std::string &certHash,
							 unsigned int channelId, const std::vector< std::string > &messageIds);

			/// Delete all entries older than the given cutoff timestamp.
			void deleteExpired(unsigned int serverID, long long cutoffMs);

			/// Clear all queue entries for a channel (e.g. channel removed).
			void clearChannel(unsigned int serverID, unsigned int channelId);

			/// Clear all queue entries for a user (e.g. user permanently banned).
			void clearUser(unsigned int serverID, const std::string &certHash);

			/// Enforce a capacity limit per (cert_hash, channel) by deleting oldest entries.
			void enforceCapacity(unsigned int serverID, const std::string &certHash,
								 unsigned int channelId, unsigned int maxCapacity);

			/// Count queued entries for a (cert_hash, channel).
			unsigned int countQueue(unsigned int serverID, const std::string &certHash,
									unsigned int channelId);

			void migrate(unsigned int fromSchemaVersion, unsigned int toSchemaVersion) override;
		};

	} // namespace db
} // namespace server
} // namespace mumble

#endif // MUMBLE_SERVER_DATABASE_PCHATOFFLINEQUEUETABLE_H_
