// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_SERVER_DATABASE_PCHATMESSAGETABLE_H_
#define MUMBLE_SERVER_DATABASE_PCHATMESSAGETABLE_H_

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

		struct PChatStoredMessage {
			unsigned int serverID  = 0;
			std::string messageId;
			unsigned int channelId = 0;
			long long timestamp    = 0;
			std::string senderHash;
			std::string mode; // "POST_JOIN" or "FULL_ARCHIVE"
			std::string payload;  // opaque bytes stored as blob
			int payloadSize       = 0;
			std::string supersededBy;
			std::string replacesId;
			long long createdAt   = 0;
		};

		struct PChatFetchResult {
			std::vector< PChatStoredMessage > messages;
			bool hasMore         = false;
			unsigned int totalStored = 0;
		};

		class PChatMessageTable : public ::mumble::db::Table {
		public:
			static constexpr const char *NAME = "pchat_messages";

			struct column {
				column()                                    = delete;
				static constexpr const char *server_id      = "server_id";
				static constexpr const char *message_id     = "message_id";
				static constexpr const char *channel_id     = "channel_id";
				static constexpr const char *timestamp      = "timestamp";
				static constexpr const char *sender_hash    = "sender_hash";
				static constexpr const char *mode           = "mode";
				static constexpr const char *payload        = "payload";
				static constexpr const char *payload_size   = "payload_size";
				static constexpr const char *superseded_by  = "superseded_by";
				static constexpr const char *replaces_id    = "replaces_id";
				static constexpr const char *created_at     = "created_at";
			};

			PChatMessageTable(soci::session &sql, ::mumble::db::Backend backend, const ServerTable &serverTable);
			~PChatMessageTable() = default;

			bool storeMessage(const PChatStoredMessage &msg);

			PChatFetchResult fetchMessages(unsigned int serverID, unsigned int channelId,
										   const std::string &requesterHash,
										   const std::string &beforeId, unsigned int limit,
										   long long joinedAtTimestamp);

			bool messageExists(unsigned int serverID, unsigned int channelId, const std::string &senderHash,
							   const std::string &messageId);

			bool markSuperseded(unsigned int serverID, unsigned int channelId, const std::string &senderHash,
								const std::string &originalId, const std::string &newId);

			unsigned int cleanupExpired(unsigned int serverID, unsigned int channelId, int retentionDays);

			void clearChannel(unsigned int serverID, unsigned int channelId);

			void clearUser(unsigned int serverID, const std::string &senderHash);

			/// Delete specific messages by their IDs. Returns count of deleted rows.
			unsigned int deleteByIds(unsigned int serverID, unsigned int channelId,
										const std::vector< std::string > &messageIds);

			/// Delete messages in a time range (inclusive bounds, millis). Returns count of deleted rows.
			unsigned int deleteByTimeRange(unsigned int serverID, unsigned int channelId,
											long long fromMs, long long toMs);

			/// Delete all messages by a specific sender hash. Returns count of deleted rows.
			unsigned int deleteBySender(unsigned int serverID, unsigned int channelId,
										const std::string &senderHash);

			void migrate(unsigned int fromSchemaVersion, unsigned int toSchemaVersion) override;
		};

	} // namespace db
} // namespace server
} // namespace mumble

#endif // MUMBLE_SERVER_DATABASE_PCHATMESSAGETABLE_H_
