// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_SERVER_DATABASE_SCHEDULEDMESSAGETABLE_H_
#define MUMBLE_SERVER_DATABASE_SCHEDULEDMESSAGETABLE_H_

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

		// One row of the scheduled_messages table. Targets are stored as
		// space-separated channel-id lists to keep the schema flat.
		struct ScheduledStoredMessage {
			unsigned int serverID = 0;
			std::string scheduleId;
			std::string channelIds; // space-separated channel ids
			std::string treeIds;    // space-separated channel ids (tree roots)
			std::string message;
			long long deliverAt = 0;
			std::string creatorHash;
			std::string creatorName;
			long long createdAt = 0;
			int status          = 0; // mirrors FancyScheduledStatus
		};

		// Persistent storage for messages queued for future delivery.
		class ScheduledMessageTable : public ::mumble::db::Table {
		public:
			static constexpr const char *NAME = "scheduled_messages";

			// Status values, kept in sync with the FancyScheduledStatus enum.
			enum Status { Pending = 0, Delivered = 1, Cancelled = 2, Rejected = 3 };

			struct column {
				column()                                  = delete;
				static constexpr const char *server_id    = "server_id";
				static constexpr const char *schedule_id  = "schedule_id";
				static constexpr const char *channel_ids  = "channel_ids";
				static constexpr const char *tree_ids     = "tree_ids";
				static constexpr const char *message      = "message";
				static constexpr const char *deliver_at   = "deliver_at";
				static constexpr const char *creator_hash = "creator_hash";
				static constexpr const char *creator_name = "creator_name";
				static constexpr const char *created_at   = "created_at";
				static constexpr const char *status       = "status";
			};

			ScheduledMessageTable(soci::session &sql, ::mumble::db::Backend backend, const ServerTable &serverTable);
			~ScheduledMessageTable() = default;

			// Insert or replace a scheduled message. Returns false on error.
			bool store(const ScheduledStoredMessage &msg);

			// Update the status column. Returns true if a row was affected.
			bool updateStatus(unsigned int serverID, const std::string &scheduleId, int status);

			// Permanently remove a scheduled message.
			bool remove(unsigned int serverID, const std::string &scheduleId);

			std::optional< ScheduledStoredMessage > get(unsigned int serverID, const std::string &scheduleId);

			// All messages for a creator (by cert hash). When pendingOnly is
			// true, only status == Pending rows are returned.
			std::vector< ScheduledStoredMessage > listByCreator(unsigned int serverID, const std::string &creatorHash,
																bool pendingOnly);

			// Pending messages whose deliver_at is <= nowMs.
			std::vector< ScheduledStoredMessage > listDue(unsigned int serverID, long long nowMs);

			// The earliest deliver_at among pending messages, if any.
			std::optional< long long > nextPendingDeliverAt(unsigned int serverID);

			void migrate(unsigned int fromSchemaVersion, unsigned int toSchemaVersion) override;
		};

	} // namespace db
} // namespace server
} // namespace mumble

#endif // MUMBLE_SERVER_DATABASE_SCHEDULEDMESSAGETABLE_H_
