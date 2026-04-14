// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_SERVER_DATABASE_PCHATPINTABLE_H_
#define MUMBLE_SERVER_DATABASE_PCHATPINTABLE_H_

#include "database/Backend.h"
#include "database/Table.h"

#include <cstdint>
#include <string>
#include <vector>

namespace soci {
class session;
}

namespace mumble::server::db {

		class ServerTable;

		struct PChatPin {
			unsigned int serverID  = 0;
			unsigned int channelId = 0;
			std::string messageId;
			std::string pinnerHash;
			std::string pinnerName;
			long long timestamp = 0;
			long long createdAt = 0;
		};

		class PChatPinTable : public ::mumble::db::Table {
		public:
			static constexpr const char *NAME = "pchat_pins";

			struct column {
				column()                                  = delete;
				static constexpr const char *server_id    = "server_id";
				static constexpr const char *channel_id   = "channel_id";
				static constexpr const char *message_id   = "message_id";
				static constexpr const char *pinner_hash  = "pinner_hash";
				static constexpr const char *pinner_name  = "pinner_name";
				static constexpr const char *timestamp    = "timestamp";
				static constexpr const char *created_at   = "created_at";
			};

			PChatPinTable(soci::session &sql, ::mumble::db::Backend backend,
			              const ServerTable &serverTable);
			~PChatPinTable() = default;

			/// Pin a message. Returns true if inserted, false if already pinned.
			bool addPin(const PChatPin &pin);

			/// Unpin a message.
			void removePin(unsigned int serverID, unsigned int channelId,
			               const std::string &messageId);

			/// Get all pinned messages for a channel.
			[[nodiscard]] std::vector< PChatPin > getChannelPins(unsigned int serverID,
			                                       unsigned int channelId) const;

			/// Check if a specific message is pinned.
			[[nodiscard]] bool isPinned(unsigned int serverID, unsigned int channelId,
			              const std::string &messageId) const;

			/// Remove all pins for a message (when a message is deleted).
			void clearMessage(unsigned int serverID, unsigned int channelId,
			                  const std::string &messageId);

			/// Remove all pins for a channel (when a channel is removed).
			void clearChannel(unsigned int serverID, unsigned int channelId);

			void migrate(unsigned int fromSchemaVersion, unsigned int toSchemaVersion) override;
		};
} // namespace mumble::server::db

#endif // MUMBLE_SERVER_DATABASE_PCHATPINTABLE_H_
