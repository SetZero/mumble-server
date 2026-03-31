// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_SERVER_DATABASE_PCHATREACTIONTABLE_H_
#define MUMBLE_SERVER_DATABASE_PCHATREACTIONTABLE_H_

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

		struct PChatReaction {
			unsigned int serverID   = 0;
			unsigned int channelId  = 0;
			std::string messageId;
			std::string emoji;
			bool isServerEmoji      = false;
			std::string senderHash;
			std::string senderName;
			long long timestamp     = 0;
			long long createdAt     = 0;
		};

		class PChatReactionTable : public ::mumble::db::Table {
		public:
			static constexpr const char *NAME = "pchat_reactions";

			struct column {
				column()                                   = delete;
				static constexpr const char *server_id     = "server_id";
				static constexpr const char *channel_id    = "channel_id";
				static constexpr const char *message_id    = "message_id";
				static constexpr const char *emoji         = "emoji";
				static constexpr const char *is_server_emoji = "is_server_emoji";
				static constexpr const char *sender_hash   = "sender_hash";
				static constexpr const char *sender_name   = "sender_name";
				static constexpr const char *timestamp     = "timestamp";
				static constexpr const char *created_at    = "created_at";
			};

			PChatReactionTable(soci::session &sql, ::mumble::db::Backend backend,
			                   const ServerTable &serverTable);
			~PChatReactionTable() = default;

			/// Add a reaction. Returns true if inserted, false if it already existed.
			bool addReaction(const PChatReaction &reaction);

			/// Remove a reaction for a specific user on a specific emoji/message.
			void removeReaction(unsigned int serverID, unsigned int channelId,
			                    const std::string &messageId, const std::string &emoji,
			                    bool isServerEmoji, const std::string &senderHash);

			/// Get all reactions for a single message.
			std::vector< PChatReaction > getMessageReactions(unsigned int serverID,
			                                                 unsigned int channelId,
			                                                 const std::string &messageId);

			/// Get all reactions for all messages in a channel.
			std::vector< PChatReaction > getChannelReactions(unsigned int serverID,
			                                                 unsigned int channelId);

			/// Get all reactions for a set of message IDs (batch fetch).
			std::vector< PChatReaction > getReactionsForMessages(unsigned int serverID,
			                                                     unsigned int channelId,
			                                                     const std::vector< std::string > &messageIds);

			/// Remove all reactions for a message (when a message is deleted).
			void clearMessage(unsigned int serverID, unsigned int channelId,
			                  const std::string &messageId);

			/// Remove all reactions for a channel (when a channel is removed).
			void clearChannel(unsigned int serverID, unsigned int channelId);

			void migrate(unsigned int fromSchemaVersion, unsigned int toSchemaVersion) override;
		};

	} // namespace db
} // namespace server
} // namespace mumble

#endif // MUMBLE_SERVER_DATABASE_PCHATREACTIONTABLE_H_
