// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_SERVER_DATABASE_PCHATMEMBERJOINTABLE_H_
#define MUMBLE_SERVER_DATABASE_PCHATMEMBERJOINTABLE_H_

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

		struct PChatMemberJoin {
			unsigned int serverID  = 0;
			unsigned int channelId = 0;
			std::string certHash;
			long long joinedAt     = 0;
			int epochAtJoin        = 0;
		};

		class PChatMemberJoinTable : public ::mumble::db::Table {
		public:
			static constexpr const char *NAME = "pchat_member_join";

			struct column {
				column()                                     = delete;
				static constexpr const char *server_id       = "server_id";
				static constexpr const char *channel_id      = "channel_id";
				static constexpr const char *cert_hash       = "cert_hash";
				static constexpr const char *joined_at       = "joined_at";
				static constexpr const char *epoch_at_join   = "epoch_at_join";
			};

			PChatMemberJoinTable(soci::session &sql, ::mumble::db::Backend backend,
								 const ServerTable &serverTable);
			~PChatMemberJoinTable() = default;

			bool recordJoin(const PChatMemberJoin &join);

			std::optional< PChatMemberJoin > getJoinRecord(unsigned int serverID, unsigned int channelId,
														   const std::string &certHash);

			std::vector< PChatMemberJoin > getChannelMembers(unsigned int serverID, unsigned int channelId);

			void removeJoin(unsigned int serverID, unsigned int channelId, const std::string &certHash);

			void clearChannel(unsigned int serverID, unsigned int channelId);

			void migrate(unsigned int fromSchemaVersion, unsigned int toSchemaVersion) override;
		};

	} // namespace db
} // namespace server
} // namespace mumble

#endif // MUMBLE_SERVER_DATABASE_PCHATMEMBERJOINTABLE_H_
