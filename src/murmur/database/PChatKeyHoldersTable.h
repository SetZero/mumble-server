// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_SERVER_DATABASE_PCHATKEYHOLDERSTABLE_H_
#define MUMBLE_SERVER_DATABASE_PCHATKEYHOLDERSTABLE_H_

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

		struct PChatKeyHolder {
			unsigned int serverID  = 0;
			unsigned int channelId = 0;
			std::string certHash;
			std::string lastKnownName;
			long long reportedAt   = 0;
		};

		class PChatKeyHoldersTable : public ::mumble::db::Table {
		public:
			static constexpr const char *NAME = "pchat_key_holders";

			struct column {
				column()                                         = delete;
				static constexpr const char *server_id           = "server_id";
				static constexpr const char *channel_id          = "channel_id";
				static constexpr const char *cert_hash           = "cert_hash";
				static constexpr const char *last_known_name     = "last_known_name";
				static constexpr const char *reported_at         = "reported_at";
			};

			PChatKeyHoldersTable(soci::session &sql, ::mumble::db::Backend backend,
								 const ServerTable &serverTable);
			~PChatKeyHoldersTable() = default;

			/// Record (or update) a key holder for a channel.
			bool recordHolder(const PChatKeyHolder &holder);

			/// Get all key holders for a channel.
			std::vector< PChatKeyHolder > getChannelHolders(unsigned int serverID, unsigned int channelId);

			/// Check whether a specific cert_hash is recorded as a holder for a channel.
			bool isHolder(unsigned int serverID, unsigned int channelId, const std::string &certHash);

			/// Remove a specific holder from a channel.
			void removeHolder(unsigned int serverID, unsigned int channelId, const std::string &certHash);

			/// Clear all holders for a channel.
			void clearChannel(unsigned int serverID, unsigned int channelId);

			void migrate(unsigned int fromSchemaVersion, unsigned int toSchemaVersion) override;
		};

	} // namespace db
} // namespace server
} // namespace mumble

#endif // MUMBLE_SERVER_DATABASE_PCHATKEYHOLDERSTABLE_H_
