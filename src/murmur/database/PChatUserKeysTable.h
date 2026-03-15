// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_SERVER_DATABASE_PCHATUSERKEYSTABLE_H_
#define MUMBLE_SERVER_DATABASE_PCHATUSERKEYSTABLE_H_

#include "database/Backend.h"
#include "database/Table.h"

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

		struct PChatUserKeys {
			unsigned int serverID      = 0;
			std::string certHash;
			int algorithmVersion       = 0;
			std::string identityPublic; // raw bytes as string
			std::string signingPublic;
			std::string signature;
			long long updatedAt        = 0;
		};

		class PChatUserKeysTable : public ::mumble::db::Table {
		public:
			static constexpr const char *NAME = "pchat_user_keys";

			struct column {
				column()                                         = delete;
				static constexpr const char *server_id           = "server_id";
				static constexpr const char *cert_hash           = "cert_hash";
				static constexpr const char *algorithm_version   = "algorithm_version";
				static constexpr const char *identity_public     = "identity_public";
				static constexpr const char *signing_public      = "signing_public";
				static constexpr const char *signature           = "signature";
				static constexpr const char *updated_at          = "updated_at";
			};

			PChatUserKeysTable(soci::session &sql, ::mumble::db::Backend backend, const ServerTable &serverTable);
			~PChatUserKeysTable() = default;

			bool storeKeys(const PChatUserKeys &keys);

			std::optional< PChatUserKeys > getKeys(unsigned int serverID, const std::string &certHash);

			std::vector< PChatUserKeys > getAllKeys(unsigned int serverID);

			void removeKeys(unsigned int serverID, const std::string &certHash);

			void migrate(unsigned int fromSchemaVersion, unsigned int toSchemaVersion) override;
		};

	} // namespace db
} // namespace server
} // namespace mumble

#endif // MUMBLE_SERVER_DATABASE_PCHATUSERKEYSTABLE_H_
