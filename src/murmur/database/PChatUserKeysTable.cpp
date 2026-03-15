// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "PChatUserKeysTable.h"
#include "ServerTable.h"

#include "database/AccessException.h"
#include "database/Column.h"
#include "database/Constraint.h"
#include "database/DataType.h"
#include "database/ForeignKey.h"
#include "database/MigrationException.h"
#include "database/PrimaryKey.h"
#include "database/TransactionHolder.h"
#include "database/Utils.h"

#include <soci/soci.h>

#include <cassert>
#include <chrono>

namespace mdb = ::mumble::db;

namespace mumble {
namespace server {
	namespace db {

		constexpr const char *PChatUserKeysTable::NAME;
		constexpr const char *PChatUserKeysTable::column::server_id;
		constexpr const char *PChatUserKeysTable::column::cert_hash;
		constexpr const char *PChatUserKeysTable::column::algorithm_version;
		constexpr const char *PChatUserKeysTable::column::identity_public;
		constexpr const char *PChatUserKeysTable::column::signing_public;
		constexpr const char *PChatUserKeysTable::column::signature;
		constexpr const char *PChatUserKeysTable::column::updated_at;

		PChatUserKeysTable::PChatUserKeysTable(soci::session &sql, ::mdb::Backend backend,
											   const ServerTable &serverTable)
			: ::mdb::Table(sql, backend, NAME) {

			::mdb::Column serverCol(column::server_id, ::mdb::DataType(::mdb::DataType::Integer));
			serverCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column certHashCol(column::cert_hash, ::mdb::DataType(::mdb::DataType::Text));
			certHashCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column algVerCol(column::algorithm_version, ::mdb::DataType(::mdb::DataType::Integer));
			algVerCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column idPubCol(column::identity_public, ::mdb::DataType(::mdb::DataType::Blob));
			::mdb::Column sigPubCol(column::signing_public, ::mdb::DataType(::mdb::DataType::Blob));
			::mdb::Column sigCol(column::signature, ::mdb::DataType(::mdb::DataType::Blob));

			::mdb::Column updatedCol(column::updated_at, ::mdb::DataType(::mdb::DataType::Integer));
			updatedCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			setColumns({ serverCol, certHashCol, algVerCol, idPubCol, sigPubCol, sigCol, updatedCol });

			::mdb::PrimaryKey pk(std::vector< std::string >{ column::server_id, column::cert_hash });
			setPrimaryKey(pk);

			::mdb::ForeignKey fk(serverTable, { serverCol });
			addForeignKey(fk);
		}

		bool PChatUserKeysTable::storeKeys(const PChatUserKeys &keys) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				// Check if entry exists
				int exists = 0;
				m_sql << "SELECT 1 FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
					  << column::cert_hash << "\" = :ch",
					soci::into(exists), soci::use(keys.serverID), soci::use(keys.certHash);

				if (exists) {
					m_sql << "UPDATE \"" << NAME << "\" SET \"" << column::algorithm_version << "\" = :av, \""
						  << column::identity_public << "\" = :ip, \"" << column::signing_public << "\" = :sp, \""
						  << column::signature << "\" = :sig, \"" << column::updated_at << "\" = :ua WHERE \""
						  << column::server_id << "\" = :sid AND \"" << column::cert_hash << "\" = :ch",
						soci::use(keys.algorithmVersion), soci::use(keys.identityPublic),
						soci::use(keys.signingPublic), soci::use(keys.signature), soci::use(keys.updatedAt),
						soci::use(keys.serverID), soci::use(keys.certHash);
				} else {
					m_sql << "INSERT INTO \"" << NAME << "\" (\"" << column::server_id << "\", \""
						  << column::cert_hash << "\", \"" << column::algorithm_version << "\", \""
						  << column::identity_public << "\", \"" << column::signing_public << "\", \""
						  << column::signature << "\", \"" << column::updated_at
						  << "\") VALUES (:sid, :ch, :av, :ip, :sp, :sig, :ua)",
						soci::use(keys.serverID), soci::use(keys.certHash), soci::use(keys.algorithmVersion),
						soci::use(keys.identityPublic), soci::use(keys.signingPublic),
						soci::use(keys.signature), soci::use(keys.updatedAt);
				}

				transaction.commit();
				return true;
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to store pchat user keys for " + keys.certHash));
			}
		}

		std::optional< PChatUserKeys > PChatUserKeysTable::getKeys(unsigned int serverID,
																   const std::string &certHash) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				PChatUserKeys keys;
				keys.serverID = serverID;

				m_sql << "SELECT \"" << column::cert_hash << "\", \"" << column::algorithm_version << "\", \""
					  << column::identity_public << "\", \"" << column::signing_public << "\", \""
					  << column::signature << "\", \"" << column::updated_at << "\" FROM \"" << NAME
					  << "\" WHERE \"" << column::server_id << "\" = :sid AND \"" << column::cert_hash
					  << "\" = :ch",
					soci::into(keys.certHash), soci::into(keys.algorithmVersion),
					soci::into(keys.identityPublic), soci::into(keys.signingPublic),
					soci::into(keys.signature), soci::into(keys.updatedAt),
					soci::use(serverID), soci::use(certHash);

				if (!m_sql.got_data()) {
					transaction.commit();
					return std::nullopt;
				}

				transaction.commit();
				return keys;
			} catch (const soci::soci_error &) {
				return std::nullopt;
			}
		}

		std::vector< PChatUserKeys > PChatUserKeysTable::getAllKeys(unsigned int serverID) {
			std::vector< PChatUserKeys > result;
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				soci::rowset< soci::row > rs =
					(m_sql.prepare << "SELECT \"" << column::cert_hash << "\", \"" << column::algorithm_version
								   << "\", \"" << column::identity_public << "\", \"" << column::signing_public
								   << "\", \"" << column::signature << "\", \"" << column::updated_at << "\" FROM \""
								   << NAME << "\" WHERE \"" << column::server_id << "\" = :sid",
					 soci::use(serverID));

				for (const auto &row : rs) {
					PChatUserKeys keys;
					keys.serverID         = serverID;
					keys.certHash         = row.get< std::string >(0);
					keys.algorithmVersion = row.get< int >(1);
					keys.identityPublic   = row.get< std::string >(2);
					keys.signingPublic    = row.get< std::string >(3);
					keys.signature        = row.get< std::string >(4);
					keys.updatedAt        = row.get< long long >(5);
					result.push_back(std::move(keys));
				}

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to fetch all pchat user keys on server "
										   + std::to_string(serverID)));
			}
			return result;
		}

		void PChatUserKeysTable::removeKeys(unsigned int serverID, const std::string &certHash) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
					  << column::cert_hash << "\" = :ch",
					soci::use(serverID), soci::use(certHash);

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to remove pchat user keys for " + certHash));
			}
		}

		void PChatUserKeysTable::migrate(unsigned int fromSchemaVersion, unsigned int toSchemaVersion) {
			assert(fromSchemaVersion <= toSchemaVersion);
			try {
				if (fromSchemaVersion < 12) {
					// Table introduced in schema version 12
				} else {
					mdb::Table::migrate(fromSchemaVersion, toSchemaVersion);
				}
			} catch (const soci::soci_error &) {
				std::throw_with_nested(::mdb::MigrationException(
					std::string("Failed at migrating table \"") + NAME + "\" from schema version "
					+ std::to_string(fromSchemaVersion) + " to " + std::to_string(toSchemaVersion)));
			}
		}

	} // namespace db
} // namespace server
} // namespace mumble
