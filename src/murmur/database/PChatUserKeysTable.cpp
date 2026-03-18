// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "PChatUserKeysTable.h"
#include "HexUtils.h"
#include "ServerTable.h"

#include <cstdio>

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

			::mdb::Column idPubCol(column::identity_public, ::mdb::DataType(::mdb::DataType::Text));
			::mdb::Column sigPubCol(column::signing_public, ::mdb::DataType(::mdb::DataType::Text));
			::mdb::Column sigCol(column::signature, ::mdb::DataType(::mdb::DataType::Text));

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

				// Hex-encode binary fields to avoid SOCI NUL-truncation on read-back.
				std::string hexIdentity  = toHex(keys.identityPublic);
				std::string hexSigning   = toHex(keys.signingPublic);
				std::string hexSignature = toHex(keys.signature);

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
						soci::use(keys.algorithmVersion), soci::use(hexIdentity),
						soci::use(hexSigning), soci::use(hexSignature), soci::use(keys.updatedAt),
						soci::use(keys.serverID), soci::use(keys.certHash);
				} else {
					m_sql << "INSERT INTO \"" << NAME << "\" (\"" << column::server_id << "\", \""
						  << column::cert_hash << "\", \"" << column::algorithm_version << "\", \""
						  << column::identity_public << "\", \"" << column::signing_public << "\", \""
						  << column::signature << "\", \"" << column::updated_at
						  << "\") VALUES (:sid, :ch, :av, :ip, :sp, :sig, :ua)",
						soci::use(keys.serverID), soci::use(keys.certHash), soci::use(keys.algorithmVersion),
						soci::use(hexIdentity), soci::use(hexSigning),
						soci::use(hexSignature), soci::use(keys.updatedAt);
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

				std::string hexIdentity, hexSigning, hexSignature;

				m_sql << "SELECT \"" << column::cert_hash << "\", \"" << column::algorithm_version << "\", \""
					  << column::identity_public << "\", \"" << column::signing_public << "\", \""
					  << column::signature << "\", \"" << column::updated_at << "\" FROM \"" << NAME
					  << "\" WHERE \"" << column::server_id << "\" = :sid AND \"" << column::cert_hash
					  << "\" = :ch",
					soci::into(keys.certHash), soci::into(keys.algorithmVersion),
					soci::into(hexIdentity), soci::into(hexSigning),
					soci::into(hexSignature), soci::into(keys.updatedAt),
					soci::use(serverID), soci::use(certHash);

			if (!m_sql.got_data()) {
				transaction.commit();
				return std::nullopt;
			}

			// Hex-decode binary fields (stored as hex to avoid SOCI NUL-truncation).
			keys.identityPublic = fromHex(hexIdentity);
			keys.signingPublic  = fromHex(hexSigning);
			keys.signature      = fromHex(hexSignature);

			// Validate expected field lengths (identity=32, signing=32, sig=64).
			// If wrong, the row was stored before the hex-encoding fix and is
			// corrupted (SOCI NUL truncation). Delete it and report as absent;
			// the user will re-announce with a fresh key on next connection.
			if (keys.identityPublic.size() != 32
					|| keys.signingPublic.size() != 32
					|| keys.signature.size() != 64) {
				std::fprintf(stderr,
						 "pchat: getKeys: deleting corrupted key row for %s "
						 "(identity=%zu signing=%zu sig=%zu)\n",
						 certHash.c_str(),
						 keys.identityPublic.size(),
						 keys.signingPublic.size(),
						 keys.signature.size());
				try {
					m_sql << "DELETE FROM \"" << NAME << "\" WHERE \""
						  << column::server_id << "\" = :sid AND \""
						  << column::cert_hash << "\" = :ch",
						soci::use(serverID), soci::use(certHash);
				} catch (...) {}
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
					// Hex-decode binary fields (stored as hex to avoid SOCI NUL-truncation).
					keys.identityPublic   = fromHex(row.get< std::string >(2));
					keys.signingPublic    = fromHex(row.get< std::string >(3));
					keys.signature        = fromHex(row.get< std::string >(4));
					keys.updatedAt        = row.get< long long >(5);

				// Skip corrupted entries (truncated by SOCI before hex-encoding fix).
				if (keys.identityPublic.size() != 32
						|| keys.signingPublic.size() != 32
						|| keys.signature.size() != 64) {
					continue;
				}
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

		void PChatUserKeysTable::cleanupCorruptedKeys(unsigned int serverID) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				soci::rowset< soci::row > rs =
					(m_sql.prepare << "SELECT \"" << column::cert_hash << "\", \""
								   << column::identity_public << "\", \""
								   << column::signing_public << "\", \""
								   << column::signature << "\" FROM \""
								   << NAME << "\" WHERE \"" << column::server_id << "\" = :sid",
					 soci::use(serverID));

				std::vector< std::string > toDelete;
				for (const auto &row : rs) {
					const std::string id   = fromHex(row.get< std::string >(1));
					const std::string sign = fromHex(row.get< std::string >(2));
					const std::string sig  = fromHex(row.get< std::string >(3));
					if (id.size() != 32 || sign.size() != 32 || sig.size() != 64) {
						toDelete.push_back(row.get< std::string >(0));
					}
				}

				for (const auto &hash : toDelete) {
					std::fprintf(stderr, "pchat: cleanupCorruptedKeys: deleting corrupted key row for %s\n",
							 hash.c_str());
					m_sql << "DELETE FROM \"" << NAME << "\" WHERE \""
						  << column::server_id << "\" = :sid AND \""
						  << column::cert_hash << "\" = :ch",
						soci::use(serverID), soci::use(hash);
				}

				transaction.commit();
			} catch (const soci::soci_error &e) {
				std::fprintf(stderr, "pchat: cleanupCorruptedKeys failed: %s\n", e.what());
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
