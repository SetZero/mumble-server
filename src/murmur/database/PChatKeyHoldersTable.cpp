// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "PChatKeyHoldersTable.h"
#include "ServerTable.h"

#include "database/AccessException.h"
#include "database/Column.h"
#include "database/Constraint.h"
#include "database/DataType.h"
#include "database/ForeignKey.h"
#include "database/Index.h"
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

		constexpr const char *PChatKeyHoldersTable::NAME;
		constexpr const char *PChatKeyHoldersTable::column::server_id;
		constexpr const char *PChatKeyHoldersTable::column::channel_id;
		constexpr const char *PChatKeyHoldersTable::column::cert_hash;
		constexpr const char *PChatKeyHoldersTable::column::last_known_name;
		constexpr const char *PChatKeyHoldersTable::column::reported_at;

		PChatKeyHoldersTable::PChatKeyHoldersTable(soci::session &sql, ::mdb::Backend backend,
												   const ServerTable &serverTable)
			: ::mdb::Table(sql, backend, NAME) {

			::mdb::Column serverCol(column::server_id, ::mdb::DataType(::mdb::DataType::Integer));
			serverCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column channelCol(column::channel_id, ::mdb::DataType(::mdb::DataType::Integer));
			channelCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column certHashCol(column::cert_hash, ::mdb::DataType(::mdb::DataType::Text));
			certHashCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column nameCol(column::last_known_name, ::mdb::DataType(::mdb::DataType::Text));

			::mdb::Column reportedCol(column::reported_at, ::mdb::DataType(::mdb::DataType::Integer));
			reportedCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			setColumns({ serverCol, channelCol, certHashCol, nameCol, reportedCol });

			// Unique per (server, channel, cert_hash)
			::mdb::PrimaryKey pk(
				std::vector< std::string >{ column::server_id, column::channel_id, column::cert_hash });
			setPrimaryKey(pk);

			::mdb::ForeignKey fk(serverTable, { serverCol });
			addForeignKey(fk);

			// Index for channel-based queries
			::mdb::Index channelIdx("idx_pchat_key_holders_channel",
									{ column::server_id, column::channel_id });
			addIndex(channelIdx, false);
		}

		bool PChatKeyHoldersTable::recordHolder(const PChatKeyHolder &holder) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				int exists = 0;
				m_sql << "SELECT 1 FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
					  << column::channel_id << "\" = :cid AND \"" << column::cert_hash << "\" = :ch",
					soci::into(exists), soci::use(holder.serverID), soci::use(holder.channelId),
					soci::use(holder.certHash);

				if (m_sql.got_data()) {
					// Update name and timestamp
					m_sql << "UPDATE \"" << NAME << "\" SET \"" << column::last_known_name << "\" = :name, \""
						  << column::reported_at << "\" = :ra WHERE \"" << column::server_id << "\" = :sid AND \""
						  << column::channel_id << "\" = :cid AND \"" << column::cert_hash << "\" = :ch",
						soci::use(holder.lastKnownName), soci::use(holder.reportedAt),
						soci::use(holder.serverID), soci::use(holder.channelId), soci::use(holder.certHash);
				} else {
					m_sql << "INSERT INTO \"" << NAME << "\" (\"" << column::server_id << "\", \""
						  << column::channel_id << "\", \"" << column::cert_hash << "\", \""
						  << column::last_known_name << "\", \"" << column::reported_at
						  << "\") VALUES (:sid, :cid, :ch, :name, :ra)",
						soci::use(holder.serverID), soci::use(holder.channelId), soci::use(holder.certHash),
						soci::use(holder.lastKnownName), soci::use(holder.reportedAt);
				}

				transaction.commit();
				return true;
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to record key holder " + holder.certHash
										   + " for channel " + std::to_string(holder.channelId)));
			}
		}

		std::vector< PChatKeyHolder > PChatKeyHoldersTable::getChannelHolders(unsigned int serverID,
																			  unsigned int channelId) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				std::vector< PChatKeyHolder > result;

				soci::rowset< soci::row > rows =
					(m_sql.prepare << "SELECT \"" << column::cert_hash << "\", \"" << column::last_known_name
								   << "\", \"" << column::reported_at << "\" FROM \"" << NAME << "\" WHERE \""
								   << column::server_id << "\" = :sid AND \"" << column::channel_id << "\" = :cid",
					 soci::use(serverID), soci::use(channelId));

				for (const auto &row : rows) {
					PChatKeyHolder h;
					h.serverID      = serverID;
					h.channelId     = channelId;
					h.certHash      = row.get< std::string >(0);
					h.lastKnownName = row.get< std::string >(1, "");
					h.reportedAt    = row.get< long long >(2);
					result.push_back(std::move(h));
				}

				return result;
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to get key holders for channel " + std::to_string(channelId)));
			}
		}

		bool PChatKeyHoldersTable::isHolder(unsigned int serverID, unsigned int channelId,
											const std::string &certHash) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				int exists = 0;
				m_sql << "SELECT 1 FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
					  << column::channel_id << "\" = :cid AND \"" << column::cert_hash << "\" = :ch",
					soci::into(exists), soci::use(serverID), soci::use(channelId), soci::use(certHash);

				bool found = m_sql.got_data();
				transaction.commit();
				return found;
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to check key holder " + certHash
										   + " for channel " + std::to_string(channelId)));
			}
		}

		void PChatKeyHoldersTable::removeHolder(unsigned int serverID, unsigned int channelId,
												const std::string &certHash) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
					  << column::channel_id << "\" = :cid AND \"" << column::cert_hash << "\" = :ch",
					soci::use(serverID), soci::use(channelId), soci::use(certHash);

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to remove key holder " + certHash
										   + " from channel " + std::to_string(channelId)));
			}
		}

		void PChatKeyHoldersTable::clearChannel(unsigned int serverID, unsigned int channelId) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
					  << column::channel_id << "\" = :cid",
					soci::use(serverID), soci::use(channelId);

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to clear key holders for channel " + std::to_string(channelId)));
			}
		}

		void PChatKeyHoldersTable::migrate(unsigned int fromSchemaVersion, unsigned int toSchemaVersion) {
			// Table was introduced at the current schema version - no migrations needed yet.
			(void) fromSchemaVersion;
			(void) toSchemaVersion;
		}

	} // namespace db
} // namespace server
} // namespace mumble
