// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "PChatMemberJoinTable.h"
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

namespace mdb = ::mumble::db;

namespace mumble {
namespace server {
	namespace db {

		constexpr const char *PChatMemberJoinTable::NAME;
		constexpr const char *PChatMemberJoinTable::column::server_id;
		constexpr const char *PChatMemberJoinTable::column::channel_id;
		constexpr const char *PChatMemberJoinTable::column::cert_hash;
		constexpr const char *PChatMemberJoinTable::column::joined_at;
		constexpr const char *PChatMemberJoinTable::column::epoch_at_join;

		PChatMemberJoinTable::PChatMemberJoinTable(soci::session &sql, ::mdb::Backend backend,
												   const ServerTable &serverTable)
			: ::mdb::Table(sql, backend, NAME) {

			::mdb::Column serverCol(column::server_id, ::mdb::DataType(::mdb::DataType::Integer));
			serverCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column channelCol(column::channel_id, ::mdb::DataType(::mdb::DataType::Integer));
			channelCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column certHashCol(column::cert_hash, ::mdb::DataType(::mdb::DataType::Text));
			certHashCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column joinedAtCol(column::joined_at, ::mdb::DataType(::mdb::DataType::Integer));
			joinedAtCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column epochCol(column::epoch_at_join, ::mdb::DataType(::mdb::DataType::Integer));
			epochCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			setColumns({ serverCol, channelCol, certHashCol, joinedAtCol, epochCol });

			// Unique per (server, channel, user)
			::mdb::PrimaryKey pk(std::vector< std::string >{ column::server_id, column::channel_id, column::cert_hash });
			setPrimaryKey(pk);

			::mdb::ForeignKey fk(serverTable, { serverCol });
			addForeignKey(fk);

			// Index for channel-based queries
			::mdb::Index channelIdx("idx_pchat_member_join_channel",
									{ column::server_id, column::channel_id });
			addIndex(channelIdx, false);
		}

		bool PChatMemberJoinTable::recordJoin(const PChatMemberJoin &join) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				// Use INSERT OR IGNORE semantics - only record first join
				int exists = 0;
				m_sql << "SELECT 1 FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
					  << column::channel_id << "\" = :cid AND \"" << column::cert_hash << "\" = :ch",
					soci::into(exists), soci::use(join.serverID), soci::use(join.channelId),
					soci::use(join.certHash);

				if (m_sql.got_data()) {
					// Already joined, don't update
					transaction.commit();
					return false;
				}

				m_sql << "INSERT INTO \"" << NAME << "\" (\"" << column::server_id << "\", \""
					  << column::channel_id << "\", \"" << column::cert_hash << "\", \""
					  << column::joined_at << "\", \"" << column::epoch_at_join
					  << "\") VALUES (:sid, :cid, :ch, :ja, :eaj)",
					soci::use(join.serverID), soci::use(join.channelId), soci::use(join.certHash),
					soci::use(join.joinedAt), soci::use(join.epochAtJoin);

				transaction.commit();
				return true;
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to record pchat member join for " + join.certHash));
			}
		}

		std::optional< PChatMemberJoin > PChatMemberJoinTable::getJoinRecord(unsigned int serverID,
																			 unsigned int channelId,
																			 const std::string &certHash) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				PChatMemberJoin join;
				join.serverID  = serverID;
				join.channelId = channelId;

				m_sql << "SELECT \"" << column::cert_hash << "\", \"" << column::joined_at << "\", \""
					  << column::epoch_at_join << "\" FROM \"" << NAME << "\" WHERE \""
					  << column::server_id << "\" = :sid AND \"" << column::channel_id << "\" = :cid AND \""
					  << column::cert_hash << "\" = :ch",
					soci::into(join.certHash), soci::into(join.joinedAt), soci::into(join.epochAtJoin),
					soci::use(serverID), soci::use(channelId), soci::use(certHash);

				if (!m_sql.got_data()) {
					transaction.commit();
					return std::nullopt;
				}

				transaction.commit();
				return join;
			} catch (const soci::soci_error &) {
				return std::nullopt;
			}
		}

		std::vector< PChatMemberJoin > PChatMemberJoinTable::getChannelMembers(unsigned int serverID,
																			   unsigned int channelId) {
			std::vector< PChatMemberJoin > result;
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				soci::rowset< soci::row > rs =
					(m_sql.prepare << "SELECT \"" << column::cert_hash << "\", \"" << column::joined_at
								   << "\", \"" << column::epoch_at_join << "\" FROM \"" << NAME
								   << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
								   << column::channel_id << "\" = :cid",
					 soci::use(serverID), soci::use(channelId));

				for (const auto &row : rs) {
					PChatMemberJoin join;
					join.serverID    = serverID;
					join.channelId   = channelId;
					join.certHash    = row.get< std::string >(0);
					join.joinedAt    = row.get< long long >(1);
					join.epochAtJoin = row.get< int >(2);
					result.push_back(std::move(join));
				}

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to fetch pchat member joins for channel "
										   + std::to_string(channelId)));
			}
			return result;
		}

		void PChatMemberJoinTable::removeJoin(unsigned int serverID, unsigned int channelId,
											  const std::string &certHash) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
					  << column::channel_id << "\" = :cid AND \"" << column::cert_hash << "\" = :ch",
					soci::use(serverID), soci::use(channelId), soci::use(certHash);

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to remove pchat member join for " + certHash));
			}
		}

		void PChatMemberJoinTable::clearChannel(unsigned int serverID, unsigned int channelId) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
					  << column::channel_id << "\" = :cid",
					soci::use(serverID), soci::use(channelId);

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to clear pchat member joins for channel "
										   + std::to_string(channelId)));
			}
		}

		void PChatMemberJoinTable::migrate(unsigned int fromSchemaVersion, unsigned int toSchemaVersion) {
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
