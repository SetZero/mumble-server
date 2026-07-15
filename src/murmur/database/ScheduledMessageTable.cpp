// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "ScheduledMessageTable.h"
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

#include <soci/soci.h>

#include <cassert>

namespace mdb = ::mumble::db;

namespace mumble {
namespace server {
	namespace db {

		constexpr const char *ScheduledMessageTable::NAME;
		constexpr const char *ScheduledMessageTable::column::server_id;
		constexpr const char *ScheduledMessageTable::column::schedule_id;
		constexpr const char *ScheduledMessageTable::column::channel_ids;
		constexpr const char *ScheduledMessageTable::column::tree_ids;
		constexpr const char *ScheduledMessageTable::column::message;
		constexpr const char *ScheduledMessageTable::column::deliver_at;
		constexpr const char *ScheduledMessageTable::column::creator_hash;
		constexpr const char *ScheduledMessageTable::column::creator_name;
		constexpr const char *ScheduledMessageTable::column::created_at;
		constexpr const char *ScheduledMessageTable::column::status;

		ScheduledMessageTable::ScheduledMessageTable(soci::session &sql, ::mdb::Backend backend,
													 const ServerTable &serverTable)
			: ::mdb::Table(sql, backend, NAME) {

			::mdb::Column serverCol(column::server_id, ::mdb::DataType(::mdb::DataType::Integer));
			serverCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column scheduleIdCol(column::schedule_id, ::mdb::DataType(::mdb::DataType::Text));
			scheduleIdCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column channelIdsCol(column::channel_ids, ::mdb::DataType(::mdb::DataType::Text));
			::mdb::Column treeIdsCol(column::tree_ids, ::mdb::DataType(::mdb::DataType::Text));

			::mdb::Column messageCol(column::message, ::mdb::DataType(::mdb::DataType::Text));
			messageCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column deliverAtCol(column::deliver_at, ::mdb::DataType(::mdb::DataType::Integer));
			deliverAtCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column creatorHashCol(column::creator_hash, ::mdb::DataType(::mdb::DataType::Text));
			creatorHashCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column creatorNameCol(column::creator_name, ::mdb::DataType(::mdb::DataType::Text));

			::mdb::Column createdAtCol(column::created_at, ::mdb::DataType(::mdb::DataType::Integer));
			createdAtCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column statusCol(column::status, ::mdb::DataType(::mdb::DataType::Integer));
			statusCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			setColumns({ serverCol, scheduleIdCol, channelIdsCol, treeIdsCol, messageCol, deliverAtCol, creatorHashCol,
						 creatorNameCol, createdAtCol, statusCol });

			::mdb::PrimaryKey pk(std::vector< std::string >{ column::server_id, column::schedule_id });
			setPrimaryKey(pk);

			::mdb::ForeignKey fk(serverTable, { serverCol });
			addForeignKey(fk);
		}

		bool ScheduledMessageTable::store(const ScheduledStoredMessage &msg) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
					  << column::schedule_id << "\" = :schid",
					soci::use(msg.serverID), soci::use(msg.scheduleId);

				m_sql << "INSERT INTO \"" << NAME << "\" (\"" << column::server_id << "\", \"" << column::schedule_id
					  << "\", \"" << column::channel_ids << "\", \"" << column::tree_ids << "\", \"" << column::message
					  << "\", \"" << column::deliver_at << "\", \"" << column::creator_hash << "\", \""
					  << column::creator_name << "\", \"" << column::created_at << "\", \"" << column::status
					  << "\") VALUES (:sid, :schid, :cids, :tids, :msg, :dat, :ch, :cn, :cat, :st)",
					soci::use(msg.serverID), soci::use(msg.scheduleId), soci::use(msg.channelIds),
					soci::use(msg.treeIds), soci::use(msg.message), soci::use(msg.deliverAt),
					soci::use(msg.creatorHash), soci::use(msg.creatorName), soci::use(msg.createdAt),
					soci::use(msg.status);

				transaction.commit();
				return true;
			} catch (const soci::soci_error &) {
				return false;
			}
		}

		bool ScheduledMessageTable::updateStatus(unsigned int serverID, const std::string &scheduleId, int status) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "UPDATE \"" << NAME << "\" SET \"" << column::status << "\" = :st WHERE \""
					  << column::server_id << "\" = :sid AND \"" << column::schedule_id << "\" = :schid",
					soci::use(status), soci::use(serverID), soci::use(scheduleId);

				bool affected = m_sql.got_data();
				transaction.commit();
				return affected;
			} catch (const soci::soci_error &) {
				return false;
			}
		}

		bool ScheduledMessageTable::remove(unsigned int serverID, const std::string &scheduleId) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
					  << column::schedule_id << "\" = :schid",
					soci::use(serverID), soci::use(scheduleId);

				bool affected = m_sql.got_data();
				transaction.commit();
				return affected;
			} catch (const soci::soci_error &) {
				return false;
			}
		}

		static ScheduledStoredMessage rowToMessage(unsigned int serverID, const soci::row &row) {
			ScheduledStoredMessage msg;
			msg.serverID    = serverID;
			msg.scheduleId  = row.get< std::string >(0);
			msg.channelIds  = row.get< std::string >(1, std::string());
			msg.treeIds     = row.get< std::string >(2, std::string());
			msg.message     = row.get< std::string >(3);
			msg.deliverAt   = row.get< long long >(4);
			msg.creatorHash = row.get< std::string >(5);
			msg.creatorName = row.get< std::string >(6, std::string());
			msg.createdAt   = row.get< long long >(7);
			msg.status      = static_cast< int >(row.get< long long >(8));
			return msg;
		}

		std::optional< ScheduledStoredMessage > ScheduledMessageTable::get(unsigned int serverID,
																		  const std::string &scheduleId) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				std::string sql =
					"SELECT \"" + std::string(column::schedule_id) + "\", \"" + column::channel_ids + "\", \""
					+ column::tree_ids + "\", \"" + column::message + "\", \"" + column::deliver_at + "\", \""
					+ column::creator_hash + "\", \"" + column::creator_name + "\", \"" + column::created_at + "\", \""
					+ column::status + "\" FROM \"" + std::string(NAME) + "\" WHERE \"" + column::server_id
					+ "\" = :sid AND \"" + column::schedule_id + "\" = :schid";

				soci::row row;
				m_sql << sql, soci::into(row), soci::use(serverID), soci::use(scheduleId);

				bool found = m_sql.got_data();
				transaction.commit();
				if (!found) {
					return std::nullopt;
				}
				return rowToMessage(serverID, row);
			} catch (const soci::soci_error &) {
				return std::nullopt;
			}
		}

		std::vector< ScheduledStoredMessage >
			ScheduledMessageTable::listByCreator(unsigned int serverID, const std::string &creatorHash,
												 bool pendingOnly) {
			std::vector< ScheduledStoredMessage > out;
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				std::string sql =
					"SELECT \"" + std::string(column::schedule_id) + "\", \"" + column::channel_ids + "\", \""
					+ column::tree_ids + "\", \"" + column::message + "\", \"" + column::deliver_at + "\", \""
					+ column::creator_hash + "\", \"" + column::creator_name + "\", \"" + column::created_at + "\", \""
					+ column::status + "\" FROM \"" + std::string(NAME) + "\" WHERE \"" + column::server_id
					+ "\" = :sid AND \"" + column::creator_hash + "\" = :ch";
				if (pendingOnly) {
					sql += " AND \"" + std::string(column::status) + "\" = 0";
				}
				sql += " ORDER BY \"" + std::string(column::deliver_at) + "\" ASC";

				soci::rowset< soci::row > rs = (m_sql.prepare << sql, soci::use(serverID), soci::use(creatorHash));
				for (const auto &row : rs) {
					out.push_back(rowToMessage(serverID, row));
				}

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(::mdb::AccessException("Failed to list scheduled messages for user "
															  + creatorHash + " on server " + std::to_string(serverID)));
			}
			return out;
		}

		std::vector< ScheduledStoredMessage > ScheduledMessageTable::listDue(unsigned int serverID, long long nowMs) {
			std::vector< ScheduledStoredMessage > out;
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				std::string sql =
					"SELECT \"" + std::string(column::schedule_id) + "\", \"" + column::channel_ids + "\", \""
					+ column::tree_ids + "\", \"" + column::message + "\", \"" + column::deliver_at + "\", \""
					+ column::creator_hash + "\", \"" + column::creator_name + "\", \"" + column::created_at + "\", \""
					+ column::status + "\" FROM \"" + std::string(NAME) + "\" WHERE \"" + column::server_id
					+ "\" = :sid AND \"" + column::status + "\" = 0 AND \"" + column::deliver_at
					+ "\" <= :now ORDER BY \"" + std::string(column::deliver_at) + "\" ASC";

				soci::rowset< soci::row > rs = (m_sql.prepare << sql, soci::use(serverID), soci::use(nowMs));
				for (const auto &row : rs) {
					out.push_back(rowToMessage(serverID, row));
				}

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(::mdb::AccessException("Failed to list due scheduled messages on server "
															  + std::to_string(serverID)));
			}
			return out;
		}

		std::optional< long long > ScheduledMessageTable::nextPendingDeliverAt(unsigned int serverID) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				long long next = 0;
				soci::indicator ind = soci::i_null;
				m_sql << "SELECT MIN(\"" << column::deliver_at << "\") FROM \"" << NAME << "\" WHERE \""
					  << column::server_id << "\" = :sid AND \"" << column::status << "\" = 0",
					soci::into(next, ind), soci::use(serverID);

				transaction.commit();
				if (ind != soci::i_ok) {
					return std::nullopt;
				}
				return next;
			} catch (const soci::soci_error &) {
				return std::nullopt;
			}
		}

		void ScheduledMessageTable::migrate(unsigned int fromSchemaVersion, unsigned int toSchemaVersion) {
			assert(fromSchemaVersion <= toSchemaVersion);
			try {
				if (fromSchemaVersion < 19) {
					// Table introduced in schema version 19, nothing to migrate from.
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
