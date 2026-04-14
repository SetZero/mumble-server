// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "PChatPinTable.h"
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

		constexpr const char *PChatPinTable::NAME;
		constexpr const char *PChatPinTable::column::server_id;
		constexpr const char *PChatPinTable::column::channel_id;
		constexpr const char *PChatPinTable::column::message_id;
		constexpr const char *PChatPinTable::column::pinner_hash;
		constexpr const char *PChatPinTable::column::pinner_name;
		constexpr const char *PChatPinTable::column::timestamp;
		constexpr const char *PChatPinTable::column::created_at;

		PChatPinTable::PChatPinTable(soci::session &sql, ::mdb::Backend backend,
		                             const ServerTable &serverTable)
			: ::mdb::Table(sql, backend, NAME) {

			::mdb::Column serverCol(column::server_id, ::mdb::DataType(::mdb::DataType::Integer));
			serverCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column channelCol(column::channel_id, ::mdb::DataType(::mdb::DataType::Integer));
			channelCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column messageCol(column::message_id, ::mdb::DataType(::mdb::DataType::Text));
			messageCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column pinnerCol(column::pinner_hash, ::mdb::DataType(::mdb::DataType::Text));
			pinnerCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column nameCol(column::pinner_name, ::mdb::DataType(::mdb::DataType::Text));

			::mdb::Column tsCol(column::timestamp, ::mdb::DataType(::mdb::DataType::Integer));
			tsCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column createdCol(column::created_at, ::mdb::DataType(::mdb::DataType::Integer));
			createdCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			setColumns({ serverCol, channelCol, messageCol, pinnerCol, nameCol, tsCol, createdCol });

			// One pin per message per (server, channel)
			::mdb::PrimaryKey pk(std::vector< std::string >{
				column::server_id, column::channel_id, column::message_id });
			setPrimaryKey(pk);

			::mdb::ForeignKey fk(serverTable, { serverCol });
			addForeignKey(fk);

			// Index for channel-based queries (list all pins)
			::mdb::Index chanIdx("idx_pchat_pins_channel",
			                     { column::server_id, column::channel_id });
			addIndex(chanIdx, false);
		}

		bool PChatPinTable::addPin(const PChatPin &pin) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				int exists = 0;
				m_sql << "SELECT 1 FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
				      << column::channel_id << "\" = :cid AND \"" << column::message_id << "\" = :mid",
					soci::into(exists), soci::use(pin.serverID), soci::use(pin.channelId),
					soci::use(pin.messageId);

				if (m_sql.got_data()) {
					transaction.commit();
					return false;
				}

				m_sql << "INSERT INTO \"" << NAME << "\" (\"" << column::server_id << "\", \""
				      << column::channel_id << "\", \"" << column::message_id << "\", \""
				      << column::pinner_hash << "\", \"" << column::pinner_name << "\", \""
				      << column::timestamp << "\", \"" << column::created_at
				      << "\") VALUES (:sid, :cid, :mid, :ph, :pn, :ts, :ca)",
					soci::use(pin.serverID), soci::use(pin.channelId),
					soci::use(pin.messageId), soci::use(pin.pinnerHash),
					soci::use(pin.pinnerName), soci::use(pin.timestamp),
					soci::use(pin.createdAt);

				transaction.commit();
				return true;
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to add pin on message " + pin.messageId));
			}
		}

		void PChatPinTable::removePin(unsigned int serverID, unsigned int channelId,
		                              const std::string &messageId) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
				      << column::channel_id << "\" = :cid AND \"" << column::message_id << "\" = :mid",
					soci::use(serverID), soci::use(channelId), soci::use(messageId);

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to remove pin on message " + messageId));
			}
		}

		std::vector< PChatPin > PChatPinTable::getChannelPins(unsigned int serverID,
		                                                      unsigned int channelId) const {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				std::vector< PChatPin > result;

				soci::rowset< soci::row > rows =
					(m_sql.prepare << "SELECT \"" << column::message_id << "\", \"" << column::pinner_hash
					               << "\", \"" << column::pinner_name << "\", \""
					               << column::timestamp << "\", \"" << column::created_at
					               << "\" FROM \"" << NAME << "\" WHERE \""
					               << column::server_id << "\" = :sid AND \"" << column::channel_id
					               << "\" = :cid ORDER BY \"" << column::timestamp << "\" ASC",
					 soci::use(serverID), soci::use(channelId));

				for (const auto &row : rows) {
					PChatPin p;
					p.serverID   = serverID;
					p.channelId  = channelId;
					p.messageId  = row.get< std::string >(0);
					p.pinnerHash = row.get< std::string >(1);
					p.pinnerName = row.get< std::string >(2, "");
					p.timestamp  = row.get< long long >(3);
					p.createdAt  = row.get< long long >(4);
					result.push_back(std::move(p));
				}

				return result;
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to get pins for channel " + std::to_string(channelId)));
			}
		}

		bool PChatPinTable::isPinned(unsigned int serverID, unsigned int channelId,
		                             const std::string &messageId) const {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				int exists = 0;
				m_sql << "SELECT 1 FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
				      << column::channel_id << "\" = :cid AND \"" << column::message_id << "\" = :mid",
					soci::into(exists), soci::use(serverID), soci::use(channelId), soci::use(messageId);

				return m_sql.got_data();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to check pin status for message " + messageId));
			}
		}

		void PChatPinTable::clearMessage(unsigned int serverID, unsigned int channelId,
		                                 const std::string &messageId) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
				      << column::channel_id << "\" = :cid AND \"" << column::message_id << "\" = :mid",
					soci::use(serverID), soci::use(channelId), soci::use(messageId);

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to clear pin for message " + messageId));
			}
		}

		void PChatPinTable::clearChannel(unsigned int serverID, unsigned int channelId) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
				      << column::channel_id << "\" = :cid",
					soci::use(serverID), soci::use(channelId);

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to clear pins for channel " + std::to_string(channelId)));
			}
		}

		void PChatPinTable::migrate(unsigned int fromSchemaVersion, unsigned int toSchemaVersion) {
			// Table introduced at schema version 17 - no migrations needed yet.
			(void) fromSchemaVersion;
			(void) toSchemaVersion;
		}

	} // namespace db
} // namespace server
} // namespace mumble
