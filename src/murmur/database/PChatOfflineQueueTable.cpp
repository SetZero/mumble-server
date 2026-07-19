// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "PChatOfflineQueueTable.h"
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

		constexpr const char *PChatOfflineQueueTable::NAME;
		constexpr const char *PChatOfflineQueueTable::column::server_id;
		constexpr const char *PChatOfflineQueueTable::column::cert_hash;
		constexpr const char *PChatOfflineQueueTable::column::channel_id;
		constexpr const char *PChatOfflineQueueTable::column::message_id;
		constexpr const char *PChatOfflineQueueTable::column::sender_hash;
		constexpr const char *PChatOfflineQueueTable::column::timestamp;
		constexpr const char *PChatOfflineQueueTable::column::envelope;
		constexpr const char *PChatOfflineQueueTable::column::created_at;

		PChatOfflineQueueTable::PChatOfflineQueueTable(soci::session &sql, ::mdb::Backend backend,
													   const ServerTable &serverTable)
			: ::mdb::Table(sql, backend, NAME) {

			::mdb::Column serverCol(column::server_id, ::mdb::DataType(::mdb::DataType::Integer));
			serverCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column certHashCol(column::cert_hash, ::mdb::DataType(::mdb::DataType::Text));
			certHashCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column channelCol(column::channel_id, ::mdb::DataType(::mdb::DataType::Integer));
			channelCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column messageIdCol(column::message_id, ::mdb::DataType(::mdb::DataType::Text));
			messageIdCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column senderHashCol(column::sender_hash, ::mdb::DataType(::mdb::DataType::Text));
			senderHashCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column timestampCol(column::timestamp, ::mdb::DataType(::mdb::DataType::Integer));
			timestampCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column envelopeCol(column::envelope, ::mdb::DataType(::mdb::DataType::Text));
			envelopeCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column createdAtCol(column::created_at, ::mdb::DataType(::mdb::DataType::Integer));
			createdAtCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			setColumns({ serverCol, certHashCol, channelCol, messageIdCol,
						 senderHashCol, timestampCol, envelopeCol, createdAtCol });

			// Unique per (server, cert_hash, channel, message_id)
			::mdb::PrimaryKey pk(std::vector< std::string >{
				column::server_id, column::cert_hash, column::channel_id, column::message_id });
			setPrimaryKey(pk);

			::mdb::ForeignKey fk(serverTable, { serverCol });
			addForeignKey(fk);

			// Index for queue drain queries (cert_hash + channel)
			::mdb::Index queueIdx("idx_pchat_offline_queue_recipient",
								  { column::server_id, column::cert_hash, column::channel_id });
			addIndex(queueIdx, false);

			// Index for expiry cleanup (created_at)
			::mdb::Index expiryIdx("idx_pchat_offline_queue_expiry",
								   { column::server_id, column::created_at });
			addIndex(expiryIdx, false);
		}

		void PChatOfflineQueueTable::enqueue(const PChatOfflineQueueEntry &entry) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "INSERT INTO \"" << NAME << "\" (\"" << column::server_id << "\", \""
					  << column::cert_hash << "\", \"" << column::channel_id << "\", \""
					  << column::message_id << "\", \"" << column::sender_hash << "\", \""
					  << column::timestamp << "\", \"" << column::envelope << "\", \""
					  << column::created_at
					  << "\") VALUES (:sid, :ch, :cid, :mid, :sh, :ts, :env, :ca)",
					soci::use(entry.serverID), soci::use(entry.certHash),
					soci::use(entry.channelId), soci::use(entry.messageId),
					soci::use(entry.senderHash), soci::use(entry.timestamp),
					soci::use(entry.envelope), soci::use(entry.createdAt);

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to enqueue offline message for " + entry.certHash));
			}
		}

		std::vector< PChatOfflineQueueEntry > PChatOfflineQueueTable::fetchQueue(
			unsigned int serverID, const std::string &certHash, unsigned int channelId) {
			std::vector< PChatOfflineQueueEntry > result;
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				soci::rowset< soci::row > rs =
					(m_sql.prepare << "SELECT \"" << column::message_id << "\", \""
								   << column::sender_hash << "\", \"" << column::timestamp << "\", \""
								   << column::envelope << "\", \"" << column::created_at
								   << "\" FROM \"" << NAME << "\" WHERE \""
								   << column::server_id << "\" = :sid AND \""
								   << column::cert_hash << "\" = :ch AND \""
								   << column::channel_id << "\" = :cid ORDER BY \""
								   << column::timestamp << "\" ASC",
					 soci::use(serverID), soci::use(certHash), soci::use(channelId));

				for (const auto &row : rs) {
					PChatOfflineQueueEntry entry;
					entry.serverID  = serverID;
					entry.certHash  = certHash;
					entry.channelId = channelId;
					entry.messageId  = row.get< std::string >(0);
					entry.senderHash = row.get< std::string >(1);
					entry.timestamp  = row.get< long long >(2);
					entry.envelope   = row.get< std::string >(3);
					entry.createdAt  = row.get< long long >(4);
					result.push_back(std::move(entry));
				}

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to fetch offline queue for " + certHash));
			}
			return result;
		}

		void PChatOfflineQueueTable::deleteByIds(unsigned int serverID, const std::string &certHash,
												 unsigned int channelId,
												 const std::vector< std::string > &messageIds) {
			if (messageIds.empty()) {
				return;
			}
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				for (const auto &mid : messageIds) {
					m_sql << "DELETE FROM \"" << NAME << "\" WHERE \""
						  << column::server_id << "\" = :sid AND \""
						  << column::cert_hash << "\" = :ch AND \""
						  << column::channel_id << "\" = :cid AND \""
						  << column::message_id << "\" = :mid",
						soci::use(serverID), soci::use(certHash),
						soci::use(channelId), soci::use(mid);
				}

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to delete offline queue entries for " + certHash));
			}
		}

		void PChatOfflineQueueTable::deleteExpired(unsigned int serverID, long long cutoffMs) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \""
					  << column::server_id << "\" = :sid AND \""
					  << column::created_at << "\" < :cutoff",
					soci::use(serverID), soci::use(cutoffMs);

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to delete expired offline queue entries"));
			}
		}

		void PChatOfflineQueueTable::clearChannel(unsigned int serverID, unsigned int channelId) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \""
					  << column::server_id << "\" = :sid AND \""
					  << column::channel_id << "\" = :cid",
					soci::use(serverID), soci::use(channelId);

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to clear offline queue for channel "
										   + std::to_string(channelId)));
			}
		}

		void PChatOfflineQueueTable::clearUser(unsigned int serverID, const std::string &certHash) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \""
					  << column::server_id << "\" = :sid AND \""
					  << column::cert_hash << "\" = :ch",
					soci::use(serverID), soci::use(certHash);

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to clear offline queue for user " + certHash));
			}
		}

		void PChatOfflineQueueTable::enforceCapacity(unsigned int serverID, const std::string &certHash,
													 unsigned int channelId, unsigned int maxCapacity) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				// Count current entries
				int count = 0;
				m_sql << "SELECT COUNT(*) FROM \"" << NAME << "\" WHERE \""
					  << column::server_id << "\" = :sid AND \""
					  << column::cert_hash << "\" = :ch AND \""
					  << column::channel_id << "\" = :cid",
					soci::into(count), soci::use(serverID), soci::use(certHash), soci::use(channelId);

				if (static_cast< unsigned int >(count) <= maxCapacity) {
					transaction.commit();
					return;
				}

				// Delete oldest entries to bring count under the limit
				unsigned int toDelete = static_cast< unsigned int >(count) - maxCapacity;

				// Subquery to find the oldest N message_ids to delete
				soci::rowset< soci::row > rs =
					(m_sql.prepare << "SELECT \"" << column::message_id << "\" FROM \"" << NAME
								   << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
								   << column::cert_hash << "\" = :ch AND \""
								   << column::channel_id << "\" = :cid ORDER BY \""
								   << column::timestamp << "\" ASC LIMIT :lim",
					 soci::use(serverID), soci::use(certHash),
					 soci::use(channelId), soci::use(toDelete));

				std::vector< std::string > idsToDelete;
				for (const auto &row : rs) {
					idsToDelete.push_back(row.get< std::string >(0));
				}

				for (const auto &mid : idsToDelete) {
					m_sql << "DELETE FROM \"" << NAME << "\" WHERE \""
						  << column::server_id << "\" = :sid AND \""
						  << column::cert_hash << "\" = :ch AND \""
						  << column::channel_id << "\" = :cid AND \""
						  << column::message_id << "\" = :mid",
						soci::use(serverID), soci::use(certHash),
						soci::use(channelId), soci::use(mid);
				}

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to enforce offline queue capacity for " + certHash));
			}
		}

		unsigned int PChatOfflineQueueTable::countQueue(unsigned int serverID, const std::string &certHash,
													   unsigned int channelId) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				int count = 0;
				m_sql << "SELECT COUNT(*) FROM \"" << NAME << "\" WHERE \""
					  << column::server_id << "\" = :sid AND \""
					  << column::cert_hash << "\" = :ch AND \""
					  << column::channel_id << "\" = :cid",
					soci::into(count), soci::use(serverID), soci::use(certHash), soci::use(channelId);

				transaction.commit();
				return static_cast< unsigned int >(count);
			} catch (const soci::soci_error &) {
				return 0;
			}
		}

		void PChatOfflineQueueTable::migrate(unsigned int fromSchemaVersion, unsigned int toSchemaVersion) {
			assert(fromSchemaVersion <= toSchemaVersion);
			try {
				if (fromSchemaVersion < 15) {
					// Table introduced in schema version 15 - nothing to migrate from older schemas.
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
