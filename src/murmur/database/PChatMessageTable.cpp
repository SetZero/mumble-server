// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "PChatMessageTable.h"
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
#include <chrono>

namespace mdb = ::mumble::db;

namespace mumble {
namespace server {
	namespace db {

		constexpr const char *PChatMessageTable::NAME;
		constexpr const char *PChatMessageTable::column::server_id;
		constexpr const char *PChatMessageTable::column::message_id;
		constexpr const char *PChatMessageTable::column::channel_id;
		constexpr const char *PChatMessageTable::column::timestamp;
		constexpr const char *PChatMessageTable::column::sender_hash;
		constexpr const char *PChatMessageTable::column::mode;
		constexpr const char *PChatMessageTable::column::payload;
		constexpr const char *PChatMessageTable::column::payload_size;
		constexpr const char *PChatMessageTable::column::superseded_by;
		constexpr const char *PChatMessageTable::column::replaces_id;
		constexpr const char *PChatMessageTable::column::created_at;

		static long long nowMillis() {
			return std::chrono::duration_cast< std::chrono::milliseconds >(
					   std::chrono::system_clock::now().time_since_epoch())
				.count();
		}

		PChatMessageTable::PChatMessageTable(soci::session &sql, ::mdb::Backend backend,
											 const ServerTable &serverTable)
			: ::mdb::Table(sql, backend, NAME) {

			::mdb::Column serverCol(column::server_id, ::mdb::DataType(::mdb::DataType::Integer));
			serverCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column messageIdCol(column::message_id, ::mdb::DataType(::mdb::DataType::Text));
			messageIdCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column channelIdCol(column::channel_id, ::mdb::DataType(::mdb::DataType::Integer));
			channelIdCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column timestampCol(column::timestamp, ::mdb::DataType(::mdb::DataType::Integer));
			timestampCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column senderHashCol(column::sender_hash, ::mdb::DataType(::mdb::DataType::Text));
			senderHashCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column modeCol(column::mode, ::mdb::DataType(::mdb::DataType::Text));
			modeCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column payloadCol(column::payload, ::mdb::DataType(::mdb::DataType::Blob));
			payloadCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column payloadSizeCol(column::payload_size, ::mdb::DataType(::mdb::DataType::Integer));
			payloadSizeCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column supersededByCol(column::superseded_by, ::mdb::DataType(::mdb::DataType::Text));
			::mdb::Column replacesIdCol(column::replaces_id, ::mdb::DataType(::mdb::DataType::Text));

			::mdb::Column createdAtCol(column::created_at, ::mdb::DataType(::mdb::DataType::Integer));
			createdAtCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			setColumns({ serverCol, messageIdCol, channelIdCol, timestampCol, senderHashCol, modeCol, payloadCol,
						 payloadSizeCol, supersededByCol, replacesIdCol, createdAtCol });

			::mdb::PrimaryKey pk(std::vector< std::string >{ column::server_id, column::channel_id, column::sender_hash, column::message_id });
			setPrimaryKey(pk);

			::mdb::ForeignKey fk(serverTable, { serverCol });
			addForeignKey(fk);
		}

		bool PChatMessageTable::storeMessage(const PChatStoredMessage &msg) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				long long createdAt = nowMillis();

				m_sql << "INSERT INTO \"" << NAME << "\" (\"" << column::server_id << "\", \"" << column::message_id
					  << "\", \"" << column::channel_id << "\", \"" << column::timestamp << "\", \""
					  << column::sender_hash << "\", \"" << column::mode << "\", \"" << column::payload << "\", \""
					  << column::payload_size << "\", \"" << column::replaces_id << "\", \"" << column::created_at
					  << "\") VALUES (:sid, :mid, :cid, :ts, :sh, :mode, :payload, :psize, :rid, :cat)",
					soci::use(msg.serverID), soci::use(msg.messageId), soci::use(msg.channelId),
					soci::use(msg.timestamp), soci::use(msg.senderHash), soci::use(msg.protocol),
					soci::use(msg.payload), soci::use(msg.payloadSize), soci::use(msg.replacesId),
					soci::use(createdAt);

				transaction.commit();
				return true;
			} catch (const soci::soci_error &) {
				return false;
			}
		}

		PChatFetchResult PChatMessageTable::fetchMessages(unsigned int serverID, unsigned int channelId,
														  const std::string & /*requesterHash*/,
														  const std::string &beforeId, unsigned int limit,
														  long long joinedAtTimestamp) {
			PChatFetchResult result;
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				// Count total non-superseded messages
				int total = 0;
				m_sql << "SELECT COUNT(*) FROM \"" << NAME << "\" WHERE \"" << column::server_id
					  << "\" = :sid AND \"" << column::channel_id << "\" = :cid AND \"" << column::superseded_by
					  << "\" IS NULL",
					soci::into(total), soci::use(serverID), soci::use(channelId);
				result.totalStored = static_cast< unsigned int >(total);

				// Build query with optional cursor and join-time filter
				std::string sql = "SELECT \"" + std::string(column::message_id) + "\", \""
								  + column::channel_id + "\", \"" + column::timestamp + "\", \""
								  + column::sender_hash + "\", \"" + column::mode + "\", \""
								  + column::payload + "\", \"" + column::payload_size + "\", \""
								  + column::replaces_id + "\", \""
								  + column::created_at + "\" FROM \"" + std::string(NAME)
								  + "\" WHERE \"" + column::server_id + "\" = :sid AND \""
								  + column::channel_id + "\" = :cid AND \""
								  + column::superseded_by + "\" IS NULL";

				if (joinedAtTimestamp > 0) {
					sql += " AND \"" + std::string(column::timestamp) + "\" >= :jat";
				}

				if (!beforeId.empty()) {
					sql += " AND \"" + std::string(column::timestamp) + "\" < ("
						   "SELECT \"" + std::string(column::timestamp) + "\" FROM \"" + std::string(NAME)
						   + "\" WHERE \"" + column::message_id + "\" = :bid AND \""
						   + column::server_id + "\" = :sid2 AND \""
						   + column::channel_id + "\" = :cid2 LIMIT 1)";
				}

				sql += " ORDER BY \"" + std::string(column::timestamp) + "\" DESC LIMIT :lim";

				soci::statement st = (m_sql.prepare << sql);

				// Bind parameters - we need to use separate variables for binding
				unsigned int sid = serverID;
				unsigned int cid = channelId;
				int lim          = static_cast< int >(limit + 1);

				st.exchange(soci::use(sid, "sid"));
				st.exchange(soci::use(cid, "cid"));
				if (joinedAtTimestamp > 0) {
					st.exchange(soci::use(joinedAtTimestamp, "jat"));
				}
				if (!beforeId.empty()) {
					st.exchange(soci::use(beforeId, "bid"));
					st.exchange(soci::use(sid, "sid2"));
					st.exchange(soci::use(cid, "cid2"));
				}
				st.exchange(soci::use(lim, "lim"));

				std::string msgId, senderHash, mode, payload, replacesId;
				int chId = 0, psize = 0;
				long long ts = 0, cat = 0;
				st.exchange(soci::into(msgId));
				st.exchange(soci::into(chId));
				st.exchange(soci::into(ts));
				st.exchange(soci::into(senderHash));
				st.exchange(soci::into(mode));
				st.exchange(soci::into(payload));
				st.exchange(soci::into(psize));
				st.exchange(soci::into(replacesId));
				st.exchange(soci::into(cat));

				st.define_and_bind();
				st.execute();

				unsigned int count = 0;
				while (st.fetch()) {
					if (count >= limit) {
						result.hasMore = true;
						break;
					}
					PChatStoredMessage msg;
					msg.serverID    = serverID;
					msg.messageId   = msgId;
					msg.channelId   = static_cast< unsigned int >(chId);
					msg.timestamp   = ts;
					msg.senderHash  = senderHash;
					msg.protocol        = mode;
					msg.payload     = payload;
					msg.payloadSize = psize;
					msg.replacesId  = replacesId;
					msg.createdAt   = cat;
					if (static_cast<int>(payload.size()) != psize) {
						fprintf(stderr, "pchat: PAYLOAD TRUNCATION DETECTED for msg id=%s: stored_size=%d actual_size=%zu\n",
								 msgId.c_str(), psize, payload.size());
					}
					result.messages.push_back(std::move(msg));
					++count;
				}

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to fetch pchat messages for channel "
										   + std::to_string(channelId) + " on server " + std::to_string(serverID)));
			}
			return result;
		}

		bool PChatMessageTable::messageExists(unsigned int serverID, unsigned int channelId,
											  const std::string &senderHash, const std::string &messageId) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				int exists = 0;
				m_sql << "SELECT 1 FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
					  << column::channel_id << "\" = :cid AND \"" << column::sender_hash << "\" = :sh AND \""
					  << column::message_id << "\" = :mid",
					soci::into(exists), soci::use(serverID), soci::use(channelId), soci::use(senderHash),
					soci::use(messageId);

				transaction.commit();
				return exists != 0;
			} catch (const soci::soci_error &) {
				return false;
			}
		}

		bool PChatMessageTable::markSuperseded(unsigned int serverID, unsigned int channelId,
											   const std::string &senderHash, const std::string &originalId,
											   const std::string &newId) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "UPDATE \"" << NAME << "\" SET \"" << column::superseded_by << "\" = :newid WHERE \""
					  << column::message_id << "\" = :oid AND \"" << column::server_id << "\" = :sid AND \""
					  << column::channel_id << "\" = :cid AND \"" << column::sender_hash << "\" = :sh",
					soci::use(newId), soci::use(originalId), soci::use(serverID), soci::use(channelId),
					soci::use(senderHash);

				transaction.commit();
				return m_sql.got_data();
			} catch (const soci::soci_error &) {
				return false;
			}
		}

		unsigned int PChatMessageTable::cleanupExpired(unsigned int serverID, unsigned int channelId,
													   int retentionDays) {
			if (retentionDays <= 0) {
				return 0;
			}
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				long long cutoff = nowMillis() - static_cast< long long >(retentionDays) * 86400000LL;

				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
					  << column::channel_id << "\" = :cid AND \"" << column::created_at << "\" < :cutoff",
					soci::use(serverID), soci::use(channelId), soci::use(cutoff);

				transaction.commit();
				// SOCI doesn't provide affected row count easily; return 0 as a safe default
				return 0;
			} catch (const soci::soci_error &) {
				return 0;
			}
		}

		void PChatMessageTable::clearChannel(unsigned int serverID, unsigned int channelId) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
					  << column::channel_id << "\" = :cid",
					soci::use(serverID), soci::use(channelId);

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to clear pchat messages for channel "
										   + std::to_string(channelId) + " on server " + std::to_string(serverID)));
			}
		}

		void PChatMessageTable::clearUser(unsigned int serverID, const std::string &senderHash) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
					  << column::sender_hash << "\" = :sh",
					soci::use(serverID), soci::use(senderHash);

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to clear pchat messages for user "
										   + senderHash + " on server " + std::to_string(serverID)));
			}
		}

		unsigned int PChatMessageTable::deleteByIds(unsigned int serverID, unsigned int channelId,
											const std::vector< std::string > &messageIds) {
			if (messageIds.empty()) {
				return 0;
			}
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				for (const auto &mid : messageIds) {
					m_sql << "DELETE FROM \"" << NAME << "\" WHERE \""
							<< column::server_id << "\" = :sid AND \""
							<< column::channel_id << "\" = :cid AND \""
							<< column::message_id << "\" = :mid",
						soci::use(serverID), soci::use(channelId), soci::use(mid);
				}

				transaction.commit();
				return static_cast< unsigned int >(messageIds.size());
			} catch (const soci::soci_error &) {
				return 0;
			}
		}

		unsigned int PChatMessageTable::deleteByTimeRange(unsigned int serverID, unsigned int channelId,
											long long fromMs, long long toMs) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \""
							<< column::server_id << "\" = :sid AND \""
							<< column::channel_id << "\" = :cid AND \""
							<< column::timestamp << "\" >= :from_ms AND \""
							<< column::timestamp << "\" <= :to_ms",
						soci::use(serverID), soci::use(channelId), soci::use(fromMs), soci::use(toMs);

				transaction.commit();
				return 0;
			} catch (const soci::soci_error &) {
				return 0;
			}
		}

		unsigned int PChatMessageTable::deleteBySender(unsigned int serverID, unsigned int channelId,
											const std::string &senderHash) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \""
							<< column::server_id << "\" = :sid AND \""
							<< column::channel_id << "\" = :cid AND \""
							<< column::sender_hash << "\" = :sh",
						soci::use(serverID), soci::use(channelId), soci::use(senderHash);

				transaction.commit();
				return 0;
			} catch (const soci::soci_error &) {
				return 0;
			}
		}

		void PChatMessageTable::migrate(unsigned int fromSchemaVersion, unsigned int toSchemaVersion) {
			assert(fromSchemaVersion <= toSchemaVersion);
			try {
				if (fromSchemaVersion < 12) {
					// Table introduced in schema version 12, nothing to migrate from
				} else {
					mdb::Table::migrate(fromSchemaVersion, toSchemaVersion);
				}

				if (fromSchemaVersion >= 12 && fromSchemaVersion < 14) {
					// v14: Rename legacy protocol string values in the mode column.
					// Old values: "POST_JOIN", "FULL_ARCHIVE"
					// New values: "FANCY_V1_POST_JOIN", "FANCY_V1_FULL_ARCHIVE"
					m_sql << "UPDATE \"" << NAME << "\" SET \"" << column::mode
						  << "\" = 'FANCY_V1_POST_JOIN' WHERE \"" << column::mode
						  << "\" = 'POST_JOIN'";
					m_sql << "UPDATE \"" << NAME << "\" SET \"" << column::mode
						  << "\" = 'FANCY_V1_FULL_ARCHIVE' WHERE \"" << column::mode
						  << "\" = 'FULL_ARCHIVE'";
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
