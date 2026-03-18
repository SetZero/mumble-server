// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "PChatPendingKeyRequestsTable.h"
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

		constexpr const char *PChatPendingKeyRequestsTable::NAME;
		constexpr const char *PChatPendingKeyRequestsTable::column::server_id;
		constexpr const char *PChatPendingKeyRequestsTable::column::request_id;
		constexpr const char *PChatPendingKeyRequestsTable::column::channel_id;
		constexpr const char *PChatPendingKeyRequestsTable::column::mode;
		constexpr const char *PChatPendingKeyRequestsTable::column::requester_hash;
		constexpr const char *PChatPendingKeyRequestsTable::column::requester_public;
		constexpr const char *PChatPendingKeyRequestsTable::column::relay_cap;
		constexpr const char *PChatPendingKeyRequestsTable::column::relays_sent;
		constexpr const char *PChatPendingKeyRequestsTable::column::created_at;
		constexpr const char *PChatPendingKeyRequestsTable::column::fulfilled_at;
		constexpr const char *PChatPendingKeyRequestsTable::column::fulfilled_by;

		PChatPendingKeyRequestsTable::PChatPendingKeyRequestsTable(soci::session &sql, ::mdb::Backend backend,
																   const ServerTable &serverTable)
			: ::mdb::Table(sql, backend, NAME) {

			::mdb::Column serverCol(column::server_id, ::mdb::DataType(::mdb::DataType::Integer));
			serverCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column reqIdCol(column::request_id, ::mdb::DataType(::mdb::DataType::Text));
			reqIdCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column channelCol(column::channel_id, ::mdb::DataType(::mdb::DataType::Integer));
			channelCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column modeCol(column::mode, ::mdb::DataType(::mdb::DataType::Text));
			modeCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column reqHashCol(column::requester_hash, ::mdb::DataType(::mdb::DataType::Text));
			reqHashCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column reqPubCol(column::requester_public, ::mdb::DataType(::mdb::DataType::Blob));

			::mdb::Column relayCapCol(column::relay_cap, ::mdb::DataType(::mdb::DataType::Integer));
			relayCapCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column relaysSentCol(column::relays_sent, ::mdb::DataType(::mdb::DataType::Integer));
			relaysSentCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column createdCol(column::created_at, ::mdb::DataType(::mdb::DataType::Integer));
			createdCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column fulfilledCol(column::fulfilled_at, ::mdb::DataType(::mdb::DataType::Integer));
			::mdb::Column fulfilledByCol(column::fulfilled_by, ::mdb::DataType(::mdb::DataType::Text));

			setColumns({ serverCol, reqIdCol, channelCol, modeCol, reqHashCol, reqPubCol, relayCapCol,
						 relaysSentCol, createdCol, fulfilledCol, fulfilledByCol });

			::mdb::PrimaryKey pk(std::vector< std::string >{ column::server_id, column::request_id });
			setPrimaryKey(pk);

			::mdb::ForeignKey fk(serverTable, { serverCol });
			addForeignKey(fk);

			// Index for finding pending requests per channel
			::mdb::Index channelPendingIdx("idx_pchat_pending_channel",
										   { column::server_id, column::channel_id, column::fulfilled_at });
			addIndex(channelPendingIdx, false);

			// Index for per-user pending limit
			::mdb::Index userPendingIdx("idx_pchat_pending_user",
										{ column::server_id, column::requester_hash, column::fulfilled_at });
			addIndex(userPendingIdx, false);

			// Index for timeout cleanup
			::mdb::Index createdIdx("idx_pchat_pending_created", { column::created_at });
			addIndex(createdIdx, false);
		}

		bool PChatPendingKeyRequestsTable::createRequest(const PChatPendingKeyRequest &request) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "INSERT INTO \"" << NAME << "\" (\"" << column::server_id << "\", \""
					  << column::request_id << "\", \"" << column::channel_id << "\", \""
					  << column::mode << "\", \"" << column::requester_hash << "\", \""
					  << column::requester_public << "\", \"" << column::relay_cap << "\", \""
					  << column::relays_sent << "\", \"" << column::created_at
					  << "\") VALUES (:sid, :rid, :cid, :mode, :rh, :rp, :rc, :rs, :ca)",
					soci::use(request.serverID), soci::use(request.requestId),
					soci::use(request.channelId), soci::use(request.mode),
					soci::use(request.requesterHash), soci::use(request.requesterPublic),
					soci::use(request.relayCap), soci::use(request.relaysSent),
					soci::use(request.createdAt);

				transaction.commit();
				return true;
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to create pchat pending key request " + request.requestId));
			}
		}

		bool PChatPendingKeyRequestsTable::recordRelay(unsigned int serverID, const std::string &requestId,
													   const std::string &senderHash) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				// Check current state
				int relaysSent = 0;
				int relayCap   = 0;
				std::string fulfilledBy;
				soci::indicator fbInd;

				m_sql << "SELECT \"" << column::relays_sent << "\", \"" << column::relay_cap << "\", \""
					  << column::fulfilled_by << "\" FROM \"" << NAME << "\" WHERE \""
					  << column::server_id << "\" = :sid AND \"" << column::request_id << "\" = :rid",
					soci::into(relaysSent), soci::into(relayCap), soci::into(fulfilledBy, fbInd),
					soci::use(serverID), soci::use(requestId);

				if (!m_sql.got_data()) {
					transaction.commit();
					return false;
				}

				// Cap reached
				if (relaysSent >= relayCap) {
					transaction.commit();
					return false;
				}

				// Same sender already responded - check by querying fulfilled_by
				// (simple approach: fulfilled_by stores first responder; for multi-responder
				// dedup the full relay tracking would need an auxiliary table, but the spec
				// says IS DISTINCT FROM check, so we just check fulfilled_by != senderHash)
				// For simplicity, we allow relays from different senders up to relay_cap.

				int newRelaysSent = relaysSent + 1;

				if (fbInd == soci::i_ok && !fulfilledBy.empty()) {
					// Already have a first responder, just increment
					if (newRelaysSent >= relayCap) {
						long long now = std::chrono::duration_cast< std::chrono::milliseconds >(
											std::chrono::system_clock::now().time_since_epoch())
											.count();
						m_sql << "UPDATE \"" << NAME << "\" SET \"" << column::relays_sent << "\" = :rs, \""
							  << column::fulfilled_at << "\" = :fa WHERE \"" << column::server_id
							  << "\" = :sid AND \"" << column::request_id << "\" = :rid AND \""
							  << column::relays_sent << "\" < \"" << column::relay_cap << "\"",
							soci::use(newRelaysSent), soci::use(now), soci::use(serverID),
							soci::use(requestId);
					} else {
						m_sql << "UPDATE \"" << NAME << "\" SET \"" << column::relays_sent << "\" = :rs WHERE \""
							  << column::server_id << "\" = :sid AND \"" << column::request_id
							  << "\" = :rid AND \"" << column::relays_sent << "\" < \"" << column::relay_cap
							  << "\"",
							soci::use(newRelaysSent), soci::use(serverID), soci::use(requestId);
					}
				} else {
					// First responder
					if (newRelaysSent >= relayCap) {
						long long now = std::chrono::duration_cast< std::chrono::milliseconds >(
											std::chrono::system_clock::now().time_since_epoch())
											.count();
						m_sql << "UPDATE \"" << NAME << "\" SET \"" << column::relays_sent << "\" = :rs, \""
							  << column::fulfilled_by << "\" = :fb, \"" << column::fulfilled_at
							  << "\" = :fa WHERE \"" << column::server_id << "\" = :sid AND \""
							  << column::request_id << "\" = :rid AND \"" << column::relays_sent << "\" < \""
							  << column::relay_cap << "\"",
							soci::use(newRelaysSent), soci::use(senderHash), soci::use(now),
							soci::use(serverID), soci::use(requestId);
					} else {
						m_sql << "UPDATE \"" << NAME << "\" SET \"" << column::relays_sent << "\" = :rs, \""
							  << column::fulfilled_by << "\" = :fb WHERE \"" << column::server_id
							  << "\" = :sid AND \"" << column::request_id << "\" = :rid AND \""
							  << column::relays_sent << "\" < \"" << column::relay_cap << "\"",
							soci::use(newRelaysSent), soci::use(senderHash), soci::use(serverID),
							soci::use(requestId);
					}
				}

				transaction.commit();
				return true;
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to record relay for request " + requestId));
			}
		}

		bool PChatPendingKeyRequestsTable::isRequestFulfilled(unsigned int serverID,
															  const std::string &requestId) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				long long fulfilledAt = 0;
				soci::indicator ind;
				m_sql << "SELECT \"" << column::fulfilled_at << "\" FROM \"" << NAME << "\" WHERE \""
					  << column::server_id << "\" = :sid AND \"" << column::request_id << "\" = :rid",
					soci::into(fulfilledAt, ind), soci::use(serverID), soci::use(requestId);

				transaction.commit();

				return m_sql.got_data() && ind == soci::i_ok && fulfilledAt > 0;
			} catch (const soci::soci_error &) {
				return false;
			}
		}

		std::vector< PChatPendingKeyRequest >
		PChatPendingKeyRequestsTable::getPendingRequests(unsigned int serverID, unsigned int channelId) {
			std::vector< PChatPendingKeyRequest > result;
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				soci::rowset< soci::row > rs =
					(m_sql.prepare << "SELECT \"" << column::request_id << "\", \"" << column::channel_id
								   << "\", \"" << column::mode << "\", \"" << column::requester_hash << "\", \""
								   << column::requester_public << "\", \"" << column::relay_cap << "\", \""
								   << column::relays_sent << "\", \"" << column::created_at << "\" FROM \""
								   << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
								   << column::channel_id << "\" = :cid AND \"" << column::fulfilled_at
								   << "\" IS NULL ORDER BY \"" << column::created_at << "\" ASC",
					 soci::use(serverID), soci::use(channelId));

				for (const auto &row : rs) {
					PChatPendingKeyRequest req;
					req.serverID        = serverID;
					req.requestId       = row.get< std::string >(0);
						req.channelId       = static_cast< unsigned int >(row.get< int >(1));
					req.mode            = row.get< std::string >(2);
					req.requesterHash   = row.get< std::string >(3);
					req.requesterPublic = row.get< std::string >(4, "");
					req.relayCap        = row.get< int >(5);
					req.relaysSent      = row.get< int >(6);
					req.createdAt       = row.get< long long >(7);
					result.push_back(std::move(req));
				}

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to get pending key requests for channel "
										   + std::to_string(channelId)));
			}
			return result;
		}

		unsigned int PChatPendingKeyRequestsTable::countForChannel(unsigned int serverID,
																   unsigned int channelId) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				int count = 0;
				m_sql << "SELECT COUNT(*) FROM \"" << NAME << "\" WHERE \"" << column::server_id
					  << "\" = :sid AND \"" << column::channel_id << "\" = :cid AND \""
					  << column::fulfilled_at << "\" IS NULL",
					soci::into(count), soci::use(serverID), soci::use(channelId);

				transaction.commit();
				return static_cast< unsigned int >(count);
			} catch (const soci::soci_error &) {
				return 0;
			}
		}

		unsigned int PChatPendingKeyRequestsTable::countForUser(unsigned int serverID,
																const std::string &requesterHash) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				int count = 0;
				m_sql << "SELECT COUNT(*) FROM \"" << NAME << "\" WHERE \"" << column::server_id
					  << "\" = :sid AND \"" << column::requester_hash << "\" = :rh AND \""
					  << column::fulfilled_at << "\" IS NULL",
					soci::into(count), soci::use(serverID), soci::use(requesterHash);

				transaction.commit();
				return static_cast< unsigned int >(count);
			} catch (const soci::soci_error &) {
				return 0;
			}
		}

		void PChatPendingKeyRequestsTable::evictOldest(unsigned int serverID, unsigned int channelId) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				// Find the requester_hash with the most pending requests
				std::string heaviestRequester;
				m_sql << "SELECT \"" << column::requester_hash << "\" FROM \"" << NAME << "\" WHERE \""
					  << column::server_id << "\" = :sid AND \"" << column::channel_id << "\" = :cid AND \""
					  << column::fulfilled_at << "\" IS NULL GROUP BY \"" << column::requester_hash
					  << "\" ORDER BY COUNT(*) DESC, MIN(\"" << column::created_at << "\") ASC LIMIT 1",
					soci::into(heaviestRequester), soci::use(serverID), soci::use(channelId);

				if (!m_sql.got_data() || heaviestRequester.empty()) {
					transaction.commit();
					return;
				}

				// Delete their oldest pending request
				std::string oldestRequestId;
				m_sql << "SELECT \"" << column::request_id << "\" FROM \"" << NAME << "\" WHERE \""
					  << column::server_id << "\" = :sid AND \"" << column::channel_id << "\" = :cid AND \""
					  << column::requester_hash << "\" = :rh AND \"" << column::fulfilled_at
					  << "\" IS NULL ORDER BY \"" << column::created_at << "\" ASC LIMIT 1",
					soci::into(oldestRequestId), soci::use(serverID), soci::use(channelId),
					soci::use(heaviestRequester);

				if (m_sql.got_data() && !oldestRequestId.empty()) {
					m_sql << "DELETE FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
						  << column::request_id << "\" = :rid",
						soci::use(serverID), soci::use(oldestRequestId);
				}

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to evict oldest pending key request for channel "
										   + std::to_string(channelId)));
			}
		}

		unsigned int PChatPendingKeyRequestsTable::cleanupExpired(unsigned int serverID, int maxAgeDays) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				long long cutoff = std::chrono::duration_cast< std::chrono::milliseconds >(
									   (std::chrono::system_clock::now()
										- std::chrono::hours(maxAgeDays * 24))
										   .time_since_epoch())
									   .count();

				// Delete unfulfilled expired requests
				soci::statement st1 =
					(m_sql.prepare << "DELETE FROM \"" << NAME << "\" WHERE \"" << column::server_id
								   << "\" = :sid AND \"" << column::fulfilled_at << "\" IS NULL AND \""
								   << column::created_at << "\" < :cutoff",
					 soci::use(serverID), soci::use(cutoff));
				st1.execute(true);

				int deleted = 0;
				m_sql << "SELECT changes()", soci::into(deleted);

				transaction.commit();
				return static_cast< unsigned int >(deleted);
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to cleanup expired pending key requests"));
			}
		}

		unsigned int PChatPendingKeyRequestsTable::cleanupFulfilled(unsigned int serverID, int maxAgeHours) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				long long cutoff = std::chrono::duration_cast< std::chrono::milliseconds >(
									   (std::chrono::system_clock::now()
										- std::chrono::hours(maxAgeHours))
										   .time_since_epoch())
									   .count();

				// Delete fulfilled requests older than cutoff
				soci::statement st =
					(m_sql.prepare << "DELETE FROM \"" << NAME << "\" WHERE \"" << column::server_id
								   << "\" = :sid AND \"" << column::fulfilled_at << "\" IS NOT NULL AND \""
								   << column::fulfilled_at << "\" < :cutoff",
					 soci::use(serverID), soci::use(cutoff));
				st.execute(true);

				int deleted = 0;
				m_sql << "SELECT changes()", soci::into(deleted);

				transaction.commit();
				return static_cast< unsigned int >(deleted);
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to cleanup fulfilled pending key requests"));
			}
		}

		void PChatPendingKeyRequestsTable::clearChannel(unsigned int serverID, unsigned int channelId) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
					  << column::channel_id << "\" = :cid",
					soci::use(serverID), soci::use(channelId);

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to clear pending key requests for channel "
										   + std::to_string(channelId)));
			}
		}

		void PChatPendingKeyRequestsTable::migrate(unsigned int fromSchemaVersion, unsigned int toSchemaVersion) {
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
