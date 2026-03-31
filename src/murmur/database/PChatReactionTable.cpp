// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "PChatReactionTable.h"
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

		constexpr const char *PChatReactionTable::NAME;
		constexpr const char *PChatReactionTable::column::server_id;
		constexpr const char *PChatReactionTable::column::channel_id;
		constexpr const char *PChatReactionTable::column::message_id;
		constexpr const char *PChatReactionTable::column::emoji;
		constexpr const char *PChatReactionTable::column::is_server_emoji;
		constexpr const char *PChatReactionTable::column::sender_hash;
		constexpr const char *PChatReactionTable::column::sender_name;
		constexpr const char *PChatReactionTable::column::timestamp;
		constexpr const char *PChatReactionTable::column::created_at;

		PChatReactionTable::PChatReactionTable(soci::session &sql, ::mdb::Backend backend,
		                                       const ServerTable &serverTable)
			: ::mdb::Table(sql, backend, NAME) {

			::mdb::Column serverCol(column::server_id, ::mdb::DataType(::mdb::DataType::Integer));
			serverCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column channelCol(column::channel_id, ::mdb::DataType(::mdb::DataType::Integer));
			channelCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column messageCol(column::message_id, ::mdb::DataType(::mdb::DataType::Text));
			messageCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column emojiCol(column::emoji, ::mdb::DataType(::mdb::DataType::Text));
			emojiCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column isServerCol(column::is_server_emoji, ::mdb::DataType(::mdb::DataType::Integer));
			isServerCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column senderCol(column::sender_hash, ::mdb::DataType(::mdb::DataType::Text));
			senderCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column nameCol(column::sender_name, ::mdb::DataType(::mdb::DataType::Text));

			::mdb::Column tsCol(column::timestamp, ::mdb::DataType(::mdb::DataType::Integer));
			tsCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column createdCol(column::created_at, ::mdb::DataType(::mdb::DataType::Integer));
			createdCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			setColumns({ serverCol, channelCol, messageCol, emojiCol, isServerCol, senderCol, nameCol, tsCol, createdCol });

			// Unique per (server, channel, message, emoji, sender)
			::mdb::PrimaryKey pk(std::vector< std::string >{
				column::server_id, column::channel_id, column::message_id, column::emoji, column::sender_hash });
			setPrimaryKey(pk);

			::mdb::ForeignKey fk(serverTable, { serverCol });
			addForeignKey(fk);

			// Index for message-based queries (most common access pattern)
			::mdb::Index msgIdx("idx_pchat_reactions_message",
			                    { column::server_id, column::channel_id, column::message_id });
			addIndex(msgIdx, false);

			// Index for channel-based queries (batch fetch)
			::mdb::Index chanIdx("idx_pchat_reactions_channel",
			                     { column::server_id, column::channel_id });
			addIndex(chanIdx, false);
		}

		bool PChatReactionTable::addReaction(const PChatReaction &reaction) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				int exists = 0;
				m_sql << "SELECT 1 FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
				      << column::channel_id << "\" = :cid AND \"" << column::message_id << "\" = :mid AND \""
				      << column::emoji << "\" = :em AND \"" << column::sender_hash << "\" = :sh",
					soci::into(exists), soci::use(reaction.serverID), soci::use(reaction.channelId),
					soci::use(reaction.messageId), soci::use(reaction.emoji), soci::use(reaction.senderHash);

				if (m_sql.got_data()) {
					// Already exists
					transaction.commit();
					return false;
				}

				int isServer = reaction.isServerEmoji ? 1 : 0;
				m_sql << "INSERT INTO \"" << NAME << "\" (\"" << column::server_id << "\", \""
				      << column::channel_id << "\", \"" << column::message_id << "\", \""
				      << column::emoji << "\", \"" << column::is_server_emoji << "\", \""
				      << column::sender_hash << "\", \"" << column::sender_name << "\", \""
				      << column::timestamp << "\", \"" << column::created_at
				      << "\") VALUES (:sid, :cid, :mid, :em, :ise, :sh, :sn, :ts, :ca)",
					soci::use(reaction.serverID), soci::use(reaction.channelId),
					soci::use(reaction.messageId), soci::use(reaction.emoji),
					soci::use(isServer), soci::use(reaction.senderHash),
					soci::use(reaction.senderName), soci::use(reaction.timestamp),
					soci::use(reaction.createdAt);

				transaction.commit();
				return true;
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to add reaction on message " + reaction.messageId));
			}
		}

		void PChatReactionTable::removeReaction(unsigned int serverID, unsigned int channelId,
		                                        const std::string &messageId, const std::string &emoji,
		                                        bool isServerEmoji, const std::string &senderHash) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				int isServer = isServerEmoji ? 1 : 0;
				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
				      << column::channel_id << "\" = :cid AND \"" << column::message_id << "\" = :mid AND \""
				      << column::emoji << "\" = :em AND \"" << column::is_server_emoji << "\" = :ise AND \""
				      << column::sender_hash << "\" = :sh",
					soci::use(serverID), soci::use(channelId), soci::use(messageId),
					soci::use(emoji), soci::use(isServer), soci::use(senderHash);

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to remove reaction on message " + messageId));
			}
		}

		std::vector< PChatReaction > PChatReactionTable::getMessageReactions(unsigned int serverID,
		                                                                     unsigned int channelId,
		                                                                     const std::string &messageId) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				std::vector< PChatReaction > result;

				soci::rowset< soci::row > rows =
					(m_sql.prepare << "SELECT \"" << column::emoji << "\", \"" << column::is_server_emoji
					               << "\", \"" << column::sender_hash << "\", \"" << column::sender_name
					               << "\", \"" << column::timestamp << "\", \"" << column::created_at
					               << "\" FROM \"" << NAME << "\" WHERE \""
					               << column::server_id << "\" = :sid AND \"" << column::channel_id
					               << "\" = :cid AND \"" << column::message_id << "\" = :mid ORDER BY \""
					               << column::timestamp << "\" ASC",
					 soci::use(serverID), soci::use(channelId), soci::use(messageId));

				for (const auto &row : rows) {
					PChatReaction r;
					r.serverID      = serverID;
					r.channelId     = channelId;
					r.messageId     = messageId;
					r.emoji         = row.get< std::string >(0);
					r.isServerEmoji = row.get< int >(1, 0) != 0;
					r.senderHash    = row.get< std::string >(2);
					r.senderName    = row.get< std::string >(3, "");
					r.timestamp     = row.get< long long >(4);
					r.createdAt     = row.get< long long >(5);
					result.push_back(std::move(r));
				}

				return result;
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to get reactions for message " + messageId));
			}
		}

		std::vector< PChatReaction > PChatReactionTable::getChannelReactions(unsigned int serverID,
		                                                                     unsigned int channelId) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				std::vector< PChatReaction > result;

				soci::rowset< soci::row > rows =
					(m_sql.prepare << "SELECT \"" << column::message_id << "\", \"" << column::emoji
					               << "\", \"" << column::is_server_emoji << "\", \""
					               << column::sender_hash << "\", \"" << column::sender_name << "\", \""
					               << column::timestamp << "\", \"" << column::created_at
					               << "\" FROM \"" << NAME << "\" WHERE \""
					               << column::server_id << "\" = :sid AND \"" << column::channel_id
					               << "\" = :cid ORDER BY \"" << column::timestamp << "\" ASC",
					 soci::use(serverID), soci::use(channelId));

				for (const auto &row : rows) {
					PChatReaction r;
					r.serverID      = serverID;
					r.channelId     = channelId;
					r.messageId     = row.get< std::string >(0);
					r.emoji         = row.get< std::string >(1);
					r.isServerEmoji = row.get< int >(2, 0) != 0;
					r.senderHash    = row.get< std::string >(3);
					r.senderName    = row.get< std::string >(4, "");
					r.timestamp     = row.get< long long >(5);
					r.createdAt     = row.get< long long >(6);
					result.push_back(std::move(r));
				}

				return result;
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to get reactions for channel " + std::to_string(channelId)));
			}
		}

		std::vector< PChatReaction > PChatReactionTable::getReactionsForMessages(
			unsigned int serverID, unsigned int channelId,
			const std::vector< std::string > &messageIds) {

			if (messageIds.empty()) {
				return {};
			}

			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				std::vector< PChatReaction > result;

				// Build IN clause with placeholders
				for (const auto &mid : messageIds) {
					soci::rowset< soci::row > rows =
						(m_sql.prepare << "SELECT \"" << column::message_id << "\", \"" << column::emoji
						               << "\", \"" << column::is_server_emoji << "\", \""
						               << column::sender_hash << "\", \"" << column::sender_name << "\", \""
						               << column::timestamp << "\", \"" << column::created_at
						               << "\" FROM \"" << NAME << "\" WHERE \""
						               << column::server_id << "\" = :sid AND \"" << column::channel_id
						               << "\" = :cid AND \"" << column::message_id << "\" = :mid ORDER BY \""
						               << column::timestamp << "\" ASC",
						 soci::use(serverID), soci::use(channelId), soci::use(mid));

					for (const auto &row : rows) {
						PChatReaction r;
						r.serverID      = serverID;
						r.channelId     = channelId;
						r.messageId     = row.get< std::string >(0);
						r.emoji         = row.get< std::string >(1);
						r.isServerEmoji = row.get< int >(2, 0) != 0;
						r.senderHash    = row.get< std::string >(3);
						r.senderName    = row.get< std::string >(4, "");
						r.timestamp     = row.get< long long >(5);
						r.createdAt     = row.get< long long >(6);
						result.push_back(std::move(r));
					}
				}

				return result;
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to get reactions for message batch in channel "
					                       + std::to_string(channelId)));
			}
		}

		void PChatReactionTable::clearMessage(unsigned int serverID, unsigned int channelId,
		                                      const std::string &messageId) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
				      << column::channel_id << "\" = :cid AND \"" << column::message_id << "\" = :mid",
					soci::use(serverID), soci::use(channelId), soci::use(messageId);

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to clear reactions for message " + messageId));
			}
		}

		void PChatReactionTable::clearChannel(unsigned int serverID, unsigned int channelId) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
				      << column::channel_id << "\" = :cid",
					soci::use(serverID), soci::use(channelId);

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(
					::mdb::AccessException("Failed to clear reactions for channel " + std::to_string(channelId)));
			}
		}

		void PChatReactionTable::migrate(unsigned int fromSchemaVersion, unsigned int toSchemaVersion) {
			// Table introduced at schema version 16 - no migrations needed yet.
			(void) fromSchemaVersion;
			(void) toSchemaVersion;
		}

	} // namespace db
} // namespace server
} // namespace mumble
