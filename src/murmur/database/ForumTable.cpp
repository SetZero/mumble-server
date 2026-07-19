// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "ForumTable.h"
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

		constexpr const char *ForumTable::NAME;
		constexpr const char *ForumTable::column::server_id;
		constexpr const char *ForumTable::column::post_id;
		constexpr const char *ForumTable::column::thread_id;
		constexpr const char *ForumTable::column::channel_id;
		constexpr const char *ForumTable::column::title;
		constexpr const char *ForumTable::column::body;
		constexpr const char *ForumTable::column::author_hash;
		constexpr const char *ForumTable::column::author_name;
		constexpr const char *ForumTable::column::created_at;
		constexpr const char *ForumTable::column::edited_at;
		constexpr const char *ForumTable::column::deleted;

		ForumTable::ForumTable(soci::session &sql, ::mdb::Backend backend, const ServerTable &serverTable)
			: ::mdb::Table(sql, backend, NAME) {

			::mdb::Column serverCol(column::server_id, ::mdb::DataType(::mdb::DataType::Integer));
			serverCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column postIdCol(column::post_id, ::mdb::DataType(::mdb::DataType::Text));
			postIdCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column threadIdCol(column::thread_id, ::mdb::DataType(::mdb::DataType::Text));
			threadIdCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column channelIdCol(column::channel_id, ::mdb::DataType(::mdb::DataType::Integer));
			channelIdCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column titleCol(column::title, ::mdb::DataType(::mdb::DataType::Text));
			::mdb::Column bodyCol(column::body, ::mdb::DataType(::mdb::DataType::Text));
			bodyCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column authorHashCol(column::author_hash, ::mdb::DataType(::mdb::DataType::Text));
			authorHashCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column authorNameCol(column::author_name, ::mdb::DataType(::mdb::DataType::Text));

			::mdb::Column createdAtCol(column::created_at, ::mdb::DataType(::mdb::DataType::Integer));
			createdAtCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			::mdb::Column editedAtCol(column::edited_at, ::mdb::DataType(::mdb::DataType::Integer));

			::mdb::Column deletedCol(column::deleted, ::mdb::DataType(::mdb::DataType::Integer));
			deletedCol.addConstraint(::mdb::Constraint(::mdb::Constraint::NotNull));

			setColumns({ serverCol, postIdCol, threadIdCol, channelIdCol, titleCol, bodyCol, authorHashCol,
						 authorNameCol, createdAtCol, editedAtCol, deletedCol });

			::mdb::PrimaryKey pk(std::vector< std::string >{ column::server_id, column::post_id });
			setPrimaryKey(pk);

			::mdb::ForeignKey fk(serverTable, { serverCol });
			addForeignKey(fk);
		}

		bool ForumTable::storePost(const ForumStoredPost &post) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				// Upsert: replace any existing row with the same id. Works on
				// every backend without relying on ON CONFLICT syntax.
				m_sql << "DELETE FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
					  << column::post_id << "\" = :pid",
					soci::use(post.serverID), soci::use(post.postId);

				int deletedFlag = post.deleted ? 1 : 0;
				m_sql << "INSERT INTO \"" << NAME << "\" (\"" << column::server_id << "\", \"" << column::post_id
					  << "\", \"" << column::thread_id << "\", \"" << column::channel_id << "\", \"" << column::title
					  << "\", \"" << column::body << "\", \"" << column::author_hash << "\", \"" << column::author_name
					  << "\", \"" << column::created_at << "\", \"" << column::edited_at << "\", \"" << column::deleted
					  << "\") VALUES (:sid, :pid, :tid, :cid, :title, :body, :ah, :an, :cat, :eat, :del)",
					soci::use(post.serverID), soci::use(post.postId), soci::use(post.threadId),
					soci::use(post.channelId), soci::use(post.title), soci::use(post.body),
					soci::use(post.authorHash), soci::use(post.authorName), soci::use(post.createdAt),
					soci::use(post.editedAt), soci::use(deletedFlag);

				transaction.commit();
				return true;
			} catch (const soci::soci_error &) {
				return false;
			}
		}

		std::optional< ForumStoredPost > ForumTable::getPost(unsigned int serverID, const std::string &postId) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				std::string threadId, title, body, authorHash, authorName;
				int chId = 0, deletedFlag = 0;
				long long createdAt = 0, editedAt = 0;
				soci::indicator titleInd = soci::i_ok, nameInd = soci::i_ok;

				m_sql << "SELECT \"" << column::thread_id << "\", \"" << column::channel_id << "\", \"" << column::title
					  << "\", \"" << column::body << "\", \"" << column::author_hash << "\", \"" << column::author_name
					  << "\", \"" << column::created_at << "\", \"" << column::edited_at << "\", \"" << column::deleted
					  << "\" FROM \"" << NAME << "\" WHERE \"" << column::server_id << "\" = :sid AND \""
					  << column::post_id << "\" = :pid",
					soci::into(threadId), soci::into(chId), soci::into(title, titleInd), soci::into(body),
					soci::into(authorHash), soci::into(authorName, nameInd), soci::into(createdAt),
					soci::into(editedAt), soci::into(deletedFlag), soci::use(serverID), soci::use(postId);

				bool found = m_sql.got_data();
				transaction.commit();
				if (!found) {
					return std::nullopt;
				}

				ForumStoredPost post;
				post.serverID   = serverID;
				post.postId     = postId;
				post.threadId   = threadId;
				post.channelId  = static_cast< unsigned int >(chId);
				post.title      = (titleInd == soci::i_ok) ? title : std::string();
				post.body       = body;
				post.authorHash = authorHash;
				post.authorName = (nameInd == soci::i_ok) ? authorName : std::string();
				post.createdAt  = createdAt;
				post.editedAt   = editedAt;
				post.deleted    = deletedFlag != 0;
				return post;
			} catch (const soci::soci_error &) {
				return std::nullopt;
			}
		}

		std::vector< ForumStoredPost > ForumTable::listThreadRoots(unsigned int serverID, unsigned int channelId,
																   unsigned int limit) {
			std::vector< ForumStoredPost > roots;
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				// Roots are posts whose thread_id equals their own post_id.
				// Order by the most recent activity in the thread.
				std::string sql =
					"SELECT r.\"" + std::string(column::post_id) + "\", r.\"" + column::title + "\", r.\""
					+ column::body + "\", r.\"" + column::author_hash + "\", r.\"" + column::author_name + "\", r.\""
					+ column::created_at + "\", r.\"" + column::edited_at + "\" FROM \"" + std::string(NAME)
					+ "\" r WHERE r.\"" + column::server_id + "\" = :sid AND r.\"" + column::channel_id
					+ "\" = :cid AND r.\"" + column::thread_id + "\" = r.\"" + column::post_id + "\" AND r.\""
					+ column::deleted + "\" = 0 ORDER BY (SELECT MAX(a.\"" + std::string(column::created_at)
					+ "\") FROM \"" + std::string(NAME) + "\" a WHERE a.\"" + column::server_id + "\" = :sid AND a.\""
					+ column::thread_id + "\" = r.\"" + column::post_id + "\" AND a.\"" + column::deleted
					+ "\" = 0) DESC LIMIT :lim";

				soci::statement st = (m_sql.prepare << sql);

				unsigned int sid = serverID;
				unsigned int cid = channelId;
				int lim          = static_cast< int >(limit == 0 ? 50 : limit);
				st.exchange(soci::use(sid, "sid"));
				st.exchange(soci::use(cid, "cid"));
				st.exchange(soci::use(lim, "lim"));

				std::string postId, title, body, authorHash, authorName;
				long long createdAt = 0, editedAt = 0;
				soci::indicator titleInd = soci::i_ok, nameInd = soci::i_ok;
				st.exchange(soci::into(postId));
				st.exchange(soci::into(title, titleInd));
				st.exchange(soci::into(body));
				st.exchange(soci::into(authorHash));
				st.exchange(soci::into(authorName, nameInd));
				st.exchange(soci::into(createdAt));
				st.exchange(soci::into(editedAt));

				st.define_and_bind();
				st.execute();

				while (st.fetch()) {
					ForumStoredPost post;
					post.serverID   = serverID;
					post.channelId  = channelId;
					post.postId     = postId;
					post.threadId   = postId;
					post.title      = (titleInd == soci::i_ok) ? title : std::string();
					post.body       = body;
					post.authorHash = authorHash;
					post.authorName = (nameInd == soci::i_ok) ? authorName : std::string();
					post.createdAt  = createdAt;
					post.editedAt   = editedAt;
					roots.push_back(std::move(post));
				}

				// Count replies per returned thread (excludes the root itself).
				// NB: SOCI binds use() values positionally, so the repeated
				// thread id needs its own placeholder + use() - reusing :tid
				// twice leaves the second occurrence unbound (NULL), which
				// made the count come out 0 for every thread.
				for (auto &root : roots) {
					int count = 0;
					m_sql << "SELECT COUNT(*) FROM \"" << NAME << "\" WHERE \"" << column::server_id
						  << "\" = :sid AND \"" << column::thread_id << "\" = :tid AND \"" << column::post_id
						  << "\" <> :pid AND \"" << column::deleted << "\" = 0",
						soci::into(count), soci::use(serverID), soci::use(root.threadId), soci::use(root.threadId);
					root.replyCount = static_cast< unsigned int >(count);
				}

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(::mdb::AccessException("Failed to list forum threads for channel "
															  + std::to_string(channelId) + " on server "
															  + std::to_string(serverID)));
			}
			return roots;
		}

		std::vector< ForumStoredPost > ForumTable::listThreadPosts(unsigned int serverID, const std::string &threadId,
																   unsigned int limit) {
			std::vector< ForumStoredPost > posts;
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				// Root first (post_id == thread_id sorts identical created_at
				// ties are broken by the root having the earliest timestamp).
				std::string sql =
					"SELECT \"" + std::string(column::post_id) + "\", \"" + column::channel_id + "\", \"" + column::title
					+ "\", \"" + column::body + "\", \"" + column::author_hash + "\", \"" + column::author_name
					+ "\", \"" + column::created_at + "\", \"" + column::edited_at + "\" FROM \"" + std::string(NAME)
					+ "\" WHERE \"" + column::server_id + "\" = :sid AND \"" + column::thread_id + "\" = :tid AND \""
					+ column::deleted + "\" = 0 ORDER BY \"" + std::string(column::created_at) + "\" ASC LIMIT :lim";

				soci::statement st = (m_sql.prepare << sql);

				unsigned int sid = serverID;
				std::string tid  = threadId;
				int lim          = static_cast< int >(limit == 0 ? 200 : limit);
				st.exchange(soci::use(sid, "sid"));
				st.exchange(soci::use(tid, "tid"));
				st.exchange(soci::use(lim, "lim"));

				std::string postId, title, body, authorHash, authorName;
				int chId            = 0;
				long long createdAt = 0, editedAt = 0;
				soci::indicator titleInd = soci::i_ok, nameInd = soci::i_ok;
				st.exchange(soci::into(postId));
				st.exchange(soci::into(chId));
				st.exchange(soci::into(title, titleInd));
				st.exchange(soci::into(body));
				st.exchange(soci::into(authorHash));
				st.exchange(soci::into(authorName, nameInd));
				st.exchange(soci::into(createdAt));
				st.exchange(soci::into(editedAt));

				st.define_and_bind();
				st.execute();

				while (st.fetch()) {
					ForumStoredPost post;
					post.serverID   = serverID;
					post.channelId  = static_cast< unsigned int >(chId);
					post.postId     = postId;
					post.threadId   = threadId;
					post.title      = (titleInd == soci::i_ok) ? title : std::string();
					post.body       = body;
					post.authorHash = authorHash;
					post.authorName = (nameInd == soci::i_ok) ? authorName : std::string();
					post.createdAt  = createdAt;
					post.editedAt   = editedAt;
					posts.push_back(std::move(post));
				}

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(::mdb::AccessException("Failed to list forum posts for thread " + threadId
															  + " on server " + std::to_string(serverID)));
			}
			return posts;
		}

		bool ForumTable::markDeleted(unsigned int serverID, const std::string &postId) {
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				// got_data() only reports fetched rows, so it is always false
				// for an UPDATE - callers saw "nothing deleted" and skipped
				// the removal broadcast. Count the affected rows instead.
				int one            = 1;
				soci::statement st = (m_sql.prepare << "UPDATE \"" << NAME << "\" SET \"" << column::deleted
													<< "\" = :one WHERE \"" << column::server_id << "\" = :sid AND \""
													<< column::post_id << "\" = :pid",
									  soci::use(one), soci::use(serverID), soci::use(postId));
				st.execute(true);
				const bool affected = st.get_affected_rows() > 0;
				transaction.commit();
				return affected;
			} catch (const soci::soci_error &) {
				return false;
			}
		}

		std::vector< std::string > ForumTable::markThreadDeleted(unsigned int serverID, const std::string &threadId) {
			std::vector< std::string > deletedIds;
			try {
				::mdb::TransactionHolder transaction = ensureTransaction();

				// Collect ids first so callers can broadcast the removals.
				soci::rowset< std::string > rs =
					(m_sql.prepare << "SELECT \"" << column::post_id << "\" FROM \"" << NAME << "\" WHERE \""
									<< column::server_id << "\" = :sid AND \"" << column::thread_id << "\" = :tid AND \""
									<< column::deleted << "\" = 0",
					 soci::use(serverID), soci::use(threadId));
				for (const auto &id : rs) {
					deletedIds.push_back(id);
				}

				int one = 1;
				m_sql << "UPDATE \"" << NAME << "\" SET \"" << column::deleted << "\" = :one WHERE \""
					  << column::server_id << "\" = :sid AND \"" << column::thread_id << "\" = :tid",
					soci::use(one), soci::use(serverID), soci::use(threadId);

				transaction.commit();
			} catch (const soci::soci_error &) {
				std::throw_with_nested(::mdb::AccessException("Failed to delete forum thread " + threadId
															  + " on server " + std::to_string(serverID)));
			}
			return deletedIds;
		}

		void ForumTable::migrate(unsigned int fromSchemaVersion, unsigned int toSchemaVersion) {
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
