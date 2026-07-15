// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_SERVER_DATABASE_FORUMTABLE_H_
#define MUMBLE_SERVER_DATABASE_FORUMTABLE_H_

#include "database/Backend.h"
#include "database/Table.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace soci {
class session;
}

namespace mumble {
namespace server {
	namespace db {

		class ServerTable;

		// One row of the forum_posts table. A post is either a thread root
		// (threadId == postId) or a reply within a thread.
		struct ForumStoredPost {
			unsigned int serverID  = 0;
			unsigned int channelId = 0;
			std::string postId;
			std::string threadId;
			std::string title;
			std::string body;
			std::string authorHash;
			std::string authorName;
			long long createdAt = 0;
			long long editedAt  = 0;
			bool deleted        = false;
			// Populated only by listThreadRoots(): number of (non-deleted)
			// replies in the thread. Not a stored column.
			unsigned int replyCount = 0;
		};

		// Persistent storage for the per-channel threaded forums.
		class ForumTable : public ::mumble::db::Table {
		public:
			static constexpr const char *NAME = "forum_posts";

			struct column {
				column()                                 = delete;
				static constexpr const char *server_id   = "server_id";
				static constexpr const char *post_id     = "post_id";
				static constexpr const char *thread_id   = "thread_id";
				static constexpr const char *channel_id  = "channel_id";
				static constexpr const char *title       = "title";
				static constexpr const char *body        = "body";
				static constexpr const char *author_hash = "author_hash";
				static constexpr const char *author_name = "author_name";
				static constexpr const char *created_at  = "created_at";
				static constexpr const char *edited_at   = "edited_at";
				static constexpr const char *deleted     = "deleted";
			};

			ForumTable(soci::session &sql, ::mumble::db::Backend backend, const ServerTable &serverTable);
			~ForumTable() = default;

			// Insert a new post or replace an existing one with the same
			// (server_id, post_id). Returns false on a database error.
			bool storePost(const ForumStoredPost &post);

			// Fetch a single post by id (regardless of deleted flag).
			std::optional< ForumStoredPost > getPost(unsigned int serverID, const std::string &postId);

			// List thread roots in a channel, most recently active first.
			// "Active" is the greatest created_at among the thread's posts.
			// replyCount is filled for each returned root. Deleted roots are
			// excluded.
			std::vector< ForumStoredPost > listThreadRoots(unsigned int serverID, unsigned int channelId,
														   unsigned int limit);

			// List all posts within a thread (root first), oldest reply first.
			// Deleted posts are excluded.
			std::vector< ForumStoredPost > listThreadPosts(unsigned int serverID, const std::string &threadId,
														   unsigned int limit);

			// Mark a single post as deleted (soft delete). Returns true if a
			// row was affected.
			bool markDeleted(unsigned int serverID, const std::string &postId);

			// Mark every post in a thread as deleted. Returns the ids of the
			// posts that were affected (so callers can broadcast the removal).
			std::vector< std::string > markThreadDeleted(unsigned int serverID, const std::string &threadId);

			void migrate(unsigned int fromSchemaVersion, unsigned int toSchemaVersion) override;
		};

	} // namespace db
} // namespace server
} // namespace mumble

#endif // MUMBLE_SERVER_DATABASE_FORUMTABLE_H_
