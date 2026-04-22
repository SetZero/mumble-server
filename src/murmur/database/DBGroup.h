// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_SERVER_DATABASE_DBGROUP_H_
#define MUMBLE_SERVER_DATABASE_DBGROUP_H_

#include <cstdint>
#include <string>
#include <vector>

namespace mumble {
namespace server {
	namespace db {

		struct DBGroup {
			unsigned int serverID  = {};
			unsigned int groupID   = {};
			unsigned int channelID = {};
			std::string name       = {};
			bool inherit           = true;
			bool is_inheritable    = true;

			// FancyMumble role customization fields.
			// `color`         - arbitrary CSS color string (e.g. "#5865F2"); empty when unset (TEXT).
			// `icon`          - raw image bytes (PNG/JPEG); empty when unset (BLOB).
			// `style_preset`  - named visual preset id; empty when unset (TEXT).
			// `metadata_json` - UTF-8 JSON object with arbitrary string keys/values; empty when unset (TEXT).
			std::string color                  = {};
			std::vector< std::uint8_t > icon   = {};
			std::string style_preset           = {};
			std::string metadata_json          = {};

			DBGroup() = default;

			friend bool operator==(const DBGroup &lhs, const DBGroup &rhs);
			friend bool operator!=(const DBGroup &lhs, const DBGroup &rhs);
		};

	} // namespace db
} // namespace server
} // namespace mumble

#endif // MUMBLE_SERVER_DATABASE_DBGROUP_H_
