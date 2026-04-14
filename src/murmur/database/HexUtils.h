// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_SERVER_DATABASE_HEXUTILS_H_
#define MUMBLE_SERVER_DATABASE_HEXUTILS_H_

// Hex encoding helpers to avoid SOCI/SQLite BLOB NUL-truncation.
// SOCI's SQLite backend may use sqlite3_column_text() for std::string
// results, which truncates at the first NUL byte.  Binary fields are
// stored as hex TEXT so that round-tripping through SOCI is lossless.

#include <cctype>
#include <iomanip>
#include <sstream>
#include <string>

namespace mumble {
namespace server {
	namespace db {

		inline std::string toHex(const std::string &raw) {
			std::ostringstream oss;
			oss << std::hex << std::setfill('0');
			for (char rawC : raw) {
				oss << std::setw(2) << static_cast< unsigned int >(static_cast< unsigned char >(rawC));
			}
			return oss.str();
		}

		inline std::string fromHex(const std::string &hex) {
			// If the data is not valid hex (odd length or non-hex chars),
			// return it as-is -- this handles legacy raw BLOB data that
			// was stored before the hex-encoding migration.
			if (hex.size() % 2 != 0) {
				return hex;
			}
			for (char c : hex) {
				if (!std::isxdigit(static_cast< unsigned char >(c))) {
					return hex;
				}
			}
			std::string raw;
			raw.reserve(hex.size() / 2);
			for (size_t i = 0; i + 1 < hex.size(); i += 2) {
				unsigned int byte = 0;
				std::istringstream iss(hex.substr(i, 2));
				iss >> std::hex >> byte;
				raw.push_back(static_cast< char >(byte));
			}
			return raw;
		}

	} // namespace db
} // namespace server
} // namespace mumble

#endif // MUMBLE_SERVER_DATABASE_HEXUTILS_H_
