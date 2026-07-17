// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_SERVER_DATABASE_USERPROPERTY_H_
#define MUMBLE_SERVER_DATABASE_USERPROPERTY_H_

namespace mumble {
namespace server {
	namespace db {

		/**
		 * An enum for all existing user properties
		 */
		enum class UserProperty : unsigned int {
			Name,
			Email,
			Comment,
			CertificateHash,
			Password,
			LastActive,
			kdfIterations,
			// Fancy extension: base32-encoded RFC 6238 TOTP shared secret.
			// Empty / absent = two-factor authentication disabled. Must never
			// be handed out to clients (see DBWrapper::getUserProperties).
			TOTPSecret,
		};

	} // namespace db
} // namespace server
} // namespace mumble

#endif // MUMBLE_SERVER_DATABASE_USERPROPERTY_H_
