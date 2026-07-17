// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#ifndef MUMBLE_MURMUR_TOTP_H_
#define MUMBLE_MURMUR_TOTP_H_

#include <QtCore/QString>

///
/// Fully static helper implementing RFC 6238 TOTP (HMAC-SHA1, 30 s time
/// step, 6 digits) as consumed by the common authenticator apps (Google
/// Authenticator, Microsoft Authenticator, Authy, Aegis, 1Password, ...).
///
class Totp {
public:
	/// Number of random octets in a generated shared secret (160 bit, the
	/// RFC 4226 recommended minimum and what authenticator apps expect).
	static const int SECRET_OCTETS = 20;
	/// Time-step size in seconds (RFC 6238 default).
	static const int PERIOD_SECONDS = 30;
	/// Number of code digits (RFC 4226 default).
	static const int DIGITS = 6;
	/// Accepted clock drift in time steps in each direction.
	static const int DRIFT_STEPS = 1;

	/// @return A freshly generated random shared secret, base32 encoded
	///         (RFC 3548 alphabet, no padding) for manual entry into an
	///         authenticator app. Empty string on RNG failure.
	static QString generateSecret();

	/// Verify a user-supplied code against the shared secret, allowing
	/// DRIFT_STEPS of clock drift in both directions.
	///
	/// @param secretBase32 Base32-encoded shared secret (as produced by
	///        generateSecret()).
	/// @param code The user-supplied code ("123456").
	/// @param unixTime Current time in seconds since the epoch.
	/// @return True when the code is valid for the given time.
	static bool verify(const QString &secretBase32, const QString &code, qint64 unixTime);

	/// Build an otpauth://totp/ provisioning URI understood by
	/// authenticator apps.
	///
	/// @param issuer Human-readable service name (percent-encoded into the URI).
	/// @param account Account label, usually the registered user name.
	/// @param secretBase32 Base32-encoded shared secret.
	static QString buildProvisioningUri(const QString &issuer, const QString &account,
										const QString &secretBase32);

	/// Compute the TOTP code for one specific time step. Exposed for tests.
	///
	/// @param secret Raw (decoded) shared secret.
	/// @param timeStep Time-step counter, i.e. floor(unixTime / PERIOD_SECONDS).
	/// @return Zero-padded DIGITS-character code.
	static QString codeForTimeStep(const QByteArray &secret, quint64 timeStep);

	/// Decode an RFC 3548 base32 string (case-insensitive, '=' padding and
	/// spaces ignored). Exposed for tests.
	///
	/// @return The decoded octets, or an empty array for invalid input.
	static QByteArray base32Decode(const QString &encoded);

	/// Encode octets using the RFC 3548 base32 alphabet without padding.
	/// Exposed for tests.
	static QString base32Encode(const QByteArray &data);
};

#endif // MUMBLE_MURMUR_TOTP_H_
