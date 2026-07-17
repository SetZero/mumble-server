// Copyright The Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// Mumble source tree or at <https://www.mumble.info/LICENSE>.

#include "Totp.h"
#include "crypto/CryptographicRandom.h"

#include <QtCore/QMessageAuthenticationCode>
#include <QtCore/QUrl>

#include <cstring>

namespace {
const char BASE32_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
}

QString Totp::base32Encode(const QByteArray &data) {
	QString out;
	out.reserve((data.size() * 8 + 4) / 5);

	int buffer  = 0;
	int bits    = 0;
	for (const char byte : data) {
		buffer = (buffer << 8) | static_cast< unsigned char >(byte);
		bits += 8;
		while (bits >= 5) {
			bits -= 5;
			out.append(QLatin1Char(BASE32_ALPHABET[(buffer >> bits) & 0x1f]));
		}
	}
	if (bits > 0) {
		out.append(QLatin1Char(BASE32_ALPHABET[(buffer << (5 - bits)) & 0x1f]));
	}
	return out;
}

QByteArray Totp::base32Decode(const QString &encoded) {
	QByteArray out;
	out.reserve(encoded.size() * 5 / 8);

	int buffer = 0;
	int bits   = 0;
	for (const QChar qc : encoded) {
		const char c = qc.toUpper().toLatin1();
		if (c == '=' || c == ' ' || c == '-') {
			// Padding / grouping characters some apps emit; ignore.
			continue;
		}
		const char *pos = strchr(BASE32_ALPHABET, c);
		if (!pos || c == '\0') {
			return QByteArray();
		}
		buffer = (buffer << 5) | static_cast< int >(pos - BASE32_ALPHABET);
		bits += 5;
		if (bits >= 8) {
			bits -= 8;
			out.append(static_cast< char >((buffer >> bits) & 0xff));
		}
	}
	return out;
}

QString Totp::generateSecret() {
	QByteArray secret(SECRET_OCTETS, 0);
	CryptographicRandom::fillBuffer(secret.data(), static_cast< int >(secret.size()));
	return base32Encode(secret);
}

QString Totp::codeForTimeStep(const QByteArray &secret, quint64 timeStep) {
	// RFC 4226 5.3: HMAC-SHA1 over the big-endian 8-octet counter, then
	// dynamic truncation to a 31-bit integer, reduced to DIGITS digits.
	QByteArray counter(8, 0);
	for (int i = 7; i >= 0; --i) {
		counter[i] = static_cast< char >(timeStep & 0xff);
		timeStep >>= 8;
	}

	const QByteArray hmac = QMessageAuthenticationCode::hash(counter, secret, QCryptographicHash::Sha1);

	const int offset    = hmac.at(hmac.size() - 1) & 0x0f;
	const quint32 value = ((static_cast< quint32 >(hmac.at(offset)) & 0x7f) << 24)
						  | ((static_cast< quint32 >(hmac.at(offset + 1)) & 0xff) << 16)
						  | ((static_cast< quint32 >(hmac.at(offset + 2)) & 0xff) << 8)
						  | (static_cast< quint32 >(hmac.at(offset + 3)) & 0xff);

	quint32 modulus = 1;
	for (int i = 0; i < DIGITS; ++i) {
		modulus *= 10;
	}

	return QString(QLatin1String("%1")).arg(value % modulus, DIGITS, 10, QLatin1Char('0'));
}

bool Totp::verify(const QString &secretBase32, const QString &code, qint64 unixTime) {
	const QByteArray secret = base32Decode(secretBase32);
	if (secret.isEmpty() || code.length() != DIGITS || unixTime < 0) {
		return false;
	}

	const quint64 currentStep = static_cast< quint64 >(unixTime) / PERIOD_SECONDS;
	for (int drift = -DRIFT_STEPS; drift <= DRIFT_STEPS; ++drift) {
		if (drift < 0 && currentStep < static_cast< quint64 >(-drift)) {
			continue;
		}
		const quint64 step = currentStep + static_cast< quint64 >(drift);
		if (codeForTimeStep(secret, step) == code) {
			return true;
		}
	}
	return false;
}

QString Totp::buildProvisioningUri(const QString &issuer, const QString &account,
								   const QString &secretBase32) {
	// otpauth://totp/<issuer>:<account>?secret=..&issuer=..&algorithm=SHA1&digits=6&period=30
	const QString label = QString::fromLatin1("%1:%2").arg(issuer, account);
	return QString::fromLatin1("otpauth://totp/%1?secret=%2&issuer=%3&algorithm=SHA1&digits=%4&period=%5")
		.arg(QString::fromLatin1(QUrl::toPercentEncoding(label)), secretBase32,
			 QString::fromLatin1(QUrl::toPercentEncoding(issuer)), QString::number(DIGITS),
			 QString::number(PERIOD_SECONDS));
}
