// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#include "LinkPreviewPlugin.h"

#include <QHostAddress>

bool LinkPreviewPlugin::isSafeUrl(const QUrl &url) {
	QString scheme = url.scheme().toLower();
	if (scheme != QLatin1String("http") && scheme != QLatin1String("https"))
		return false;

	QString host = url.host().toLower();
	if (host.isEmpty())
		return false;
	return !isPrivateAddress(host);
}

bool LinkPreviewPlugin::isPrivateAddress(const QString &host) {
	QHostAddress addr(host);
	if (!addr.isNull()) {
		if (addr.isLoopback() || addr.isLinkLocal() || addr.isBroadcast() || addr.isMulticast())
			return true;
		if (addr.isInSubnet(QHostAddress(QStringLiteral("10.0.0.0")), 8))
			return true;
		if (addr.isInSubnet(QHostAddress(QStringLiteral("172.16.0.0")), 12))
			return true;
		if (addr.isInSubnet(QHostAddress(QStringLiteral("192.168.0.0")), 16))
			return true;
		if (addr.isInSubnet(QHostAddress(QStringLiteral("169.254.0.0")), 16))
			return true;
		if (addr.isInSubnet(QHostAddress(QStringLiteral("127.0.0.0")), 8))
			return true;
		// IPv6 unique local + link-local.
		if (addr.isInSubnet(QHostAddress(QStringLiteral("fc00::")), 7))
			return true;
		if (addr.isInSubnet(QHostAddress(QStringLiteral("fe80::")), 10))
			return true;
		if (addr == QHostAddress(QStringLiteral("::1")))
			return true;
		return false;
	}

	// Hostname-based checks.
	if (host == QLatin1String("localhost") || host.endsWith(QLatin1String(".localhost"))
		|| host.endsWith(QLatin1String(".local")) || host.endsWith(QLatin1String(".internal"))) {
		return true;
	}
	return false;
}

QString LinkPreviewPlugin::decodeHtmlEntities(const QString &input) {
	QString s = input;
	s.replace(QStringLiteral("&amp;"), QStringLiteral("&"));
	s.replace(QStringLiteral("&lt;"), QStringLiteral("<"));
	s.replace(QStringLiteral("&gt;"), QStringLiteral(">"));
	s.replace(QStringLiteral("&quot;"), QStringLiteral("\""));
	s.replace(QStringLiteral("&#39;"), QStringLiteral("'"));
	s.replace(QStringLiteral("&apos;"), QStringLiteral("'"));
	return s;
}
