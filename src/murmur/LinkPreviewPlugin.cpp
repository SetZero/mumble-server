// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#include "LinkPreviewPlugin.h"

#include <QHostAddress>
#include <QHostInfo>

bool LinkPreviewPlugin::isSafeUrl(const QUrl &url) {
	QString scheme = url.scheme().toLower();
	if (scheme != QLatin1String("http") && scheme != QLatin1String("https"))
		return false;

	QString host = url.host().toLower();
	if (host.isEmpty())
		return false;
	return !isPrivateAddress(host);
}

bool LinkPreviewPlugin::isBlockedIp(const QHostAddress &addr) {
	// An address we could not parse is never safe to connect to.
	if (addr.isNull())
		return true;

	if (addr.isLoopback() || addr.isLinkLocal() || addr.isBroadcast() || addr.isMulticast())
		return true;

	// Normalise IPv4 and IPv4-mapped/compat IPv6 (e.g. ::ffff:127.0.0.1,
	// ::ffff:7f00:1) down to their embedded IPv4 address so alternate
	// encodings cannot smuggle an internal target past the range checks.
	bool isIPv4 = false;
	const quint32 v4 = addr.toIPv4Address(&isIPv4);
	if (isIPv4) {
		const QHostAddress a(v4);
		if (a.isInSubnet(QHostAddress(QStringLiteral("0.0.0.0")), 8)) // "this host" / 0.0.0.0
			return true;
		if (a.isInSubnet(QHostAddress(QStringLiteral("10.0.0.0")), 8))
			return true;
		if (a.isInSubnet(QHostAddress(QStringLiteral("100.64.0.0")), 10)) // CGNAT (RFC 6598)
			return true;
		if (a.isInSubnet(QHostAddress(QStringLiteral("127.0.0.0")), 8))
			return true;
		if (a.isInSubnet(QHostAddress(QStringLiteral("169.254.0.0")), 16))
			return true;
		if (a.isInSubnet(QHostAddress(QStringLiteral("172.16.0.0")), 12))
			return true;
		if (a.isInSubnet(QHostAddress(QStringLiteral("192.0.0.0")), 24)) // IETF protocol assignments
			return true;
		if (a.isInSubnet(QHostAddress(QStringLiteral("192.168.0.0")), 16))
			return true;
		return false;
	}

	// Pure IPv6.
	if (addr == QHostAddress(QHostAddress::LocalHostIPv6)) // ::1
		return true;
	if (addr == QHostAddress(QHostAddress::AnyIPv6)) // ::
		return true;
	if (addr.isInSubnet(QHostAddress(QStringLiteral("fc00::")), 7)) // unique local
		return true;
	if (addr.isInSubnet(QHostAddress(QStringLiteral("fe80::")), 10)) // link-local
		return true;
	return false;
}

bool LinkPreviewPlugin::isPrivateAddress(const QString &host) {
	QHostAddress addr(host);
	if (!addr.isNull())
		return isBlockedIp(addr);

	// Host-name based checks.  These are a best-effort fast path only; the
	// authoritative check happens after DNS resolution in resolveAndCheck(),
	// because a public name can still resolve to an internal address.
	const QString h = host.toLower();
	if (h == QLatin1String("localhost") || h.endsWith(QLatin1String(".localhost"))
		|| h.endsWith(QLatin1String(".local")) || h.endsWith(QLatin1String(".internal"))) {
		return true;
	}
	return false;
}

void LinkPreviewPlugin::resolveAndCheck(const QUrl &url, QObject *ctx,
										std::function< void() > onSafe,
										std::function< void() > onUnsafe) {
	// Scheme / structural / literal-IP checks first (no DNS).
	if (!isSafeUrl(url)) {
		onUnsafe();
		return;
	}

	// A literal IP host was already classified authoritatively by isSafeUrl()
	// (via isBlockedIp), so no resolution is required.
	const QString host = url.host();
	if (!QHostAddress(host).isNull()) {
		onSafe();
		return;
	}

	// Host name: resolve it and reject the URL if ANY returned address is
	// internal.  This closes the SSRF hole where a public name (e.g.
	// metadata.attacker.com) carries an A record pointing at 127.0.0.1,
	// 169.254.169.254, an RFC1918 host, etc.
	QHostInfo::lookupHost(host, ctx,
						  [onSafe = std::move(onSafe), onUnsafe = std::move(onUnsafe)](
							  const QHostInfo &info) {
							  if (info.error() != QHostInfo::NoError || info.addresses().isEmpty()) {
								  onUnsafe();
								  return;
							  }
							  for (const QHostAddress &addr : info.addresses()) {
								  if (isBlockedIp(addr)) {
									  onUnsafe();
									  return;
								  }
							  }
							  onSafe();
						  });
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
