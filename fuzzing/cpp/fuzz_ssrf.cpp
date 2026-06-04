// libFuzzer harness for the link-preview SSRF URL classifier.
//
// Targets the synchronous, network-free surface that decides whether a
// user-supplied URL is safe to fetch:
//   * LinkPreviewPlugin::isSafeUrl(QUrl)
//   * LinkPreviewPlugin::isBlockedIp(QHostAddress)
//   * LinkPreviewPlugin::decodeHtmlEntities(QString)
//
// Besides crash/UB detection (ASan/UBSan), the harness asserts an invariant
// that backs the SSRF fix: any URL whose host is a literal IP and that
// isSafeUrl() accepts must NOT be classified as a blocked address.

#include "LinkPreviewPlugin.h"

#include <QHostAddress>
#include <QString>
#include <QUrl>

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	const QString input = QString::fromUtf8(reinterpret_cast< const char * >(data),
											static_cast< int >(size));

	// 1. URL safety classifier (scheme + literal-IP/host checks).
	const QUrl url(input, QUrl::StrictMode);
	const bool safe = LinkPreviewPlugin::isSafeUrl(url);

	// Invariant: if the host parses as a literal IP and isSafeUrl() says the
	// URL is safe, isBlockedIp() must agree it is not an internal address.
	const QHostAddress hostAddr(url.host());
	if (safe && !hostAddr.isNull()) {
		if (LinkPreviewPlugin::isBlockedIp(hostAddr)) {
			__builtin_trap(); // isSafeUrl accepted a blocked literal IP
		}
	}

	// 2. Direct IP classifier over the raw input interpreted as an address.
	const QHostAddress rawAddr(input);
	(void) LinkPreviewPlugin::isBlockedIp(rawAddr);

	// 3. HTML entity decoder (used on parsed metadata before it is returned).
	(void) LinkPreviewPlugin::decodeHtmlEntities(input);

	return 0;
}
