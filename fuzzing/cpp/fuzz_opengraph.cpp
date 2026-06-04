// libFuzzer harness for the Open Graph / HTML meta-tag parser.
//
// This is the QRegularExpression-heavy code path that runs over untrusted,
// remotely-fetched HTML.  It is the most likely place for catastrophic
// backtracking (ReDoS) or parsing UB.  Run with `-rss_limit_mb` and a
// per-input timeout so libFuzzer reports slow inputs as ReDoS candidates,
// e.g.:
//
//   fuzz_opengraph -timeout=2 -rss_limit_mb=2048 corpus/opengraph
//
// A 2 s single-input timeout that trips on a small input is a strong ReDoS
// signal worth investigating.

#include "OpenGraphPlugin.h"

#include <QByteArray>

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	const QByteArray html(reinterpret_cast< const char * >(data), static_cast< int >(size));
	(void) OpenGraphPlugin::fuzzParse(html);
	return 0;
}
