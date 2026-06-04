// libFuzzer harness for HTMLFilter::filter().
//
// The server runs this over untrusted chat messages / comments when it is
// configured to strip HTML, so it is a genuine handler-level parser of
// attacker-controlled input (it drives a QXmlStreamReader internally).

#include "HTMLFilter.h"

#include <QString>

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	const QString in = QString::fromUtf8(reinterpret_cast< const char * >(data),
										 static_cast< int >(size));
	QString out;
	(void) HTMLFilter::filter(in, out);
	return 0;
}
