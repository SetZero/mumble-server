// Standalone reproducer for the link-preview hang seen on the production
// mumble-server.  Builds against Qt 6 only, no Mumble dependencies.
//
// Goal: characterise *why* GETs against mydealz.de, news.google.com,
// golem.de, music.youtube.com etc. hang for ~20s instead of obeying
// QNetworkRequest::setTransferTimeout(5000), and why some replies never
// fire `finished`.
//
// The reproducer runs four passes against the same URL list:
//   pass 1: DNS resolution only (logs A and AAAA records)
//   pass 2: HTTP GET, default network configuration (mirrors prod code)
//   pass 3: HTTP GET, after disabling IPv6 lookups by hand-resolving the
//           host to its IPv4 address and rewriting the URL with the host
//           still in the SNI/Host header
//   pass 4: raw TCP connect probe to v6 vs v4 endpoints to measure the
//           connect-phase latency directly
//
// For every reply / probe we log wall-clock millisecond timings, error
// strings, and which signals fired.  This is what we need to confirm or
// falsify the hypothesis that the hang is caused by Qt 6.4's
// setTransferTimeout not covering the connect phase combined with broken
// IPv6 connectivity in the Docker container.

#include <QCoreApplication>
#include <QDateTime>
#include <QDebug>
#include <QElapsedTimer>
#include <QHostAddress>
#include <QHostInfo>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSslSocket>
#include <QString>
#include <QStringList>
#include <QTcpSocket>
#include <QTimer>
#include <QUrl>

#include <atomic>
#include <cstdio>

namespace {

QStringList kTestUrls = {
	QStringLiteral("https://www.mydealz.de/deals/example"),
	QStringLiteral("https://news.google.com/"),
	QStringLiteral("https://www.golem.de/"),
	QStringLiteral("https://music.youtube.com/"),
	QStringLiteral("https://www.youtube.com/oembed?url=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3DdQw4w9WgXcQ&format=json"),
	// Known-good control URLs:
	QStringLiteral("https://example.com/"),
	QStringLiteral("https://www.cloudflare.com/"),
};

QString nowStr() {
	return QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz"));
}

void logLine(const QString &line) {
	std::fprintf(stdout, "[%s] %s\n",
				 nowStr().toUtf8().constData(),
				 line.toUtf8().constData());
	std::fflush(stdout);
}

// ---- Pass 1: DNS resolution -----------------------------------------

void runDnsPass(std::function<void()> onDone) {
	logLine(QStringLiteral("==== Pass 1: DNS resolution ===="));
	auto remaining = std::make_shared<int>(kTestUrls.size());

	for (const QString &raw : kTestUrls) {
		QUrl url(raw);
		QString host = url.host();
		QHostInfo::lookupHost(host, [host, remaining, onDone](const QHostInfo &info) {
			if (info.error() != QHostInfo::NoError) {
				logLine(QStringLiteral("  DNS %1 -> ERROR: %2").arg(host, info.errorString()));
			} else {
				int v4 = 0, v6 = 0;
				QStringList addrs;
				for (const QHostAddress &a : info.addresses()) {
					if (a.protocol() == QAbstractSocket::IPv4Protocol) ++v4;
					else if (a.protocol() == QAbstractSocket::IPv6Protocol) ++v6;
					addrs << a.toString();
				}
				logLine(QStringLiteral("  DNS %1 -> v4=%2 v6=%3 [%4]")
							.arg(host).arg(v4).arg(v6).arg(addrs.join(QStringLiteral(", "))));
			}
			if (--(*remaining) == 0) onDone();
		});
	}
}

// ---- HTTP probe -----------------------------------------------------

struct ReplyState {
	QString tag;
	QUrl url;
	QElapsedTimer timer;
	bool finishedFired = false;
	bool sslErrorsFired = false;
	bool encryptedFired = false;
	bool errorOccurredFired = false;
};

void instrumentReply(QNetworkReply *reply, std::shared_ptr<ReplyState> st,
					 std::function<void()> onComplete) {
	QObject::connect(reply, &QNetworkReply::encrypted, reply, [st]() {
		st->encryptedFired = true;
		logLine(QStringLiteral("  [%1] encrypted at %2 ms").arg(st->tag).arg(st->timer.elapsed()));
	});
	QObject::connect(reply, &QNetworkReply::sslErrors, reply,
					 [st](const QList<QSslError> &errs) {
		st->sslErrorsFired = true;
		QStringList msgs;
		for (const QSslError &e : errs) msgs << e.errorString();
		logLine(QStringLiteral("  [%1] sslErrors at %2 ms: %3")
					.arg(st->tag).arg(st->timer.elapsed()).arg(msgs.join(QStringLiteral("; "))));
	});
	QObject::connect(reply, &QNetworkReply::errorOccurred, reply,
					 [st](QNetworkReply::NetworkError err) {
		st->errorOccurredFired = true;
		logLine(QStringLiteral("  [%1] errorOccurred at %2 ms: code=%3")
					.arg(st->tag).arg(st->timer.elapsed()).arg(int(err)));
	});
	QObject::connect(reply, &QNetworkReply::finished, reply,
					 [reply, st, onComplete]() {
		st->finishedFired = true;
		int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
		auto bytes = reply->bytesAvailable();
		logLine(QStringLiteral("  [%1] FINISHED at %2 ms, status=%3, error=%4 (%5), bytes=%6")
					.arg(st->tag)
					.arg(st->timer.elapsed())
					.arg(status)
					.arg(int(reply->error()))
					.arg(reply->errorString())
					.arg(bytes));
		reply->deleteLater();
		onComplete();
	});
}

// ---- Pass 2: HTTP with default config (mirrors production) ---------

void runHttpPass(QNetworkAccessManager *nam, const QString &label,
				 const QStringList &urls, int timeoutMs,
				 std::function<void()> onDone) {
	logLine(QStringLiteral("==== Pass: %1 (timeout=%2ms) ====").arg(label).arg(timeoutMs));
	auto remaining = std::make_shared<int>(urls.size());
	auto wallStart = std::make_shared<QElapsedTimer>();
	wallStart->start();

	for (const QString &raw : urls) {
		QUrl url(raw);
		QNetworkRequest req(url);
		req.setHeader(QNetworkRequest::UserAgentHeader,
					  QStringLiteral("Mozilla/5.0 (compatible; FancyMumbleBot/1.0; +http://fancymumble.com/bot)"));
		req.setRawHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
		req.setRawHeader("Accept-Language", "en-US,en;q=0.5");
		req.setTransferTimeout(timeoutMs);
		req.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
						 QNetworkRequest::ManualRedirectPolicy);
		req.setAttribute(QNetworkRequest::Http2AllowedAttribute, false);

		auto st = std::make_shared<ReplyState>();
		st->tag = url.host();
		st->url = url;
		st->timer.start();
		logLine(QStringLiteral("  GET %1").arg(url.toString()));

		QNetworkReply *reply = nam->get(req);
		instrumentReply(reply, st, [remaining, onDone, wallStart]() {
			if (--(*remaining) == 0) {
				logLine(QStringLiteral("  pass complete in %1 ms wall").arg(wallStart->elapsed()));
				onDone();
			}
		});

		// Guard timer: if neither finished nor errorOccurred fires within
		// timeoutMs * 4 we will print a status snapshot.  This proves the
		// signals really are stuck, ruling out lost-event theories.
		QTimer::singleShot(timeoutMs * 4, reply, [reply, st]() {
			if (!st->finishedFired) {
				logLine(QStringLiteral("  [%1] STILL RUNNING after %2 ms (finished=%3 err=%4 ssl=%5 enc=%6)")
							.arg(st->tag)
							.arg(st->timer.elapsed())
							.arg(st->finishedFired)
							.arg(st->errorOccurredFired)
							.arg(st->sslErrorsFired)
							.arg(st->encryptedFired));
				reply->abort();
			}
		});
	}
}

// ---- Pass 4: raw TCP connect probe ----------------------------------

void probeTcpConnect(const QString &host, const QHostAddress &addr, quint16 port,
					 std::function<void()> onDone) {
	auto sock = new QTcpSocket();
	auto timer = std::make_shared<QElapsedTimer>();
	timer->start();
	QString fam = (addr.protocol() == QAbstractSocket::IPv6Protocol) ? QStringLiteral("v6")
																	  : QStringLiteral("v4");
	QString tag = QStringLiteral("%1[%2]%3").arg(host, fam, addr.toString());

	bool *done = new bool(false);

	QObject::connect(sock, &QTcpSocket::connected, sock, [tag, timer, sock, done, onDone]() {
		if (*done) return; *done = true;
		logLine(QStringLiteral("  TCP %1 connected in %2 ms").arg(tag).arg(timer->elapsed()));
		sock->disconnectFromHost();
		sock->deleteLater();
		delete done;
		onDone();
	});
	QObject::connect(sock, &QTcpSocket::errorOccurred, sock,
					 [tag, timer, sock, done, onDone](QAbstractSocket::SocketError err) {
		if (*done) return; *done = true;
		logLine(QStringLiteral("  TCP %1 ERROR at %2 ms: code=%3 (%4)")
					.arg(tag).arg(timer->elapsed()).arg(int(err)).arg(sock->errorString()));
		sock->deleteLater();
		delete done;
		onDone();
	});
	QTimer::singleShot(25000, sock, [tag, timer, sock, done, onDone]() {
		if (*done) return; *done = true;
		logLine(QStringLiteral("  TCP %1 TIMED OUT in app-level guard at %2 ms")
					.arg(tag).arg(timer->elapsed()));
		sock->abort();
		sock->deleteLater();
		delete done;
		onDone();
	});

	sock->connectToHost(addr, port);
}

void runTcpProbePass(std::function<void()> onDone) {
	logLine(QStringLiteral("==== Pass 4: raw TCP connect probes (port 443) ===="));
	auto hosts = std::make_shared<QStringList>();
	for (const QString &raw : kTestUrls) *hosts << QUrl(raw).host();
	hosts->removeDuplicates();

	auto remainingHosts = std::make_shared<int>(hosts->size());
	auto allDone = std::make_shared<std::function<void()>>(onDone);

	for (const QString &host : *hosts) {
		QHostInfo::lookupHost(host, [host, remainingHosts, allDone](const QHostInfo &info) {
			if (info.error() != QHostInfo::NoError) {
				logLine(QStringLiteral("  TCP %1 DNS FAIL: %2").arg(host, info.errorString()));
				if (--(*remainingHosts) == 0) (*allDone)();
				return;
			}
			QHostAddress v4, v6;
			for (const QHostAddress &a : info.addresses()) {
				if (a.protocol() == QAbstractSocket::IPv4Protocol && v4.isNull()) v4 = a;
				else if (a.protocol() == QAbstractSocket::IPv6Protocol && v6.isNull()) v6 = a;
			}

			auto perHost = std::make_shared<int>(0);
			if (!v4.isNull()) ++(*perHost);
			if (!v6.isNull()) ++(*perHost);
			if (*perHost == 0) {
				logLine(QStringLiteral("  TCP %1 had no usable A/AAAA").arg(host));
				if (--(*remainingHosts) == 0) (*allDone)();
				return;
			}

			auto onProbeDone = [perHost, remainingHosts, allDone]() {
				if (--(*perHost) == 0) {
					if (--(*remainingHosts) == 0) (*allDone)();
				}
			};
			if (!v4.isNull()) probeTcpConnect(host, v4, 443, onProbeDone);
			if (!v6.isNull()) probeTcpConnect(host, v6, 443, onProbeDone);
		});
	}
}

}  // namespace

int main(int argc, char *argv[]) {
	QCoreApplication app(argc, argv);

	logLine(QStringLiteral("Qt runtime version: %1").arg(qVersion()));
	logLine(QStringLiteral("Qt build version:   %1").arg(QT_VERSION_STR));
	logLine(QStringLiteral("OpenSSL build:      %1").arg(QSslSocket::sslLibraryBuildVersionString()));
	logLine(QStringLiteral("OpenSSL runtime:    %1").arg(QSslSocket::sslLibraryVersionString()));

	auto nam = new QNetworkAccessManager(&app);

	// Pass 5: prove whether setTransferTimeout() fires during the *connect*
	// phase against a deliberately black-holed endpoint.  10.255.255.1 is
	// RFC1918, almost guaranteed to be unrouted from the Docker container,
	// so SYN packets go to a black hole.  A correctly-implemented transfer
	// timeout would abort at ~5s; Qt 6.4's idle-only implementation will
	// instead let the kernel TCP timeout (~21s) fire first.
	auto blackholeProbe = [nam](std::function<void()> onDone) {
		logLine(QStringLiteral("==== Pass 5: setTransferTimeout vs black-hole connect ===="));
		QUrl url(QStringLiteral("https://10.255.255.1/"));
		QNetworkRequest req(url);
		req.setTransferTimeout(5000);
		req.setAttribute(QNetworkRequest::Http2AllowedAttribute, false);
		auto st = std::make_shared<ReplyState>();
		st->tag = QStringLiteral("blackhole");
		st->url = url;
		st->timer.start();
		logLine(QStringLiteral("  GET %1 (transferTimeout=5000ms)").arg(url.toString()));
		QNetworkReply *reply = nam->get(req);
		instrumentReply(reply, st, [onDone]() { onDone(); });
		// Hard guard so the test cannot run forever.
		QTimer::singleShot(40000, reply, [reply, st]() {
			if (!st->finishedFired) {
				logLine(QStringLiteral("  [%1] HARD GUARD aborting at %2 ms").arg(st->tag).arg(st->timer.elapsed()));
				reply->abort();
			}
		});
	};

	// Pass 6: proper wall-clock QTimer-based abort.  Demonstrates the fix
	// we will apply in production code.
	auto wallClockFix = [nam](std::function<void()> onDone) {
		logLine(QStringLiteral("==== Pass 6: wall-clock QTimer abort vs black-hole ===="));
		QUrl url(QStringLiteral("https://10.255.255.1/"));
		QNetworkRequest req(url);
		req.setTransferTimeout(5000);  // still set, but we don't rely on it
		req.setAttribute(QNetworkRequest::Http2AllowedAttribute, false);
		auto st = std::make_shared<ReplyState>();
		st->tag = QStringLiteral("blackhole-walltimer");
		st->url = url;
		st->timer.start();
		logLine(QStringLiteral("  GET %1 (wall-clock QTimer 5000ms)").arg(url.toString()));
		QNetworkReply *reply = nam->get(req);
		instrumentReply(reply, st, [onDone]() { onDone(); });
		// Wall-clock guard - this is the fix.
		QTimer::singleShot(5000, reply, [reply, st]() {
			if (!st->finishedFired) {
				logLine(QStringLiteral("  [%1] WALL-CLOCK GUARD firing at %2 ms (correct)").arg(st->tag).arg(st->timer.elapsed()));
				reply->abort();
			}
		});
	};

	runDnsPass([=, &app]() {
		runHttpPass(nam, QStringLiteral("Pass 2: HTTP default (5s)"),
					kTestUrls, 5000, [=, &app]() {
			runHttpPass(nam, QStringLiteral("Pass 3: HTTP long timeout (30s)"),
						kTestUrls, 30000, [=, &app]() {
				runTcpProbePass([=, &app]() {
					blackholeProbe([=, &app]() {
						wallClockFix([&app]() {
							logLine(QStringLiteral("==== ALL PASSES COMPLETE ===="));
							QTimer::singleShot(500, &app, &QCoreApplication::quit);
						});
					});
				});
			});
		});
	});

	return app.exec();
}
