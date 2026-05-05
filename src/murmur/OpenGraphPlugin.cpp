// Copyright Fancy Mumble Developers. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file at the root of the
// source tree.

#include "OpenGraphPlugin.h"

#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QUrlQuery>
#include <QtDebug>

#include <optional>

OpenGraphPlugin::OpenGraphPlugin(QObject *parent) : LinkPreviewPlugin(parent) {
}

QString OpenGraphPlugin::name() const {
	return QStringLiteral("OpenGraph");
}

bool OpenGraphPlugin::canHandle(const QUrl &url) const {
	return isSafeUrl(url);
}

void OpenGraphPlugin::fetchPreview(const QUrl &url, QNetworkAccessManager *nam,
								   SuccessCallback onSuccess, FailureCallback onFailure) {
	fetchPage(url, nam, std::move(onSuccess), std::move(onFailure), 0);
}

// ---- HTTP request helpers -------------------------------------------

// Builds the standard HTML-fetch request.  Accept-Encoding is intentionally
// omitted: Qt negotiates gzip/deflate transparently; setting it manually
// disables that and leaves the compressed payload unparsed.  HTTP/2 is
// disabled because Qt 6's HTTP/2 client stalls on flow-control updates
// against large CDNs, causing the transfer timeout to fire prematurely.
QNetworkRequest OpenGraphPlugin::buildPageRequest(const QUrl &url) {
	QNetworkRequest request(url);
	request.setHeader(QNetworkRequest::UserAgentHeader,
					  QStringLiteral("Mozilla/5.0 (compatible; FancyMumbleBot/1.0; +http://fancymumble.com/bot)"));
	request.setRawHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
	request.setRawHeader("Accept-Language", "en-US,en;q=0.5");
	request.setTransferTimeout(FETCH_TIMEOUT_MS);
	request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
	request.setAttribute(QNetworkRequest::Http2AllowedAttribute, false);
	return request;
}

// ---- Page fetching with manual redirect (SSRF-safe) -----------------

void OpenGraphPlugin::fetchPage(const QUrl &url, QNetworkAccessManager *nam,
								SuccessCallback onSuccess, FailureCallback onFailure,
								int redirectCount) {
	if (redirectCount > MAX_REDIRECTS) {
		qInfo() << "[OpenGraph] too many redirects";
		onFailure();
		return;
	}

	qInfo() << "[OpenGraph] GET (redirect" << redirectCount << ")";
	QNetworkReply *reply = nam->get(buildPageRequest(url));

	connect(reply, &QNetworkReply::finished, this,
			[this, reply, url, nam, onSuccess, onFailure, redirectCount]() {
				reply->deleteLater();

				int statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
				QNetworkReply::NetworkError netErr = reply->error();
				qInfo() << "[OpenGraph] reply status=" << statusCode
						<< "netError=" << netErr;

				if (statusCode >= 300 && statusCode < 400) {
					QUrl redirectUrl = reply->header(QNetworkRequest::LocationHeader).toUrl();
					if (redirectUrl.isRelative())
						redirectUrl = url.resolved(redirectUrl);
					qInfo() << "[OpenGraph] following redirect";
					if (!isSafeUrl(redirectUrl)) {
						qWarning() << "[OpenGraph] unsafe redirect target, aborting";
						onFailure();
						return;
					}
					fetchPage(redirectUrl, nam, onSuccess, onFailure, redirectCount + 1);
					return;
				}

				if (netErr != QNetworkReply::NoError) {
					qWarning() << "[OpenGraph] network error, aborting";
					onFailure();
					return;
				}

				QByteArray data  = reply->read(MAX_RESPONSE_BYTES);
				qInfo() << "[OpenGraph] received" << data.size() << "bytes";
				QJsonObject embed = parseOpenGraphTags(data, url);
				QString parsedTitle = embed.value(QStringLiteral("title")).toString();

				// If OG yielded no title, try oEmbed discovery from <link> tags.
				if (parsedTitle.isEmpty()) {
					QString discoveredEndpoint = discoverOEmbedLink(data);
					if (!discoveredEndpoint.isEmpty()) {
						qInfo() << "[OpenGraph] discovered oEmbed endpoint, retrying";
						fetchDiscoveredOEmbed(discoveredEndpoint, url, nam, onSuccess, onFailure);
						return;
					}
				}

				if (embed.isEmpty() || parsedTitle.isEmpty()) {
					qWarning() << "[OpenGraph] no usable embed data extracted";
					onFailure();
					return;
				}

				qInfo() << "[OpenGraph] success";
				onSuccess(embed);
			});
}

// ---- HTML <meta> tag parsing ----------------------------------------

void OpenGraphPlugin::parseMetaTags(const QString &content, QHash< QString, QString > &meta) {
	// Matches <meta> with property/name + content in either order.
	// Accepts single OR double-quoted attribute values - some sites
	// (notably tagesschau.de and other German news sites) use single
	// quotes which the original double-quote-only regex missed entirely.
	QRegularExpression metaRe(
		QString::fromUtf8(
			R"REGEX(<meta\s+[^>]*?(?:(?:property|name)\s*=\s*["']([^"']+)["'][^>]*?content\s*=\s*["']([^"']*?)["']|content\s*=\s*["']([^"']*?)["'][^>]*?(?:property|name)\s*=\s*["']([^"']+)["']))REGEX"
		),
		QRegularExpression::CaseInsensitiveOption | QRegularExpression::DotMatchesEverythingOption);

	auto it = metaRe.globalMatch(content);
	int matchCount = 0;
	while (it.hasNext()) {
		QRegularExpressionMatch m = it.next();
		QString prop, val;
		if (!m.captured(1).isEmpty()) {
			prop = m.captured(1).toLower();
			val  = m.captured(2);
		} else {
			prop = m.captured(4).toLower();
			val  = m.captured(3);
		}
		if (!prop.isEmpty() && !val.isEmpty()) {
			meta.insert(prop, decodeHtmlEntities(val));
			++matchCount;
		}
	}
	qInfo() << "[OpenGraph] parsed" << matchCount << "meta tags";
}

void OpenGraphPlugin::populateImageAndVideo(QJsonObject &embed,
											const QHash< QString, QString > &meta,
											const QUrl &pageUrl) {
	// Image / thumbnail.  Promote OG/Twitter image to BOTH `image`
	// (high-resolution hero) and `thumbnail` (small preview) so the
	// client can render whichever fits its layout.
	QString imageUrl = meta.value(QStringLiteral("og:image"),
								  meta.value(QStringLiteral("og:image:url"),
											 meta.value(QStringLiteral("twitter:image"))));
	if (!imageUrl.isEmpty()) {
		QUrl resolved = pageUrl.resolved(QUrl(imageUrl));
		if (isSafeUrl(resolved)) {
			QJsonObject img;
			img.insert(QStringLiteral("url"), resolved.toString());
			QString w = meta.value(QStringLiteral("og:image:width"));
			QString h = meta.value(QStringLiteral("og:image:height"));
			if (!w.isEmpty())
				img.insert(QStringLiteral("width"), w.toInt());
			if (!h.isEmpty())
				img.insert(QStringLiteral("height"), h.toInt());
			QString alt = meta.value(QStringLiteral("og:image:alt"),
									 meta.value(QStringLiteral("twitter:image:alt")));
			if (!alt.isEmpty())
				img.insert(QStringLiteral("alt"), alt);
			embed.insert(QStringLiteral("image"), img);
			embed.insert(QStringLiteral("thumbnail"), img);
		}
	}

	// Video.
	QString videoUrl = meta.value(
		QStringLiteral("og:video"),
		meta.value(QStringLiteral("og:video:url"),
				   meta.value(QStringLiteral("og:video:secure_url"),
							  meta.value(QStringLiteral("twitter:player")))));
	if (!videoUrl.isEmpty()) {
		QUrl resolved = pageUrl.resolved(QUrl(videoUrl));
		if (isSafeUrl(resolved)) {
			QJsonObject vid;
			vid.insert(QStringLiteral("url"), resolved.toString());
			QString w = meta.value(QStringLiteral("og:video:width"),
								   meta.value(QStringLiteral("twitter:player:width")));
			QString h = meta.value(QStringLiteral("og:video:height"),
								   meta.value(QStringLiteral("twitter:player:height")));
			if (!w.isEmpty())
				vid.insert(QStringLiteral("width"), w.toInt());
			if (!h.isEmpty())
				vid.insert(QStringLiteral("height"), h.toInt());
			embed.insert(QStringLiteral("video"), vid);
		}
	}
}

void OpenGraphPlugin::classifyEmbedType(QJsonObject &embed,
										const QHash< QString, QString > &meta) {
	QString ogType     = meta.value(QStringLiteral("og:type"), QStringLiteral("website")).toLower();
	QString twitterCard = meta.value(QStringLiteral("twitter:card"));

	if (embed.contains(QStringLiteral("video"))) {
		embed.insert(QStringLiteral("type"), QStringLiteral("video"));
	} else if (ogType == QLatin1String("article") || ogType == QLatin1String("blog")) {
		embed.insert(QStringLiteral("type"), QStringLiteral("article"));
	} else if (twitterCard == QLatin1String("summary_large_image")
			   || ogType.startsWith(QLatin1String("image"))) {
		embed.insert(QStringLiteral("type"), QStringLiteral("image"));
	} else {
		embed.insert(QStringLiteral("type"), QStringLiteral("link"));
	}
}

// ---- Sub-functions of parseOpenGraphTags ---------------------------

void OpenGraphPlugin::populateBasicFields(QJsonObject &embed,
										  const QHash< QString, QString > &meta,
										  const QString &content, const QUrl &url) {
	static const QRegularExpression titleRe(QStringLiteral(R"(<title[^>]*>([^<]+)</title>)"),
											QRegularExpression::CaseInsensitiveOption);
	QString title = meta.value(QStringLiteral("og:title"),
							   meta.value(QStringLiteral("twitter:title")));
	if (title.isEmpty()) {
		const auto m = titleRe.match(content);
		if (m.hasMatch())
			title = decodeHtmlEntities(m.captured(1).trimmed());
	}
	if (!title.isEmpty())
		embed.insert(QStringLiteral("title"), title.left(256));

	const QString description = meta.value(
		QStringLiteral("og:description"),
		meta.value(QStringLiteral("twitter:description"), meta.value(QStringLiteral("description"))));
	if (!description.isEmpty())
		embed.insert(QStringLiteral("description"), description.left(4096));

	const QString siteName = meta.value(QStringLiteral("og:site_name"));
	embed.insert(QStringLiteral("site_name"),
				 !siteName.isEmpty()
					 ? siteName
					 : url.host().remove(QRegularExpression(QStringLiteral("^www\\."))));

	QString themeColor = meta.value(QStringLiteral("theme-color"));
	if (themeColor.startsWith(QLatin1Char('#')))
		themeColor = themeColor.mid(1);
	if (!themeColor.isEmpty()) {
		bool ok      = false;
		int colorInt = themeColor.toInt(&ok, 16);
		if (ok)
			embed.insert(QStringLiteral("color"), colorInt);
	}
}

void OpenGraphPlugin::populateAuthorAndMetadata(QJsonObject &embed,
												const QHash< QString, QString > &meta,
												const QString &content, const QUrl &url) {
	const QString articleAuthor = meta.value(QStringLiteral("article:author"),
											 meta.value(QStringLiteral("author")));
	if (!articleAuthor.isEmpty()) {
		QJsonObject author;
		author.insert(QStringLiteral("name"), articleAuthor);
		embed.insert(QStringLiteral("author"), author);
	}

	const QString canonicalMeta = meta.value(QStringLiteral("og:url"));
	const QString canonical     = !canonicalMeta.isEmpty() ? canonicalMeta
														   : extractCanonical(content, url);
	if (!canonical.isEmpty())
		embed.insert(QStringLiteral("canonical_url"), canonical);

	const QString lang = meta.value(QStringLiteral("og:locale"), extractHtmlLang(content));
	if (!lang.isEmpty())
		embed.insert(QStringLiteral("lang"), lang);

	const QString published = meta.value(QStringLiteral("article:published_time"),
										 meta.value(QStringLiteral("datepublished")));
	if (!published.isEmpty())
		embed.insert(QStringLiteral("published_time"), published);

	const QString modified = meta.value(QStringLiteral("article:modified_time"),
										meta.value(QStringLiteral("datemodified")));
	if (!modified.isEmpty())
		embed.insert(QStringLiteral("modified_time"), modified);
}

void OpenGraphPlugin::populateKeywords(QJsonObject &embed,
									   const QHash< QString, QString > &meta) {
	const QString keywordsRaw =
		meta.value(QStringLiteral("keywords"), meta.value(QStringLiteral("news_keywords")));
	if (keywordsRaw.isEmpty())
		return;
	QJsonArray kw;
	for (const QString &part : keywordsRaw.split(QLatin1Char(','), Qt::SkipEmptyParts)) {
		const QString trimmed = part.trimmed();
		if (!trimmed.isEmpty() && kw.size() < 16)
			kw.append(trimmed);
	}
	if (!kw.isEmpty())
		embed.insert(QStringLiteral("keywords"), kw);
}

void OpenGraphPlugin::populateNsfw(QJsonObject &embed,
								   const QHash< QString, QString > &meta) {
	const QString rating       = meta.value(QStringLiteral("rating")).toLower();
	const QString restrictions = meta.value(QStringLiteral("og:restrictions:content")).toLower();
	if (rating == QLatin1String("adult") || rating == QLatin1String("mature")
		|| rating == QLatin1String("rta-5042-1996-1400-1577-rta")
		|| restrictions.contains(QLatin1String("adult")))
		embed.insert(QStringLiteral("nsfw"), true);
}

void OpenGraphPlugin::populateFaviconField(QJsonObject &embed,
										   const QString &content, const QUrl &url) {
	const QString fav = extractFavicon(content, url);
	if (fav.isEmpty())
		return;
	QJsonObject favObj;
	favObj.insert(QStringLiteral("url"), fav);
	embed.insert(QStringLiteral("favicon"), favObj);
}

void OpenGraphPlugin::populateSummaryAndReadingTime(QJsonObject &embed, const QString &content) {
	const QString mainText = extractMainText(content);
	if (mainText.isEmpty())
		return;
	const QString summary = summarise(mainText, 800);
	if (!summary.isEmpty()) {
		embed.insert(QStringLiteral("summary"), summary);
		// Fall back to the first paragraph of the summary when no description
		// was found in the meta tags (common on JS-heavy pages).
		if (embed.value(QStringLiteral("description")).toString().isEmpty())
			embed.insert(QStringLiteral("description"), summary.left(280));
	}
	const QString rt = readingTime(mainText);
	if (!rt.isEmpty())
		embed.insert(QStringLiteral("reading_time"), rt);
}

QJsonObject OpenGraphPlugin::parseOpenGraphTags(const QByteArray &html, const QUrl &url) {
	const QString content = QString::fromUtf8(html.left(MAX_RESPONSE_BYTES));

	QHash< QString, QString > meta;
	parseMetaTags(content, meta);

	QJsonObject embed;
	embed.insert(QStringLiteral("url"), url.toString());
	embed.insert(QStringLiteral("fetched_at"),
				 QDateTime::currentDateTimeUtc().toString(Qt::ISODate));

	populateBasicFields(embed, meta, content, url);
	populateImageAndVideo(embed, meta, url);
	classifyEmbedType(embed, meta);
	populateAuthorAndMetadata(embed, meta, content, url);
	populateKeywords(embed, meta);
	populateNsfw(embed, meta);
	populateFaviconField(embed, content, url);
	populateSummaryAndReadingTime(embed, content);
	populateExtraFields(embed, meta);

	return embed;
}

// ---- Tiny extractive helpers ---------------------------------------

QString OpenGraphPlugin::extractHtmlLang(const QString &content) {
	static const QRegularExpression re(QStringLiteral(R"(<html[^>]*\blang\s*=\s*["']([^"']+)["'])"),
									   QRegularExpression::CaseInsensitiveOption);
	const auto m = re.match(content);
	if (m.hasMatch())
		return m.captured(1).trimmed();
	return {};
}

QString OpenGraphPlugin::extractCanonical(const QString &content, const QUrl &pageUrl) {
	static const QRegularExpression re(
		QStringLiteral(R"(<link[^>]+rel\s*=\s*["']canonical["'][^>]+href\s*=\s*["']([^"']+)["'])"),
		QRegularExpression::CaseInsensitiveOption);
	static const QRegularExpression reRev(
		QStringLiteral(R"(<link[^>]+href\s*=\s*["']([^"']+)["'][^>]+rel\s*=\s*["']canonical["'])"),
		QRegularExpression::CaseInsensitiveOption);
	auto m = re.match(content);
	if (!m.hasMatch())
		m = reRev.match(content);
	if (m.hasMatch()) {
		QUrl resolved = pageUrl.resolved(QUrl(decodeHtmlEntities(m.captured(1).trimmed())));
		if (resolved.isValid() && isSafeUrl(resolved))
			return resolved.toString();
	}
	return {};
}

QString OpenGraphPlugin::extractFavicon(const QString &content, const QUrl &pageUrl) {
	// Prefer high-resolution apple-touch / icon links.
	static const QRegularExpression iconRe(
		QStringLiteral(R"(<link[^>]+rel\s*=\s*["']([^"']*icon[^"']*)["'][^>]+href\s*=\s*["']([^"']+)["'])"),
		QRegularExpression::CaseInsensitiveOption);
	static const QRegularExpression iconReRev(
		QStringLiteral(R"(<link[^>]+href\s*=\s*["']([^"']+)["'][^>]+rel\s*=\s*["']([^"']*icon[^"']*)["'])"),
		QRegularExpression::CaseInsensitiveOption);

	QString best;
	int bestScore = -1;
	auto consider = [&](const QString &rel, const QString &href) {
		int score = 0;
		const QString relLower = rel.toLower();
		if (relLower.contains(QLatin1String("apple-touch-icon")))
			score += 30;
		else if (relLower.contains(QLatin1String("shortcut")))
			score += 5;
		else if (relLower == QLatin1String("icon"))
			score += 10;
		if (score > bestScore) {
			bestScore = score;
			best      = href;
		}
	};

	auto it = iconRe.globalMatch(content);
	while (it.hasNext()) {
		const auto m = it.next();
		consider(m.captured(1), m.captured(2));
	}
	it = iconReRev.globalMatch(content);
	while (it.hasNext()) {
		const auto m = it.next();
		consider(m.captured(2), m.captured(1));
	}

	if (best.isEmpty()) {
		// Fallback: /favicon.ico at the site root.
		QUrl fallback = pageUrl;
		fallback.setPath(QStringLiteral("/favicon.ico"));
		fallback.setQuery(QString());
		fallback.setFragment(QString());
		return fallback.toString();
	}

	QUrl resolved = pageUrl.resolved(QUrl(decodeHtmlEntities(best.trimmed())));
	if (resolved.isValid() && isSafeUrl(resolved))
		return resolved.toString();
	return {};
}

QString OpenGraphPlugin::stripTags(const QString &fragment) {
	QString s = fragment;
	// Drop script/style blocks entirely.
	static const QRegularExpression scriptRe(
		QStringLiteral(R"(<(script|style|noscript)[^>]*>[\s\S]*?</\1>)"),
		QRegularExpression::CaseInsensitiveOption);
	s.remove(scriptRe);
	static const QRegularExpression tagRe(QStringLiteral(R"(<[^>]+>)"));
	s.replace(tagRe, QStringLiteral(" "));
	s = decodeHtmlEntities(s);
	static const QRegularExpression wsRe(QStringLiteral(R"(\s+)"));
	s.replace(wsRe, QStringLiteral(" "));
	return s.trimmed();
}

QString OpenGraphPlugin::extractMainText(const QString &content) {
	// Prefer <article>; fall back to <main>; fall back to <body>.
	static const QRegularExpression articleRe(QStringLiteral(R"(<article[^>]*>([\s\S]*?)</article>)"),
											  QRegularExpression::CaseInsensitiveOption);
	auto m = articleRe.match(content);
	if (m.hasMatch())
		return stripTags(m.captured(1));

	static const QRegularExpression mainRe(QStringLiteral(R"(<main[^>]*>([\s\S]*?)</main>)"),
										   QRegularExpression::CaseInsensitiveOption);
	m = mainRe.match(content);
	if (m.hasMatch())
		return stripTags(m.captured(1));

	static const QRegularExpression bodyRe(QStringLiteral(R"(<body[^>]*>([\s\S]*?)</body>)"),
										   QRegularExpression::CaseInsensitiveOption);
	m = bodyRe.match(content);
	if (m.hasMatch())
		return stripTags(m.captured(1));
	return {};
}

QString OpenGraphPlugin::summarise(const QString &mainText, int maxChars) {
	if (mainText.isEmpty())
		return {};

	// Pick the first ~3 sentences that are non-trivial. This is a
	// deliberately tiny extractive summariser; we avoid pulling in a
	// transformer model on the server. Any heavier summarisation
	// (transformer / LLM) can be slotted in here behind a config flag.
	static const QRegularExpression sentRe(QStringLiteral(R"((.+?[\.\!\?\u3002])(?:\s|$))"));
	auto it = sentRe.globalMatch(mainText);
	QString result;
	int sentences = 0;
	while (it.hasNext() && result.size() < maxChars && sentences < 4) {
		const auto m       = it.next();
		const QString sent = m.captured(1).trimmed();
		if (sent.length() < 25)
			continue;
		if (!result.isEmpty())
			result.append(QLatin1Char(' '));
		result.append(sent);
		++sentences;
	}
	if (result.isEmpty())
		result = mainText.left(maxChars);
	return result.left(maxChars);
}

QString OpenGraphPlugin::readingTime(const QString &mainText) {
	if (mainText.isEmpty())
		return {};
	const auto words = mainText.split(QRegularExpression(QStringLiteral(R"(\s+)")),
									 Qt::SkipEmptyParts);
	const int wordCount = static_cast< int >(words.size());
	if (wordCount < 80)
		return {};
	// 220 words/min is a typical online-reading benchmark.
	const int minutes = qMax(1, (wordCount + 110) / 220);
	return QStringLiteral("%1 min read").arg(minutes);
}

void OpenGraphPlugin::populateExtraFields(QJsonObject &embed,
										  const QHash< QString, QString > &meta) {
	QJsonArray fields;
	auto pushField = [&](const QString &name, const QString &value, bool inlineFlag) {
		if (value.isEmpty())
			return;
		QJsonObject f;
		f.insert(QStringLiteral("name"), name);
		f.insert(QStringLiteral("value"), value.left(256));
		f.insert(QStringLiteral("inline"), inlineFlag);
		fields.append(f);
	};

	pushField(QStringLiteral("Section"), meta.value(QStringLiteral("article:section")), true);
	pushField(QStringLiteral("Tag"), meta.value(QStringLiteral("article:tag")), true);
	pushField(QStringLiteral("Price"),
			  meta.value(QStringLiteral("product:price:amount")), true);
	pushField(QStringLiteral("Currency"),
			  meta.value(QStringLiteral("product:price:currency")), true);
	pushField(QStringLiteral("Availability"),
			  meta.value(QStringLiteral("product:availability")), true);
	pushField(QStringLiteral("Brand"), meta.value(QStringLiteral("product:brand")), true);

	if (!fields.isEmpty())
		embed.insert(QStringLiteral("fields"), fields);
}

// ---- oEmbed discovery from HTML <link> tags -------------------------

QString OpenGraphPlugin::discoverOEmbedLink(const QByteArray &html) {
	QString content = QString::fromUtf8(html.left(65536));

	QRegularExpression linkRe(
		QString::fromUtf8(
			R"REGEX(<link[^>]+type\s*=\s*"application/json\+oembed"[^>]+href\s*=\s*"([^"]+)")REGEX"
		),
		QRegularExpression::CaseInsensitiveOption);
	auto m = linkRe.match(content);
	if (m.hasMatch())
		return decodeHtmlEntities(m.captured(1));

	// Reverse attribute order.
	QRegularExpression linkReReverse(
		QString::fromUtf8(
			R"REGEX(<link[^>]+href\s*=\s*"([^"]+)"[^>]+type\s*=\s*"application/json\+oembed")REGEX"
		),
		QRegularExpression::CaseInsensitiveOption);
	m = linkReReverse.match(content);
	if (m.hasMatch())
		return decodeHtmlEntities(m.captured(1));

	return {};
}

// ---- Fetch a discovered oEmbed endpoint (inline fallback) -----------

std::optional< QJsonObject > OpenGraphPlugin::parseDiscoveredOEmbed(const QByteArray &data,
																	const QUrl &originalUrl) {
	QJsonParseError parseError;
	const QJsonDocument doc = QJsonDocument::fromJson(data, &parseError);
	if (parseError.error != QJsonParseError::NoError || !doc.isObject())
		return std::nullopt;

	const QJsonObject oembed = doc.object();
	const QString title = oembed.value(QStringLiteral("title")).toString();
	if (title.isEmpty())
		return std::nullopt;

	QJsonObject embed;
	embed.insert(QStringLiteral("url"), originalUrl.toString());
	embed.insert(QStringLiteral("title"), title.left(256));
	embed.insert(QStringLiteral("type"), QStringLiteral("link"));

	const QString providerName = oembed.value(QStringLiteral("provider_name")).toString();
	if (!providerName.isEmpty())
		embed.insert(QStringLiteral("site_name"), providerName);

	return embed;
}

void OpenGraphPlugin::fetchDiscoveredOEmbed(const QString &endpoint, const QUrl &originalUrl,
											QNetworkAccessManager *nam, SuccessCallback onSuccess,
											FailureCallback onFailure) {
	QUrl oembedUrl(endpoint);
	if (!isSafeUrl(oembedUrl)) {
		onFailure();
		return;
	}

	QNetworkRequest request(oembedUrl);
	request.setHeader(QNetworkRequest::UserAgentHeader, QStringLiteral("FancyMumbleBot/1.0"));
	request.setTransferTimeout(FETCH_TIMEOUT_MS);
	request.setAttribute(QNetworkRequest::Http2AllowedAttribute, false);

	QNetworkReply *reply = nam->get(request);
	connect(reply, &QNetworkReply::finished, this,
			[reply, originalUrl, onSuccess, onFailure]() {
				reply->deleteLater();
				if (reply->error() != QNetworkReply::NoError
					|| reply->bytesAvailable() > MAX_RESPONSE_BYTES) {
					onFailure();
					return;
				}
				const auto embed = parseDiscoveredOEmbed(reply->readAll(), originalUrl);
				if (embed)
					onSuccess(*embed);
				else
					onFailure();
			});
}
