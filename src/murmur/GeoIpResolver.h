#include <QHostAddress>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTimer>
#include <QUrl>
#include <iostream>
#include <mutex>
#include <optional>

#include <nlohmann/json.hpp>

enum class GeoIpStatus { SUCCESS, FAIL, TIMEOUT };

struct GeoIpSuccessData {
	std::string country;
	std::string countryCode;
	std::string region;
	std::string regionName;
	std::string city;
	std::string zip;
	double lat;
	double lon;
	std::string timezone;
	std::string isp;
	std::string org;
	std::string as;
};

struct GeoIpInformation {
	std::string query;
	GeoIpStatus status;
	std::optional< GeoIpSuccessData > data;
	std::optional< std::string > message;
};



class GeoIpResolver : public QObject {
public:
	GeoIpResolver() : m_Manager{ std::make_unique< QNetworkAccessManager >() } {
		QObject::connect(m_Manager.get(), &QNetworkAccessManager::finished, this, &GeoIpResolver::finishRequest);
	}

	~GeoIpResolver() { std::cout << "~GeoIpResolver()\n"; }

	GeoIpResolver(const GeoIpResolver &)            = delete;
	GeoIpResolver &operator=(const GeoIpResolver &) = delete;
	GeoIpResolver(GeoIpResolver &&)                 = delete;
	GeoIpResolver &operator=(GeoIpResolver &&)      = delete;

	/**
	 * @brief Resolves the geographical information of an IP address using an external API.
	 *
	 * This function sends a request to the ip-api.com service to retrieve geographical information
	 * about the provided IP address. The result is passed to the provided callback function.
	 *
	 * @tparam Func The type of the callback function.
	 * @param ip The IP address to resolve.
	 * @param callback The callback function to be called with the resolved geographical information.
	 *
	 * @warning This function uses an external service (ip-api.com) which may have rate limits or
	 *          may not be available at all times.
	 *
	 * @example
	 * @code
	 * GeoIpResolver resolver;
	 * resolver.resolve("8.8.8.8", [](const GeoIpInformation &info) {
	 *     qDebug() << "Country:" << info.country;
	 * });
	 * @endcode
	 */
	template< typename Func > void resolve(const std::string &connectionString, Func callback) {
		QNetworkRequest request;

		request.setUrl(QUrl("http://ip-api.com/json/" + QString::fromStdString(connectionString)));
		request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

		QNetworkReply *rep = m_Manager->get(request);
		QObject::connect(m_Manager.get(), &QNetworkAccessManager::finished, rep, &QNetworkReply::deleteLater);
		{
			std::lock_guard< std::mutex > lock(m_CallbackMapMutex);
			m_CallbackMap[connectionString] = callback;
		}

	}

	static std::string getGeoIpSuccessDataAsJson(const std::string &query, const GeoIpSuccessData &data) {
		nlohmann::json jsonData = { { "query", query },
									{ "country", data.country },
									{ "countryCode", data.countryCode },
									{ "region", data.region },
									{ "regionName", data.regionName },
									{ "city", data.city },
									{ "zip", data.zip },
									{ "lat", data.lat },
									{ "lon", data.lon },
									{ "timezone", data.timezone },
									{ "isp", data.isp },
									{ "org", data.org },
									{ "as", data.as } };

		return jsonData.dump();
	}

private:
	void finishRequest(QNetworkReply *reply) {
		std::string connectionString;
		std::function< void(GeoIpInformation) > callback;
		{
			std::lock_guard< std::mutex > lock(m_CallbackMapMutex);

			// Extract the IP address from the URL
			auto connectionString = reply->url().toString().toStdString();
			connectionString.erase(0, connectionString.find_last_of('/') + 1);
			auto it = m_CallbackMap.find(connectionString);
			if (it == m_CallbackMap.end()) {
				return;
			}

			callback = it->second;
			m_CallbackMap.erase(it);
		}

		if (reply->error()) {
			qDebug() << "ERROR!";
			return;
		}

		auto data = reply->readAll();

		if (data.trimmed().isEmpty()) {
			GeoIpInformation info;
			info.query   = connectionString;
			info.status  = GeoIpStatus::FAIL;
			info.message = "Empty response from server";
			callback(info);
			return;
		}

		using json = nlohmann::json;

		GeoIpInformation info;

		try {
			auto jsonData = json::parse(data);

			if (!jsonData.contains("query") || !jsonData.contains("status")) {
				info.status  = GeoIpStatus::FAIL;
				info.message = "Invalid response format: missing 'query' or 'status'";
				callback(info);
				return;
			}

			info.query  = jsonData.value("query", "");
			info.status = parseStatus(jsonData);

			if (info.status == GeoIpStatus::SUCCESS) {
				GeoIpSuccessData data;
				data.country     = jsonData.value("country", "");
				data.countryCode = jsonData.value("countryCode", "");
				data.region      = jsonData.value("region", "");
				data.regionName  = jsonData.value("regionName", "");
				data.city        = jsonData.value("city", "");
				data.zip         = jsonData.value("zip", "");
				data.lat         = jsonData.value("lat", 0.0);
				data.lon         = jsonData.value("lon", 0.0);
				data.timezone    = jsonData.value("timezone", "");
				data.isp         = jsonData.value("isp", "");
				data.org         = jsonData.value("org", "");
				data.as          = jsonData.value("as", "");

				info.data = data;
			} else {
				info.message = jsonData.value("message", "");
			}

		} catch (const json::parse_error &e) {
			info.status  = GeoIpStatus::FAIL;
			info.message = "JSON parse error: " + std::string(e.what()) + ", request data: " + connectionString;
		}

		callback(info);
	}

	static GeoIpStatus parseStatus(const nlohmann::json &data) {
		if (data.contains("status")) {
			if (data["status"] == "success") {
				return GeoIpStatus::SUCCESS;
			} else {
				return GeoIpStatus::FAIL;
			}
		}

		return GeoIpStatus::FAIL;
	}

	std::unique_ptr< QNetworkAccessManager > m_Manager;
	std::map< std::string, std::function< void(GeoIpInformation) > > m_CallbackMap;
	std::mutex m_CallbackMapMutex;
};