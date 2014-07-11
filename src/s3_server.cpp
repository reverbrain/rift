#include "s3_server.hpp"
#include <rift/auth.hpp>

namespace s3 {

s3_server::s3_server()
{
}

s3_server::~s3_server()
{
}

bool s3_server::initialize(const rapidjson::Value &config)
{
	if (!base_server::initialize(config))
		return false;

	if (!m_bucket) {
		logger().log(swarm::SWARM_LOG_ERROR, "\"bucket\" field is missed");
		return false;
	}

	if (config.HasMember("host")) {
		const auto &host = config["host"];
		m_host.assign(host.GetString(), host.GetStringLength());
	}

	m_auth[std::string()] = std::make_shared<rift::no_authorization>(shared_from_this());
	m_auth["AWS"] = std::make_shared<rift::s3_v2_authorization<s3_server>>(shared_from_this(), m_host);
	m_auth["AWS4-HMAC-SHA256"] = std::make_shared<rift::s3_v4_authorization<s3_server>>(shared_from_this());

	on_bucket<meta_head>(
		options::methods("HEAD")
	);

	on_object<on_upload>(
		options::methods("PUT", "POST")
	);

	on_object<on_get>(
		options::methods("GET")
	);

	return true;
}

bool s3_server::check_query(const swarm::http_request &request) const
{
	(void) request;
	return true;
}

template <typename Stream>
std::string s3_server::extract_key(Stream &stream, const swarm::http_request &request) const
{
	switch (stream.mixin_s3_calling_format) {
	case ordinary_format: {
		const size_t prefix_size = 1 + request.url().path_components()[0].size() + 1;
		return request.url().path().substr(prefix_size);
	}
	case subdomain_format: {
		const size_t prefix_size = 1;
		return request.url().path().substr(prefix_size);
	}
	}

	logger().log(swarm::SWARM_LOG_ERROR, "url: %s, invalid calling format: %d",
		request.url().to_human_readable().c_str(), int(stream.mixin_s3_calling_format));
	abort();
	return std::string();
}

template <typename Stream>
std::string s3_server::extract_bucket(Stream &, const swarm::http_request &request) const
{
	switch (static_cast<calling_format>(Stream::s3_calling_format)) {
	case ordinary_format: {
		return request.url().path_components()[0];
	}
	case subdomain_format: {
		// It's known that Host exists and it's length is appropriate due to handler checks
		auto host_ptr = request.headers().get("Host");
		const std::string &host = *host_ptr;
		const size_t host_size = std::min(host.size(), host.find_first_of(':'));
		return host.substr(0, host_size - m_host.size() - 1);
	}
	}
	return std::string();
}

template <typename T, typename... Args>
void s3_server::on_object(Args &&...args)
{
	if (!m_host.empty()) {
		on<bucket_processor<T, subdomain_format>>(
			options::regex_match("/.+"),
			options::host_suffix('.' + m_host),
			std::forward<Args>(args)...
		);
		on<bucket_processor<T, ordinary_format>>(
			options::regex_match("/[^/]+/.+"),
			options::host_exact(m_host),
			std::forward<Args>(args)...
		);
	} else {
		on<bucket_processor<T, ordinary_format>>(
			options::regex_match("/[^/]+/.+"),
			std::forward<Args>(args)...
		);
	}
}

template <typename T, typename... Args>
void s3_server::on_bucket(Args &&...args)
{
	if (!m_host.empty()) {
		on<bucket_processor<T, subdomain_format>>(
			options::exact_match("/"),
			options::host_suffix('.' + m_host),
			std::forward<Args>(args)...
		);
		on<bucket_processor<T, ordinary_format>>(
			options::regex_match("/[^/]+/"),
			options::host_exact(m_host),
			std::forward<Args>(args)...
		);
	} else {
		on<bucket_processor<T, ordinary_format>>(
			options::regex_match("/[^/]+/"),
			std::forward<Args>(args)...
		);
	}
}

} // namespace s3

int main(int argc, char **argv)
{
	return ioremap::thevoid::run_server<s3::s3_server>(argc, argv);
}
