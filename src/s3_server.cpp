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

	m_auth[std::string()] = std::make_shared<rift::no_authorization>(shared_from_this());
	m_auth["AWS"] = std::make_shared<rift::s3_v2_authorization<s3_server>>(shared_from_this());
	m_auth["AWS4-HMAC-SHA256"] = std::make_shared<rift::s3_v4_authorization<s3_server>>(shared_from_this());

	on<rift::bucket_processor<s3_server, rift::bucket_ctl::meta_head<s3_server>>>(
		options::prefix_match("/"),
		options::methods("HEAD"),
		options::exact_path_components_count(1)
	);

	on<rift::bucket_processor<s3_server, on_get>>(
		options::prefix_match("/"),
		options::methods("GET"),
		options::minimal_path_components_count(2)
	);

	return true;
}

bool s3_server::check_query(const swarm::http_request &request) const
{
	(void) request;
	return true;
}

std::string s3_server::extract_key(const swarm::http_request &request) const
{
	return request.url().path_components()[1];
}

std::string s3_server::extract_bucket(const swarm::http_request &request) const
{
	return request.url().path_components()[0];
}

} // namespace s3

int main(int argc, char **argv)
{
	return ioremap::thevoid::run_server<s3::s3_server>(argc, argv);
}
