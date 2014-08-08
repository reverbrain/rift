#include "rift_server.hpp"
#include <rift/auth.hpp>

namespace rift_server {

example_server::example_server() {
}

example_server::~example_server() {
	m_async->stop();
	m_cache.reset();
}

bool example_server::initialize(const rapidjson::Value &config) {
	if (!base_server::initialize(config))
		return false;

	m_auth[std::string()] = std::make_shared<rift::no_authorization>();
	m_auth["riftv1"] = std::make_shared<rift::rift_authorization>();

	on<rift::bucket_processor<example_server, on_update>>(
		options::prefix_match("/update/"),
		options::methods("POST")
	);
	on<rift::bucket_processor<example_server, on_find>>(
		options::prefix_match("/find/"),
		options::methods("POST")
	);
	on<rift::bucket_processor<example_server, on_redirectable_get>>(
		options::prefix_match("/redirect/"),
		options::methods("GET")
	);
	on<rift::bucket_processor<example_server, on_get>>(
		options::prefix_match("/get/"),
		options::methods("GET")
	);
	on<rift::bucket_processor<example_server, on_upload>>(
		options::prefix_match("/upload/"),
		options::methods("POST")
	);
	on<rift::bucket_processor<example_server, rift::list::on_list<example_server, rift::list::list_bucket>>>(
		options::prefix_match("/list/"),
		options::methods("GET")
	);
	on<rift::bucket_processor<example_server, on_download_info>>(
		options::prefix_match("/download-info/"),
		options::methods("GET")
	);
	on<rift::common::on_ping<example_server>>(
		options::prefix_match("/ping/"),
		options::methods("GET")
	);
	on<rift::common::on_echo<example_server>>(
		options::prefix_match("/echo/"),
		options::methods("POST")
	);
	on<rift::stat::on_stat<example_server>>(
		options::prefix_match("/stat/"),
		options::methods("GET")
	);

	on<rift::bucket_processor<example_server, on_delete>>(
		options::prefix_match("/delete/"),
		options::methods("POST")
	);

	on<rift::bucket_processor<example_server, rift::bucket_ctl::on_delete<example_server>>>(
		options::prefix_match("/delete-bucket-directory/"),
		options::methods("POST")
	);
	on<rift::bucket_processor<example_server, rift::bucket_ctl::on_delete<example_server>>>(
		options::prefix_match("/delete-bucket/"),
		options::methods("POST")
	);

	on<rift::bucket_processor<example_server, rift::bucket_ctl::meta_read<example_server>>>(
		options::prefix_match("/read-bucket/"),
		options::methods("GET")
	);

	on<rift::bucket_processor<example_server, rift::bucket_ctl::meta_head<example_server>>>(
		options::prefix_match("/read-bucket/"),
		options::methods("HEAD")
	);

	on<rift::bucket_processor<example_server, rift::bucket_ctl::meta_create<example_server,
			rift::bucket_ctl::update_bucket_directory>>>(
		options::prefix_match("/update-bucket-directory/"),
		options::methods("POST")
	);

	on<rift::bucket_processor<example_server, rift::bucket_ctl::meta_create<example_server,
			rift::bucket_ctl::update_bucket>>>(
		options::prefix_match("/update-bucket/"),
		options::methods("POST")
	);

	on<rift::bucket_processor<example_server, rift::list::on_list<example_server,
			rift::list::list_bucket_directory>>>(
		options::prefix_match("/list-bucket-directory/"),
		options::methods("GET")
	);

	return true;
}

bool example_server::check_query(const thevoid::http_request &request) const {
	const auto &pc = request.url().path_components();
	size_t min_component_num = 2;
	if (m_bucket) {
		min_component_num = 3;
		if (pc.size() > 1) {
			if (pc[0] == "list" || pc[0] == "list-bucket-directory" || pc[0] == "update-bucket-directory" ||
					pc[0] == "delete-bucket" || pc[0] == "read-bucket")
				min_component_num = 2;
		}
	}

	if (pc.size() < min_component_num) {
		elliptics::throw_error(thevoid::http_response::bad_request, "query parser error: path: '%s?%s', "
			"error: path must have at least %zd '/'-separated components",
			request.url().path().c_str(), request.url().query().to_string().c_str(), min_component_num);
	}

	return true;
}

template <typename Stream>
std::string example_server::extract_key(Stream &, const thevoid::http_request &request) const
{
	return rift::url::key(request, !!m_bucket);
}

template <typename Stream>
std::string example_server::extract_bucket(Stream &, const thevoid::http_request &request) const
{
	return rift::url::bucket(request);
}

} // namespace rift_server

int main(int argc, char **argv)
{
	return ioremap::thevoid::run_server<rift_server::example_server>(argc, argv);
}
