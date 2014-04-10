#include "rift/bucket.hpp"
#include "rift/cache.hpp"
#include "rift/common.hpp"
#include "rift/index.hpp"
#include "rift/io.hpp"
#include "rift/list.hpp"
#include "rift/meta_ctl.hpp"
#include "rift/server.hpp"

#include <boost/algorithm/string.hpp>

using namespace ioremap;

class example_server : public thevoid::server<example_server>
{
public:
	struct signature_info {
		std::string key;
		std::string path;
	};

	example_server() {
	}

	~example_server() {
		m_async.stop();
		m_cache.reset();
	}

	virtual bool initialize(const rapidjson::Value &config) {
		daemonize();

		if (!m_elliptics.initialize(config, logger()))
			return false;

		m_async.initialize(logger());

		if (config.HasMember("cache")) {
			m_cache = std::make_shared<rift::cache>();
			if (!m_cache->initialize(config["cache"], m_elliptics.node(), logger(),
						&m_async, m_elliptics.metadata_groups()))
				return false;
		}

		if (config.HasMember("bucket")) {
			m_bucket = std::make_shared<rift::bucket>();
			if (!m_bucket->initialize(config["bucket"], m_elliptics, &m_async))
				return false;
		}

		if (config.HasMember("redirect-port")) {
			m_redirect_port = config["redirect-port"].GetInt();
		} else {
			m_redirect_port = -1;
		}

		if (config.HasMember("use-hostname")) {
			m_use_hostname = config["use-hostname"].GetBool();
		} else {
			m_use_hostname = false;
		}

		if (config.HasMember("https")) {
			m_secured_http = config["https"].GetBool();
		} else {
			m_secured_http = false;
		}

		on<rift::index::on_update<example_server>>(
			options::prefix_match("/update/"),
			options::methods("POST")
		);
		on<rift::index::on_find<example_server>>(
			options::prefix_match("/find/"),
			options::methods("GET")
		);
		on<rift::io::on_redirectable_get<example_server>>(
			options::prefix_match("/redirect/"),
			options::methods("GET")
		);
		on<rift::io::on_get<example_server>>(
			options::prefix_match("/get/"),
			options::methods("GET")
		);
		on<rift::io::on_buffered_get<example_server>>(
			options::prefix_match("/get-big/"),
			options::methods("GET")
		);
		on<rift::io::on_upload<example_server>>(
			options::prefix_match("/upload/"),
			options::methods("POST")
		);
		on<rift::io::on_buffered_upload<example_server>>(
			options::prefix_match("/upload-big/"),
			options::methods("POST")
		);

		on<rift::io::on_delete<example_server>>(
			options::prefix_match("/delete/"),
			options::methods("POST")
		);

		on<rift::io::on_download_info<example_server>>(
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

		on<rift::bucket_ctl::meta_create<example_server>>(
			options::prefix_match("/update-bucket-directory/"),
			options::methods("POST")
		);
		on<rift::list::on_list<example_server>>(
			options::prefix_match("/list-bucket-directory/"),
			options::methods("GET")
		);
		on<rift::bucket_ctl::on_delete<example_server>>(
			options::prefix_match("/delete-bucket-directory/"),
			options::methods("POST")
		);

		on<rift::bucket_ctl::meta_create<example_server>>(
			options::prefix_match("/update-bucket/"),
			options::methods("POST")
		);
		on<rift::list::on_list<example_server>>(
			options::prefix_match("/list-bucket/"),
			options::methods("GET")
		);
		on<rift::bucket_ctl::on_delete<example_server>>(
			options::prefix_match("/delete-bucket/"),
			options::methods("POST")
		);
	
		return true;
	}

	swarm::url generate_url_base(dnet_addr *addr, const std::string &path, swarm::http_response::status_type *type) {
		char buffer[128];

		swarm::url url;
		url.set_scheme(m_secured_http ? "https" : "http");

		if (m_use_hostname) {
			char buffer[NI_MAXHOST];
			int err = getnameinfo(reinterpret_cast<sockaddr *>(addr), addr->addr_len, buffer, sizeof(buffer), NULL, 0, 0);
			if (err == 0) {
				url.set_host(buffer);
			} else {
				*type = swarm::http_response::internal_server_error;
			}
		} else {
			url.set_host(dnet_server_convert_dnet_addr_raw(addr, buffer, sizeof(buffer)));
		}

		if (m_redirect_port > 0) {
			url.set_port(m_redirect_port);
		}

		if (m_path_prefix.empty()) {
			url.set_path(path);
		} else if (path.compare(0, m_path_prefix.size(), m_path_prefix) == 0) {
			url.set_path(path.substr(m_path_prefix.size()));
		} else {
			*type = swarm::http_response::forbidden;
		}

		return std::move(url);
	}

	const rift::elliptics_base *elliptics() const {
		return &m_elliptics;
	}

	bool process(const swarm::http_request &req, const boost::asio::const_buffer &buffer,
			const rift::continue_handler_t &continue_handler) const {
		if (!m_bucket) {
			rift::bucket_meta_raw meta;
			meta.flags = RIFT_BUCKET_META_NO_INDEX_UPDATE;
			rift::bucket_acl acl;
			continue_handler(req, buffer, meta, acl, swarm::http_response::ok);
		} else {
			if (!query_ok(req)) {
				return false;
			}

			const auto &query = req.url().query();
			auto bucket = query.item_value("bucket");
			m_bucket->check(bucket.get(), req, buffer, continue_handler);
		}

		return true;
	}

	void check_cache(const elliptics::key &key, elliptics::session &sess) const {
		if (m_cache) {
			auto cache_groups = m_cache->groups(key);
			if (!cache_groups.empty()) {
				auto groups = sess.get_groups();
				groups.insert(groups.end(), cache_groups.begin(), cache_groups.end());
				sess.set_groups(groups);
			}
		}
	}

	bool query_ok(const swarm::http_request &request) const {
		const auto &path = request.url().path_components();
		if (path.size() < 2) {
			elliptics::throw_error(swarm::http_response::bad_request, "query parser error: path: '%s/%s', "
				"error: path must have at least 2 '/'-separated components",
				request.url().path().c_str(), request.url().query().to_string().c_str());
		}

		const auto &query = request.url().query();

		if (m_bucket) {
			auto ns = query.item_value("bucket");
			if (!ns) {
				elliptics::throw_error(swarm::http_response::bad_request, "query parser error: path: '%s/%s', "
					"error: there is no bucket parameter and buckets are turned on in config",
					request.url().path().c_str(), request.url().query().to_string().c_str());
			}
		}

		return true;
	}

	elliptics::session read_data_session_cache(const swarm::http_request &req, const rift::bucket_meta_raw &meta, elliptics::key &key) const {
		auto session = m_elliptics.read_data_session(req, meta, key);
		check_cache(key, session);

		return session;
	}

	elliptics::session write_data_session_cache(const swarm::http_request &req, const rift::bucket_meta_raw &meta, elliptics::key &key) const {
		auto session = m_elliptics.write_data_session(req, meta, key);
		check_cache(key, session);

		return session;
	}

private:
	int m_redirect_port;
	bool m_secured_http;
	bool m_use_hostname;
	std::string m_path_prefix;
	rift::elliptics_base m_elliptics;
	std::shared_ptr<rift::cache> m_cache;
	std::shared_ptr<rift::bucket> m_bucket;
	rift::async_performer m_async;
};

int main(int argc, char **argv)
{
	return thevoid::run_server<example_server>(argc, argv);
}
