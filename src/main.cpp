#include "rift/bucket.hpp"
#include "rift/cache.hpp"
#include "rift/common.hpp"
#include "rift/index.hpp"
#include "rift/io.hpp"
#include "rift/server.hpp"

using namespace ioremap;

class example_server : public thevoid::server<example_server>
{
public:
	struct signature_info {
		std::string key;
		std::string path;
	};

	example_server() : m_noauth_allowed(false) {
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

		if (config.HasMember("noauth")) {
			m_noauth_allowed = std::string(config["noauth"].GetString()) == "allowed";
		}

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
		} else {
			m_noauth_allowed = true;
		}

		if (config.HasMember("redirect-port")) {
			m_redirect_port = config["redirect-port"].GetInt();
		} else {
			m_redirect_port = -1;
		}

		if (config.HasMember("https")) {
			m_secured_http = config["https"].GetBool();
		} else {
			m_secured_http = false;
		}

		on<rift::index::on_update<example_server>>(
			options::exact_match("/update"),
			options::methods("POST")
		);
		on<rift::index::on_find<example_server>>(
			options::exact_match("/find"),
			options::methods("GET")
		);
		on<rift::io::on_redirectable_get<example_server>>(
			options::exact_match("/redirect"),
			options::methods("GET")
		);
		on<rift::io::on_get<example_server>>(
			options::exact_match("/get"),
			options::methods("GET")
		);
		on<rift::io::on_buffered_get<example_server>>(
			options::exact_match("/get-big"),
			options::methods("GET")
		);
		on<rift::io::on_upload<example_server>>(
			options::exact_match("/upload"),
			options::methods("POST")
		);
		on<rift::io::on_buffered_upload<example_server>>(
			options::exact_match("/upload-big"),
			options::methods("POST")
		);
		on<rift::io::on_download_info<example_server>>(
			options::exact_match("/download-info"),
			options::methods("GET")
		);
		on<rift::common::on_ping<example_server>>(
			options::exact_match("/ping"),
			options::methods("GET")
		);
		on<rift::common::on_echo<example_server>>(
			options::exact_match("/echo"),
			options::methods("GET")
		);
	
		return true;
	}

	swarm::url generate_url_base(dnet_addr *addr) {
		char buffer[128];

		swarm::url url;
		url.set_scheme(m_secured_http ? "https" : "http");
		url.set_host(dnet_server_convert_dnet_addr_raw(addr, buffer, sizeof(buffer)));
		if (m_redirect_port > 0) {
			url.set_port(m_redirect_port);
		}

		return std::move(url);
	}

	const rift::elliptics_base *elliptics() const {
		return &m_elliptics;
	}

	void process(const swarm::http_request &request, const boost::asio::const_buffer &buffer,
			const rift::continue_handler_t &continue_handler) const {
		auto ns = request.url().query().item_value("namespace");
		if (!ns || !m_bucket) {
			auto verdict = swarm::http_response::bad_request;
			if (m_noauth_allowed || !m_bucket)
				verdict = swarm::http_response::ok;

			rift::bucket_meta_raw meta;
			continue_handler(request, buffer, meta, verdict);
		} else {
			m_bucket->check(*ns, request, buffer, continue_handler);
		}
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
		const auto &query = request.url().query();

		if (auto name = query.item_value("name")) {
			return true;
		} else if (auto sid = query.item_value("id")) {
			if (m_noauth_allowed)
				return true;
		}

		return false;
	}

	elliptics::session extract_key(const swarm::http_request &request, const rift::bucket_meta_raw &meta,
			elliptics::key &key) const {
		const auto &query = request.url().query();

		if (auto name = query.item_value("name")) {
			key = *name;
		} else if (auto sid = query.item_value("id")) {
			struct dnet_id id;
			memset(&id, 0, sizeof(struct dnet_id));

			dnet_parse_numeric_id(sid->c_str(), id.id);

			key = id;
		}

		elliptics::session session = m_elliptics.session();

		if (meta.groups.size() && meta.key.size()) {
			session.set_namespace(meta.key.c_str(), meta.key.size());
			session.set_groups(meta.groups);
		}

		session.transform(key);

		return session;
	}

private:
	int m_redirect_port;
	bool m_secured_http;
	rift::elliptics_base m_elliptics;
	std::shared_ptr<rift::cache> m_cache;
	std::shared_ptr<rift::bucket> m_bucket;
	rift::async_performer m_async;
	bool m_noauth_allowed;
};

int main(int argc, char **argv)
{
	return thevoid::run_server<example_server>(argc, argv);
}
