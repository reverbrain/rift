#include "server.hpp"
#include <rift/auth.hpp>

namespace rift_server {

example_server::example_server() {
}

example_server::~example_server() {
	m_async.stop();
	m_cache.reset();
}

bool example_server::initialize(const rapidjson::Value &config) {
	daemonize();

	if (!m_elliptics.initialize(config, logger()))
		return false;

	m_async.initialize(logger());

	m_auth[std::string()] = std::make_shared<rift::no_authorization>(logger());
	m_auth["riftv1"] = std::make_shared<rift::rift_authorization>(logger());

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

	int stat_timeout = 30;
	if (config.HasMember("stat-timeout") && config["stat-timeout"].IsInt()) {
		stat_timeout = config["stat-timeout"].GetInt();
	}

	m_async.add_action(std::bind(&ioremap::rift::elliptics_base::stat_update, &m_elliptics), stat_timeout);

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

	if (config.HasMember("path-prefix")) {
		m_path_prefix.assign(config["path-prefix"].GetString());
	} else {
		m_path_prefix = std::string();
	}

	if (config.HasMember("https")) {
		m_secured_http = config["https"].GetBool();
	} else {
		m_secured_http = false;
	}

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

	on<rift::bucket_processor<example_server, rift::bucket_ctl::meta_create<example_server, rift::bucket_ctl::update_bucket_directory>>>(
		options::prefix_match("/update-bucket-directory/"),
		options::methods("POST")
	);

	on<rift::bucket_processor<example_server, rift::bucket_ctl::meta_create<example_server, rift::bucket_ctl::update_bucket>>>(
		options::prefix_match("/update-bucket/"),
		options::methods("POST")
	);

	on<rift::bucket_processor<example_server, rift::list::on_list<example_server, rift::list::list_bucket_directory>>>(
		options::prefix_match("/list-bucket-directory/"),
		options::methods("GET")
	);

	return true;
}

swarm::url example_server::generate_url_base(dnet_addr *addr, const std::string &path, swarm::http_response::status_type *type) {
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
		url.set_host(dnet_state_dump_addr_only(addr));
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

template <typename BaseStream, uint64_t Flags>
std::string example_server::signature_token(rift::bucket_mixin<BaseStream, Flags> &mixin) const
{
	return mixin.bucket_mixin_acl.token;
}

const rift::elliptics_base *example_server::elliptics() const {
	return &m_elliptics;
}

bool example_server::process(const rift::authorization_info &info) const {
	if (!m_bucket) {
		// If there is no bucket support we should create presudo-bucket and give user rights to write files
		rift::authorization_check_result result;
		result.meta.flags = RIFT_BUCKET_META_NO_INDEX_UPDATE;
		result.verdict = swarm::http_response::ok;
		result.stream = info.stream;
		result.acl.flags = rift::bucket_acl::auth_write;
		info.handler(result);
	} else {
		rift::authorization_info tmp = info;
		std::string method;

		if (auto auth = info.request->headers().get("Authorization")) {
			// Authorization field always looks like 'method-name method-specific-data', so we take the first component
			const std::string &authorization = *auth;
			const size_t end_of_method = authorization.find(' ');
			method = authorization.substr(0, end_of_method);
		}

		const auto it = m_auth.find(method);
		if (it != m_auth.end()) {
			tmp.checker = it->second;
		} else {
			// We don't support this authorization method, return 403 Forbidden
			logger().log(swarm::SWARM_LOG_NOTICE, "verdict: url: %s, invalid method: %s",
					info.request->url().to_human_readable().c_str(), method.c_str());

			rift::authorization_check_result result;
			result.verdict = swarm::http_response::forbidden;
			info.handler(result);
			return false;
		}

		if (!query_ok(*info.request)) {
			return false;
		}

		m_bucket->check(ioremap::rift::url::bucket(*info.request), tmp);
	}

	return true;
}

void example_server::check_cache(const elliptics::key &key, elliptics::session &sess) const {
	if (m_cache) {
		auto cache_groups = m_cache->groups(key);
		if (!cache_groups.empty()) {
			auto groups = sess.get_groups();
			groups.insert(groups.end(), cache_groups.begin(), cache_groups.end());
			sess.set_groups(groups);
		}
	}
}

bool example_server::query_ok(const swarm::http_request &request) const {
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
		elliptics::throw_error(swarm::http_response::bad_request, "query parser error: path: '%s?%s', "
			"error: path must have at least %zd '/'-separated components",
			request.url().path().c_str(), request.url().query().to_string().c_str(), min_component_num);
	}

	return true;
}

template <typename BaseStream, uint64_t Flags>
elliptics::session example_server::create_session(rift::bucket_mixin<BaseStream, Flags> &mixin, const swarm::http_request &req, elliptics::key &key) const {
	const bool is_read = (Flags & rift::bucket_acl::handler_read);

	key = ioremap::rift::url::key(req, !!m_bucket);
	auto session = is_read
		? m_elliptics.read_data_session(req, mixin.bucket_mixin_meta)
		: m_elliptics.write_data_session(req, mixin.bucket_mixin_meta);
	check_cache(key, session);

	return session;
}

} // namespace rift_server
