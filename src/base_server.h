#ifndef RIFT_SERVER_BASE_SERVER_H
#define RIFT_SERVER_BASE_SERVER_H

#include "rift/bucket.hpp"
#include "rift/cache.hpp"
#include "rift/common.hpp"
#include "rift/index.hpp"
#include "rift/io.hpp"
#include "rift/list.hpp"
#include "rift/meta_ctl.hpp"
#include "rift/server.hpp"
#include "rift/stat.hpp"
#include "rift/url.hpp"

namespace rift_server {

using namespace ioremap;

template <typename Server>
class base_server : public thevoid::server<Server>
{
public:
	base_server() {
	}

	~base_server() {
		m_async.stop();
		m_cache.reset();
	}

	bool initialize(const rapidjson::Value &config) {
		this->daemonize();

		if (!m_elliptics.initialize(config, this->logger()))
			return false;

		m_async.initialize(this->logger());

		if (config.HasMember("cache")) {
			m_cache = std::make_shared<rift::cache>();
			if (!m_cache->initialize(config["cache"], m_elliptics.node(), this->logger(),
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

		m_async.add_action(std::bind(&rift::elliptics_base::stat_update, &m_elliptics), stat_timeout);

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

		return true;
	}

	swarm::url generate_url_base(dnet_addr *addr, const std::string &path, swarm::http_response::status_type *type) {
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
	std::string signature_token(rift::bucket_mixin<BaseStream, Flags> &mixin) const
	{
		return mixin.bucket_mixin_acl.token;
	}

	const rift::elliptics_base *elliptics() const {
		return &m_elliptics;
	}

	template <typename Stream>
	bool process(Stream &stream, const rift::authorization_info &info) const {
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
				this->logger().log(swarm::SWARM_LOG_NOTICE, "verdict: url: %s, invalid method: %s",
						info.request->url().to_human_readable().c_str(), method.c_str());

				rift::authorization_check_result result;
				result.verdict = swarm::http_response::forbidden;
				result.stream = info.stream;
				info.handler(result);
				return false;
			}

			if (!static_cast<const Server *>(this)->check_query(*info.request)) {
				return false;
			}

			m_bucket->check(static_cast<const Server *>(this)->extract_bucket(stream, *info.request), tmp);
		}

		return true;
	}

	template <typename Stream>
	elliptics::session create_session(Stream &stream, const swarm::http_request &req, elliptics::key &key) const {
		const bool is_read = (Stream::bucket_mixin_flags & rift::bucket_acl::handler_read);

		key = static_cast<const Server *>(this)->extract_key(stream, req);
		auto session = is_read
			? m_elliptics.read_data_session(req, stream.bucket_mixin_meta)
			: m_elliptics.write_data_session(req, stream.bucket_mixin_meta);
		check_cache(key, session);

		return session;
	}

protected:
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

	int m_redirect_port;
	bool m_secured_http;
	bool m_use_hostname;
	std::string m_path_prefix;
	rift::elliptics_base m_elliptics;
	std::shared_ptr<rift::cache> m_cache;
	std::shared_ptr<rift::bucket> m_bucket;
	rift::async_performer m_async;
	std::map<std::string, rift::authorization_checker_base::ptr> m_auth;
};

} // namespace rift_server

#endif // RIFT_SERVER_BASE_SERVER_H
