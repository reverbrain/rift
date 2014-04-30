#ifndef RIFT_SERVER_SERVER_HPP
#define RIFT_SERVER_SERVER_HPP

#include "rift/bucket.hpp"
#include "rift/cache.hpp"
#include "rift/common.hpp"
#include "rift/index.hpp"
#include "rift/io.hpp"
#include "rift/list.hpp"
#include "rift/meta_ctl.hpp"
#include "rift/server.hpp"
#include "rift/url.hpp"

#include <boost/algorithm/string.hpp>

namespace rift_server {

using namespace ioremap;

class example_server : public thevoid::server<example_server>
{
public:
	struct signature_info {
		std::string key;
		std::string path;
	};

	example_server();
	~example_server();

	virtual bool initialize(const rapidjson::Value &config);

	swarm::url generate_url_base(dnet_addr *addr, const std::string &path, swarm::http_response::status_type *type);

	const rift::elliptics_base *elliptics() const;

	bool process(const swarm::http_request &req, const boost::asio::const_buffer &buffer,
			const rift::continue_handler_t &continue_handler) const;
	void check_cache(const elliptics::key &key, elliptics::session &sess) const;
	bool query_ok(const swarm::http_request &request) const;

	std::string key(const swarm::http_request &req) const {
		return ioremap::rift::url::key(req, !!m_bucket);
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

} // namespace rift_server

#endif // RIFT_SERVER_SERVER_HPP
