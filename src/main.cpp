/*
 * 2013+ Copyright (c) Ruslan Nigatullin <euroelessar@yandex.ru>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "rift/auth.hpp"
#include "rift/cache.hpp"
#include "rift/server.hpp"
#include "rift/signature.hpp"

using namespace ioremap;

class example_server : public thevoid::server<example_server>
{
public:
	struct signature_info {
		std::string key;
		std::string path;
	};

	example_server() : m_elliptics(this) {
	}

	~example_server() {
		if (m_cache) {
			m_cache->stop();
			m_cache.reset();
		}
	}

	virtual bool initialize(const rapidjson::Value &config) {
		daemonize();

		if (!m_elliptics.initialize(config, logger()))
			return false;

		m_async.initialize(logger());

		if (config.HasMember("signatures")) {
			auto &signatures = config["signatures"];
			for (auto it = signatures.Begin(); it != signatures.End(); ++it) {
				if (!it->HasMember("key")) {
					logger().log(swarm::SWARM_LOG_ERROR, "\"signatures[i].key\" field is missed");
					return false;
				}
				if (!it->HasMember("path")) {
					logger().log(swarm::SWARM_LOG_ERROR, "\"signatures[i].path\" field is missed");
					return false;
				}

				signature_info info = {
					(*it)["key"].GetString(),
					(*it)["path"].GetString()
				};

				m_signatures.emplace_back(std::move(info));
			}
		}

		if (config.HasMember("cache")) {
			m_cache = std::make_shared<rift::cache>();
			if (!m_cache->initialize(config, m_elliptics.node(), logger(), &m_async, m_elliptics.metadata_groups()))
				return false;
		}

		if (config.HasMember("auth")) {
			m_auth.reset(new rift::auth);
			if (!m_auth->initialize(config, m_elliptics.node(), logger()))
				return false;
			m_elliptics.set_auth(m_auth.get());
		}

		if (config.HasMember("redirect")) {
			m_redirect_read = config["redirect"].GetBool();
		} else {
			m_redirect_read = false;
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
		if (m_redirect_read) {
			on<rift::io::on_redirectable_get<example_server>>(
				options::exact_match("/get"),
				options::methods("GET")
			);
		} else {
			on<rift::io::on_get<example_server>>(
				options::exact_match("/get"),
				options::methods("GET")
			);
		}
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

	const std::string *find_signature(const std::string &path) {
		for (auto it = m_signatures.begin(); it != m_signatures.end(); ++it) {
			if (it->path.size() <= path.size()
				&& path.compare(0, it->path.size(), it->path) == 0) {
				return &it->key;
			}
		}

		return NULL;
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

	const rift::elliptics_base *elliptics() {
		return &m_elliptics;
	}

	class elliptics_impl : public rift::elliptics_base
	{
	public:
		elliptics_impl(example_server *server) : m_server(server) {
		}

		virtual swarm::http_response::status_type process(const swarm::http_request &request,
			elliptics::key &key, elliptics::session &session) const	{
			auto result = elliptics_base::process(request, key, session);

			if (result != swarm::http_response::ok) {
				return result;
			}

			if (m_server->m_cache) {
				auto cache_groups = m_server->m_cache->groups(key);
				if (!cache_groups.empty()) {
					auto groups = session.get_groups();
					groups.insert(groups.end(), cache_groups.begin(), cache_groups.end());
					session.set_groups(groups);
				}
			}

			return swarm::http_response::ok;
		}

	private:
		example_server *m_server;
	};

private:
	rift::async_performer m_async;
	std::vector<signature_info> m_signatures;
	bool m_redirect_read;
	int m_redirect_port;
	bool m_secured_http;
	std::shared_ptr<rift::cache> m_cache;
	std::unique_ptr<rift::auth> m_auth;
	elliptics_impl m_elliptics;
	rift::signature m_signature;
	std::vector<int> m_groups;
};

int main(int argc, char **argv)
{
	return thevoid::run_server<example_server>(argc, argv);
}
