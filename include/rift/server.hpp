#ifndef __IOREMAP_RIFT_SERVER_HPP
#define __IOREMAP_RIFT_SERVER_HPP

#include "rift/bucket.hpp"
#include "rift/logger.hpp"

#include <thevoid/server.hpp>
#include <swarm/logger.hpp>
#include <elliptics/session.hpp>

namespace ioremap {
namespace rift {

class elliptics_base
{
public:
	elliptics_base() : m_read_timeout(0), m_write_timeout(0) {}

	bool initialize(const rapidjson::Value &config, const swarm::logger &logger) {
		m_logger = logger;

		dnet_config node_config;
		memset(&node_config, 0, sizeof(node_config));

		if (!prepare_config(config, node_config)) {
			return false;
		}

		m_node.reset(new elliptics::node(swarm_logger(logger), node_config));

		if (!prepare_node(config, *m_node)) {
			return false;
		}

		m_session.reset(new elliptics::session(*m_node));

		if (!prepare_session(config, *m_session)) {
			return false;
		}

		return true;
	}

	elliptics::node node() const {
		return *m_node;
	}

	elliptics::session read_data_session(const swarm::http_request &req, const bucket_meta_raw &meta, elliptics::key &key) const {
		auto session = m_session->clone();
		session.set_timeout(m_read_timeout);

		if (meta.key.size() && meta.groups.size()) {
			session.set_namespace(meta.key.c_str(), meta.key.size());
			session.set_groups(meta.groups);
		}

		const auto &query = req.url().query();
		uint32_t ioflags = query.item_value("ioflags", 0u);
		uint64_t cflags = query.item_value("cflags", 0llu);
		session.set_ioflags(ioflags);
		session.set_cflags(cflags);

		const auto &path = req.url().path_components();
		size_t prefix_size = 1 + path[0].size() + 1;
		key = elliptics::key(req.url().path().substr(prefix_size));
		session.transform(key);

		return session;
	}

	elliptics::session write_data_session(const swarm::http_request &req, const bucket_meta_raw &meta, elliptics::key &key) const {
		auto session = read_data_session(req, meta, key);
		session.set_timeout(m_write_timeout);

		return session;
	}

	elliptics::session read_metadata_session(const swarm::http_request &req, const bucket_meta_raw &meta, elliptics::key &key) const {
		auto session = read_data_session(req, meta, key);
		session.set_groups(m_metadata_groups);

		return session;
	}

	elliptics::session write_metadata_session(const swarm::http_request &req, const bucket_meta_raw &meta, elliptics::key &key) const {
		auto session = write_data_session(req, meta, key);
		session.set_groups(m_metadata_groups);

		return session;
	}

	swarm::logger logger() const {
		return m_logger;
	}

	const std::vector<int> metadata_groups(void) const {
		return m_metadata_groups;
	}

protected:
	virtual bool prepare_config(const rapidjson::Value &config, dnet_config &node_config) {
		(void) config;
		(void) node_config;
		return true;
	}

	virtual bool prepare_node(const rapidjson::Value &config, elliptics::node &node) {
		if (!config.HasMember("remotes")) {
			m_logger.log(swarm::SWARM_LOG_ERROR, "\"remotes\" field is missed");
			return false;
		}

		std::vector<std::string> remotes;

		auto &remotesArray = config["remotes"];
		std::transform(remotesArray.Begin(), remotesArray.End(),
			std::back_inserter(remotes),
			std::bind(&rapidjson::Value::GetString, std::placeholders::_1));

		bool any_added = false;
		for (auto it = remotes.begin(); it != remotes.end(); ++it) {
			try {
				node.add_remote(it->c_str());
				any_added = true;
			} catch (...) {
				// do nothing - its ok not to add some nodes
			}
		}

		if (!any_added) {
			m_logger.log(swarm::SWARM_LOG_ERROR, "Didn't add any remote node, exiting.");
			return false;
		}

		return true;
	}

	virtual bool prepare_session(const rapidjson::Value &config, elliptics::session &session) {
		if (!config.HasMember("groups")) {
			m_logger.log(swarm::SWARM_LOG_ERROR, "\"application.groups\" field is missed");
			return false;
		}

		if (!config.HasMember("metadata-groups")) {
			m_logger.log(swarm::SWARM_LOG_ERROR, "\"application.metadata-groups\" field is missed");
			return false;
		}

		if (config.HasMember("read-timeout")) {
			m_read_timeout = config["read-timeout"].GetInt();
		}

		if (config.HasMember("write-timeout")) {
			m_write_timeout = config["write-timeout"].GetInt();
		}

		std::vector<int> groups;

		auto &groups_array = config["groups"];
		std::transform(groups_array.Begin(), groups_array.End(),
			std::back_inserter(groups),
			std::bind(&rapidjson::Value::GetInt, std::placeholders::_1));

		session.set_groups(groups);

		auto &groups_meta_array = config["metadata-groups"];
		std::transform(groups_meta_array.Begin(), groups_meta_array.End(),
			std::back_inserter(m_metadata_groups),
			std::bind(&rapidjson::Value::GetInt, std::placeholders::_1));

		return true;
	}

private:
	swarm::logger m_logger;
	std::unique_ptr<elliptics::node> m_node;
	std::unique_ptr<elliptics::session> m_session;
	std::vector<int> m_metadata_groups;

	long m_read_timeout;
	long m_write_timeout;
};

}} // namespace ioremap::rift

#endif /*__IOREMAP_RIFT_SERVER_HPP */
