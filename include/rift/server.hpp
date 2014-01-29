#ifndef __IOREMAP_RIFT_SERVER_HPP
#define __IOREMAP_RIFT_SERVER_HPP

// must be the first, since thevoid internally uses X->boost::buffer conversion,
// which must be present at compile time
#include "rift/asio.hpp"
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

	elliptics::session session() const {
		return m_session->clone();
	}

	std::vector<int> metadata_groups() const {
		return m_metadata_groups;
	}

	swarm::logger logger() const {
		return m_logger;
	}

	long read_timeout(void) const {
		return m_read_timeout;
	}

	long write_timeout(void) const {
		return m_write_timeout;
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

		for (auto it = remotes.begin(); it != remotes.end(); ++it) {
			node.add_remote(it->c_str());
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
