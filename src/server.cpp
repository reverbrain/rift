#include <elliptics/utils.hpp>

#include "rift/logger.hpp"
#include "rift/server.hpp"

#include <iostream>

using namespace ioremap;
using namespace ioremap::rift;

elliptics_base::elliptics_base()
{
}

bool elliptics_base::initialize(const rapidjson::Value &config, const swarm::logger &logger)
{
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

elliptics::node elliptics_base::node() const
{
	return *m_node;
}

elliptics::session elliptics_base::session() const
{
	return m_session->clone();
}

bool elliptics_base::prepare_config(const rapidjson::Value &config, dnet_config &node_config)
{
	(void) config;
	(void) node_config;
	return true;
}

bool elliptics_base::prepare_node(const rapidjson::Value &config, elliptics::node &node)
{
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

bool elliptics_base::prepare_session(const rapidjson::Value &config, elliptics::session &session)
{
	if (!config.HasMember("groups")) {
		m_logger.log(swarm::SWARM_LOG_ERROR, "\"application.groups\" field is missed");
		return false;
	}

	if (!config.HasMember("metadata-groups")) {
		m_logger.log(swarm::SWARM_LOG_ERROR, "\"application.metadata-groups\" field is missed");
		return false;
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

swarm::logger elliptics_base::logger() const
{
	return m_logger;
}

std::vector<int> elliptics_base::metadata_groups() const
{
	return m_metadata_groups;
}
