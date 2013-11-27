#include "rift/metadata_updater.hpp"

using namespace ioremap::rift;

metadata_updater::metadata_updater() : m_async(NULL)
{
}

bool metadata_updater::initialize(const rapidjson::Value &config, const elliptics::node &node,
	const swarm::logger &logger, async_performer *async, const std::vector<int> &groups)
{
	m_logger = logger;
	m_async = async;

	if (!groups.size()) {
		m_logger.log(swarm::SWARM_LOG_ERROR, "invalid metadata-groups, size: 0");
		return false;
	}

	m_timeout = 30;
	if (config.HasMember("timeout")) {
		m_timeout = config["timeout"].GetInt();
	}

	m_session.reset(new elliptics::session(node));
	m_session->set_groups(groups);

	return true;
}

void metadata_updater::add_action(const std::function<void ()> &handler)
{
	m_async->add_action(handler, m_timeout);
}

ioremap::swarm::logger metadata_updater::logger() const
{
	return m_logger;
}

ioremap::elliptics::session metadata_updater::metadata_session() const
{
	return m_session->clone();
}
