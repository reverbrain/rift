#include "rift/metadata_updater.hpp"

using namespace ioremap::rift;

metadata_updater::metadata_updater(const swarm::logger &logger) :
	m_async(NULL),
	m_logger(logger, blackhole::log::attributes_t())
{
}

bool metadata_updater::initialize(const rapidjson::Value &config, const elliptics::node &node,
	async_performer *async, const std::vector<int> &groups)
{
	m_async = async;

	if (!groups.size()) {
		BH_LOG(m_logger, SWARM_LOG_ERROR, "invalid metadata-groups, size: 0");
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

const ioremap::swarm::logger &metadata_updater::logger() const
{
	return m_logger;
}

ioremap::elliptics::session metadata_updater::metadata_session() const
{
	return m_session->clone();
}
