#include "rift/signature.hpp"

using namespace ioremap;
using namespace ioremap::rift;

signature::signature(const swarm::logger &logger) :
	m_logger(logger, blackhole::log::attributes_t({ swarm::keyword::source() = "cache" }))

{
}

bool signature::initialize(const rapidjson::Value &config, const elliptics::node &node)
{
	if (!config.HasMember("signature")) {
		BH_LOG(m_logger, SWARM_LOG_ERROR, "\"signature\" field is missed");
		return false;
	}

	const rapidjson::Value &signature_config = config["signature"];
	if (!signature_config.HasMember("key")) {
		BH_LOG(m_logger, SWARM_LOG_ERROR, "\"signature.key\" field is missed");
		return false;
	}

	m_node.reset(new elliptics::node(node));
	m_key = signature_config["key"].GetString();

	return true;
}

std::string signature::sign(const swarm::url &url) const
{
	const swarm::url_query &query = url.query();

	std::vector<std::pair<std::string, std::string>> items;
	for (size_t i = 0; i < query.count(); ++i) {
		items.emplace_back(query.item(i));
	}
	items.emplace_back("key", m_key);

	std::sort(items.begin(), items.end());

	swarm::url_query new_query;
	for (auto it = items.begin(); it != items.end(); ++it) {
		new_query.add_item(it->first, it->second);
	}

	swarm::url new_url = url;
	new_url.set_query(new_query);

	std::string result = new_url.to_string();

	dnet_raw_id signature_id;
	dnet_transform_node(m_node->get_native(),
		result.c_str(), result.size(),
		signature_id.id, sizeof(signature_id.id));

	char signature_str[2 * DNET_ID_SIZE + 1];
	dnet_dump_id_len_raw(signature_id.id, DNET_ID_SIZE, signature_str);

	return std::string(signature_str, 2 * DNET_ID_SIZE);
}

const swarm::logger &signature::logger() const
{
	return m_logger;
}
