#ifndef IOREMAP_RIFT_CACHE_HPP
#define IOREMAP_RIFT_CACHE_HPP

#include "rift/metadata_updater.hpp"

#include <elliptics/session.hpp>
#include <swarm/logger.hpp>
#include <thevoid/server.hpp>

#include <mutex>
#include <unordered_map>

namespace ioremap {
namespace rift {

class cache : public metadata_updater, public std::enable_shared_from_this<cache>
{
public:
	cache();

	bool initialize(const rapidjson::Value &config, const ioremap::elliptics::node &node,
		const swarm::logger &logger, async_performer *async, const std::vector<int> &groups);

	std::vector<int> groups(const ioremap::elliptics::key &key);

protected:
	void on_sync_action();
	void on_read_finished(const ioremap::elliptics::sync_read_result &result, const ioremap::elliptics::error_info &error);

private:
	struct hash_impl
	{
		size_t operator() (const dnet_raw_id &key) const;
	};
	struct equal_impl
	{
		bool operator() (const dnet_raw_id &first, const dnet_raw_id &second) const;
	};

	typedef std::unordered_map<dnet_raw_id, std::vector<int>, hash_impl, equal_impl> unordered_map;

	ioremap::elliptics::key m_key;
	std::mutex m_mutex;
	unordered_map m_cache_groups;
};

} // namespace cache
} // namespace ioremap

#endif // IOREMAP_RIFT_CACHE_HPP
