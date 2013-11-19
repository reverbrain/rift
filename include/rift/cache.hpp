#ifndef IOREMAP_RIFT_CACHE_HPP
#define IOREMAP_RIFT_CACHE_HPP

// must be the first, since thevoid internally uses X->boost::buffer conversion,
// which must be present at compile time
#include "rift/asio.hpp"

#include <elliptics/session.hpp>
#include <swarm/logger.hpp>
#include <thevoid/server.hpp>

#include <boost/thread.hpp>
#include <mutex>
#include <unordered_map>

namespace ioremap {
namespace rift {

class cache : public std::enable_shared_from_this<cache>
{
public:
	cache();

	bool initialize(const rapidjson::Value &config, const ioremap::elliptics::node &node, const swarm::logger &logger, const std::vector<int> &groups);
	void stop();

	std::vector<int> groups(const ioremap::elliptics::key &key);

protected:
	void sync_thread();
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

	boost::thread m_thread;
	swarm::logger m_logger;
	ioremap::elliptics::key m_key;
	std::unique_ptr<ioremap::elliptics::session> m_session;
	std::mutex m_mutex;
	unordered_map m_cache_groups;
	int m_timeout;
	bool m_need_exit;
};

} // namespace cache
} // namespace ioremap

#endif // IOREMAP_RIFT_CACHE_HPP
