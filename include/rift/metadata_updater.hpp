#ifndef IOREMAP_RIFT_METADATA_UPDATER_HPP
#define IOREMAP_RIFT_METADATA_UPDATER_HPP

// must be the first, since thevoid internally uses X->boost::buffer conversion,
// which must be present at compile time
#include "rift/asio.hpp"

#include "async_performer.hpp"

#include <elliptics/session.hpp>
#include <swarm/logger.hpp>
#include <thevoid/server.hpp>

#include <boost/thread.hpp>
#include <mutex>
#include <unordered_map>

namespace ioremap {
namespace rift {

class metadata_updater
{
public:
	metadata_updater();

	bool initialize(const rapidjson::Value &config, const elliptics::node &node,
		const swarm::logger &logger, async_performer *async, const std::vector<int> &groups);

protected:
	void add_action(const std::function<void ()> &handler);
	swarm::logger logger() const;
	elliptics::session create_session() const;

private:
	async_performer *m_async;
	swarm::logger m_logger;
	std::unique_ptr<ioremap::elliptics::session> m_session;
	int m_timeout;
};

} // namespace metadata_updater
} // namespace ioremap

#endif // IOREMAP_RIFT_METADATA_UPDATER_HPP
