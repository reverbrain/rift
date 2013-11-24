#ifndef __IOREMAP_RIFT_SERVER_HPP
#define __IOREMAP_RIFT_SERVER_HPP

// must be the first, since thevoid internally uses X->boost::buffer conversion,
// which must be present at compile time
#include "rift/asio.hpp"

#include "rift/bucket.hpp"
#include "rift/common.hpp"
#include "rift/io.hpp"
#include "rift/index.hpp"

#include <thevoid/server.hpp>
#include <swarm/logger.hpp>
#include <elliptics/session.hpp>

namespace ioremap {
namespace rift {

class elliptics_base
{
public:
	elliptics_base();

	bool initialize(const rapidjson::Value &config, const swarm::logger &logger);

	elliptics::node node() const;
	elliptics::session session() const;
	virtual swarm::http_response::status_type process(const swarm::http_request &request, elliptics::key &key, elliptics::session &session) const;

	std::vector<int> metadata_groups() const;

protected:
	virtual bool prepare_config(const rapidjson::Value &config, dnet_config &node_config);
	virtual bool prepare_node(const rapidjson::Value &config, elliptics::node &node);
	virtual bool prepare_session(const rapidjson::Value &config, elliptics::session &session);

	swarm::logger logger() const;

private:
	swarm::logger m_logger;
	std::unique_ptr<elliptics::node> m_node;
	std::unique_ptr<elliptics::session> m_session;
	std::vector<int> m_metadata_groups;
	std::unique_ptr<rift::bucket> m_bucket;
};

}} // namespace ioremap::rift

#endif /*__IOREMAP_RIFT_SERVER_HPP */
