#ifndef __IOREMAP_RIFT_SIGNATURE_HPP
#define __IOREMAP_RIFT_SIGNATURE_HPP

// must be the first, since thevoid internally uses X->boost::buffer conversion,
// which must be present at compile time
#include "rift/asio.hpp"

#include <thevoid/server.hpp>
#include <swarm/logger.hpp>
#include <elliptics/session.hpp>

namespace ioremap {
namespace rift {

class signature
{
public:
    signature();

    bool initialize(const rapidjson::Value &config, const ioremap::elliptics::node &node, const swarm::logger &logger);

    std::string sign(const swarm::url &url) const;

protected:
    swarm::logger logger() const;

private:
    std::string m_key;
    std::unique_ptr<ioremap::elliptics::node> m_node;
    swarm::logger m_logger;
};

}} // namespace ioremap::rift

#endif // __IOREMAP_RIFT_SIGNATURE_HPP
