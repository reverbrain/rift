#ifndef IOREMAP_RIFT_AUTH_HPP
#define IOREMAP_RIFT_AUTH_HPP

// must be the first, since thevoid internally uses X->boost::buffer conversion,
// which must be present at compile time
#include "rift/asio.hpp"

#include <thevoid/server.hpp>
#include <swarm/http_request.hpp>
#include <swarm/logger.hpp>
#include <elliptics/session.hpp>

namespace ioremap {
namespace rift {

class auth_interface
{
public:
	virtual ~auth_interface() {}
	virtual bool check(const swarm::http_request &request) = 0;
};

class simple_password_auth : public auth_interface
{
public:
	simple_password_auth();

	bool initialize(const rapidjson::Value &config, const swarm::logger &logger);
	bool check(const swarm::http_request &request);

protected:
	swarm::logger m_logger;
	std::map<std::string, std::string> m_keys;
};

class auth : public simple_password_auth
{
public:
	auth();

	bool initialize(const rapidjson::Value &config, const ioremap::elliptics::node &node, const swarm::logger &logger);
	bool check(const swarm::http_request &request);

	std::string generate_signature(const swarm::http_request &request, const std::string &key) const;

private:
	std::unique_ptr<ioremap::elliptics::node> m_node;
};

} // namespace rift
} // namespace ioremap

#endif // IOREMAP_RIFT_AUTH_HPP
