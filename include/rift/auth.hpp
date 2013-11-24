#ifndef __IOREMAP_RIFT_AUTH_HPP
#define __IOREMAP_RIFT_AUTH_HPP

// must be the first, since thevoid internally uses X->boost::buffer conversion,
// which must be present at compile time
#include "rift/asio.hpp"

#include <swarm/http_request.hpp>
#include <swarm/logger.hpp>

#include <mutex>

namespace ioremap {
namespace rift {

class auth_interface
{
public:
	virtual ~auth_interface() {}
	virtual bool initialize(const swarm::logger &logger);
	virtual bool check(const swarm::http_request &request) = 0;
};

class http_auth
{
	public:
		static std::string generate_signature(const swarm::http_request &request, const std::string &key);
};

class auth : public auth_interface
{
public:
	auth();

	bool initialize(const swarm::logger &logger);
	void add_key(const std::string &key, const std::string &token);
	bool check(const swarm::http_request &request);

private:
	std::mutex m_lock;
	std::map<std::string, std::string> m_keys;
	swarm::logger m_logger;
};

} // namespace rift
} // namespace ioremap

#endif // __IOREMAP_RIFT_AUTH_HPP
