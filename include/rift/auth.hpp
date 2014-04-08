#ifndef __IOREMAP_RIFT_AUTH_HPP
#define __IOREMAP_RIFT_AUTH_HPP

#include <swarm/http_request.hpp>
#include <swarm/logger.hpp>

#include <mutex>

namespace ioremap {
namespace rift {

class http_auth
{
	public:
		static std::string generate_signature(const swarm::http_request &request, const std::string &key);
};

} // namespace rift
} // namespace ioremap

#endif // __IOREMAP_RIFT_AUTH_HPP
