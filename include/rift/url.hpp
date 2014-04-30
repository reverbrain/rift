#ifndef __IOREMAP_RIFT_URL_HPP
#define __IOREMAP_RIFT_URL_HPP

#include <swarm/http_request.hpp>

#include <string>

namespace ioremap { namespace rift { namespace url {

static inline const std::string key(const swarm::http_request &req, bool m_bucket) {
	std::string key;

	const auto &path = req.url().path_components();

	if (!m_bucket) {
		size_t prefix_size = 1 + path[0].size() + 1;
		key = req.url().path().substr(prefix_size);
	} else {
		size_t prefix_size = 1 + path[0].size() + 1 + path[1].size() + 1;
		key = req.url().path().substr(prefix_size);
	}

	return key;
}

static inline const std::string bucket(const swarm::http_request &req) {
	const auto &path = req.url().path_components();

	size_t prefix_size = 1 + path[0].size() + 1;

	return req.url().path().substr(prefix_size, path[1].size());
}

}}} // namespace ioremap::rift::url

#endif /* __IOREMAP_RIFT_URL_HPP */
