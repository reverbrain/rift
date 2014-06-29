#ifndef __IOREMAP_RIFT_URL_HPP
#define __IOREMAP_RIFT_URL_HPP

#include <swarm/http_request.hpp>

#include <string>

namespace ioremap { namespace rift { namespace url {

static inline const std::string key(const swarm::http_request &req, bool has_bucket) {
	std::string key;

	const auto &path = req.url().path_components();

	if (!has_bucket) {
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

	// This is the only method where bucket's name is second component but not the first one
	if (path[0] == "update-bucket")
		return path[2];
	return path[1];
}

}}} // namespace ioremap::rift::url

#endif /* __IOREMAP_RIFT_URL_HPP */
