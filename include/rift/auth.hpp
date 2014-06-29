#ifndef __IOREMAP_RIFT_AUTH_HPP
#define __IOREMAP_RIFT_AUTH_HPP

#include <swarm/http_request.hpp>
#include <swarm/logger.hpp>

#include <mutex>
#include "bucket.hpp"

namespace ioremap {
namespace rift {

/*!
 * \brief The rift_authorization class provides riftv1 authorization method
 */
class rift_authorization : public authorization_checker_base
{
public:
	rift_authorization(const swarm::logger &logger);

	virtual result_tuple check_permission(
		const request_stream_ptr &stream, const swarm::http_request &request, const bucket_meta_raw &meta);

	static std::string generate_signature(const swarm::http_request &request, const std::string &key);

	result_tuple check_permission_with_username_and_token(
		const request_stream_ptr &stream, const swarm::http_request &request, const bucket_meta_raw &meta, const std::string &user, const std::string &token);

protected:
	swarm::logger m_logger;
};

/*!
 * \brief The no_authorization class provides authorization method
 * in case if there is no Authorization field. It's assumed that
 * the user is '*' and there is no token.
 */
class no_authorization : public rift_authorization
{
public:
	no_authorization(const swarm::logger &logger);

	virtual result_tuple check_permission(
		const std::shared_ptr<thevoid::base_request_stream> &stream, const swarm::http_request &request, const bucket_meta_raw &meta);
};

} // namespace rift
} // namespace ioremap

#endif // __IOREMAP_RIFT_AUTH_HPP
