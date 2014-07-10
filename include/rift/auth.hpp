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
	rift_authorization(const std::shared_ptr<thevoid::base_server> &server);

	virtual result_tuple check_permission(
		const request_stream_ptr &stream, const swarm::http_request &request, const bucket_meta_raw &meta);

	static std::string generate_signature(const swarm::http_request &request, const std::string &key);

	result_tuple check_permission_with_username_and_token(
		const request_stream_ptr &stream, const swarm::http_request &request, const bucket_meta_raw &meta, const std::string &user, const std::string &token);
};

/*!
 * \brief The no_authorization class provides authorization method
 * in case if there is no Authorization field. It's assumed that
 * the user is '*' and there is no token.
 */
class no_authorization : public rift_authorization
{
public:
	no_authorization(const std::shared_ptr<thevoid::base_server> &server);

	virtual result_tuple check_permission(
		const std::shared_ptr<thevoid::base_request_stream> &stream, const swarm::http_request &request, const bucket_meta_raw &meta);
};

class s3_v2_signature
{
public:
	s3_v2_signature(const swarm::logger &logger);

	struct info
	{
		std::string access_id;
		std::string signature;
	};

	boost::optional<info> extract_info(const swarm::http_request &request);
	swarm::http_response::status_type check(const swarm::http_request &request, const info &info, const bucket_acl &acl);

protected:
	swarm::logger m_logger;
};

template <typename Server>
class s3_v2_authorization : public authorization_checker<Server>, public s3_v2_signature
{
public:
	s3_v2_authorization(const std::shared_ptr<Server> &server) : authorization_checker<Server>(server), s3_v2_signature(server->logger())
	{
	}

	virtual authorization_checker_base::result_tuple check_permission(const authorization_checker_base::request_stream_ptr &stream, const swarm::http_request &request, const bucket_meta_raw &meta)
	{
		boost::optional<s3_v2_signature::info> info = s3_v2_signature::extract_info(request);
		if (!info) {
			return std::make_tuple(swarm::http_response::forbidden, stream, bucket_acl());
		}

		swarm::http_response::status_type verdict;
		bucket_acl acl;
		std::tie(verdict, acl) = this->find_user(request, meta, info->access_id);
		if (verdict != swarm::http_response::continue_code) {
			return std::make_tuple(verdict, stream, acl);
		}

		verdict = s3_v2_signature::check(request, *info, acl);

		return std::make_tuple(verdict, stream, acl);
	}
};

class s3_v4_signature
{
public:
	s3_v4_signature(const swarm::logger &logger);

	struct info
	{
		std::string access_id;
		std::string scope;
		std::vector<std::string> headers;
		std::string signature;
	};

	boost::optional<info> extract_info(const swarm::http_request &request);
	swarm::http_response::status_type check(const swarm::http_request &request, const info &info, const bucket_acl &acl);

protected:
	swarm::logger m_logger;
};

template <typename Server>
class s3_v4_authorization : public authorization_checker<Server>, public s3_v4_signature
{
public:
	s3_v4_authorization(const std::shared_ptr<Server> &server) : authorization_checker<Server>(server), s3_v4_signature(server->logger())
	{
	}

	virtual authorization_checker_base::result_tuple check_permission(const authorization_checker_base::request_stream_ptr &stream, const swarm::http_request &request, const bucket_meta_raw &meta)
	{
		boost::optional<s3_v4_signature::info> info = s3_v4_signature::extract_info(request);
		if (!info) {
			return std::make_tuple(swarm::http_response::forbidden, stream, bucket_acl());
		}

		swarm::http_response::status_type verdict;
		bucket_acl acl;
		std::tie(verdict, acl) = this->find_user(request, meta, info->access_id);
		if (verdict != swarm::http_response::continue_code) {
			return std::make_tuple(verdict, stream, acl);
		}

		verdict = s3_v4_signature::check(request, *info, acl);

		return std::make_tuple(verdict, stream, acl);
	}
};

} // namespace rift
} // namespace ioremap

#endif // __IOREMAP_RIFT_AUTH_HPP
