#ifndef __IOREMAP_RIFT_AUTH_HPP
#define __IOREMAP_RIFT_AUTH_HPP

#include <swarm/http_request.hpp>
#include <swarm/logger.hpp>

#include <mutex>
#include "bucket.hpp"

#include "crypto.hpp"

namespace ioremap {
namespace rift {

/*!
 * \brief The rift_authorization class provides riftv1 authorization method
 */
class rift_authorization : public authorization_checker_base
{
public:
	rift_authorization();

	virtual result_tuple check_permission(
		const request_stream_ptr &stream, const thevoid::http_request &request, const bucket_meta_raw &meta, const swarm::logger &logger);

	static std::string generate_signature(const thevoid::http_request &request, const std::string &key);

	result_tuple check_permission_with_username_and_token(
		const request_stream_ptr &stream, const thevoid::http_request &request,
		const bucket_meta_raw &meta, const std::string &user, const std::string &token,
		const swarm::logger &logger);
};

/*!
 * \brief The no_authorization class provides authorization method
 * in case if there is no Authorization field. It's assumed that
 * the user is '*' and there is no token.
 */
class no_authorization : public rift_authorization
{
public:
	no_authorization();

	virtual result_tuple check_permission(
		const std::shared_ptr<thevoid::base_request_stream> &stream, const thevoid::http_request &request,
		const bucket_meta_raw &meta, const swarm::logger &logger);
};

template <typename Server>
class md5_check_proxy : public thevoid::simple_request_stream<Server>
{
public:
	md5_check_proxy(const authorization_checker_base::request_stream_ptr &stream, const std::string &content_md5)
		: m_stream(stream), m_content_md5(content_md5)
	{
	}

	virtual void on_request(const thevoid::http_request &req, const boost::asio::const_buffer &buffer)
	{
		std::string content_md5 = rift::crypto::calc_hash<CryptoPP::Weak::MD5>(buffer);

		if (content_md5 != m_content_md5) {
			BH_LOG(this->logger(), SWARM_LOG_ERROR, "md5_check_proxy, url: %s, mismatched content-md5, local: %s, remote: %s",
				req.url().to_human_readable().c_str(), content_md5.c_str(), m_content_md5.c_str());
			this->send_reply(thevoid::http_response::forbidden);
			return;
		}

		m_stream->initialize(this->reply());
		m_stream->on_headers(thevoid::http_request(req));
		m_stream->on_data(buffer);
		m_stream->on_close(boost::system::error_code());
	}

private:
	authorization_checker_base::request_stream_ptr m_stream;
	std::string m_content_md5;
};

class s3_v2_signature
{
public:
	s3_v2_signature(const std::string &host);

	struct info
	{
		std::string access_id;
		std::string signature;
	};

	boost::optional<info> extract_info(const thevoid::http_request &request, const swarm::logger &logger);
	thevoid::http_response::status_type check(const thevoid::http_request &request, const info &info, const bucket_acl &acl, const swarm::logger &logger);

protected:
	std::string m_host;
};

template <typename Server>
class s3_v2_authorization : public authorization_checker<Server>, public s3_v2_signature
{
public:
	s3_v2_authorization(Server *server, const std::string &host) :
		authorization_checker<Server>(server), s3_v2_signature(host)
	{
	}

	virtual authorization_checker_base::result_tuple check_permission(const authorization_checker_base::request_stream_ptr &stream,
		const thevoid::http_request &request, const bucket_meta_raw &meta, const swarm::logger &logger)
	{
		boost::optional<s3_v2_signature::info> info = s3_v2_signature::extract_info(request, logger);
		if (!info) {
			return std::make_tuple(thevoid::http_response::forbidden, stream, bucket_acl());
		}

		thevoid::http_response::status_type verdict;
		bucket_acl acl;
		std::tie(verdict, acl) = this->find_user(request, meta, info->access_id, logger);
		if (verdict != thevoid::http_response::continue_code) {
			return std::make_tuple(verdict, stream, acl);
		}

		verdict = s3_v2_signature::check(request, *info, acl, logger);

		if (auto content_md5 = request.headers().get("Content-MD5")) {
			auto new_stream = std::make_shared<md5_check_proxy<Server>>(stream, *content_md5);
			new_stream->set_server(this->m_server);
			return std::make_tuple(verdict, new_stream, acl);
		}

		return std::make_tuple(verdict, stream, acl);
	}
};

class s3_v4_signature
{
public:
	s3_v4_signature();

	struct info
	{
		std::string access_id;
		std::string scope;
		std::vector<std::string> headers;
		std::string signature;
	};

	boost::optional<info> extract_info(const thevoid::http_request &request, const swarm::logger &logger);
	thevoid::http_response::status_type check(const thevoid::http_request &request, const info &info, const bucket_acl &acl, const swarm::logger &logger);
};

template <typename Server>
class s3_v4_authorization : public authorization_checker<Server>, public s3_v4_signature
{
public:
	s3_v4_authorization(Server *server) : authorization_checker<Server>(server)
	{
	}

	virtual authorization_checker_base::result_tuple check_permission(const authorization_checker_base::request_stream_ptr &stream,
		const thevoid::http_request &request, const bucket_meta_raw &meta, const swarm::logger &logger)
	{
		boost::optional<s3_v4_signature::info> info = s3_v4_signature::extract_info(request, logger);
		if (!info) {
			return std::make_tuple(thevoid::http_response::forbidden, stream, bucket_acl());
		}

		thevoid::http_response::status_type verdict;
		bucket_acl acl;
		std::tie(verdict, acl) = this->find_user(request, meta, info->access_id, logger);
		if (verdict != thevoid::http_response::continue_code) {
			return std::make_tuple(verdict, stream, acl);
		}

		verdict = s3_v4_signature::check(request, *info, acl, logger);

		return std::make_tuple(verdict, stream, acl);
	}
};

} // namespace rift
} // namespace ioremap

#endif // __IOREMAP_RIFT_AUTH_HPP
