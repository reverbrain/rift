#include "rift/auth.hpp"
#include <elliptics/interface.h>

#include <iostream>

namespace ioremap {
namespace rift {

static std::string to_lower(const std::string &str)
{
	std::string result;
	result.resize(str.size());
	std::transform(str.begin(), str.end(), result.begin(), tolower);
	return result;
}

std::string rift_authorization::generate_signature(const swarm::http_request &request, const std::string &key)
{
	const auto &url = request.url();
	const auto &query = url.query();
	const auto &original_headers = request.headers().all();

	std::vector<swarm::headers_entry> headers;
	for (auto it = original_headers.begin(); it != original_headers.end(); ++it) {
		std::string name = to_lower(it->first);
		if (name.compare(0, 6, "x-ell-") == 0) {
			headers.emplace_back(std::move(name), it->second);
		}
	}

	std::sort(headers.begin(), headers.end());

	std::vector<std::pair<std::string, std::string> > query_items;

	for (size_t i = 0; i < query.count(); ++i) {
		const auto &item = query.item(i);
		query_items.emplace_back(to_lower(item.first), item.second);
	}

	std::sort(query_items.begin(), query_items.end());

	std::string text = request.method();
	text += '\n';
	text += url.path();
	if (!query_items.empty()) {
		swarm::url_query query;
		for (auto it = query_items.begin(); it != query_items.end(); ++it) {
			query.add_item(it->first, it->second);
		}

		text += '?';
		text += query.to_string();
	}
	text += '\n';

	for (auto it = headers.begin(); it != headers.end(); ++it) {
		text += it->first;
		text += ':';
		text += it->second;
		text += '\n';
	}

	dnet_raw_id signature;
	char signature_str[DNET_ID_SIZE * 2 + 1];

	dnet_digest_auth_transform_raw(text.c_str(), text.size(), key.c_str(), key.size(), signature.id, DNET_ID_SIZE);
	dnet_dump_id_len_raw(signature.id, DNET_ID_SIZE, signature_str);

	return signature_str;
}

std::tuple<swarm::http_response::status_type, no_authorization::request_stream_ptr, bucket_acl> no_authorization::check_permission(
	const request_stream_ptr &stream, const swarm::http_request &request, const bucket_meta_raw &meta)
{
	std::string user = "*";
	std::string token;

	return check_permission_with_username_and_token(stream, request, meta, user, token);
}

rift_authorization::rift_authorization(const swarm::logger &logger) : m_logger(logger)
{
}

rift_authorization::result_tuple rift_authorization::check_permission(
	const request_stream_ptr &stream, const swarm::http_request &request, const bucket_meta_raw &meta)
{
	auto verdict = swarm::http_response::not_found;

	std::string user;
	std::string token;

	if (auto auth = request.headers().get("Authorization")) {
		// Authorization: riftv1 user:token

		const std::string &authorization = *auth;
		const size_t end_of_method = authorization.find(' ');
		if (end_of_method == std::string::npos) {
			verdict = swarm::http_response::forbidden;
			m_logger.log(swarm::SWARM_LOG_NOTICE, "verdict: url: %s, bucket: %s: acls: %zd: invalid auth: %s",
					request.url().to_human_readable().c_str(), meta.key.c_str(), meta.acl.size(), auth->c_str());
			return std::make_tuple(verdict, stream, bucket_acl());
		} else {
			if (authorization.compare(0, end_of_method, "riftv1", 6) != 0) {
				verdict = swarm::http_response::forbidden;
				m_logger.log(swarm::SWARM_LOG_NOTICE, "verdict: url: %s, bucket: %s: acls: %zd: unknown auth: %s",
						request.url().to_human_readable().c_str(), meta.key.c_str(), meta.acl.size(), auth->c_str());
				return std::make_tuple(verdict, stream, bucket_acl());
			}

			const size_t end_of_user = authorization.find(':', end_of_method + 1);
			user = authorization.substr(end_of_method + 1, end_of_user - end_of_method - 1);

			if (end_of_user != std::string::npos)
				token = authorization.substr(end_of_user + 1);
		}
	} else {
		user = "*";
	}

	return check_permission_with_username_and_token(stream, request, meta, user, token);
}

no_authorization::no_authorization(const swarm::logger &logger) : rift_authorization(logger)
{
}

authorization_checker_base::result_tuple rift_authorization::check_permission_with_username_and_token(const request_stream_ptr &stream, const swarm::http_request &request, const bucket_meta_raw &meta, const std::string &user, const std::string &token)
{
	auto verdict = swarm::http_response::not_found;

	auto it = meta.acl.find(user);
	if (it == meta.acl.end()) {
		// There is no user with this name, return error
		verdict = swarm::http_response::forbidden;


		m_logger.log(swarm::SWARM_LOG_ERROR, "verdict: url: %s, bucket: %s: user: %s, acls: %zd: "
				"no user in acl list -> %d",
				request.url().to_human_readable().c_str(), meta.key.c_str(), user.c_str(),
				meta.acl.size(), verdict);

		for (auto a = meta.acl.begin(); a != meta.acl.end(); ++a) {
			m_logger.log(swarm::SWARM_LOG_INFO, "url: %s, acl: '%s'\n",
					request.url().to_human_readable().c_str(), a->first.c_str());
		}
		return std::make_tuple(verdict, stream, bucket_acl());
	}

	bucket_acl acl = it->second;

	if (acl.has_no_token()) {
		// User has no token so we don't have to authenticate him
		verdict = swarm::http_response::ok;

		m_logger.log(swarm::SWARM_LOG_INFO, "verdict: url: %s, bucket: %s: user: %s, acls: %zd: "
				"passed total noauth check -> %d",
				request.url().to_human_readable().c_str(), meta.key.c_str(), user.c_str(), meta.acl.size(), verdict);
		return std::make_tuple(verdict, stream, acl);
	}

	if (token.empty()) {
		verdict = swarm::http_response::unauthorized;

		m_logger.log(swarm::SWARM_LOG_ERROR, "verdict: url: %s, bucket: %s: user: %s, acls: %zd: "
				"no 'Authorization' header -> %d",
				request.url().to_human_readable().c_str(), meta.key.c_str(), user.c_str(),
				meta.acl.size(), verdict);
		return std::make_tuple(verdict, stream, acl);
	}

	auto key = generate_signature(request, acl.token);
	if (key != token) {
		verdict = swarm::http_response::forbidden;

		m_logger.log(swarm::SWARM_LOG_ERROR, "verdict: url: %s, bucket: %s: user: %s, acls: %zd: "
				"calculated-key: %s, auth-header: %s: incorrect auth header -> %d",
				request.url().to_human_readable().c_str(), meta.key.c_str(), user.c_str(), meta.acl.size(),
				key.c_str(), token.c_str(), verdict);
		return std::make_tuple(verdict, stream, acl);
	}

	verdict = swarm::http_response::ok;

	m_logger.log(swarm::SWARM_LOG_INFO, "verdict: url: %s, bucket: %s: user: %s, acls: %zd: auth-header: %s: OK -> %d",
			request.url().to_human_readable().c_str(), meta.key.c_str(), user.c_str(), meta.acl.size(), key.c_str(), verdict);

	return std::make_tuple(verdict, stream, acl);
}

}} // namespace ioremap::rift
