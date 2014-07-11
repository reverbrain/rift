#include "rift/auth.hpp"
#include <elliptics/interface.h>

#include <iostream>

namespace ioremap {
namespace rift {

authorization_checker_base::authorization_checker_base(const std::shared_ptr<thevoid::base_server> &server) : m_logger(server->logger())
{
}

std::tuple<swarm::http_response::status_type, ioremap::rift::bucket_acl> authorization_checker_base::find_user(const swarm::http_request &request, const bucket_meta_raw &meta, const std::string &user)
{
	swarm::http_response::status_type verdict;

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
		return std::make_tuple(verdict, rift::bucket_acl());
	}

	const bucket_acl &acl = it->second;

	if (acl.has_no_token()) {
		// User has no token so we don't have to authenticate him
		verdict = swarm::http_response::ok;

		m_logger.log(swarm::SWARM_LOG_INFO, "verdict: url: %s, bucket: %s: user: %s, acls: %zd: "
				"passed total noauth check -> %d",
				request.url().to_human_readable().c_str(), meta.key.c_str(), user.c_str(), meta.acl.size(), verdict);
		return std::make_tuple(verdict, acl);
	}

	return std::make_tuple(swarm::http_response::continue_code, acl);
}

static std::string to_lower(const std::string &str)
{
	std::string result;
	result.resize(str.size());
	std::transform(str.begin(), str.end(), result.begin(), tolower);
	return result;
}

template <size_t Size>
static std::vector<swarm::headers_entry> extract_special_headers(const swarm::http_headers &headers, const char (&prefix)[Size])
{
	const auto &original_headers = headers.all();

	std::vector<swarm::headers_entry> result;
	for (auto it = original_headers.begin(); it != original_headers.end(); ++it) {
		std::string name = to_lower(it->first);
		if (name.compare(0, Size - 1, prefix) == 0) {
			result.emplace_back(std::move(name), it->second);
		}
	}

	std::sort(result.begin(), result.end());

	return std::move(result);
}

std::string rift_authorization::generate_signature(const swarm::http_request &request, const std::string &key)
{
	const auto &url = request.url();
	const auto &query = url.query();

	std::vector<swarm::headers_entry> headers = extract_special_headers(request.headers(), "x-ell-");

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

rift_authorization::rift_authorization(const std::shared_ptr<thevoid::base_server> &server) : authorization_checker_base(server)
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

no_authorization::no_authorization(const std::shared_ptr<thevoid::base_server> &server) : rift_authorization(server)
{
}

authorization_checker_base::result_tuple rift_authorization::check_permission_with_username_and_token(const request_stream_ptr &stream, const swarm::http_request &request, const bucket_meta_raw &meta, const std::string &user, const std::string &token)
{
	auto verdict = swarm::http_response::not_found;

	bucket_acl acl;
	std::tie(verdict, acl) = find_user(request, meta, user);
	if (verdict != swarm::http_response::continue_code) {
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

s3_v2_signature::s3_v2_signature(const swarm::logger &logger, const std::string &host) : m_logger(logger), m_host(host)
{
}

boost::optional<s3_v2_signature::info> s3_v2_signature::extract_info(const swarm::http_request &request)
{
	auto auth_ptr = request.headers().get("Authorization");
	if (!auth_ptr)
		return boost::none;

	// Authorization: AWS AKIAIOSFODNN7EXAMPLE:frJIUN8DYpKDtOLCwo//yllqDzg=

	const std::string &authorization = *auth_ptr;
	const size_t method_end = authorization.find(' ');
	if (method_end == std::string::npos || method_end + 1 >= authorization.size())
		return boost::none;

	const size_t token_begin = method_end + 1;
	const size_t token_end = authorization.find(':', token_begin);

	if (token_end == std::string::npos || token_end + 1 >= authorization.size())
		return boost::none;

	s3_v2_signature::info info;
	info.access_id = authorization.substr(token_begin, token_end - token_begin);
	info.signature = authorization.substr(token_end + 1);

	m_logger.log(swarm::SWARM_LOG_DEBUG, "auth: '%s', access_id: '%s', signature: '%s'", authorization.c_str(), info.access_id.c_str(), info.signature.c_str());

	return std::move(info);
}

swarm::http_response::status_type s3_v2_signature::check(const swarm::http_request &request, const s3_v2_signature::info &info, const bucket_acl &acl)
{
	std::string string_to_sign;
	string_to_sign += request.method();
	string_to_sign += '\n';
	if (auto tmp = request.headers().get("Content-MD5"))
		string_to_sign += *tmp;
	string_to_sign += '\n';
	if (auto tmp = request.headers().content_type())
		string_to_sign += *tmp;
	string_to_sign += '\n';

	if (auto date = request.headers().get("Date")) {
		string_to_sign += *date;
	} else {
		m_logger.log(swarm::SWARM_LOG_ERROR, "s3_v2_signature: url: %s, verdict: 403, 'Date' field is missed", request.url().original().c_str());
		return swarm::http_response::forbidden;
	}
	string_to_sign += '\n';

	std::vector<swarm::headers_entry> headers = extract_special_headers(request.headers(), "x-amz-");
	for (size_t i = 0; i < headers.size(); ++i) {
		if (i == 0 || headers[i - 1].first != headers[i].first) {
			string_to_sign += headers[i].first;
			string_to_sign += ':';
		} else {
			string_to_sign += ',';
		}
		string_to_sign += headers[i].second;
	}

	if (auto host_ptr = request.headers().get("Host")) {
		const std::string &host = *host_ptr;
		const size_t host_size = std::min(host.size(), host.find_first_of(':'));
		if (host_size >= m_host.size() + 1) {
			string_to_sign += '/';
			string_to_sign += host.substr(0, host_size - m_host.size() - 1);
		}
	}

	string_to_sign += request.url().path();

	m_logger.log(swarm::SWARM_LOG_DEBUG, "s3_v2_signature: url: %s, string: '%s'", request.url().original().c_str(), string_to_sign.c_str());

	std::string signature = rift::crypto::calc_hmac<CryptoPP::SHA1>(string_to_sign, acl.token);

	if (signature != info.signature) {
		m_logger.log(swarm::SWARM_LOG_DEBUG, "s3_v2_signature: url: %s, signature mismatch, remote: '%s', local: '%s'",
			request.url().original().c_str(), info.signature.c_str(), signature.c_str());
		return swarm::http_response::forbidden;
	}

	m_logger.log(swarm::SWARM_LOG_DEBUG, "s3_v2_signature: url: %s, signature: '%s'", request.url().original().c_str(), signature.c_str());

	return swarm::http_response::ok;
}

s3_v4_signature::s3_v4_signature(const swarm::logger &logger) : m_logger(logger)
{
}

boost::optional<s3_v4_signature::info> s3_v4_signature::extract_info(const swarm::http_request &request)
{
	if (auto auth = request.headers().get("Authorization")) {
		// Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,
		// SignedHeaders=host;range;x-amz-date,
		// Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024

		const std::string &authorization = *auth;
//		size_t authorization.find(' ');
	}

	return boost::optional<s3_v4_signature::info>();
}

swarm::http_response::status_type s3_v4_signature::check(const swarm::http_request &request, const s3_v4_signature::info &info, const bucket_acl &acl)
{
	return swarm::http_response::forbidden;
}

}} // namespace ioremap::rift
