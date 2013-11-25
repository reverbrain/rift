#include "rift/auth.hpp"

namespace ioremap {
namespace rift {

static std::string to_lower(const std::string &str)
{
	std::string result;
	result.resize(str.size());
	std::transform(str.begin(), str.end(), result.begin(), tolower);
	return result;
}

static void check_hash(const std::string &message)
{
	dnet_raw_id signature;
	char signature_str[DNET_ID_SIZE * 2 + 1];

	dnet_digest_transform_raw(message.c_str(), message.size(), signature.id, DNET_ID_SIZE);
	dnet_dump_id_len_raw(signature.id, DNET_ID_SIZE, signature_str);
}

std::string http_auth::generate_signature(const swarm::http_request &request, const std::string &key)
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

	swarm::url result_url;
	result_url.set_path(url.path());

	for (auto it = query_items.begin(); it != query_items.end(); ++it) {
		result_url.query().add_item(it->first, it->second);
	}

	std::string text = request.method();
	text += '\n';
	text += result_url.to_string();
	text += '\n';

	for (auto it = headers.begin(); it != headers.end(); ++it) {
		text += it->first;
		text += ':';
		text += it->second;
		text += '\n';
	}

	check_hash(key);
	check_hash(text);

	dnet_raw_id signature;
	char signature_str[DNET_ID_SIZE * 2 + 1];

	dnet_digest_auth_transform_raw(text.c_str(), text.size(), key.c_str(), key.size(), signature.id, DNET_ID_SIZE);
	dnet_dump_id_len_raw(signature.id, DNET_ID_SIZE, signature_str);

	return signature_str;
}

}} // namespace ioremap::rift
