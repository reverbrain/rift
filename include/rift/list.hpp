#ifndef __IOREMAP_RIFT_LIST_HPP
#define __IOREMAP_RIFT_LIST_HPP

// must be the first, since thevoid internally uses X->boost::buffer conversion,
// which must be present at compile time
#include "rift/asio.hpp"

#include "rift/jsonvalue.hpp"
#include "rift/bucket.hpp"

#include <swarm/url.hpp>
#include <swarm/url_query.hpp>

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

#include <elliptics/debug.hpp>

namespace ioremap { namespace rift { namespace list {

// return list of keys in bucket
template <typename Server, typename Stream>
class on_list_base : public bucket_processing<Server, Stream>
{
public:
	virtual void checked(const swarm::http_request &req, const boost::asio::const_buffer &buffer,
			const bucket_meta_raw &meta, swarm::http_response::status_type verdict) {
		const auto &query = req.url().query();

		if ((verdict != swarm::http_response::ok) && !meta.noauth_read()) {
			this->log(swarm::SWARM_LOG_ERROR, "list-base: checked: url: %s, flags: 0x%lx, verdict: %d",
					query.to_string().c_str(), meta.flags, verdict);

			this->send_reply(verdict);
			return;
		}

		auto ns = query.item_value("namespace");
		if (!ns) {
			this->log(swarm::SWARM_LOG_ERROR, "list-base: checked: url: %s, flags: 0x%lx: there must be a namespace parameter",
					query.to_string().c_str(), meta.flags);

			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		this->log(swarm::SWARM_LOG_NOTICE, "list-base: checked: url: %s, flags: 0x%lx, verdict: %d",
				query.to_string().c_str(), meta.flags, verdict);

		(void) buffer;

		elliptics::key key;
		elliptics::session session = this->server()->extract_key(req, meta, key);
		session.set_timeout(this->server()->elliptics()->read_timeout());

		std::vector<std::string> keys;
		keys.emplace_back(*ns + ".index");

		session.find_all_indexes(keys).connect(std::bind(&on_list_base::on_find_finished, this->shared_from_this(),
					meta, std::placeholders::_1, std::placeholders::_2));
	}

	virtual void on_find_finished(const bucket_meta_raw &meta, const elliptics::sync_find_indexes_result &result, const elliptics::error_info &error) {
		if (error) {
			this->log(swarm::SWARM_LOG_ERROR, "list-base: find-finished: flags: 0x%lx, error: %s",
					meta.flags, error.message().c_str());

			if (error.code() == -ENOENT) {
				this->send_reply(swarm::http_response::not_found);
				return;
			}

			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		rift::JsonValue result_object;
		rapidjson::Value infos;
		infos.SetArray();

		for (auto idx = result.begin(); idx != result.end(); ++idx) {
			const auto & d = idx->indexes[0].data;

			bucket_meta_index_data index_data;
			try {
				msgpack::unpacked msg;
				msgpack::unpack(&msg, d.data<char>(), d.size());

				msg.get().convert(&index_data);
			} catch (const std::exception &e) {
				index_data.key = e.what();
			}

			rapidjson::Value info;
			info.SetObject();

			char id_str[2 * DNET_ID_SIZE + 1];
			dnet_dump_id_len_raw(idx->id.id, DNET_ID_SIZE, id_str);
			rapidjson::Value id_str_value(id_str, 2 * DNET_ID_SIZE, result_object.GetAllocator());
			info.AddMember("id", id_str_value, result_object.GetAllocator());

			rapidjson::Value key_str_value(index_data.key.c_str(), index_data.key.size(), result_object.GetAllocator());
			info.AddMember("key", key_str_value, result_object.GetAllocator());

			std::ostringstream ss;
			ss << index_data.ts;

			std::string time_str = ss.str();

			rapidjson::Value ts_str_value(time_str.c_str(), time_str.size(), result_object.GetAllocator());
			info.AddMember("timestamp", ts_str_value, result_object.GetAllocator());

			time_str = boost::lexical_cast<std::string>(index_data.ts.tsec);
			rapidjson::Value ts_sec_str_value(time_str.c_str(), time_str.size(), result_object.GetAllocator());
			info.AddMember("time_seconds", ts_sec_str_value, result_object.GetAllocator());


			infos.PushBack(info, result_object.GetAllocator());
		}

		result_object.AddMember("indexes", infos, result_object.GetAllocator());

		auto data = result_object.ToString();

		swarm::http_response reply;
		reply.set_code(swarm::http_response::ok);
		reply.headers().set_content_length(data.size());
		reply.headers().set_content_type("text/json");

		this->send_reply(std::move(reply), std::move(data));
	}
};

template <typename Server>
class on_list : public on_list_base<Server, on_list<Server>>
{
public:
};

}}} // namespace ioremap::rift::list

#endif /* __IOREMAP_RIFT_LIST_HPP */
