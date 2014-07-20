#ifndef __IOREMAP_RIFT_STAT_HPP
#define __IOREMAP_RIFT_STAT_HPP

#include "rift/jsonvalue.hpp"
#include "rift/server.hpp"

#include <thevoid/server.hpp>

namespace ioremap { namespace rift { namespace stat {

template <typename T>
struct on_stat : public thevoid::simple_request_stream<T> {
	virtual void on_request(const swarm::http_request &req, const boost::asio::const_buffer &buffer) {
		(void) req;
		(void) buffer;

		rift::JsonValue ret;
		const_cast<ioremap::rift::elliptics_base *>(this->server()->elliptics())->stat(ret, ret.GetAllocator());
		std::string data = ret.ToString();

		swarm::http_response reply;
		reply.set_code(swarm::http_response::ok);
		reply.headers().set_content_type("text/json; charset=utf-8");
		reply.headers().set_content_length(data.size());

		this->send_reply(std::move(reply), std::move(data));
	}
};

template <typename T>
struct on_route : public thevoid::simple_request_stream<T> {
	virtual void on_request(const swarm::http_request &req, const boost::asio::const_buffer &buffer) {
		(void) req;
		(void) buffer;

		rift::JsonValue ret;

		auto routes = this->server()->elliptics()->get_routes();

		struct addr_comp {
			bool operator() (const dnet_addr &a1, const dnet_addr &a2) const {
				return memcmp(a1.addr, a2.addr, sizeof(a1.addr)) < 0;
			}
		};
		
		struct id_comp {
			bool operator() (const dnet_id &id1, const dnet_id &id2) const {
				return dnet_id_cmp(&id1, &id2) < 0;
			}
		};

		std::map<int, std::map<dnet_addr, std::vector<dnet_id>, addr_comp>> group_addrs;
		for (auto it = routes.begin(); it != routes.end(); ++it) {
			const auto & addr = it->second;
			const auto & id = it->first;

			int group_id = id.group_id;

			auto group_it = group_addrs.find(group_id);
			if (group_it == group_addrs.end()) {
				group_addrs[group_id] = std::map<dnet_addr, std::vector<dnet_id>, addr_comp>();
				group_it = group_addrs.find(group_id);
			}

			auto & addrs = group_it->second;

			auto tmp = addrs.find(addr);
			if (tmp == addrs.end()) {
				tmp = addrs.insert(std::make_pair(addr, std::vector<dnet_id>())).first;
			}

			tmp->second.push_back(id);
		}

		rapidjson::Value groups_json(rapidjson::kArrayType);

		for (auto group_it = group_addrs.begin(); group_it != group_addrs.end(); ++group_it) {
			int group_id = group_it->first;
			auto & addrs = group_it->second;

			rapidjson::Value group_entry(rapidjson::kObjectType);

			rapidjson::Value addrs_json(rapidjson::kArrayType);
			for (auto it = addrs.begin(); it != addrs.end(); ++it) {
				rapidjson::Value entry(rapidjson::kObjectType);

				auto & addr = it->first;
				char addr_str[128];
				dnet_server_convert_dnet_addr_raw(&addr, addr_str, sizeof(addr_str));
				rapidjson::Value addr_json(addr_str, strlen(addr_str), ret.GetAllocator());
				entry.AddMember("addr", addr_json, ret.GetAllocator());

				auto & ids = it->second;
				std::sort(ids.begin(), ids.end(), id_comp());

				rapidjson::Value ids_json(rapidjson::kArrayType);
				char id_str[2*DNET_ID_SIZE + 1];
				for (auto id = ids.begin(); id != ids.end(); ++id) {
					dnet_dump_id_len_raw(id->id, DNET_ID_SIZE, id_str);
					rapidjson::Value id_val(id_str, DNET_ID_SIZE*2, ret.GetAllocator());

					ids_json.PushBack(id_val, ret.GetAllocator());
				}

				entry.AddMember("ids", ids_json, ret.GetAllocator());

				addrs_json.PushBack(entry, ret.GetAllocator());
			}

			group_entry.AddMember("group", group_id, ret.GetAllocator());
			group_entry.AddMember("addrs", addrs_json, ret.GetAllocator());

			groups_json.PushBack(group_entry, ret.GetAllocator());
		}

		ret.AddMember("groups", groups_json, ret.GetAllocator());

		std::string data = ret.ToString();

		swarm::http_response reply;
		reply.set_code(swarm::http_response::ok);
		reply.headers().set_content_type("text/json; charset=utf-8");
		reply.headers().set_content_length(data.size());

		this->send_reply(std::move(reply), std::move(data));
	}
};

}}} // namespace ioremap::rift::stat

#endif /*__IOREMAP_RIFT_STAT_HPP */
