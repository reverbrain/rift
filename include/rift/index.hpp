#ifndef __IOREMAP_RIFT_INDEX_HPP
#define __IOREMAP_RIFT_INDEX_HPP

#include <thevoid/server.hpp>

#include "rift/asio.hpp"
#include "rift/bucket.hpp"
#include "rift/jsonvalue.hpp"

namespace ioremap { namespace rift { namespace index { 

// set indexes for given ID
template <typename Server, typename Stream>
class on_update_base : public bucket_processing<Server, Stream>
{
public:
	virtual void checked(const swarm::http_request &req, const boost::asio::const_buffer &buffer,
			const bucket_meta_raw &meta, const bucket_acl &acl, swarm::http_response::status_type verdict) {
		const auto &query = req.url().query();

		if ((verdict != swarm::http_response::ok) && !acl.noauth_all()) {
			this->log(swarm::SWARM_LOG_ERROR, "update-base: checked: url: %s, verdict: %d, did-not-pass-noauth-check",
				query.to_string().c_str(), verdict);
			this->send_reply(verdict);
			return;
		}

		this->log(swarm::SWARM_LOG_NOTICE, "update-base: checked: url: %s, original-verdict: %d, passed-noauth-check",
			query.to_string().c_str(), verdict);

		(void) meta;

		std::string buf(boost::asio::buffer_cast<const char*>(buffer), boost::asio::buffer_size(buffer));
		rapidjson::Document doc;
		doc.Parse<0>(buf.c_str());

		if (doc.HasParseError()) {
			this->log(swarm::SWARM_LOG_ERROR, "update-base: url: %s: request parsing error offset: %zd, message: %s",
					query.to_string().c_str(), doc.GetErrorOffset(), doc.GetParseError());
			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		if (!doc.HasMember("indexes")) {
			this->log(swarm::SWARM_LOG_ERROR, "update-base: url: %s: document doesn't contain 'indexes' member",
					query.to_string().c_str());
			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		elliptics::key key;
		elliptics::session session = this->server()->elliptics()->write_data_session(req, meta, key);

		std::vector<elliptics::index_entry> indexes_entries;

		elliptics::index_entry entry;

		auto &indexes = doc["indexes"];
		for (auto it = indexes.MemberBegin(); it != indexes.MemberEnd(); ++it) {
			session.transform(it->name.GetString(), entry.index);
			entry.data = elliptics::data_pointer::copy(it->value.GetString(),
					it->value.GetStringLength());

			indexes_entries.push_back(entry);
		}

		session.set_indexes(key, indexes_entries)
				.connect(std::bind(&on_update_base::on_update_finished,
							this->shared_from_this(), std::placeholders::_2));
	}

	virtual void on_update_finished(const elliptics::error_info &error) {
		if (error) {
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		this->send_reply(swarm::http_response::ok);
	}
};

template <typename Server>
class on_update : public on_update_base<Server, on_update<Server>>
{
public:
};

struct read_result_cmp {
	bool operator ()(const elliptics::read_result_entry &e1,
			const elliptics::read_result_entry &e2) const {
		return dnet_id_cmp(&e1.command()->id, &e2.command()->id) < 0;
	}

	const dnet_raw_id &operator()(const elliptics::find_indexes_result_entry &e) const {
		return e.id;
	}

	bool operator ()(const elliptics::read_result_entry &e1, const dnet_raw_id &id) const {
		return dnet_id_cmp_str((const unsigned char *)e1.command()->id.id, id.id) < 0;
	}
};

struct find_serializer {
	static const std::string basic_convert(const elliptics::data_pointer &data) {
		std::string str(reinterpret_cast<const char *>(data.data()), data.size());
		return str;
	}

	static void pack_indexes_json(JsonValue &result_object,
			const elliptics::sync_read_result &const_read_result,
			const std::function<std::string (const elliptics::data_pointer &)> read_convert,
			const elliptics::sync_find_indexes_result &find_result,
			const std::function<std::string (const elliptics::data_pointer &)> index_convert,
			const elliptics::id_to_name_map_t &map) {
		for (size_t i = 0; i < find_result.size(); ++i) {
			const elliptics::find_indexes_result_entry &entry = find_result[i];

			rapidjson::Value val;
			val.SetObject();

			rapidjson::Value indexes;
			indexes.SetObject();

			for (auto it = entry.indexes.begin(); it != entry.indexes.end(); ++it) {
				std::string index_data = index_convert(it->data);
				rapidjson::Value value(index_data.c_str(), index_data.size(), result_object.GetAllocator());

				auto name_it = map.find(it->index);
				if (name_it != map.end())
					indexes.AddMember(name_it->second.c_str(), value, result_object.GetAllocator());
			}

			if (const_read_result.size()) {
				elliptics::sync_read_result read_result = const_read_result;

				read_result_cmp cmp;
				std::sort(read_result.begin(), read_result.end(), cmp);

				rapidjson::Value obj;
				obj.SetObject();

				auto it = std::lower_bound(read_result.begin(), read_result.end(), entry.id, cmp);
				if (it != read_result.end()) {
					std::string res = read_convert(it->file());
					rapidjson::Value data_str(res.c_str(), res.size(), result_object.GetAllocator());
					obj.AddMember("data", data_str, result_object.GetAllocator());

					rapidjson::Value tobj;
					JsonValue::set_time(tobj, result_object.GetAllocator(),
							it->io_attribute()->timestamp.tsec,
							it->io_attribute()->timestamp.tnsec / 1000);
					obj.AddMember("mtime", tobj, result_object.GetAllocator());
				}

				val.AddMember("data-object", obj, result_object.GetAllocator());
			}

			val.AddMember("indexes", indexes, result_object.GetAllocator());

			char id_str[2 * DNET_ID_SIZE + 1];
			dnet_dump_id_len_raw(entry.id.id, DNET_ID_SIZE, id_str);
			result_object.AddMember(id_str, result_object.GetAllocator(),
					val, result_object.GetAllocator());
		}
	}
};

// find (using 'AND' or 'OR' operator) indexes, which contain given ID
template <typename Server, typename Stream>
class on_find_base : public bucket_processing<Server, Stream>
{
public:
	virtual void checked(const swarm::http_request &req, const boost::asio::const_buffer &buffer,
			const bucket_meta_raw &meta, const bucket_acl &acl, swarm::http_response::status_type verdict) {
		const auto &query = req.url().query();

		if ((verdict != swarm::http_response::ok) && !acl.noauth_read()) {
			this->log(swarm::SWARM_LOG_ERROR, "find-base: checked: url: %s, verdict: %d, did-not-pass-noauth-check",
				query.to_string().c_str(), verdict);
			this->send_reply(verdict);
			return;
		}

		this->log(swarm::SWARM_LOG_NOTICE, "find-base: checked: url: %s, original-verdict: %d, passed-noauth-check",
				query.to_string().c_str(), verdict);


		(void) meta;

		std::string buf(boost::asio::buffer_cast<const char*>(buffer), boost::asio::buffer_size(buffer));
		rapidjson::Document data;
		data.Parse<0>(buf.c_str());

		if (data.HasParseError()) {
			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		if (!data.HasMember("type") || !data.HasMember("indexes")) {
			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		m_view = "id-only";
		if (data.HasMember("view"))
			m_view = data["view"].GetString();

		elliptics::key key;
		m_session.reset(new elliptics::session(this->server()->elliptics()->read_data_session(req, meta, key)));

		const std::string type = data["type"].GetString();

		auto &indexesArray = data["indexes"];

		std::vector<dnet_raw_id> indexes;

		for (auto it = indexesArray.Begin(); it != indexesArray.End(); ++it) {
			elliptics::key index = std::string(it->GetString());
			m_session->transform(index);

			indexes.push_back(index.raw_id());
			m_map[index.raw_id()] = index.to_string();
		}

		if (type != "and" && type != "or") {
			this->log(swarm::SWARM_LOG_ERROR, "find-base: checked: url: %s, 'type' field must be 'and' or 'or', not '%s'",
				query.to_string().c_str(), type.c_str());
			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		(type == "and" ? m_session->find_all_indexes(indexes) : m_session->find_any_indexes(indexes))
				.connect(std::bind(&on_find_base::on_find_finished,
					this->shared_from_this(), std::placeholders::_1, std::placeholders::_2));
	}

	virtual void on_find_finished(const elliptics::sync_find_indexes_result &result,
			const elliptics::error_info &error) {
		if (error) {
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		if (m_view == "extended") {
			read_result_cmp cmp;
			std::vector<elliptics::key> ids;
			std::transform(result.begin(), result.end(), std::back_inserter(ids), cmp);

			m_result = result;

			m_session->bulk_read(ids).connect(std::bind(&on_find_base::on_ready_to_parse_indexes,
					this->shared_from_this(), std::placeholders::_1, std::placeholders::_2));
		} else {
			elliptics::sync_read_result data;
			send_indexes_reply(data, result);
		}
	}

	virtual void on_ready_to_parse_indexes(const elliptics::sync_read_result &data,
			const elliptics::error_info &error) {
		if (error) {
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		send_indexes_reply(data, m_result);
	}

	virtual void send_indexes_reply(const elliptics::sync_read_result &read_result,
		const elliptics::sync_find_indexes_result &find_result) {
		JsonValue result_object;

		find_serializer::pack_indexes_json(result_object, read_result, find_serializer::basic_convert, find_result, find_serializer::basic_convert, m_map);

		auto data = result_object.ToString();

		swarm::http_response reply;
		reply.set_code(swarm::http_response::ok);
		reply.headers().set_content_type("text/json");
		reply.headers().set_content_length(data.size());

		this->send_reply(std::move(reply), std::move(data));
	}

private:
	std::unique_ptr<elliptics::session> m_session;
	elliptics::id_to_name_map_t m_map;
	std::string m_view;
	elliptics::sync_find_indexes_result m_result;

};

template <typename Server>
class on_find : public on_find_base<Server, on_find<Server>>
{
public:
};

}}} // namespace ioremap::rift::index

#endif /*__IOREMAP_RIFT_INDEX_HPP */
