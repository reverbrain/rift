#ifndef __IOREMAP_RIFT_IO_HPP
#define __IOREMAP_RIFT_IO_HPP

// must be the first, since thevoid internally uses X->boost::buffer conversion,
// which must be present at compile time
#include "rift/asio.hpp"

#include "rift/jsonvalue.hpp"
#include "rift/bucket.hpp"

#include <swarm/url.hpp>
#include <swarm/url_query.hpp>

#include <thevoid/server.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

namespace ioremap { namespace rift { namespace io {

static inline elliptics::data_pointer create_data(const boost::asio::const_buffer &buffer)
{
	return elliptics::data_pointer::from_raw(
		const_cast<char *>(boost::asio::buffer_cast<const char*>(buffer)),
		boost::asio::buffer_size(buffer)
	);
}

template <typename Server, typename Stream>
class bucket_processing : public thevoid::simple_request_stream<Server>, public std::enable_shared_from_this<Stream>
{
public:
	virtual void on_request(const swarm::http_request &req, const boost::asio::const_buffer &buffer) {
		if (!this->server()->query_ok(req)) {
			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		this->server()->process(req, buffer, std::bind(&bucket_processing::checked, this->shared_from_this(),
					std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
	}

	virtual void checked(const swarm::http_request &req, const boost::asio::const_buffer &buffer,
			const bucket_meta_raw &meta, swarm::http_response::status_type verdict) = 0;
};

// read data object
template <typename Server, typename Stream>
class on_get_base : public bucket_processing<Server, Stream>
{
public:
	virtual void checked(const swarm::http_request &req, const boost::asio::const_buffer &buffer,
			const bucket_meta_raw &meta, swarm::http_response::status_type verdict) {
		const auto &query = req.url().query();
		this->log(swarm::SWARM_LOG_NOTICE, "get-base: checked: url: %s, flags: 0x%lx, verdict: %d", query.to_string().c_str(), meta.flags, verdict);

		if ((verdict != swarm::http_response::ok) && !meta.noauth_read()) {
			this->send_reply(verdict);
			return;
		}

		(void) buffer;

		elliptics::key key;
		elliptics::session session = this->server()->extract_key(req, meta, key);

		this->server()->check_cache(key, session);

		size_t offset = 0;
		size_t size = 0;

		try {
			offset = query.item_value("offset", 0llu);
			size = query.item_value("size", 0llu);
		} catch (std::exception &e) {
			this->log(swarm::SWARM_LOG_ERROR, "get-base: checked: url: %s, flags: 0x%lx, invalid size/offset cast: %s", query.to_string().c_str(), meta.flags, e.what());
			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		session.read_data(key, offset, size).connect(std::bind(
			&on_get_base::on_read_finished, this->shared_from_this(), std::placeholders::_1, std::placeholders::_2));
	}

	virtual void on_read_finished(const elliptics::sync_read_result &result,
			const elliptics::error_info &error) {
		if (error.code() == -ENOENT) {
			this->send_reply(swarm::http_response::not_found);
			return;
		} else if (error) {
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		const elliptics::read_result_entry &entry = result[0];

		elliptics::data_pointer file = entry.file();

		const dnet_time &ts = entry.io_attribute()->timestamp;
		const swarm::http_request &request = this->request();

		if (auto tmp = request.headers().if_modified_since()) {
			if ((time_t)ts.tsec <= *tmp) {
				this->send_reply(swarm::http_response::not_modified);
				return;
			}
		}

		if (auto tmp = request.headers().get("Range")) {
			std::string range = *tmp;
			this->log(swarm::SWARM_LOG_DATA, "GET, Range: \"%s\"", range.c_str());
			if (range.compare(0, 6, "bytes=") == 0) {
				range.erase(range.begin(), range.begin() + 6);
				std::vector<std::string> ranges;
				boost::split(ranges, range, boost::is_any_of(","));
				if (ranges.size() == 1)
					on_range(ranges[0], file, ts);
				else
					on_ranges(ranges, file, ts);
				return;
			}
		}

		swarm::http_response reply;
		reply.set_code(swarm::http_response::ok);
		reply.headers().set_content_length(file.size());
		reply.headers().set_content_type("text/plain");
		reply.headers().set_last_modified(ts.tsec);

		this->send_reply(std::move(reply), std::move(file));
	}

	bool parse_range(const std::string &range, size_t data_size, size_t &begin, size_t &end)
	{
		begin = 0;
		end = data_size - 1;

		if (range.size() <= 1)
			return false;

		try {
			const auto separator = range.find('-');
			if (separator == std::string::npos)
				return false;

			if (separator == 0) {
				auto tmp = boost::lexical_cast<size_t>(range.substr(separator + 1));
				if (tmp > data_size)
					begin = 0;
				else
					begin = data_size - tmp;
			} else {
				if (separator > 0)
					begin = boost::lexical_cast<size_t>(range.substr(0, separator));

				if (separator + 1 < range.size())
					end = boost::lexical_cast<size_t>(range.substr(separator + 1));
			}
		} catch (...) {
			return false;
		}

		if (begin > end)
			return false;

		if (begin >= data_size)
			return false;

		end = std::min(data_size - 1, end);

		return true;
	}

	std::string create_content_range(size_t begin, size_t end, size_t data_size)
	{
		std::string result = "bytes ";
		result += boost::lexical_cast<std::string>(begin);
		result += "-";
		result += boost::lexical_cast<std::string>(end);
		result += "/";
		result += boost::lexical_cast<std::string>(data_size);
		return result;
	}

	virtual void on_range(const std::string &range, const elliptics::data_pointer &data, const dnet_time &ts)
	{
		size_t begin;
		size_t end;
		if (!parse_range(range, data.size(), begin, end)) {
			this->send_reply(swarm::http_response::requested_range_not_satisfiable);
			return;
		}

		auto data_part = data.slice(begin, end + 1 - begin);

		swarm::http_response reply;
		reply.set_code(swarm::http_response::partial_content);
		reply.headers().set_content_type("text/plain");
		reply.headers().set_last_modified(ts.tsec);
		reply.headers().add("Accept-Ranges", "bytes");
		reply.headers().add("Content-Range", create_content_range(begin, end, data.size()));
		reply.headers().set_content_length(data_part.size());

		this->send_reply(std::move(reply), std::move(data_part));
	}

	struct range_info
	{
		size_t begin;
		size_t end;
	};

	virtual void on_ranges(const std::vector<std::string> &ranges_str, const elliptics::data_pointer &data, const dnet_time &ts)
	{
		std::vector<range_info> ranges;
		for (auto it = ranges_str.begin(); it != ranges_str.end(); ++it) {
			range_info info;
			if (parse_range(*it, data.size(), info.begin, info.end))
				ranges.push_back(info);
		}

		if (ranges.empty()) {
			this->send_reply(swarm::http_response::requested_range_not_satisfiable);
			return;
		}

		char boundary[17];
		for (size_t i = 0; i < 2; ++i) {
			uint32_t tmp = rand();
			sprintf(boundary + i * 8, "%08X", tmp);
		}

		std::string result;
		for (auto it = ranges.begin(); it != ranges.end(); ++it) {
			result += "--";
			result += boundary;
			result += "\r\n"
				"Content-Type: text/plain\r\n"
				"Content-Range: ";
			result += create_content_range(it->begin, it->end, data.size());
			result += "\r\n\r\n";
			result += data.slice(it->begin, it->end + 1 - it->begin).to_string();
			result += "\r\n";
		}
		result += "--";
		result += boundary;
		result += "--\r\n";

		swarm::http_response reply;
		reply.set_code(swarm::http_response::partial_content);
		reply.headers().set_content_type(std::string("multipart/byteranges; boundary=") + boundary);
		reply.headers().set_last_modified(ts.tsec);
		reply.headers().add("Accept-Ranges", "bytes");
		reply.headers().set_content_length(result.size());

		this->send_reply(std::move(reply), std::move(result));
	}
};

template <typename Server>
class on_get : public on_get_base<Server, on_get<Server>>
{
public:
};

// write data object, get file-info json in response
template <typename Server, typename Stream>
class on_upload_base : public bucket_processing<Server, Stream>
{
	elliptics::key m_key;
	bucket_meta_raw m_meta;
	swarm::http_request m_req;
	std::unique_ptr<elliptics::session> m_session;

public:
	virtual void checked(const swarm::http_request &req, const boost::asio::const_buffer &buffer,
			const bucket_meta_raw &meta, swarm::http_response::status_type verdict) {
		auto data = elliptics::data_pointer::from_raw(
			const_cast<char *>(boost::asio::buffer_cast<const char*>(buffer)),
			boost::asio::buffer_size(buffer));

		const auto &query = req.url().query();
		this->log(swarm::SWARM_LOG_NOTICE, "upload-base: checked: url: %s, flags: 0x%lx, verdict: %d", query.to_string().c_str(), meta.flags, verdict);

		if ((verdict != swarm::http_response::ok) && !meta.noauth_all()) {
			this->send_reply(verdict);
			return;
		}

		(void) buffer;

		m_req = req;
		m_meta = meta;

		m_session.reset(new elliptics::session(this->server()->extract_key(req, meta, m_key)));

		this->server()->check_cache(m_key, *m_session);

		try {
			write_data(req, *m_session, m_key, data).connect(
				std::bind(&on_upload_base::on_write_finished, this->shared_from_this(),
					std::placeholders::_1, std::placeholders::_2));
		} catch (std::exception &e) {
			this->log(swarm::SWARM_LOG_NOTICE, "post-base: checked-write: url: %s, flags: 0x%lx, exception: %s",
					query.to_string().c_str(), meta.flags, e.what());
			this->send_reply(swarm::http_response::bad_request);
		}
	}

	elliptics::async_write_result write_data(
			const swarm::http_request &req,
			elliptics::session &sess,
			const elliptics::key &key,
			const elliptics::data_pointer &data) {
		const auto &query = req.url().query();

		size_t offset = query.item_value("offset", 0llu);

		if (auto tmp = query.item_value("prepare")) {
			size_t size = boost::lexical_cast<size_t>(*tmp);
			return sess.write_prepare(key, data, offset, size);
		} else if (auto tmp = query.item_value("commit")) {
			size_t size = boost::lexical_cast<size_t>(*tmp);
			return sess.write_commit(key, data, offset, size);
		} else if (query.has_item("plain-write")) {
			return sess.write_plain(key, data, offset);
		} else {
			return sess.write_data(key, data, offset);
		}
	}

	template <typename Allocator>
	static void fill_upload_reply(const elliptics::write_result_entry &entry, rapidjson::Value &result_object, Allocator &allocator) {
		char id_str[2 * DNET_ID_SIZE + 1];
		dnet_dump_id_len_raw(entry.command()->id.id, DNET_ID_SIZE, id_str);
		rapidjson::Value id_str_value(id_str, 2 * DNET_ID_SIZE, allocator);
		result_object.AddMember("id", id_str_value, allocator);

		char csum_str[2 * DNET_ID_SIZE + 1];
		dnet_dump_id_len_raw(entry.file_info()->checksum, DNET_ID_SIZE, csum_str);
		rapidjson::Value csum_str_value(csum_str, 2 * DNET_ID_SIZE, allocator);
		result_object.AddMember("csum", csum_str_value, allocator);

		if (entry.file_path())
			result_object.AddMember("filename", entry.file_path(), allocator);

		result_object.AddMember("size", entry.file_info()->size, allocator);
		result_object.AddMember("offset-within-data-file", entry.file_info()->offset,
				allocator);

		rapidjson::Value tobj;
		JsonValue::set_time(tobj, allocator,
				entry.file_info()->mtime.tsec,
				entry.file_info()->mtime.tnsec / 1000);
		result_object.AddMember("mtime", tobj, allocator);

		char addr_str[128];
		dnet_server_convert_dnet_addr_raw(entry.storage_address(), addr_str, sizeof(addr_str));
		
		rapidjson::Value server_addr(addr_str, strlen(addr_str), allocator);
		result_object.AddMember("server", server_addr, allocator);
	}

	template <typename Allocator>
	static void fill_upload_reply(const elliptics::sync_write_result &result, rapidjson::Value &result_object, Allocator &allocator) {
		rapidjson::Value infos;
		infos.SetArray();

		for (auto it = result.begin(); it != result.end(); ++it) {
			rapidjson::Value download_info;
			download_info.SetObject();

			fill_upload_reply(*it, download_info, allocator);

			infos.PushBack(download_info, allocator);
		}

		result_object.AddMember("info", infos, allocator);
	}

	virtual void on_write_finished(const elliptics::sync_write_result &result,
			const elliptics::error_info &error) {
		if (error) {
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		try {
			std::vector<std::string> indexes;
			indexes.push_back(m_meta.key + ".index");

			msgpack::sbuffer buf;
			bucket_meta_index_data index_data;
			index_data.key = m_key.to_string();
			msgpack::pack(buf, index_data);

			std::vector<elliptics::data_pointer> datas;
			datas.emplace_back(elliptics::data_pointer::copy(buf.data(), buf.size()));

			elliptics::session session = this->server()->elliptics()->session();

			// only update indexes in non-cached groups
			session.set_namespace(m_meta.key.c_str(), m_meta.key.size());
			session.set_groups(m_meta.groups);

			session.update_indexes(m_key, indexes, datas).connect(
				std::bind(&on_upload_base::on_index_update_finished, this->shared_from_this(),
					result, std::placeholders::_1, std::placeholders::_2));
		} catch (std::exception &e) {
			this->log(swarm::SWARM_LOG_NOTICE, "post-base: write_finished: key: %s, ns: %s, flags: 0x%lx, exception: %s",
					m_key.to_string().c_str(), m_meta.key.c_str(), m_meta.flags, e.what());
			this->send_reply(swarm::http_response::bad_request);
		}
	}

	virtual void on_index_update_finished(const elliptics::sync_write_result &write_result,
			const elliptics::sync_set_indexes_result &result, const elliptics::error_info &error)
	{
		(void) result;

		if (error) {
			this->log(swarm::SWARM_LOG_DEBUG, "on_index_update_finished, removing object '%s' on error: %s",
					m_key.to_string().c_str(), error.message().c_str());

			m_session->remove(m_key);
			this->send_reply(swarm::http_response::internal_server_error);
			return;
		}

		rift::JsonValue result_object;
		on_upload_base::fill_upload_reply(write_result, result_object, result_object.GetAllocator());

		auto data = result_object.ToString();

		swarm::http_response reply;
		reply.set_code(swarm::http_response::ok);
		reply.headers().set_content_type("text/json");
		reply.headers().set_content_length(data.size());

		this->send_reply(std::move(reply), std::move(data));
	}

};

template <typename Server>
class on_upload : public on_upload_base<Server, on_upload<Server>>
{
public:
};

// write data object, get file-info json in response
template <typename Server, typename Stream>
class on_buffered_upload_base : public thevoid::buffered_request_stream<Server>, public std::enable_shared_from_this<Stream>
{
public:
	virtual void on_request(const swarm::http_request &request)
	{
		const auto &query = request.url().query();
		this->set_chunk_size(10 * 1024 * 1024);

		m_session.reset(new elliptics::session(this->server()->elliptics()->session()));
#if 0
		auto status = this->server()->elliptics()->process(request, m_key, *m_session);
		if (status != swarm::http_response::ok) {
			m_session.reset();
			this->send_reply(status);
			return;
		}
#endif
		m_offset = query.item_value("offset", 0llu);
		if (auto size = request.headers().content_length())
			m_size = *size;
		else
			m_size = 0;
	}

	virtual void on_chunk(const boost::asio::const_buffer &buffer, unsigned int flags)
	{
		if (!m_session) {
			return;
		}

		elliptics::session sess = m_session->clone();
		const auto data = create_data(buffer);

		this->log(swarm::SWARM_LOG_INFO, "on_chunk: size: %zu, m_offset: %llu, flags: %u", data.size(), (unsigned long long)m_offset, flags);

		if (flags & thevoid::buffered_request_stream<Server>::first_chunk) {
			m_groups = sess.get_groups();
		} else {
			sess.set_groups(m_groups);
		}

		elliptics::async_write_result result = write(sess, data, flags);
		m_offset += data.size();

		if (flags & thevoid::buffered_request_stream<Server>::last_chunk) {
			result.connect(std::bind(&on_buffered_upload_base::on_write_finished, this->shared_from_this(),
				std::placeholders::_1, std::placeholders::_2));
		} else {
			result.connect(std::bind(&on_buffered_upload_base::on_write_partial, this->shared_from_this(),
				std::placeholders::_1, std::placeholders::_2));
		}
	}

	elliptics::async_write_result write(elliptics::session &sess,
		const elliptics::data_pointer &data,
		unsigned int flags)
	{
		typedef unsigned long long ull;

		if (flags == thevoid::buffered_request_stream<Server>::single_chunk) {
			return sess.write_data(m_key, data, m_offset);
		} else if (m_size > 0) {
			if (flags & thevoid::buffered_request_stream<Server>::first_chunk) {
				this->log(swarm::SWARM_LOG_INFO, "prepare, offset: %llu, size: %llu", ull(m_offset), ull(m_size));
				return sess.write_prepare(m_key, data, m_offset, m_offset + m_size);
			} else if (flags & thevoid::buffered_request_stream<Server>::last_chunk) {
				this->log(swarm::SWARM_LOG_INFO, "commit, offset: %llu, size: %llu", ull(m_offset), ull(m_offset + data.size()));
				return sess.write_commit(m_key, data, m_offset, m_offset + data.size());
			} else {
				this->log(swarm::SWARM_LOG_INFO, "plain, offset: %llu", ull(m_offset));
				return sess.write_plain(m_key, data, m_offset);
			}
		} else {
			this->log(swarm::SWARM_LOG_INFO, "write_data, offset: %llu", ull(m_offset));
			return sess.write_data(m_key, data, m_offset);
		}
	}

	virtual void on_error(const boost::system::error_code &err)
	{
		this->log(swarm::SWARM_LOG_DEBUG, "on_error, error: %s", err.message().c_str());
	}

	virtual void on_write_partial(const elliptics::sync_write_result &result, const elliptics::error_info &error)
	{
		this->log(swarm::SWARM_LOG_DEBUG, "on_write_partial, error: %s", error.message().c_str());

		if (error) {
			on_write_finished(result, error);
			return;
		}

		std::vector<int> groups;

		for (auto it = result.begin(); it != result.end(); ++it) {
			elliptics::write_result_entry entry = *it;

			if (!entry.error())
				groups.push_back(entry.command()->id.group_id);
		}

		using std::swap;
		swap(m_groups, groups);

		this->try_next_chunk();
	}

	virtual void on_write_finished(const elliptics::sync_write_result &result, const elliptics::error_info &error)
	{
		(void) result;

		this->log(swarm::SWARM_LOG_DEBUG, "on_write_finished, error: %s", error.message().c_str());

		if (error) {
			this->send_reply(swarm::http_response::internal_server_error);
			return;
		}

		this->send_reply(swarm::http_response::ok);
	}

private:
	std::vector<int> m_groups;
	std::unique_ptr<elliptics::session> m_session;
	elliptics::key m_key;
	uint64_t m_offset;
	uint64_t m_size;
};

template <typename Server>
class on_buffered_upload : public on_buffered_upload_base<Server, on_buffered_upload<Server>>
{
public:
};

// perform lookup, get file-info json in response
template <typename Server, typename Stream>
class on_download_info_base : public bucket_processing<Server, Stream>
{
public:
	virtual void checked(const swarm::http_request &req, const boost::asio::const_buffer &buffer,
			const bucket_meta_raw &meta, swarm::http_response::status_type verdict) {
		const auto &query = req.url().query();
		this->log(swarm::SWARM_LOG_NOTICE, "download-info-base: checked: url: %s, flags: 0x%lx, verdict: %d", query.to_string().c_str(), meta.flags, verdict);

		if ((verdict != swarm::http_response::ok) && !meta.noauth_read()) {
			this->send_reply(verdict);
			return;
		}

		(void) buffer;

		elliptics::key key;
		elliptics::session session = this->server()->extract_key(req, meta, key);

		this->server()->check_cache(key, session);

		session.lookup(key).connect(std::bind(&on_download_info_base::on_lookup_finished, this->shared_from_this(), meta,
			std::placeholders::_1, std::placeholders::_2));
	}

	std::string generate_signature(const elliptics::lookup_result_entry &entry, const std::string &time, const std::string &token, std::string *url_ptr) {
		if (token.empty() && !url_ptr)
			return std::string();

		const auto name = this->request().url().query().item_value("name");
		const dnet_file_info *info = entry.file_info();

		swarm::url url = this->server()->generate_url_base(entry.address());
		swarm::url_query &query = url.query();
		query.add_item("file-path", entry.file_path());
		query.add_item("offset", boost::lexical_cast<std::string>(info->offset));
		query.add_item("size", boost::lexical_cast<std::string>(info->size));
		query.add_item("time", time);

		if (!token.empty())
			query.add_item("token", token);

		url.set_query(query);

		auto sign_input = url.to_string();

		if (url_ptr) {
			*url_ptr = std::move(sign_input);
			return std::string();
		}

		if (token.empty())
			return std::string();

		dnet_raw_id signature_id;
		dnet_transform_node(this->server()->elliptics()->node().get_native(),
					sign_input.c_str(), sign_input.size(),
					signature_id.id, sizeof(signature_id.id));

		char signature_str[2 * DNET_ID_SIZE + 1];
		dnet_dump_id_len_raw(signature_id.id, DNET_ID_SIZE, signature_str);

		const std::string signature(signature_str, 2 * DNET_ID_SIZE);

		url.query().add_item("signature", signature);

		return std::move(signature);
	}

	virtual void on_lookup_finished(const bucket_meta_raw &meta, const elliptics::sync_lookup_result &result,
			const elliptics::error_info &error) {
		if (error) {
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		rift::JsonValue result_object;
		on_upload<Server>::fill_upload_reply(result[0], result_object, result_object.GetAllocator());

		dnet_time time;
		dnet_current_time(&time);
		const std::string time_str = boost::lexical_cast<std::string>(time.tsec);

		if (!meta.token.empty()) {
			std::string signature = generate_signature(result[0], time_str, meta.token, NULL);

			if (!signature.empty()) {
				rapidjson::Value signature_value(signature.c_str(), signature.size(), result_object.GetAllocator());
				result_object.AddMember("signature", signature_value, result_object.GetAllocator());
			}
		}

		result_object.AddMember("time", time_str.c_str(), result_object.GetAllocator());

		auto data = result_object.ToString();

		swarm::http_response reply;
		reply.set_code(swarm::http_response::ok);
		reply.headers().set_content_type("text/json");
		reply.headers().set_content_length(data.size());

		this->send_reply(std::move(reply), std::move(data));
	}
};

template <typename Server>
class on_download_info : public on_download_info_base<Server, on_download_info<Server>>
{
public:
};

// perform lookup, redirect in response
template <typename Server>
class on_redirectable_get : public on_download_info<Server>
{
public:
	virtual void on_lookup_finished(const bucket_meta_raw &meta, const elliptics::sync_lookup_result &result,
			const elliptics::error_info &error) {
		if (error) {
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		dnet_time time;
		dnet_current_time(&time);
		const std::string time_str = boost::lexical_cast<std::string>(time.tsec);

		std::string url;

		this->generate_signature(result[0], time_str, meta.token, &url);

		swarm::http_response reply;
		reply.set_code(swarm::http_response::moved_temporarily);
		reply.headers().set("Location", url);
		reply.headers().set_content_length(0);

		this->send_reply(std::move(reply));
	}
};

template <typename Server, typename Stream>
class on_buffered_get_base : public bucket_processing<Server, Stream>
{
public:
	on_buffered_get_base() : m_buffer_size(5 * 1025 * 1024)
	{
	}

	virtual void checked(const swarm::http_request &req, const boost::asio::const_buffer &buffer,
			const bucket_meta_raw &meta, swarm::http_response::status_type verdict) {
		auto data = elliptics::data_pointer::from_raw(
			const_cast<char *>(boost::asio::buffer_cast<const char*>(buffer)),
			boost::asio::buffer_size(buffer));

		const auto &query = req.url().query();
		this->log(swarm::SWARM_LOG_NOTICE, "buffered-get-base: checked: url: %s, flags: 0x%lx, verdict: %d", query.to_string().c_str(), meta.flags, verdict);

		if ((verdict != swarm::http_response::ok) && !meta.noauth_read()) {
			this->send_reply(verdict);
			return;
		}

		(void) buffer;

		elliptics::key key;
		elliptics::session session = this->server()->extract_key(req, meta, key);

		this->server()->check_cache(key, session);

		session.lookup(m_key).connect(std::bind(
			&on_buffered_get_base::on_lookup_finished, this->shared_from_this(), std::placeholders::_1,  std::placeholders::_2));
	}

	void on_lookup_finished(const elliptics::sync_lookup_result &result, const elliptics::error_info &error)
	{
		this->log(swarm::SWARM_LOG_DEBUG, "%s, error: %s", __FUNCTION__, error.message().c_str());
		if (error) {
			if (error.code() == -ENOENT) {
				this->send_reply(swarm::http_response::not_found);
				return;
			} else {
				this->send_reply(swarm::http_response::internal_server_error);
				return;
			}
		}

		const elliptics::lookup_result_entry &entry = result[0];
		m_size = entry.file_info()->size;

		swarm::http_response reply;
		reply.set_code(swarm::http_response::ok);
		reply.headers().set_content_length(m_size);
		reply.headers().set_content_type("text/plain");
		reply.headers().set_last_modified(entry.file_info()->mtime.tsec);

		this->send_headers(std::move(reply), std::function<void (const boost::system::error_code &)>());

		read_next(0);
	}

	virtual void on_read_finished(uint64_t offset, const elliptics::sync_read_result &result, const elliptics::error_info &error)
	{
		this->log(swarm::SWARM_LOG_DEBUG, "%s, error: %s, offset: %llu", __FUNCTION__, error.message().c_str(), (unsigned long long) offset);
//		if (offset == 0 && error) {
//			if (error.code() == -ENOENT) {
//				this->send_reply(swarm::http_response::not_found);
//				return;
//			} else {
//				this->send_reply(swarm::http_response::internal_server_error);
//				return;
//			}
//		} else
		if (error) {
			auto ec = boost::system::errc::make_error_code(static_cast<boost::system::errc::errc_t>(-error.code()));
			this->get_reply()->close(ec);
			return;
		}

		const elliptics::read_result_entry &entry = result[0];
		elliptics::data_pointer file = entry.file();

		if (offset + file.size() >= m_size) {
			this->send_data(std::move(file), std::bind(&thevoid::reply_stream::close, this->get_reply(), std::placeholders::_1));
		} else {
			auto first_part = file.slice(0, file.size() / 2);
			auto second_part = file.slice(first_part.size(), file.size() - first_part.size());

			this->send_data(std::move(first_part), std::bind(&on_buffered_get_base::on_part_sent, this->shared_from_this(),
				offset + file.size(), std::placeholders::_1));
			this->send_data(std::move(second_part), std::function<void (const boost::system::error_code &)>());
		}
	}

	virtual void on_part_sent(size_t offset, const boost::system::error_code &error)
	{
		this->log(swarm::SWARM_LOG_DEBUG, "%s, error: %s, offset: %llu", __FUNCTION__, error.message().c_str(), (unsigned long long) offset);
		read_next(offset);
	}

	virtual void read_next(uint64_t offset)
	{
		this->log(swarm::SWARM_LOG_DEBUG, "%s, offset: %llu", __FUNCTION__, (unsigned long long) offset);
		elliptics::session sess = this->server()->elliptics()->session();

		sess.read_data(m_key, offset, std::min(m_size - offset, m_buffer_size)).connect(std::bind(
			&on_buffered_get_base::on_read_finished, this->shared_from_this(),
			offset, std::placeholders::_1, std::placeholders::_2));
	}

protected:
	elliptics::key m_key;
	uint64_t m_size;
	uint64_t m_buffer_size;
};

template <typename Server>
class on_buffered_get : public on_buffered_get_base<Server, on_buffered_get<Server>>
{
public:
};

}}} // ioremap::rift::io

#endif /*__IOREMAP_RIFT_IO_HPP */
