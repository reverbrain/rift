#ifndef __IOREMAP_RIFT_IO_HPP
#define __IOREMAP_RIFT_IO_HPP

// must be the first, since thevoid internally uses X->boost::buffer conversion,
// which must be present at compile time
#include "rift/asio.hpp"

#include "rift/jsonvalue.hpp"
#include "rift/bucket.hpp"

#include <swarm/url.hpp>
#include <swarm/url_query.hpp>

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

// read data object
template <typename Server, typename Stream>
class on_get_base : public bucket_processing<Server, Stream>
{
public:
	virtual void checked(const swarm::http_request &req, const boost::asio::const_buffer &buffer,
			const bucket_meta_raw &meta, const bucket_acl &acl, swarm::http_response::status_type verdict) {
		const auto &query = req.url().query();

		if ((verdict != swarm::http_response::ok) && !acl.noauth_read()) {
			this->log(swarm::SWARM_LOG_ERROR, "get-base: checked: url: %s, verdict: %d, did-not-pass-noauth-check",
					query.to_string().c_str(), verdict);
			this->send_reply(verdict);
			return;
		}

		this->log(swarm::SWARM_LOG_NOTICE, "get-base: checked: url: %s, original-verdict: %d, passed-no-auth-check",
				query.to_string().c_str(), verdict);

		(void) buffer;

		elliptics::key key;
		elliptics::session session = this->server()->read_data_session_cache(req, meta, key);

		size_t offset = 0;
		size_t size = 0;

		try {
			offset = query.item_value("offset", 0llu);
			size = query.item_value("size", 0llu);

			session.read_data(key, offset, size).connect(std::bind(
				&on_get_base::on_read_finished, this->shared_from_this(),
					std::placeholders::_1, std::placeholders::_2));
		} catch (std::exception &e) {
			this->log(swarm::SWARM_LOG_ERROR, "get-base: checked: url: %s "
					"could not read data: %s", query.to_string().c_str(), e.what());
			this->send_reply(swarm::http_response::bad_request);
			return;
		}
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
		reply.headers().set_content_type("application/octet-stream");
		reply.headers().set_last_modified(ts.tsec);

		this->send_reply(std::move(reply), std::move(file));
	}

	bool parse_range(const std::string &range, size_t data_size, size_t &begin, size_t &end) {
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

	std::string create_content_range(size_t begin, size_t end, size_t data_size) {
		std::string result = "bytes ";
		result += boost::lexical_cast<std::string>(begin);
		result += "-";
		result += boost::lexical_cast<std::string>(end);
		result += "/";
		result += boost::lexical_cast<std::string>(data_size);
		return result;
	}

	virtual void on_range(const std::string &range, const elliptics::data_pointer &data, const dnet_time &ts) {
		size_t begin;
		size_t end;
		if (!parse_range(range, data.size(), begin, end)) {
			this->send_reply(swarm::http_response::requested_range_not_satisfiable);
			return;
		}

		auto data_part = data.slice(begin, end + 1 - begin);

		swarm::http_response reply;
		reply.set_code(swarm::http_response::partial_content);
		reply.headers().set_content_type("application/octet-stream");
		reply.headers().set_last_modified(ts.tsec);
		reply.headers().add("Accept-Ranges", "bytes");
		reply.headers().add("Content-Range", create_content_range(begin, end, data.size()));
		reply.headers().set_content_length(data_part.size());

		this->send_reply(std::move(reply), std::move(data_part));
	}

	struct range_info {
		size_t begin;
		size_t end;
	};

	virtual void on_ranges(const std::vector<std::string> &ranges_str, const elliptics::data_pointer &data,
			const dnet_time &ts) {
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

class upload_completion {
public:
	template <typename Allocator>
	static void fill_upload_reply(const elliptics::write_result_entry &entry,
			rapidjson::Value &result_object, Allocator &allocator) {
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
	static void fill_upload_reply(const elliptics::sync_write_result &result,
			rapidjson::Value &result_object, Allocator &allocator) {
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

	typedef std::function<void (const swarm::http_response::status_type, const std::string &)>
		upload_completion_callback_t;

	static void upload_update_indexes(const elliptics::session &data_session, const bucket_meta_raw &meta,
			const elliptics::key &key, const elliptics::sync_write_result &write_result,
			const upload_completion_callback_t &callback) {
		std::vector<std::string> indexes;
		indexes.push_back(meta.key + ".index");

		msgpack::sbuffer buf;
		bucket_meta_index_data index_data;
		index_data.key = key.to_string();
		dnet_current_time(&index_data.ts);
		msgpack::pack(buf, index_data);

		std::vector<elliptics::data_pointer> datas;
		datas.emplace_back(elliptics::data_pointer::copy(buf.data(), buf.size()));

		elliptics::session session = data_session;

		// only update indexes in non-cached groups
		if (meta.groups.size()) {
			session.set_groups(meta.groups);
		}

		session.update_indexes(key, indexes, datas).connect(
			std::bind(&upload_completion::on_index_update_finished,
				write_result, callback, std::placeholders::_1, std::placeholders::_2));
	}

	static void on_index_update_finished(const elliptics::sync_write_result &write_result,
			const upload_completion_callback_t &callback,
			const elliptics::sync_set_indexes_result &result, const elliptics::error_info &error) {
		(void) result;

		if (error) {
			callback(swarm::http_response::internal_server_error, std::string());
			return;
		}

		rift::JsonValue result_object;
		upload_completion::fill_upload_reply(write_result, result_object, result_object.GetAllocator());

		auto data = result_object.ToString();

		callback(swarm::http_response::ok, data);
	}
};

// write data object, get file-info json in response
template <typename Server, typename Stream>
class on_upload_base : public bucket_processing<Server, Stream>
{
public:
	virtual void checked(const swarm::http_request &req, const boost::asio::const_buffer &buffer,
			const bucket_meta_raw &meta, const bucket_acl &acl, swarm::http_response::status_type verdict) {
		const auto &query = req.url().query();

		if (!boost::asio::buffer_size(buffer)) {
			this->log(swarm::SWARM_LOG_ERROR, "upload-base: checked: url: %s, empty data",
					query.to_string().c_str());
			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		auto data = elliptics::data_pointer::from_raw(
			const_cast<char *>(boost::asio::buffer_cast<const char*>(buffer)),
			boost::asio::buffer_size(buffer));

		if ((verdict != swarm::http_response::ok) && !acl.noauth_all()) {
			this->log(swarm::SWARM_LOG_ERROR, "upload-base: checked: url: %s, verdict: %d, did-not-pass-noauth-check",
					query.to_string().c_str(), verdict);
			this->send_reply(verdict);
			return;
		}

		this->log(swarm::SWARM_LOG_NOTICE, "upload-base: checked: url: %s, original-verdict: %d, passed-noauth-check",
				query.to_string().c_str(), verdict);

		(void) buffer;

		m_req = req;
		set_meta(meta);

		set_session(this->server()->write_data_session_cache(req, meta, m_key));

		try {
			write_data(req, *m_session, m_key, data).connect(
				std::bind(&on_upload_base::on_write_finished, this->shared_from_this(),
					std::placeholders::_1, std::placeholders::_2));
		} catch (std::exception &e) {
			this->log(swarm::SWARM_LOG_NOTICE, "post-base: checked-write: url: %s, exception: %s",
					query.to_string().c_str(), e.what());
			this->send_reply(swarm::http_response::bad_request);
		}
	}

	void set_key(const elliptics::key &key) {
		m_key = key;
	}

	void set_meta(const bucket_meta_raw &meta) {
		m_meta = meta;
	}

	void set_session(const elliptics::session &session) {
		m_session.reset(new elliptics::session(session));
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

	void completion(const swarm::http_response::status_type &status, const std::string &data) {
		if (status != swarm::http_response::ok) {
			this->send_reply(status);
			return;
		}

		swarm::http_response reply;

		reply.set_code(swarm::http_response::ok);
		reply.headers().set_content_type("text/json");
		reply.headers().set_content_length(data.size());

		this->log(swarm::SWARM_LOG_NOTICE, "post-base: completion: key: %s, namespace: %s",
				m_key.to_string().c_str(), m_meta.key.c_str());

		this->send_reply(std::move(reply), std::move(data));
	}

	virtual void on_write_finished(const elliptics::sync_write_result &result,
			const elliptics::error_info &error) {
		if (error) {
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		this->log(swarm::SWARM_LOG_NOTICE, "post-base: write_finished: key: %s, namespace: %s",
				m_key.to_string().c_str(), m_meta.key.c_str());

		try {
			upload_completion::upload_update_indexes(*m_session, m_meta, m_key, result,
					std::bind(&on_upload_base::completion, this->shared_from_this(),
						std::placeholders::_1, std::placeholders::_2));
		} catch (std::exception &e) {
			this->log(swarm::SWARM_LOG_ERROR, "post-base: write_finished: key: %s, namespace: %s, exception: %s",
					m_key.to_string().c_str(), m_meta.key.c_str(), e.what());
			m_session->remove(m_key);
			this->send_reply(swarm::http_response::bad_request);
		}
	}

private:
	elliptics::key m_key;
	bucket_meta_raw m_meta;
	swarm::http_request m_req;
	std::unique_ptr<elliptics::session> m_session;
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
	virtual void on_request(const swarm::http_request &req) {
		try {
			boost::asio::const_buffer buffer;
			this->server()->process(req, buffer, std::bind(&on_buffered_upload_base::checked, this->shared_from_this(),
				std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5));
		} catch (const std::exception &e) {
			this->log(swarm::SWARM_LOG_ERROR, "%s: uri: %s, processing error: %s",
					req.url().path().c_str(), req.url().query().to_string().c_str(), e.what());

			this->send_reply(swarm::http_response::bad_request);
		}
	}

	virtual void checked(const swarm::http_request &req, const boost::asio::const_buffer &buffer,
			const bucket_meta_raw &meta, const bucket_acl &acl, swarm::http_response::status_type verdict) {
		auto data = elliptics::data_pointer::from_raw(
			const_cast<char *>(boost::asio::buffer_cast<const char*>(buffer)),
			boost::asio::buffer_size(buffer));

		this->set_chunk_size(10 * 1024 * 1024);

		const auto &query = req.url().query();

		if ((verdict != swarm::http_response::ok) && !acl.noauth_all()) {
			this->log(swarm::SWARM_LOG_ERROR, "buffered-upload-base: checked: url: %s, verdict: %d, did-not-pass-noauth-check",
					query.to_string().c_str(), verdict);
			this->send_reply(verdict);
			return;
		}

		this->log(swarm::SWARM_LOG_NOTICE, "buffered-upload-base: checked: url: %s, original-verdict: %d, passed-noauth-check",
				query.to_string().c_str(), verdict);

		(void) buffer;

		m_req = req;
		m_meta = meta;

		m_session.reset(new elliptics::session(this->server()->write_data_session_cache(req, m_meta, m_key)));

		m_offset = query.item_value("offset", 0llu);
		if (auto size = req.headers().content_length())
			m_size = *size;
		else
			m_size = 0;
	}

	virtual void on_chunk(const boost::asio::const_buffer &buffer, unsigned int flags) {
		if (!m_session)
			return;

		const auto data = create_data(buffer);

		const auto &query = m_req.url().query();
		this->log(swarm::SWARM_LOG_INFO, "on_chunk: url: %s, size: %zu, m_offset: %lu, flags: %u",
				query.to_string().c_str(), data.size(), m_offset, flags);

		elliptics::async_write_result result = write(data, flags);
		m_offset += data.size();

		if (flags & thevoid::buffered_request_stream<Server>::last_chunk) {
			result.connect(std::bind(&on_buffered_upload_base::on_write_finished, this->shared_from_this(),
				std::placeholders::_1, std::placeholders::_2));
		} else {
			result.connect(std::bind(&on_buffered_upload_base::on_write_partial, this->shared_from_this(),
				std::placeholders::_1, std::placeholders::_2));
		}
	}

	elliptics::async_write_result write(const elliptics::data_pointer &data, unsigned int flags) {
		const auto &query = m_req.url().query();

		if (flags == thevoid::buffered_request_stream<Server>::single_chunk) {
			return m_session->write_data(m_key, data, m_offset);
		} else if (m_size > 0) {
			if (flags & thevoid::buffered_request_stream<Server>::first_chunk) {
				this->log(swarm::SWARM_LOG_INFO, "buffered-write: prepare: url: %s, offset: %lu, size: %lu",
						query.to_string().c_str(), m_offset, m_size);
				return m_session->write_prepare(m_key, data, m_offset, m_offset + m_size);
			} else if (flags & thevoid::buffered_request_stream<Server>::last_chunk) {
				this->log(swarm::SWARM_LOG_INFO, "buffered-write: commit: url: %s, offset: %lu, size: %lu",
						query.to_string().c_str(), m_offset, m_offset + data.size());
				return m_session->write_commit(m_key, data, m_offset, m_offset + data.size());
			} else {
				this->log(swarm::SWARM_LOG_INFO, "buffered-write: plain: url: %s, offset: %lu, size: %zu",
						query.to_string().c_str(), m_offset, data.size());
				return m_session->write_plain(m_key, data, m_offset);
			}
		} else {
			this->log(swarm::SWARM_LOG_INFO, "buffered-write: write-data: url: %s, offset: %lu, size: %zu",
					query.to_string().c_str(), m_offset, data.size());
			return m_session->write_data(m_key, data, m_offset);
		}
	}

	virtual void on_error(const boost::system::error_code &error) {
		const auto &query = m_req.url().query();
		this->log(swarm::SWARM_LOG_ERROR, "buffered-write: url: %s, error: %s",
				query.to_string().c_str(), error.message().c_str());
	}

	virtual void on_write_partial(const elliptics::sync_write_result &result, const elliptics::error_info &error) {
		if (error) {
			const auto &query = m_req.url().query();
			this->log(swarm::SWARM_LOG_ERROR, "buffered-write: url: %s, partial write error: %s",
					query.to_string().c_str(), error.message().c_str());
			this->on_write_finished(result, error);
			return;
		}

		// continue only with the groups where update succeeded
		std::vector<int> groups, rem_groups;

		for (auto it = result.begin(); it != result.end(); ++it) {
			elliptics::write_result_entry entry = *it;

			if (entry.error())
				rem_groups.push_back(entry.command()->id.group_id);
			else
				groups.push_back(entry.command()->id.group_id);
		}

		elliptics::session tmp = *m_session;
		tmp.set_groups(rem_groups);
		tmp.remove(m_key);

		m_session->set_groups(groups);

		if (m_meta.groups.size()) {
			using std::swap;
			swap(m_meta.groups, groups);
		}

		this->try_next_chunk();
	}

	void completion(const swarm::http_response::status_type &status, const std::string &data) {
		if (status != swarm::http_response::ok) {
			this->send_reply(status);
			return;
		}

		swarm::http_response reply;

		reply.set_code(swarm::http_response::ok);
		reply.headers().set_content_type("text/json");
		reply.headers().set_content_length(data.size());

		this->send_reply(std::move(reply), std::move(data));
	}

	virtual void on_write_finished(const elliptics::sync_write_result &result,
			const elliptics::error_info &error) {
		if (error) {
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		try {
			upload_completion::upload_update_indexes(*m_session, m_meta, m_key, result,
					std::bind(&on_buffered_upload_base::completion, this->shared_from_this(),
						std::placeholders::_1, std::placeholders::_2));
		} catch (std::exception &e) {
			this->log(swarm::SWARM_LOG_ERROR, "post-base: write_finished: key: %s, namespace: %s, exception: %s",
					m_key.to_string().c_str(), m_meta.key.c_str(), e.what());
			m_session->remove(m_key);
			this->send_reply(swarm::http_response::bad_request);
		}
	}


private:
	elliptics::key m_key;
	bucket_meta_raw m_meta;
	swarm::http_request m_req;
	std::unique_ptr<elliptics::session> m_session;

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
			const bucket_meta_raw &meta, const bucket_acl &acl, swarm::http_response::status_type verdict) {
		const auto &url = req.url();

		if ((verdict != swarm::http_response::ok) && !acl.noauth_read()) {
			this->log(swarm::SWARM_LOG_ERROR, "download-info-base: checked: path: %s, url: %s, verdict: %d, did-not-pass-noauth-check",
					url.path().c_str(), url.query().to_string().c_str(), verdict);

			this->send_reply(verdict);
			return;
		}

		this->log(swarm::SWARM_LOG_NOTICE, "download-info-base: checked: path: %s, url: %s, verdict: %d, passed-noauth-check",
				url.path().c_str(), url.query().to_string().c_str(), verdict);

		(void) buffer;

		elliptics::key key;
		elliptics::session session = this->server()->read_data_session_cache(req, meta, key);

		session.lookup(key).connect(std::bind(&on_download_info_base::on_download_lookup_finished,
					this->shared_from_this(), acl, std::placeholders::_1, std::placeholders::_2));
	}

	std::string generate_signature(const elliptics::lookup_result_entry &entry, const std::string &time,
			const std::string &token, std::string *url_ptr, swarm::http_response::status_type *type) {
		if (token.empty() && !url_ptr)
			return std::string();

		const dnet_file_info *info = entry.file_info();

		/*
		 * We don't mind what real id is this request for, what namespace and so on.
		 * At this point we are sure that user has permission to know where his file
		 * is really stored. That is why we should protect only file's real position
		 * by the signature.
		 *
		 * Time is figured in the signature because of we don't want anybody else to
		 * have access to non-their files in case of defragmentation/MiTM and so on.
		 *
		 * path: /var/blob/s1/data-0.1
		 * scheme://hostname/blob/s1/data-0.1:offset:size?time=unix-timestamp&signature=resultOfHmac
		 * Signature is HMAC(url, token)
		 */
		swarm::url url = this->server()->generate_url_base(entry.address(), entry.file_path(), type);
		if (swarm::http_response::http_response::ok != *type)
			return std::string();

		swarm::url_query &query = url.query();
		query.add_item("time", time);

		std::string path = entry.file_path();
		path += ":";
		path += boost::lexical_cast<std::string>(info->offset);
		path += ":";
		path += boost::lexical_cast<std::string>(info->size);

		url.set_path(path);

		if (url_ptr && token.empty())
			*url_ptr = url.to_string();

		if (token.empty())
			return std::string();

		url.set_scheme("scheme");
		const std::string message = url.to_string();

		dnet_raw_id signature_id;
		dnet_digest_auth_transform_raw(message.c_str(), message.size(),
			token.c_str(), token.size(),
			signature_id.id, sizeof(signature_id.id));

		char signature_str[2 * DNET_ID_SIZE + 1];
		dnet_dump_id_len_raw(signature_id.id, DNET_ID_SIZE, signature_str);

		std::string signature(signature_str, 2 * DNET_ID_SIZE);

		if (url_ptr) {
			query.add_item("signature", signature);
			*url_ptr = url.to_string();
		}

		return std::move(signature);
	}

	virtual void on_download_lookup_finished(const bucket_acl &acl, const elliptics::sync_lookup_result &result,
			const elliptics::error_info &error) {
		if (error) {
			this->log(swarm::SWARM_LOG_ERROR, "download-lookup-finished: checked: error: %s",
					error.message().c_str());

			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		rift::JsonValue result_object;
		upload_completion::fill_upload_reply(result[0], result_object, result_object.GetAllocator());

		dnet_time time;
		dnet_current_time(&time);
		const std::string time_str = boost::lexical_cast<std::string>(time.tsec);

		if (!acl.token.empty()) {
			swarm::http_response::status_type status = swarm::http_response::ok;
			std::string signature = generate_signature(result[0], time_str, acl.token, NULL, &status);
			if (status != swarm::http_response::ok) {
				this->log(swarm::SWARM_LOG_ERROR, "download-lookup-finished: checked: error: %s",
						error.message().c_str());

				this->send_reply(status);
				return;
			}

			if (!signature.empty()) {
				rapidjson::Value signature_value(signature.c_str(),
						signature.size(), result_object.GetAllocator());
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
	virtual void on_download_lookup_finished(const bucket_acl &acl, const elliptics::sync_lookup_result &result,
			const elliptics::error_info &error) {
		if (error.code() == -ENOENT) {
			this->send_reply(swarm::http_response::not_found);
			return;
		} else if (error) {
			this->log(swarm::SWARM_LOG_ERROR, "redirect-base: lookup-finished: error: %s",
					error.message().c_str());
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		dnet_time time;
		dnet_current_time(&time);
		const std::string time_str = boost::lexical_cast<std::string>(time.tsec);

		std::string url;

		swarm::http_response::status_type status = swarm::http_response::ok;
		this->generate_signature(result[0], time_str, acl.token, &url, &status);
		if (status != swarm::http_response::ok) {
			this->log(swarm::SWARM_LOG_ERROR, "download-lookup-finished: checked: error: %s",
					error.message().c_str());

			this->send_reply(status);
			return;
		}

		this->log(swarm::SWARM_LOG_NOTICE, "redirect-base: lookup-finished: url: %s", url.c_str());

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
			const bucket_meta_raw &meta, const bucket_acl &acl, swarm::http_response::status_type verdict) {
		auto data = elliptics::data_pointer::from_raw(
			const_cast<char *>(boost::asio::buffer_cast<const char*>(buffer)),
			boost::asio::buffer_size(buffer));

		const auto &query = req.url().query();

		if ((verdict != swarm::http_response::ok) && !acl.noauth_read()) {
			this->log(swarm::SWARM_LOG_ERROR, "buffered-get-base: checked: url: %s, verdict: %d, did-not-pass-noauth-check",
					query.to_string().c_str(), verdict);

			this->send_reply(verdict);
			return;
		}

		this->log(swarm::SWARM_LOG_NOTICE, "buffered-get-base: checked: url: %s, original-verdict: %d, passed-noauth-check",
				query.to_string().c_str(), verdict);

		m_offset = query.item_value("offset", 0llu);

		(void) buffer;

		m_session.reset(new elliptics::session(this->server()->read_data_session_cache(req, meta, m_key)));

		m_session->lookup(m_key).connect(std::bind(
			&on_buffered_get_base::on_buffered_get_lookup_finished, this->shared_from_this(),
				std::placeholders::_1, std::placeholders::_2));
	}

	void on_buffered_get_lookup_finished(const elliptics::sync_lookup_result &result, const elliptics::error_info &error) {
		if (error) {
			this->log(swarm::SWARM_LOG_ERROR, "buffered-get: finished-lookup: error: %s", error.message().c_str());
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
		if (m_size <= m_offset) {
			this->log(swarm::SWARM_LOG_ERROR, "buffered-get: finished-lookup: requested offset is too big: offset: %llu, file-size: %llu",
					(unsigned long long)m_offset, (unsigned long long)m_size);

			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		swarm::http_response reply;
		reply.set_code(swarm::http_response::ok);
		reply.headers().set_content_length(m_size - m_offset);
		reply.headers().set_content_type("application/octet-stream");
		reply.headers().set_last_modified(entry.file_info()->mtime.tsec);

		this->send_headers(std::move(reply), std::function<void (const boost::system::error_code &)>());

		read_next(m_offset);
	}

	virtual void on_read_finished(uint64_t offset, const elliptics::sync_read_result &result,
			const elliptics::error_info &error)
	{

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
			this->log(swarm::SWARM_LOG_ERROR, "buffered-get-redirect: finished-read: error: %s, offset: %llu",
					error.message().c_str(), (unsigned long long)offset);
			auto ec = boost::system::errc::make_error_code(
					static_cast<boost::system::errc::errc_t>(-error.code()));
			this->get_reply()->close(ec);
			return;
		}

		const elliptics::read_result_entry &entry = result[0];
		elliptics::data_pointer file = entry.file();

		this->log(swarm::SWARM_LOG_NOTICE, "buffered-get-redirect: finished-read: offset: %llu, data-size: %llu",
				(unsigned long long)offset, (unsigned long long)file.size());

		if (offset + file.size() >= m_size) {
			this->send_data(std::move(file), std::bind(&thevoid::reply_stream::close,
						this->get_reply(), std::placeholders::_1));
		} else {
			auto first_part = file.slice(0, file.size() / 2);
			auto second_part = file.slice(first_part.size(), file.size() - first_part.size());

			this->send_data(std::move(first_part), std::bind(&on_buffered_get_base::on_part_sent,
						this->shared_from_this(), offset + file.size(), std::placeholders::_1, second_part));
		}
	}

	virtual void on_part_sent(size_t offset, const boost::system::error_code &error, const elliptics::data_pointer &second_part)
	{
		if (error) {
			this->log(swarm::SWARM_LOG_ERROR, "buffered-get-redirect: finished-part: error: %s, offset: %llu, size: %llu",
					error.message().c_str(), (unsigned long long)offset, (unsigned long long)m_size);
		} else {
			this->log(swarm::SWARM_LOG_NOTICE, "buffered-get-redirect: finished-part: offset: %llu, size: %llu",
					(unsigned long long)offset, (unsigned long long)m_size);
		}
		this->send_data(elliptics::data_pointer(second_part), std::function<void (const boost::system::error_code &)>());
		read_next(offset);
	}

	virtual void read_next(uint64_t offset)
	{
		this->log(swarm::SWARM_LOG_NOTICE, "buffered-get-redirect: read-next: offset: %llu, size: %llu",
				(unsigned long long)offset, (unsigned long long)m_size);

		m_session->read_data(m_key, offset, std::min(m_size - offset, m_buffer_size)).connect(std::bind(
			&on_buffered_get_base::on_read_finished, this->shared_from_this(),
			offset, std::placeholders::_1, std::placeholders::_2));
	}

protected:
	std::unique_ptr<elliptics::session> m_session;
	elliptics::key m_key;
	uint64_t m_size;
	uint64_t m_buffer_size;
	uint64_t m_offset;
};

template <typename Server>
class on_buffered_get : public on_buffered_get_base<Server, on_buffered_get<Server>>
{
public:
};

}}} // ioremap::rift::io

#endif /*__IOREMAP_RIFT_IO_HPP */
