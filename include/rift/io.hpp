#ifndef __IOREMAP_RIFT_IO_HPP
#define __IOREMAP_RIFT_IO_HPP

#include "rift/jsonvalue.hpp"
#include "rift/url.hpp"

#include <swarm/url.hpp>
#include <swarm/url_query.hpp>

#include <elliptics/session.hpp>

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

#include "asio.hpp"

#include <deque>

namespace ioremap { namespace rift { namespace io {

static inline elliptics::data_pointer create_data(const boost::asio::const_buffer &buffer)
{
	return elliptics::data_pointer::from_raw(
		const_cast<char *>(boost::asio::buffer_cast<const char*>(buffer)),
		boost::asio::buffer_size(buffer)
	);
}

struct srange_info;

struct range_info
{
	size_t begin;
	size_t end;

	bool operator <(const range_info &other) const
	{
		return std::make_pair(begin, end) < std::make_pair(other.begin, other.end);
	}

	static std::vector<range_info> create(size_t size, const std::vector<srange_info> &ranges);
};

struct srange_info
{
	boost::optional<size_t> begin;
	boost::optional<size_t> end;

	static bool parse_range(const std::string &range, srange_info &info) {
		info.begin.reset();
		info.end.reset();

		if (range.size() <= 1)
			return false;

		try {
			const auto separator = range.find('-');
			if (separator == std::string::npos)
				return false;

			if (separator > 0)
				info.begin = boost::lexical_cast<size_t>(range.substr(0, separator));

			if (separator + 1 < range.size())
				info.end = boost::lexical_cast<size_t>(range.substr(separator + 1));
		} catch (...) {
			return false;
		}

		if (info.begin && info.end && info.begin.get() > info.end.get())
			return false;

		return true;
	}

	static std::vector<srange_info> parse(std::string range, bool *many, bool *ok)
	{
		*many = false;
		*ok = false;

		if (range.compare(0, 6, "bytes=") != 0)
			return std::vector<srange_info>();

		*ok = true;

		std::vector<srange_info> ranges;

		std::vector<std::string> ranges_str;
		range.erase(range.begin(), range.begin() + 6);
		boost::split(ranges_str, range, boost::is_any_of(","));

		*many = ranges_str.size() > 1;

		for (auto it = ranges_str.begin(); it != ranges_str.end(); ++it) {
			srange_info info;
			if (parse_range(*it, info))
				ranges.push_back(info);
		}

		return ranges;
	}
};

inline std::vector<range_info> range_info::create(size_t size, const std::vector<srange_info> &ranges)
{
	std::vector<range_info> results;
	results.reserve(ranges.size());

	for (auto it = ranges.begin(); it != ranges.end(); ++it) {
		range_info result;
		const srange_info &info = *it;

		if (info.begin) {
			if (*info.begin >= size)
				continue;

			result.begin = *info.begin;
			result.end = info.end ? std::min(size - 1, *info.end) : (size - 1);
		} else {
			if (*info.end > size)
				result.begin = 0;
			else
				result.begin = size - *info.end;
			result.end = size - 1;
		}

		results.push_back(result);
	}

	return results;
}

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

		if (entry.file_path()) {
			// copy filename without trailing 0-byte
			rapidjson::Value filename_value(entry.file_path(), entry.file_info()->flen - 1, allocator);
			result_object.AddMember("filename", filename_value, allocator);
		}

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
};

// write data object, get file-info json in response
template <typename Server, typename Stream>
class on_upload_base : public thevoid::buffered_request_stream<Server>, public std::enable_shared_from_this<Stream>
{
public:
	virtual void on_request(const swarm::http_request &req) {
		this->set_chunk_size(10 * 1024 * 1024);

		try {
			const auto &query = this->request().url().query();
			m_offset = query.item_value("offset", 0llu);
		} catch (const std::exception &e) {
			this->log(swarm::SWARM_LOG_ERROR, "buffered-write: url: %s: invalid offset parameter: %s",
					req.url().to_human_readable().c_str(), e.what());
			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		if (auto size = req.headers().content_length())
			m_size = *size;
		else
			m_size = 0;

		this->log(swarm::SWARM_LOG_INFO, "buffered-write: on_request: url: %s, offset: %llu, size: %llu",
				this->request().url().to_human_readable().c_str(),
				(unsigned long long)m_offset, (unsigned long long)m_size);

		m_session.reset(new elliptics::session(this->server()->create_session(static_cast<Stream&>(*this), req, m_key)));
	}

	virtual void on_chunk(const boost::asio::const_buffer &buffer, unsigned int flags) {
		const auto data = create_data(buffer);

		this->log(swarm::SWARM_LOG_INFO, "buffered-write: on_chunk: url: %s, size: %zu, m_offset: %lu, flags: %u",
				this->request().url().to_human_readable().c_str(), data.size(), m_offset, flags);

		elliptics::async_write_result result = write(data, flags);
		m_offset += data.size();

		if (flags & thevoid::buffered_request_stream<Server>::last_chunk) {
			result.connect(std::bind(&on_upload_base::on_write_finished, this->shared_from_this(),
				std::placeholders::_1, std::placeholders::_2));
		} else {
			result.connect(std::bind(&on_upload_base::on_write_partial, this->shared_from_this(),
				std::placeholders::_1, std::placeholders::_2));
		}
	}

	elliptics::async_write_result write(const elliptics::data_pointer &data, unsigned int flags) {
		if (flags == thevoid::buffered_request_stream<Server>::single_chunk) {
			this->log(swarm::SWARM_LOG_INFO, "buffered-write: write-data-single-chunk: url: %s, offset: %lu, size: %zu",
					this->request().url().to_human_readable().c_str(), m_offset, data.size());
			return m_session->write_data(m_key, data, m_offset);
		} else if (m_size > 0) {
			if (flags & thevoid::buffered_request_stream<Server>::first_chunk) {
				this->log(swarm::SWARM_LOG_INFO, "buffered-write: prepare: url: %s, offset: %lu, size: %lu",
						this->request().url().to_human_readable().c_str(), m_offset, m_size);
				return m_session->write_prepare(m_key, data, m_offset, m_offset + m_size);
			} else if (flags & thevoid::buffered_request_stream<Server>::last_chunk) {
				this->log(swarm::SWARM_LOG_INFO, "buffered-write: commit: url: %s, offset: %lu, size: %lu",
						this->request().url().to_human_readable().c_str(), m_offset, m_offset + data.size());
				return m_session->write_commit(m_key, data, m_offset, m_offset + data.size());
			} else {
				this->log(swarm::SWARM_LOG_INFO, "buffered-write: plain: url: %s, offset: %lu, size: %zu",
						this->request().url().to_human_readable().c_str(), m_offset, data.size());
				return m_session->write_plain(m_key, data, m_offset);
			}
		} else {
			this->log(swarm::SWARM_LOG_INFO, "buffered-write: write-data: url: %s, offset: %lu, size: %zu",
					this->request().url().to_human_readable().c_str(), m_offset, data.size());
			return m_session->write_data(m_key, data, m_offset);
		}
	}

	virtual void on_error(const boost::system::error_code &error) {
		this->log(swarm::SWARM_LOG_ERROR, "buffered-write: on_error: url: %s, error: %s",
				this->request().url().to_human_readable().c_str(), error.message().c_str());
	}

	virtual void on_write_partial(const elliptics::sync_write_result &result, const elliptics::error_info &error) {
		this->log(swarm::SWARM_LOG_INFO, "buffered-write: on_write_partial: url: %s, offset: %lu, size: %zu, error: %s",
				this->request().url().to_human_readable().c_str(), m_offset, m_size, error.message().c_str());

		if (error) {
			this->log(swarm::SWARM_LOG_ERROR, "buffered-write: on_write_partial: url: %s, partial write error: %s",
					this->request().url().to_human_readable().c_str(), error.message().c_str());
			this->on_write_finished(result, error);
			return;
		}

		// continue only with the groups where update succeeded
		std::vector<int> groups, rem_groups;

		std::ostringstream sgroups, egroups;

		for (auto it = result.begin(); it != result.end(); ++it) {
			const elliptics::write_result_entry & entry = *it;

			int group_id = entry.command()->id.group_id;

			if (entry.error()) {
				rem_groups.push_back(group_id);

				if (egroups.tellp() != 0)
					egroups << ":";
				egroups << std::to_string(group_id);
			} else {
				groups.push_back(group_id);

				if (sgroups.tellp() != 0)
					sgroups << ":";
				sgroups << std::to_string(group_id);
			}
		}

		this->log(swarm::SWARM_LOG_INFO, "buffered-write: on_write_partial: url: %s: success-groups: %s, error-groups: %s",
				this->request().url().to_human_readable().c_str(), sgroups.str().c_str(), egroups.str().c_str());

		elliptics::session tmp = m_session->clone();
		tmp.set_groups(rem_groups);
		tmp.remove(m_key);

		m_session->set_groups(groups);

		this->try_next_chunk();
	}

	virtual void on_write_finished(const elliptics::sync_write_result &result,
			const elliptics::error_info &error) {
		this->log(swarm::SWARM_LOG_INFO, "on_write_finished: url: %s, offset: %lu, size: %zu, error: %s",
				this->request().url().to_human_readable().c_str(), m_offset, m_size, error.message().c_str());

		if (error) {
			this->log(swarm::SWARM_LOG_ERROR, "buffered-write: on_write_finished: url: %s, full write error: %s",
					this->request().url().to_human_readable().c_str(), error.message().c_str());
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		rift::JsonValue value;
		upload_completion::fill_upload_reply(result, value, value.GetAllocator());

		rapidjson::Value sgroups_val(rapidjson::kArrayType);
		rapidjson::Value egroups_val(rapidjson::kArrayType);

		std::ostringstream sgroups, egroups;
		for (auto it = result.begin(); it != result.end(); ++it) {
			const elliptics::write_result_entry & entry = *it;

			int group_id = entry.command()->id.group_id;
			std::string group_str = std::to_string(group_id);
			rapidjson::Value group_val(group_str.c_str(), group_str.size(), value.GetAllocator());

			if (entry.error()) {
				if (egroups.tellp() != 0)
					egroups << ":";
				egroups << group_str;
				egroups_val.PushBack(group_val, value.GetAllocator());
			} else {
				if (sgroups.tellp() != 0)
					sgroups << ":";
				sgroups << group_str;
				sgroups_val.PushBack(group_val, value.GetAllocator());
			}
		}

		this->log(swarm::SWARM_LOG_INFO, "buffered-write: on_write_finished: url: %s: success-groups: %s, error-groups: %s",
				this->request().url().to_human_readable().c_str(), sgroups.str().c_str(), egroups.str().c_str());

		value.AddMember("success-groups", sgroups_val, value.GetAllocator());
		value.AddMember("error-groups", egroups_val, value.GetAllocator());

		std::string data = value.ToString();

		swarm::http_response reply;
		reply.set_code(swarm::http_response::ok);
		reply.headers().set_content_type("text/json; charset=utf-8");
		reply.headers().set_content_length(data.size());

		this->send_reply(std::move(reply), std::move(data));
	}


protected:
	elliptics::key m_key;
	std::unique_ptr<elliptics::session> m_session;

	uint64_t m_offset;
	uint64_t m_size;
};

template <typename Server>
class on_upload : public on_upload_base<Server, on_upload<Server>>
{
public:
};

// perform lookup, get file-info json in response
template <typename Server, typename Stream>
class on_download_info_base : public thevoid::simple_request_stream<Server>, public std::enable_shared_from_this<Stream>
{
public:
	virtual void on_request(const swarm::http_request &req, const boost::asio::const_buffer &buffer) {
		(void) buffer;

		elliptics::key key;
		elliptics::session session = this->server()->create_session(static_cast<Stream&>(*this), req, key);

		session.lookup(key).connect(std::bind(&on_download_info_base::on_download_lookup_finished,
					this->shared_from_this(), std::placeholders::_1, std::placeholders::_2));
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
		 *
		 * Please note, that above URL will be hashed in escaped form, i.e. ':' and other symbols will be encoded
		 */
		swarm::url url = this->server()->generate_url_base(entry.address(), entry.file_path(), type);
		if (swarm::http_response::http_response::ok != *type)
			return std::string();

		swarm::url_query &query = url.query();
		query.add_item("time", time);

		std::string path = url.path();
		path += ":";
		path += boost::lexical_cast<std::string>(info->offset);
		path += ":";
		path += boost::lexical_cast<std::string>(info->size);
		url.set_path(path);

		if (url_ptr && token.empty())
			*url_ptr = url.to_string();

		if (token.empty())
			return std::string();

		swarm::url tmp = url;
		tmp.set_scheme("scheme");
		const std::string message = tmp.to_string();

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

	virtual void on_download_lookup_finished(const elliptics::sync_lookup_result &result,
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
		const std::string token = this->server()->signature_token(static_cast<Stream&>(*this));

		if (!token.empty()) {
			swarm::http_response::status_type status = swarm::http_response::ok;
			std::string url;
			std::string signature = generate_signature(result[0], time_str, token, &url, &status);
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
			if (!url.empty()) {
				rapidjson::Value url_value(url.c_str(), url.size(), result_object.GetAllocator());
				result_object.AddMember("url", url_value, result_object.GetAllocator());
			}
		}

		result_object.AddMember("time", time_str.c_str(), result_object.GetAllocator());

		auto data = result_object.ToString();

		swarm::http_response reply;
		reply.set_code(swarm::http_response::ok);
		reply.headers().set_content_type("text/json; charset=utf-8");
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
template <typename Server, typename Stream>
class on_redirectable_get_base : public on_download_info_base<Server, Stream>
{
public:
	virtual void on_download_lookup_finished(const elliptics::sync_lookup_result &result,
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
		const std::string token = this->server()->signature_token(static_cast<Stream&>(*this));

		std::string url;

		swarm::http_response::status_type status = swarm::http_response::ok;
		this->generate_signature(result[0], time_str, token, &url, &status);
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

template <typename Server>
class on_redirectable_get : public on_redirectable_get_base<Server, on_redirectable_get<Server>>
{
public:
};

class iodevice
{
public:
	typedef std::function<void (const elliptics::data_pointer &data, const elliptics::error_info &error, bool last)> function;

	iodevice(size_t size) : m_size(size)
	{
	}
	iodevice(const iodevice &) = delete;
	iodevice &operator=(const iodevice &other) = delete;
	virtual ~iodevice() {}

	size_t size() const
	{
		return m_size;
	}
	virtual void read(size_t limit, const function &handler) = 0;

private:
	size_t m_size;
};

class buffer_device : public iodevice
{
public:
	buffer_device(const std::string &data)
		: iodevice(data.size()), m_data(elliptics::data_pointer::copy(data))
	{
	}
	buffer_device(elliptics::data_pointer &&data)
		: iodevice(data.size()), m_data(std::move(data))
	{
	}

	void read(size_t limit, const function &handler)
	{
		(void) limit;
		handler(m_data, elliptics::error_info(), true);
	}
private:
	elliptics::data_pointer m_data;
};


class async_device : public iodevice
{
public:
	async_device(const elliptics::session &session, const elliptics::key &id, size_t offset, size_t size)
		: iodevice(size), m_session(session), m_id(id), m_offset(offset), m_size(size)
	{
	}

	void read(size_t limit, const function &handler)
	{
		size_t offset = m_offset;
		size_t size = std::min(m_size, limit);
		m_offset += size;
		m_size -= size;
		bool last = (m_size == 0);
		m_session.read_data(m_id, offset, size).connect(std::bind(on_result,
			std::placeholders::_1, std::placeholders::_2, handler, last));
	}
private:
	static void on_result(const elliptics::sync_read_result &result,
		const elliptics::error_info &error, const function &handler, bool last)
	{
		if (error) {
			handler(elliptics::data_pointer(), error, last);
			return;
		}

		const elliptics::read_result_entry &entry = result[0];
		elliptics::data_pointer file = entry.file();

		handler(file, elliptics::error_info(), last);
	}

	elliptics::session m_session;
	elliptics::key m_id;
	size_t m_offset;
	size_t m_size;
	std::string m_data;
};

template <typename Server, typename Stream>
class on_get_base : public thevoid::simple_request_stream<Server>, public std::enable_shared_from_this<Stream>
{
public:
	on_get_base() : m_prefetched_offset(0), m_buffer_size(5 * 1025 * 1024)
	{
	}

	virtual void on_request(const swarm::http_request &req, const boost::asio::const_buffer &buffer) {
		const auto &query = req.url().query();
		m_url = req.url().to_human_readable();

		try {
			m_offset = query.item_value("offset", 0llu);
			m_size = query.item_value("size", 0llu);
		} catch (const std::exception &e) {
			this->log(swarm::SWARM_LOG_ERROR, "buffered-get: on_request: url: %s: invalid size/offset parameters: %s", m_url.c_str(), e.what());
			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		(void) buffer;

		m_session.reset(new elliptics::session(this->server()->create_session(static_cast<Stream&>(*this), req, m_key)));

		auto range = this->request().headers().get("Range");

		if (range) {
			this->log(swarm::SWARM_LOG_INFO, "buffered-get: on_request: url: %s: range: \"%s\"", m_url.c_str(), range->c_str());
			bool ok = false;

			m_ranges = srange_info::parse(*range, &m_many_ranges, &ok);

			if (ok) {
				for (size_t i = 0; i < m_ranges.size(); ++i) {
					const srange_info &info = m_ranges.at(i);

					if (info.begin) {
						size_t size2read = info.end ? std::min(m_buffer_size, *info.end + 1 - *info.begin) : m_buffer_size;
						if (m_size)
							size2read = std::min(m_size, size2read);

						m_session->read_data(m_key, m_offset, size2read).connect(std::bind(
							&on_get_base::on_read_data_finished, this->shared_from_this(),
								std::placeholders::_1, std::placeholders::_2));

						return;
					}
				}
			} else {
				m_ranges.clear();
			}
		} else {
			size_t size2read = m_buffer_size;
			if (m_size)
				size2read = std::min(m_size, size2read);

			m_session->read_data(m_key, m_offset, size2read).connect(std::bind(
				&on_get_base::on_read_data_finished, this->shared_from_this(),
					std::placeholders::_1, std::placeholders::_2));
			return;
		}

		m_session->lookup(m_key).connect(std::bind(
			&on_get_base::on_buffered_get_lookup_finished, this->shared_from_this(),
				std::placeholders::_1, std::placeholders::_2));
	}

	void on_first_chunk_read(size_t size, const dnet_time &ts) {
		if (m_size)
			size = std::min(size, m_offset + m_size);

		if (size <= m_offset) {
			this->log(swarm::SWARM_LOG_ERROR, "buffered-get: on_first_chunk_read: url: %s: requested offset is too big: offset: %llu, file-size: %llu",
					m_url.c_str(), (unsigned long long)m_offset, (unsigned long long)size);

			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		if (!m_ranges.empty()) {
			std::vector<range_info> ranges = range_info::create(size - m_offset, m_ranges);
			for (auto it = ranges.begin(); it != ranges.end(); ++it) {
				it->begin += m_offset;
				it->end += m_offset;
			}

			if (ranges.empty()) {
				this->send_reply(swarm::http_response::requested_range_not_satisfiable);
				return;
			}

			if (m_many_ranges)
				on_ranges(ranges, size, ts);
			else
				on_range(ranges.front(), size, ts);
			return;
		}

		swarm::http_response reply;
		reply.set_code(swarm::http_response::ok);
		reply.headers().set_content_type("application/octet-stream");
		reply.headers().set_last_modified(ts.tsec);

		add_async(m_offset, size - m_offset);

		start(std::move(reply));
	}

	void on_read_data_finished(const elliptics::sync_read_result &result, const elliptics::error_info &error) {
		if (error) {
			this->log(swarm::SWARM_LOG_ERROR, "buffered-get: on_read_data_finished: url: %s: error: %s", m_url.c_str(), error.message().c_str());

			if (error.code() == -ENOENT) {
				this->send_reply(swarm::http_response::not_found);
				return;
			} else if (error.code() == -E2BIG) {
				this->log(swarm::SWARM_LOG_ERROR, "buffered-get: on_read_data_finished: url: %s: requested offset is too big: offset: %llu",
						m_url.c_str(), (unsigned long long)m_offset);
				this->send_reply(swarm::http_response::bad_request);
				return;
			} else {
				this->send_reply(swarm::http_response::internal_server_error);
				return;
			}
		}

		const elliptics::read_result_entry &entry = result[0];
		const size_t total_size = entry.io_attribute()->total_size;
		const dnet_time &ts = entry.io_attribute()->timestamp;

		m_prefetched_offset = entry.io_attribute()->offset;
		m_prefetched_data = entry.file();

		// do not request checksums for the second and the rest chunks,
		// since checksum for the first chunk already checked whole file
		// after we switched to new checksums in elliptics backend
		// (like csum per X Mb of file) this will not be needed
		m_session->set_ioflags(m_session->get_ioflags() | DNET_IO_FLAGS_NOCSUM);

		on_first_chunk_read(total_size, ts);
	}


	void on_buffered_get_lookup_finished(const elliptics::sync_lookup_result &result, const elliptics::error_info &error) {
		if (error) {
			this->log(swarm::SWARM_LOG_ERROR, "buffered-get: on_buffered_get_lookup_finished: url: %s: error: %s",
					m_url.c_str(), error.message().c_str());

			if (error.code() == -ENOENT) {
				this->send_reply(swarm::http_response::not_found);
				return;
			} else {
				this->send_reply(swarm::http_response::internal_server_error);
				return;
			}
		}

		const elliptics::lookup_result_entry &entry = result[0];
		const size_t size = entry.file_info()->size;
		const dnet_time &ts = entry.file_info()->mtime;

		on_first_chunk_read(size, ts);
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

	virtual void on_range(const range_info &range, size_t data_size, const dnet_time &ts) {
		auto content_range = create_content_range(range.begin, range.end, data_size);

		swarm::http_response reply;
		reply.set_code(swarm::http_response::partial_content);
		reply.headers().set_content_type("application/octet-stream");
		reply.headers().set_last_modified(ts.tsec);
		reply.headers().add("Accept-Ranges", "bytes");
		reply.headers().add("Content-Range", content_range);

		this->log(swarm::SWARM_LOG_INFO, "buffered-get: on_range: url: %s: Content-Range: %s", m_url.c_str(), content_range.c_str());

		add_async(range.begin, range.end - range.begin + 1);

		start(std::move(reply));
	}

	virtual void on_ranges(const std::vector<range_info> &ranges, size_t data_size, const dnet_time &ts) {
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
			result += create_content_range(it->begin, it->end, data_size);
			result += "\r\n\r\n";
			add_buffer(std::move(result));
			result.clear();

			add_async(it->begin, it->end - it->begin + 1);
			result += "\r\n";
		}
		result += "--";
		result += boundary;
		result += "--\r\n";
		add_buffer(std::move(result));

		swarm::http_response reply;
		reply.set_code(swarm::http_response::partial_content);
		reply.headers().set_content_type(std::string("multipart/byteranges; boundary=") + boundary);
		reply.headers().set_last_modified(ts.tsec);
		reply.headers().add("Accept-Ranges", "bytes");

		start(std::move(reply));
	}

	void read_next(uint64_t offset)
	{
		iodevice *device = m_devices.front().get();

		device->read(m_buffer_size, std::bind(
			&on_get_base::on_read_finished, this->shared_from_this(),
			offset, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
	}

	virtual void on_read_finished(uint64_t offset, const elliptics::data_pointer &file,
			const elliptics::error_info &error, bool last)
	{
		if (error) {
			this->log(swarm::SWARM_LOG_ERROR, "buffered-get: on_read_finished: url: %s: error: %s, "
					"offset: %llu, last: %d",
					m_url.c_str(), error.message().c_str(), (unsigned long long)offset, last);

			auto ec = boost::system::errc::make_error_code(static_cast<boost::system::errc::errc_t>(-error.code()));
			this->get_reply()->close(ec);
			return;
		}

		this->log(swarm::SWARM_LOG_NOTICE, "buffered-get-redirect: on_read_finished: url: %s: "
				"offset: %llu, data-size: %llu, last: %d",
				m_url.c_str(), (unsigned long long)offset, (unsigned long long)file.size(), last);

		if (last) {
			this->send_data(file, std::bind(&on_get_base::close, this->shared_from_this(), std::placeholders::_1));
		} else {
			const size_t second_size = file.size() / 2;

			auto first_part = file.slice(0, file.size() - second_size);
			auto second_part = file.slice(first_part.size(), second_size);

			this->log(swarm::SWARM_LOG_NOTICE, "buffered-get-redirect: on_read_finished: url: %s: "
					"fset: %llu, data-size: %llu, last: %d, "
					"first-part: offset: %zd, size: %zd, second-part: offset: %zd, size: %zd",
					m_url.c_str(), (unsigned long long)offset, (unsigned long long)file.size(), last,
					first_part.offset(), first_part.size(), second_part.offset(), second_part.size());

			this->send_data(std::move(first_part), std::bind(&on_get_base::on_part_sent,
				this->shared_from_this(), offset + file.size(), std::placeholders::_1, second_part));
		}
	}

	virtual void on_part_sent(size_t offset, const boost::system::error_code &error, const elliptics::data_pointer &second_part)
	{
		if (error) {
			this->log(swarm::SWARM_LOG_ERROR, "buffered-get: on_part_sent: url: %s: error: %s, "
					"next-read-offset: %llu, second-part-size: %llu",
					m_url.c_str(), error.message().c_str(),
					(unsigned long long)offset, (unsigned long long)second_part.size());
		} else {
			this->log(swarm::SWARM_LOG_NOTICE, "buffered-get: on_part_sent: url: %s: "
					"next-read-offset: %llu, second-part-size: %llu",
					m_url.c_str(), (unsigned long long)offset, (unsigned long long)second_part.size());
		}

		if (!second_part.empty())
			this->send_data(elliptics::data_pointer(second_part),
					std::function<void (const boost::system::error_code &)>());
		read_next(offset);
	}

protected:
	void start(swarm::http_response &&response)
	{
		m_prefetched_offset = 0;
		m_prefetched_data = elliptics::data_pointer();

		size_t size = 0;

		for (auto it = m_devices.begin(); it != m_devices.end(); ++it)
			size += (*it)->size();

		response.headers().set_content_length(size);

		this->send_headers(std::move(response), std::function<void (const boost::system::error_code &)>());
		read_next(0);
	}
	/*
	 * @offset is offset within given key to start reading @size bytes
	 */
	void add_async(size_t offset, size_t size)
	{
		if (m_prefetched_data.empty()
			|| m_prefetched_offset >= offset + size
			|| m_prefetched_offset + m_prefetched_data.size() <= offset) {
			add_async_raw(offset, size);
			return;
		}

		if (offset < m_prefetched_offset) {
			const size_t delta = std::min(size, m_prefetched_offset - offset);

			add_async_raw(offset, delta);

			size -= delta;
			offset += delta;
		}

		if (!size)
			return;

		elliptics::data_pointer data;

		if (offset > m_prefetched_offset) {
			data = m_prefetched_data.slice(offset - m_prefetched_offset, size);
		} else {
			data = m_prefetched_data.slice(0, size);
		}

		if (!data.empty()) {
			offset += data.size();
			size -= data.size();

			add_buffer(std::move(data));
		}

		if (size) {
			add_async_raw(offset, size);
		}
	}
	void add_async_raw(size_t offset, size_t size)
	{
		m_devices.emplace_back(new async_device(*m_session, m_key, offset, size));
	}
	void add_buffer(std::string &&data)
	{
		m_devices.emplace_back(new buffer_device(std::move(data)));
	}
	void add_buffer(elliptics::data_pointer &&data)
	{
		m_devices.emplace_back(new buffer_device(std::move(data)));
	}

	std::deque<std::unique_ptr<iodevice>> m_devices;
	std::unique_ptr<elliptics::session> m_session;
	std::vector<srange_info> m_ranges;
	bool m_many_ranges;
	size_t m_prefetched_offset;
	elliptics::data_pointer m_prefetched_data;
	elliptics::key m_key;
	uint64_t m_buffer_size;
	uint64_t m_offset;
	uint64_t m_size;
	std::string m_url;
};

template <typename Server>
class on_get : public on_get_base<Server, on_get<Server>>
{
public:
};

template <typename Server, typename Stream>
class on_delete_base : public thevoid::simple_request_stream<Server>, public std::enable_shared_from_this<Stream>
{
public:
	virtual void on_request(const swarm::http_request &req, const boost::asio::const_buffer &buffer) {
		(void) buffer;

		this->log(swarm::SWARM_LOG_INFO, "delete: on_request: url: %s",
				req.url().to_human_readable().c_str());

		elliptics::key key;
		elliptics::session session = this->server()->create_session(static_cast<Stream&>(*this), req, key);

		session.remove(key).connect(std::bind(
			&on_delete_base::on_delete_finished, this->shared_from_this(),
				std::placeholders::_1, std::placeholders::_2));
	}

	virtual void on_delete_finished(const elliptics::sync_remove_result &result,
			const elliptics::error_info &error) {
		this->log(swarm::SWARM_LOG_INFO, "delete: on_delete_finished: url: %s, error: %s",
				this->request().url().to_human_readable().c_str(), error.message().c_str());

		if (error.code() == -ENOENT) {
			this->send_reply(swarm::http_response::not_found);
			return;
		} else if (error) {
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		(void) result;

		this->send_reply(swarm::http_response::ok);
	}
};

template <typename Server>
class on_delete : public on_delete_base<Server, on_delete<Server>>
{
public:
};

}}} // ioremap::rift::io

#endif /*__IOREMAP_RIFT_IO_HPP */
