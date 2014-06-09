#ifndef __IOREMAP_RIFT_BUCKET_HPP
#define __IOREMAP_RIFT_BUCKET_HPP

#include "auth.hpp"
#include "metadata_updater.hpp"
#include "io.hpp"

#include <elliptics/session.hpp>
#include <swarm/logger.hpp>
#include <thevoid/server.hpp>

#include <mutex>

#include <msgpack.hpp>

namespace ioremap { namespace rift {

struct bucket_meta_index_data {
	enum {
		serialization_version = 2,
	};

	std::string key;
	dnet_time ts;

	bucket_meta_index_data() {
		ts.tsec = 0;
		ts.tnsec = 0;
	}
};

struct bucket_acl {
	enum {
		serialization_version = 1,
	};

	// bit fields
	enum flags_noauth {
		flags_noauth_read = 1<<0,
		flags_noauth_all = 1<<1,
		flags_readonly = 1<<2,
	};

	bool noauth_read() const {
		return flags & (flags_noauth_read | flags_noauth_all);
	}
	bool noauth_all() const {
		return flags & flags_noauth_all;
	}
	bool readonly() const {
		return flags & flags_readonly;
	}

	std::string to_string(void) const {
		std::ostringstream acl_ss;
		if (!user.empty())
			acl_ss << user << ":" << token << ":0x" << std::hex << flags;

		return acl_ss.str();
	}

	std::string user;
	std::string token;
	uint64_t flags;

	bucket_acl() : flags(0ULL) {}
};

#define RIFT_BUCKET_META_NO_INDEX_UPDATE	(1<<0)	// do not generate bucket index

struct bucket_meta_raw {
	enum {
		serialization_version = 1,
	};

	std::string key;
	std::map<std::string, bucket_acl> acl;
	std::vector<int> groups;
	uint64_t flags;
	uint64_t max_size;
	uint64_t max_key_num;
	uint64_t reserved[3];

	bucket_meta_raw() : flags(0ULL), max_size(0ULL), max_key_num(0ULL) {
		memset(reserved, 0, sizeof(reserved));
	}
};

class bucket;

typedef std::function<void (const swarm::http_request, const boost::asio::const_buffer &buffer,
		const bucket_meta_raw &meta, const bucket_acl &acl, swarm::http_response::status_type verdict)> continue_handler_t;

class bucket_meta
{
	public:
		bucket_meta(bucket *b, const swarm::http_request &request,
				const boost::asio::const_buffer &buffer,
				const continue_handler_t &continue_handler);

		void check_and_run(const swarm::http_request &request, const boost::asio::const_buffer &buffer,
				const continue_handler_t &continue_handler);

		void update(void);
		void update_and_check(const swarm::http_request &request, const boost::asio::const_buffer &buffer,
				const continue_handler_t &continue_handler);

		static swarm::http_response::status_type verdict(const swarm::logger &logger, const bucket_meta_raw &meta,
				const swarm::http_request &request, bucket_acl &acl);
	private:
		std::mutex m_lock;
		bucket_meta_raw m_raw;

		bucket *m_bucket;

		void update_finished(const ioremap::elliptics::sync_read_result &result,
				const ioremap::elliptics::error_info &error);
		void update_and_check_completed(const swarm::http_request &request, const boost::asio::const_buffer &buffer,
				const continue_handler_t &continue_handler, const ioremap::elliptics::sync_read_result &result,
				const ioremap::elliptics::error_info &error);

		void check_and_run_raw(const swarm::http_request &request, const boost::asio::const_buffer &buffer,
				const continue_handler_t &continue_handler, bool uptodate);
};

class elliptics_base;
class bucket : public metadata_updater, public std::enable_shared_from_this<bucket>
{
	public:
		bucket();

		bool initialize(const rapidjson::Value &config, const elliptics_base &base, async_performer *async);
		void check(const swarm::http_request &request, const boost::asio::const_buffer &buffer,
				const continue_handler_t &continue_handler);

	private:
		std::mutex m_lock;
		std::map<std::string, std::shared_ptr<bucket_meta>> m_meta;
};

/*!
 * Bucket mixin adds authorization support for rift handlers.
 *
 * It makes possible to check access for different types of actions
 * like write or read access dependent on the value of Flags parameter.
 *
 * Also this mixin stores bucket's information in \a bucket_mixin_meta.
 */
template <bucket_acl::flags_noauth Flags>
class bucket_mixin_base
{
public:
	enum {
		bucket_mixin_flags = Flags
	};

	bucket_meta_raw bucket_mixin_meta;
	bucket_acl bucket_mixin_acl;
};

template <typename BaseStream, bucket_acl::flags_noauth Flags>
class bucket_mixin : public BaseStream, public bucket_mixin_base<Flags>
{
public:
};

/*!
 * Bucket processor is a proxy handler.
 *
 * As it receives the http_request it asks server to check the access rights.
 *
 * As server gives positive verdict processor creates underlying stream and
 * initializes it with all known information.
 *
 * Underlying socket must be successor of \a bucket_mixin to be able to store
 * bucket's information.
 */
template <typename Server, typename BaseStream>
class bucket_processor : public thevoid::request_stream<Server>, public std::enable_shared_from_this<bucket_processor<Server, BaseStream>>
{
public:
	enum {
		bucket_flags = BaseStream::bucket_mixin_flags
	};

	bucket_processor() : m_closed(false), m_on_data_called(false), m_was_error(false)
	{
	}

	virtual void on_headers(swarm::http_request &&req)
	{
		m_request = std::move(req);

		try {
			this->server()->process(m_request, boost::asio::const_buffer(),
				std::bind(&bucket_processor::on_checked, this->shared_from_this(),
					std::placeholders::_3, std::placeholders::_4, std::placeholders::_5));
		} catch (const std::exception &e) {
			this->log(swarm::SWARM_LOG_ERROR, "%s: uri: %s, processing error: %s",
					req.url().path().c_str(), req.url().query().to_string().c_str(), e.what());

			this->send_reply(swarm::http_response::bad_request);
		}
	}

	virtual size_t on_data(const boost::asio::const_buffer &buffer)
	{
		{
			std::lock_guard<std::mutex> lock(m_stream_mutex);
			if (!m_stream) {
				m_on_data_called = true;
				return 0;
			}
		}

		return m_stream->on_data(buffer);
	}

	virtual void on_close(const boost::system::error_code &err)
	{
		{
			std::lock_guard<std::mutex> lock(m_stream_mutex);
			if (!m_stream) {
				const swarm::url &url = m_request.url();
				this->log(swarm::SWARM_LOG_NOTICE, "bucket_processor_base: on_close called: path: %s, url: %s, error: %s",
						url.path().c_str(), url.query().to_string().c_str(), err.message().c_str());
				m_closed = true;
				m_was_error = !!err;
				return;
			}
		}

		m_stream->on_close(err);
	}

protected:
	void on_checked(const bucket_meta_raw &meta, const bucket_acl &acl, swarm::http_response::status_type verdict)
	{
		const swarm::url &url = m_request.url();

		if ((verdict != swarm::http_response::ok) && (bucket_flags == int(bucket_acl::flags_noauth_read) ? !acl.noauth_read() : !acl.noauth_all())) {
			this->log(swarm::SWARM_LOG_ERROR, "bucket_processor_base: checked: path: %s, url: %s, verdict: %d, did-not-pass-noauth-check",
					url.path().c_str(), url.query().to_string().c_str(), verdict);

			this->send_reply(verdict);
			return;
		}

		this->log(swarm::SWARM_LOG_NOTICE, "bucket_processor_base: checked: path: %s, url: %s, verdict: %d, passed-noauth-check",
				url.path().c_str(), url.query().to_string().c_str(), verdict);

		auto stream = std::make_shared<BaseStream>();
		stream->bucket_mixin_meta = meta;
		stream->bucket_mixin_acl = acl;
		stream->initialize(this->get_reply());
		stream->set_server(this->server());

		{
			std::lock_guard<std::mutex> lock(m_stream_mutex);
			if (m_closed && m_was_error) {
				this->log(swarm::SWARM_LOG_NOTICE, "bucket_processor_base: already closed: path: %s, url: %s",
						url.path().c_str(), url.query().to_string().c_str());
				// Connection is already closed, so we should die
				return;
			}

			m_stream = stream;
			m_stream->on_headers(std::move(m_request));

			this->log(swarm::SWARM_LOG_NOTICE, "bucket_processor_base: on_headers called: path: %s, url: %s",
					url.path().c_str(), url.query().to_string().c_str());
		}

		if (m_closed) {
			m_stream->on_data(boost::asio::const_buffer());
			m_stream->on_close(boost::system::error_code());
		} else if (m_on_data_called) {
			this->log(swarm::SWARM_LOG_NOTICE, "bucket_processor_base: want_more called: path: %s, url: %s",
					url.path().c_str(), url.query().to_string().c_str());
			// on_data method was already called, so we should to call it again
			this->get_reply()->want_more();
		}
	}

	bool m_closed;
	bool m_on_data_called;
	bool m_was_error;
	std::mutex m_stream_mutex;
	std::shared_ptr<thevoid::base_request_stream> m_stream;
	swarm::http_request m_request;
	bucket_meta_raw m_meta;
	bucket_acl m_acl;
};

/*!
 * Indexed upload mixin adds ability to BaseStream to add file to secondary indexes after succesfull write.
 *
 * It overrides on_write_finished method, so it should be properly defined in BaseStream.
 */
template <typename BaseStream>
class indexed_upload_mixin : public BaseStream {
public:
	typedef std::function<void (const swarm::http_response::status_type, const std::string &)>
		upload_completion_callback_t;

	void upload_update_indexes(const elliptics::session &data_session, const bucket_meta_raw &meta,
			const elliptics::key &key, const elliptics::sync_write_result &write_result,
			const upload_completion_callback_t &callback) {
		auto result_object = std::make_shared<rift::JsonValue>();
		io::upload_completion::fill_upload_reply(write_result, *result_object, result_object->GetAllocator());

		if (meta.flags & RIFT_BUCKET_META_NO_INDEX_UPDATE) {
			auto data = result_object->ToString();
			callback(swarm::http_response::ok, data);
			return;
		}

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
			std::bind(&indexed_upload_mixin::on_index_update_finished,
				result_object, callback, std::placeholders::_1, std::placeholders::_2));
	}

	static void on_index_update_finished(const std::shared_ptr<rift::JsonValue> &result_object,
			const upload_completion_callback_t &callback,
			const elliptics::sync_set_indexes_result &result, const elliptics::error_info &error) {
		(void) result;

		if (error) {
			callback(swarm::http_response::internal_server_error, std::string());
			return;
		}

		// Here we could update result Json object and put index data there
		// But we don't

		auto data = result_object->ToString();
		callback(swarm::http_response::ok, data);
	}

	void completion(const swarm::http_response::status_type &status, const std::string &data) {
		if (status != swarm::http_response::ok) {
			this->send_reply(status);
			return;
		}

		swarm::http_response reply;

		reply.set_code(swarm::http_response::ok);
		reply.headers().set_content_type("text/json; charset=utf-8");
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
			upload_update_indexes(*this->m_session, this->bucket_mixin_meta, this->m_key, result,
					std::bind(&indexed_upload_mixin::completion, this->shared_from_this(),
						std::placeholders::_1, std::placeholders::_2));
		} catch (std::exception &e) {
			this->log(swarm::SWARM_LOG_ERROR, "post-base: write_finished: key: %s, namespace: %s, exception: %s",
					this->m_key.to_string().c_str(), this->bucket_mixin_meta.key.c_str(), e.what());
			this->m_session->remove(this->m_key);
			this->send_reply(swarm::http_response::bad_request);
		}
	}
};

}} // namespace ioremap::rift

namespace msgpack
{

static inline dnet_time &operator >>(msgpack::object o, dnet_time &tm)
{
	if (o.type != msgpack::type::ARRAY || o.via.array.size != 2)
		throw msgpack::type_error();

	object *p = o.via.array.ptr;
	p[0].convert(&tm.tsec);
	p[1].convert(&tm.tnsec);

	return tm;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const dnet_time &tm)
{
	o.pack_array(2);
	o.pack(tm.tsec);
	o.pack(tm.tnsec);

	return o;
}

static inline ioremap::rift::bucket_acl &operator >>(msgpack::object o, ioremap::rift::bucket_acl &acl)
{
	if (o.type != msgpack::type::ARRAY) {
		std::ostringstream ss;
		ss << "bucket-acl unpack: type: " << o.type <<
			", must be: " << msgpack::type::ARRAY <<
			", size: " << o.via.array.size;
		throw std::runtime_error(ss.str());
	}

	object *p = o.via.array.ptr;
	const uint32_t size = o.via.array.size;
	uint16_t version = 0;
	p[0].convert(&version);
	switch (version) {
	case 1: {
		if (size != 4) {
			std::ostringstream ss;
			ss << "bucket acl unpack: array size mismatch: read: " << size << ", must be: 4";
			throw std::runtime_error(ss.str());
		}

		p[1].convert(&acl.user);
		p[2].convert(&acl.token);
		p[3].convert(&acl.flags);
		break;
	}
	default: {
		std::ostringstream ss;
		ss << "bucket acl unpack: version mismatch: read: " << version <<
			", must be: <= " << ioremap::rift::bucket_acl::serialization_version;
		throw std::runtime_error(ss.str());
	}
	}

	return acl;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const ioremap::rift::bucket_acl &acl)
{
	o.pack_array(4);
	o.pack((int)ioremap::rift::bucket_acl::serialization_version);
	o.pack(acl.user);
	o.pack(acl.token);
	o.pack(acl.flags);

	return o;
}

template <typename Stream>
static inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const ioremap::rift::bucket_meta_raw &m)
{
	o.pack_array(10);
	o.pack((int)ioremap::rift::bucket_meta_raw::serialization_version);
	o.pack(m.key);
	o.pack(m.acl);
	o.pack(m.groups);
	o.pack(m.flags);
	o.pack(m.max_size);
	o.pack(m.max_key_num);
	for (size_t i = 0; i < ARRAY_SIZE(m.reserved); ++i)
		o.pack(m.reserved[i]);

	return o;
}

static inline ioremap::rift::bucket_meta_raw &operator >>(msgpack::object o, ioremap::rift::bucket_meta_raw &m)
{
	if (o.type != msgpack::type::ARRAY || o.via.array.size < 10) {
		std::ostringstream ss;
		ss << "bucket unpack: type: " << o.type <<
			", must be: " << msgpack::type::ARRAY <<
			", size: " << o.via.array.size;
		throw std::runtime_error(ss.str());
	}

	object *p = o.via.array.ptr;
	const uint32_t size = o.via.array.size;
	uint16_t version = 0;
	p[0].convert(&version);
	switch (version) {
	case 1: {
		if (size != 10) {
			std::ostringstream ss;
			ss << "bucket unpack: array size mismatch: read: " << size << ", must be: 10";
			throw std::runtime_error(ss.str());
		}

		p[1].convert(&m.key);
		p[2].convert(&m.acl);
		p[3].convert(&m.groups);
		p[4].convert(&m.flags);
		p[5].convert(&m.max_size);
		p[6].convert(&m.max_key_num);
		for (size_t i = 0; i < ARRAY_SIZE(m.reserved); ++i)
			p[7 + i].convert(&m.reserved[i]);
		break;
	}
	default: {
		std::ostringstream ss;
		ss << "bucket unpack: version mismatch: read: " << version <<
			", must be: <= " << ioremap::rift::bucket_meta_raw::serialization_version;
		throw std::runtime_error(ss.str());
	}
	}

	return m;
}

template <typename Stream>
static inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const ioremap::rift::bucket_meta_index_data &m)
{
	o.pack_array(3);
	o.pack((int)ioremap::rift::bucket_meta_index_data::serialization_version);
	o.pack(m.key);
	o.pack(m.ts);

	return o;
}

static inline ioremap::rift::bucket_meta_index_data &operator >>(msgpack::object o, ioremap::rift::bucket_meta_index_data &m)
{
	if (o.type != msgpack::type::ARRAY || o.via.array.size < 2) {
		std::ostringstream ss;
		ss << "bucket unpack: type: " << o.type <<
			", must be: " << msgpack::type::ARRAY <<
			", size: " << o.via.array.size;
		throw std::runtime_error(ss.str());
	}

	object *p = o.via.array.ptr;
	const uint32_t size = o.via.array.size;
	uint16_t version = 0;
	p[0].convert(&version);
	switch (version) {
	case 1: {
		if (size != 2) {
			std::ostringstream ss;
			ss << "bucket unpack: array size mismatch: read: " << size << ", must be: 2";
			throw std::runtime_error(ss.str());
		}

		p[1].convert(&m.key);
		break;
	}
	case 2: {
		if (size != 3) {
			std::ostringstream ss;
			ss << "bucket unpack: array size mismatch: read: " << size << ", must be: 3";
			throw std::runtime_error(ss.str());
		}

		p[1].convert(&m.key);
		p[2].convert(&m.ts);
		break;
	}
	default: {
		std::ostringstream ss;
		ss << "bucket unpack: version mismatch: read: " << version <<
			", must be: <= " << ioremap::rift::bucket_meta_index_data::serialization_version;
		throw std::runtime_error(ss.str());
	}
	}

	return m;
}

} // namespace msgpack

#endif /* __IOREMAP_RIFT_BUCKET_HPP */
