#ifndef __IOREMAP_RIFT_BUCKET_HPP
#define __IOREMAP_RIFT_BUCKET_HPP

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
		serialization_version = 2,
	};

	// This enum describes per-user authorization flags
	enum auth_flags {
		auth_no_token = 0x01, // this user is able to perform requests without the authorization
		auth_write = 0x02, // this user is able to write to this bucket
		auth_admin = 0x04, // this user is able to change this bucket,
		auth_all = auth_write | auth_admin,
	};

	// This enum describes per-handler authorization flags
	enum handler_flags {
		handler_read = 0x01, // user must have read rights to access this handler
		handler_write = 0x02, // user must have write rights to access this handler
		handler_bucket = 0x04, // user must have admin rights to access this handler
		handler_not_found_is_ok = 0x08 // user is able to access this handler even if bucket doesn't exist
	};

	bool has_no_token() const {
		return flags & auth_no_token;
	}

	bool can_read() const {
		return true;
	}

	bool can_write() const {
		return flags & auth_write;
	}

	bool can_admin() const {
		return flags & auth_admin;
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

class bucket_meta;

/*!
 * \brief The authorization_checker_base class is interface for authentication mechanisms
 */
class authorization_checker_base
{
public:
	typedef std::shared_ptr<authorization_checker_base> ptr;
	typedef std::shared_ptr<thevoid::base_request_stream> request_stream_ptr;
	typedef std::tuple<thevoid::http_response::status_type, request_stream_ptr, bucket_acl> result_tuple;

	authorization_checker_base();

	/*!
	 * \brief Aunthenticates user if possible and constructs the authentication proxy if needed.
	 *
	 * Returnes tuple of verdict, authentication proxy and user's acl attributes.
	 *
	 * Verdict is 200 OK in case if there is a user in bucket's acl which passes the authentication.
	 * Verdict is 403 Forbidden in case if there is no such user or it doesn't pass authentication.
	 * Verdict is 401 Unauthorized in case if authorization token is missed but it must be presented.
	 *
	 * \attention This method must not return 404 Not Found as it must be returned only in case if there is no such bucket.
	 */
	virtual result_tuple check_permission(const request_stream_ptr &stream, const thevoid::http_request &request,
		const bucket_meta_raw &meta, const swarm::logger &logger) = 0;

protected:
	std::tuple<thevoid::http_response::status_type, ioremap::rift::bucket_acl>
	find_user(const thevoid::http_request &request, const bucket_meta_raw &meta, const std::string &user, const swarm::logger &logger);
};

/*!
 * \brief The authorization_checker class helps in integration with specific Server
 */
template <typename Server>
class authorization_checker : public authorization_checker_base
{
public:
	authorization_checker(Server *server) : m_server(server)
	{
	}

protected:
	/*!
	 * \brief Returnes constructed T with server already set.
	 */
	template <typename T, typename... Args>
	std::shared_ptr<thevoid::base_request_stream> create(Args &&...args)
	{
		auto stream = std::make_shared<T>(std::forward(args)...);
		stream->set_server(m_server.lock());
		return stream;
	}

	Server *m_server;
};

struct authorization_check_result
{
	thevoid::http_response::status_type verdict;
	bucket_meta_raw meta;
	bucket_acl acl;
	std::shared_ptr<thevoid::base_request_stream> stream;
};

typedef std::function<void (const authorization_check_result &)> continue_handler_t;

struct authorization_info
{
	authorization_checker_base::ptr checker;
	const thevoid::http_request *request;
	continue_handler_t handler;
	std::shared_ptr<thevoid::base_request_stream> stream;
	const swarm::logger *logger;
};

class bucket;

class bucket_meta : public std::enable_shared_from_this<bucket_meta>
{
	public:
		bucket_meta(bucket *b, const std::string &bucket_name,
				const authorization_info &info);

		bucket_meta(const bucket_meta &) = delete;
		bucket_meta &operator =(const bucket_meta &) = delete;

		void check_and_run(const authorization_info &info);

		void lock();
		void unlock();

		bucket_meta_raw raw() const;
	private:
		mutable std::mutex m_lock;
		bucket_meta_raw m_raw;

		bucket *m_bucket;

		void update();
		void update_and_check(const authorization_info &info);

		void update_finished(const swarm::logger *logger, const ioremap::elliptics::sync_read_result &result,
				const ioremap::elliptics::error_info &error);
		void update_and_check_completed(const authorization_info &info,
				const ioremap::elliptics::sync_read_result &result, const ioremap::elliptics::error_info &error);

		void check_and_run_raw(const authorization_info &info, bool uptodate);
};

class elliptics_base;
class bucket : public metadata_updater, public std::enable_shared_from_this<bucket>
{
	public:
		bucket(const swarm::logger &logger);

		bool initialize(const rapidjson::Value &config, const elliptics_base &base, async_performer *async);
		void check(const std::string &bucket_name, const authorization_info &info);

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
template <uint64_t Flags>
class bucket_mixin_base
{
public:
	static_assert(Flags & (bucket_acl::handler_read | bucket_acl::handler_write | bucket_acl::handler_bucket), "Invalid handler flags");

	enum {
		bucket_mixin_flags = Flags
	};

	bucket_meta_raw bucket_mixin_meta;
	bucket_acl bucket_mixin_acl;
};

template <typename BaseStream, uint64_t Flags>
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
template <typename Server, typename Stream, typename BaseStream>
class bucket_processor_base : public thevoid::request_stream<Server>, public std::enable_shared_from_this<Stream>
{
public:
	enum {
		bucket_flags = BaseStream::bucket_mixin_flags
	};

	bucket_processor_base() : m_closed(false), m_on_data_called(false), m_was_error(false)
	{
	}

	virtual void on_headers(thevoid::http_request &&req)
	{
		m_request = std::move(req);

		try {
			auto stream = std::make_shared<BaseStream>();
			stream->set_server(this->server());

			authorization_info info = {
				authorization_checker_base::ptr(), // authorization_checker will be set in Server's implementation
				&m_request, // m_request is guaranteed to be alive as this processor will be alive until the callback will be called
				std::bind(&bucket_processor_base::on_checked, this->shared_from_this(), std::placeholders::_1, stream),
				stream,
				&this->logger()
			};

			this->server()->process(static_cast<Stream &>(*this), info);
		} catch (const std::exception &e) {
			BH_LOG(this->logger(), SWARM_LOG_ERROR, "url: %s, processing error: %s",
					req.url().to_human_readable().c_str(), e.what());

			this->send_reply(thevoid::http_response::bad_request);
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
				BH_LOG(this->logger(), SWARM_LOG_NOTICE, "bucket_processor_base: on_close called: url: %s, error: %s",
						m_request.url().to_human_readable().c_str(), err.message().c_str());
				m_closed = true;
				m_was_error = !!err;
				return;
			}
		}

		m_stream->on_close(err);
	}

protected:
	void on_checked(const authorization_check_result &info, const std::shared_ptr<BaseStream> &base_stream)
	{
		const bucket_meta_raw &meta = info.meta;
		const bucket_acl &acl = info.acl;
		thevoid::http_response::status_type verdict = info.verdict;
		const auto &stream = info.stream;

		if ((bucket_flags & bucket_acl::handler_not_found_is_ok) && verdict == thevoid::http_response::not_found) {
			// If verdict is 404 the bucket is not created yet,
			// in such case if handler_not_found_is_ok flag is set
			// we assume that user passes the authentication
			verdict = thevoid::http_response::ok;
		} else if (verdict == thevoid::http_response::ok) {
			if ((bucket_flags & bucket_acl::handler_read) && !acl.can_read()) {
				// Check if user has rights to read
				verdict = thevoid::http_response::forbidden;
			}
			if ((bucket_flags & bucket_acl::handler_write) && !acl.can_write()) {
				// Check if user has rights to write
				verdict = thevoid::http_response::forbidden;
			}
			if ((bucket_flags & bucket_acl::handler_bucket) && !acl.can_admin()) {
				// Check if user has rights to administrate
				verdict = thevoid::http_response::forbidden;
			}
		}

		if (verdict != thevoid::http_response::ok) {
			BH_LOG(this->logger(), SWARM_LOG_ERROR, "bucket_processor_base: checked: url: %s, verdict: %d, did-not-pass-auth-check",
					m_request.url().to_human_readable().c_str(), verdict);

			this->send_reply(verdict);
			return;
		}

		BH_LOG(this->logger(), SWARM_LOG_NOTICE, "bucket_processor_base: checked: url: %s, verdict: %d, passed-auth-check, stream: %p",
				m_request.url().to_human_readable().c_str(), verdict, info.stream.get());

		base_stream->bucket_mixin_meta = meta;
		base_stream->bucket_mixin_acl = acl;
		info.stream->initialize(this->reply());

		// copy URL here since we will move m_request to on_headers() below
		std::string url = m_request.url().to_human_readable();

		{
			std::lock_guard<std::mutex> lock(m_stream_mutex);
			if (m_closed && m_was_error) {
				BH_LOG(this->logger(), SWARM_LOG_NOTICE, "bucket_processor_base: already closed: url: %s", url.c_str());
				// Connection is already closed, so we should die
				return;
			}

			m_stream = stream;
			m_stream->on_headers(std::move(m_request));

			BH_LOG(this->logger(), SWARM_LOG_NOTICE, "bucket_processor_base: on_headers called: url: %s", url.c_str());
		}

		if (m_closed) {
			m_stream->on_data(boost::asio::const_buffer());
			m_stream->on_close(boost::system::error_code());
		} else if (m_on_data_called) {
			BH_LOG(this->logger(), SWARM_LOG_NOTICE, "bucket_processor_base: want_more called: url: %s", url.c_str());

			// on_data method was already called, so we should to call it again
			this->reply()->want_more();
		}
	}

	bool m_closed;
	bool m_on_data_called;
	bool m_was_error;
	std::mutex m_stream_mutex;
	std::shared_ptr<thevoid::base_request_stream> m_stream;
	thevoid::http_request m_request;
};

template <typename Server, typename BaseStream>
class bucket_processor : public bucket_processor_base<Server, bucket_processor<Server, BaseStream>, BaseStream>
{
public:
};

/*!
 * Indexed upload mixin adds ability to BaseStream to add file to secondary indexes after succesfull write.
 *
 * It overrides on_write_finished method, so it should be properly defined in BaseStream.
 */
template <typename BaseStream>
class indexed_upload_mixin : public BaseStream {
public:
	typedef std::function<void (const thevoid::http_response::status_type, const std::string &)>
		upload_completion_callback_t;

	void upload_update_indexes(const elliptics::session &data_session, const bucket_meta_raw &meta,
			const elliptics::key &key, const elliptics::sync_write_result &write_result,
			const upload_completion_callback_t &callback) {
		auto result_object = std::make_shared<rift::JsonValue>();
		io::upload_completion::fill_upload_reply(write_result, *result_object, result_object->GetAllocator());

		if (meta.flags & RIFT_BUCKET_META_NO_INDEX_UPDATE) {
			BH_LOG(this->logger(), SWARM_LOG_INFO, "indexed_upload_mixin: no-index, url: %s",
					this->request().url().to_human_readable().c_str());

			auto data = result_object->ToString();

			BH_LOG(this->logger(), SWARM_LOG_INFO, "indexed::upload_update_indexes: url: %s: no index update in metadata, result-size: %lld",
					this->request().url().to_human_readable().c_str(), data.size());

			callback(thevoid::http_response::ok, data);
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

		BH_LOG(this->logger(), SWARM_LOG_INFO, "indexed::upload_update_indexes: url: %s: adding object: %s to index: %s in '%s' namespace",
				this->request().url().to_human_readable().c_str(),
				key.to_string().c_str(), indexes.front().c_str(), "<unknown>");

		session.update_indexes(key, indexes, datas).connect(
			std::bind(&indexed_upload_mixin::on_index_update_finished,
				this->shared_from_this(), result_object, callback, std::placeholders::_1, std::placeholders::_2));
	}

	void on_index_update_finished(const std::shared_ptr<rift::JsonValue> &result_object,
			const upload_completion_callback_t &callback,
			const elliptics::sync_set_indexes_result &result, const elliptics::error_info &error) {
		(void) result;

		BH_LOG(this->logger(), SWARM_LOG_INFO, "buffered-write: indexed_update_finished: url: %s, err: %s",
				this->request().url().to_human_readable().c_str(), error.message().c_str());

		if (error) {
			callback(thevoid::http_response::internal_server_error, std::string());
			return;
		}

		// Here we could update result Json object and put index data there
		// But we don't

		auto data = result_object->ToString();
		callback(thevoid::http_response::ok, data);
	}

	void completion(const thevoid::http_response::status_type &status, const std::string &data) {
		BH_LOG(this->logger(), SWARM_LOG_INFO, "buffered-write: indexed: completion: url: %s, status: %d",
				this->request().url().to_human_readable().c_str(), int(status));

		if (status != thevoid::http_response::ok) {
			this->send_reply(status);
			return;
		}

		thevoid::http_response reply;

		reply.set_code(thevoid::http_response::ok);
		reply.headers().set_content_type("text/json; charset=utf-8");
		reply.headers().set_content_length(data.size());

		this->send_reply(std::move(reply), std::move(data));
	}

	virtual void on_write_finished(const elliptics::sync_write_result &result,
			const elliptics::error_info &error) {
		BH_LOG(this->logger(), SWARM_LOG_INFO, "indexed::on_write_finished: url: %s: key: %s, namespace: %s, error: %s",
				this->request().url().to_human_readable().c_str(),
				this->m_key.to_string().c_str(), this->bucket_mixin_meta.key.c_str(), error.message().c_str());
		if (error) {
			this->send_reply(thevoid::http_response::service_unavailable);
			return;
		}

		BH_LOG(this->logger(), SWARM_LOG_INFO, "buffered-write: indexed: on_write_finished: url: %s",
				this->request().url().to_human_readable().c_str());

		try {
			upload_update_indexes(*this->m_session, this->bucket_mixin_meta, this->m_key, result,
					std::bind(&indexed_upload_mixin::completion, this->shared_from_this(),
						std::placeholders::_1, std::placeholders::_2));
		} catch (std::exception &e) {
			BH_LOG(this->logger(), SWARM_LOG_ERROR, "indexed::on_write_finished: url: %s: key: %s, namespace: %s, exception: %s",
					this->request().url().to_human_readable().c_str(),
					this->m_key.to_string().c_str(), this->bucket_mixin_meta.key.c_str(), e.what());
			this->m_session->remove(this->m_key);
			this->send_reply(thevoid::http_response::bad_request);
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
	case 1:
	case 2: {
		if (size != 4) {
			std::ostringstream ss;
			ss << "bucket acl unpack: array size mismatch: read: " << size << ", must be: 4";
			throw std::runtime_error(ss.str());
		}

		p[1].convert(&acl.user);
		p[2].convert(&acl.token);
		p[3].convert(&acl.flags);

		if (version == 1) {
			using namespace ioremap::rift;
			// Convert flags from old version to new one
			const bool noauth_read = acl.flags & (1 << 0);
			const bool noauth_all = acl.flags & (1 << 1);

			acl.flags = 0;

			// If there was any noauth - we shouldn't check token
			if (noauth_all || noauth_read) {
				acl.flags |= bucket_acl::auth_no_token;
			}

			// If there wasn't 'noauth_read' flag - user is permitted to do everything he want
			if (!noauth_read) {
				acl.flags |= bucket_acl::auth_admin | bucket_acl::auth_write;
			}
		}
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
