#ifndef __IOREMAP_RIFT_BUCKET_HPP
#define __IOREMAP_RIFT_BUCKET_HPP

// must be the first, since thevoid internally uses X->boost::buffer conversion,
// which must be present at compile time
#include "rift/asio.hpp"

#include "rift/auth.hpp"
#include "rift/metadata_updater.hpp"

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
	enum {
		flags_noauth_read = 1<<0,
		flags_noauth_all = 1<<1,
	};

	bool noauth_read() const {
		return flags & (flags_noauth_read | flags_noauth_all);
	}
	bool noauth_all() const {
		return flags & flags_noauth_all;
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
		bucket_meta(const std::string &key, bucket *b, const swarm::http_request &request,
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
		void check(const std::string &name, const swarm::http_request &request, const boost::asio::const_buffer &buffer,
				const continue_handler_t &continue_handler);

	private:
		std::mutex m_lock;
		std::map<std::string, std::shared_ptr<bucket_meta>> m_meta;
};

template <typename Server, typename Stream>
class bucket_processing : public thevoid::simple_request_stream<Server>, public std::enable_shared_from_this<Stream>
{
public:
	virtual void on_request(const swarm::http_request &req, const boost::asio::const_buffer &buffer) {
		try {
			this->server()->process(req, buffer, std::bind(&bucket_processing::checked, this->shared_from_this(),
				std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5));
		} catch (const std::exception &e) {
			this->log(swarm::SWARM_LOG_ERROR, "%s: uri: %s, processing error: %s",
					req.url().path().c_str(), req.url().query().to_string().c_str(), e.what());

			this->send_reply(swarm::http_response::bad_request);
		}
	}

	virtual void checked(const swarm::http_request &req, const boost::asio::const_buffer &buffer,
			const bucket_meta_raw &meta, const bucket_acl &acl, swarm::http_response::status_type verdict) = 0;
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
