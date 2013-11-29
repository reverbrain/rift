#ifndef __IOREMAP_RIFT_BUCKET_HPP
#define __IOREMAP_RIFT_BUCKET_HPP

// must be the first, since thevoid internally uses X->boost::buffer conversion,
// which must be present at compile time
#include "rift/asio.hpp"

#include "rift/auth.hpp"
#include "rift/server.hpp"
#include "rift/metadata_updater.hpp"

#include <elliptics/session.hpp>
#include <swarm/logger.hpp>
#include <thevoid/server.hpp>

#include <mutex>

namespace ioremap { namespace rift {

struct bucket_meta_raw {
	enum {
		serialization_version = 1,
	};

	// bit fields
	enum {
		flags_noauth_read = 1<<0,
		flags_noauth_all = 1<<1,
	};

	std::string key;
	std::string token;
	std::vector<int> groups;
	uint64_t flags;

	bucket_meta_raw() : flags(0ULL) {}
	bool noauth_read() const {
		return flags & (flags_noauth_read | flags_noauth_all);
	}
	bool noauth_all() const {
		return flags & flags_noauth_all;
	}
};

class bucket;

typedef std::function<void (const swarm::http_request, const boost::asio::const_buffer &buffer, const bucket_meta_raw &meta, swarm::http_response::status_type verdict)> continue_handler_t;

class bucket_meta
{
	public:
		bucket_meta(const std::string &key, bucket *b, const swarm::http_request &request, const boost::asio::const_buffer &buffer,
				const continue_handler_t &continue_handler);

		void check_and_run(const swarm::http_request &request, const boost::asio::const_buffer &buffer,
				const continue_handler_t &continue_handler);

		void update(void);
		void update_and_check(const swarm::http_request &request, const boost::asio::const_buffer &buffer,
				const continue_handler_t &continue_handler);
	private:
		std::mutex m_lock;
		bucket_meta_raw m_raw;

		bucket *m_bucket;

		void update_finished(const ioremap::elliptics::sync_read_result &result,
				const ioremap::elliptics::error_info &error);
		void update_and_check_completed(const swarm::http_request &request, const boost::asio::const_buffer &buffer,
				const continue_handler_t &continue_handler, const ioremap::elliptics::sync_read_result &result,
				const ioremap::elliptics::error_info &error);

		swarm::http_response::status_type verdict(const swarm::http_request &request);

		void check_and_run_raw(const swarm::http_request &request, const boost::asio::const_buffer &buffer,
				const continue_handler_t &continue_handler, bool uptodate);
};

class bucket : public metadata_updater, public std::enable_shared_from_this<bucket>
{
	public:
		bucket();

		bool initialize(const rapidjson::Value &config, const elliptics_base &base, async_performer *async);
		void check(const std::string &ns, const swarm::http_request &request, const boost::asio::const_buffer &buffer,
				const continue_handler_t &continue_handler);

	private:
		std::mutex m_lock;
		std::map<std::string, std::shared_ptr<bucket_meta>> m_meta;
};

}} // namespace ioremap::bucket

#endif /* __IOREMAP_RIFT_BUCKET_HPP */
