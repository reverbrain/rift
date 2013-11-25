#ifndef __IOREMAP_RIFT_BUCKET_HPP
#define __IOREMAP_RIFT_BUCKET_HPP

// must be the first, since thevoid internally uses X->boost::buffer conversion,
// which must be present at compile time
#include "rift/asio.hpp"

#include "rift/auth.hpp"
#include "rift/signature.hpp"
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

	std::string key;
	std::string token;
	std::vector<int> groups;
	uint64_t flags;

	bucket_meta_raw() : flags(0ULL) {}
};

class bucket;

typedef std::function<void (const swarm::http_request, swarm::http_response::status_type verdict)> continue_handler_t;

class bucket_meta
{
	public:
		bucket_meta(const std::string &key, bucket *b);

		void check_and_run(const swarm::http_request &request, elliptics::session &sess, const continue_handler_t &handler);
		void set_continuation(const swarm::http_request &request, const continue_handler_t &handler);

		void update(elliptics::session &sess);
	private:
		std::mutex m_lock;
		bucket_meta_raw m_raw;

		bucket *m_bucket;
		swarm::http_request m_request;
		continue_handler_t m_continue;

		void update_finished(elliptics::session &sess,
				const ioremap::elliptics::sync_read_result &result,
				const ioremap::elliptics::error_info &error);

		swarm::http_response::status_type verdict();
};

class bucket : public metadata_updater, public std::enable_shared_from_this<bucket>
{
	public:
		bucket();

		bool initialize(const rapidjson::Value &config, const ioremap::elliptics::node &node,
			const swarm::logger &logger, async_performer *async, const std::vector<int> &groups);
		void check(const swarm::http_request &request, elliptics::session &sess, const continue_handler_t &continue_handler);

	private:
		bool m_noauth_allowed;
		std::mutex m_lock;
		std::map<std::string, std::shared_ptr<bucket_meta>> m_meta;
};

}} // namespace ioremap::bucket

#endif /* __IOREMAP_RIFT_BUCKET_HPP */
