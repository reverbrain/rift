#include "rift/bucket.hpp"

using namespace ioremap;
using namespace ioremap::rift;

bucket_meta::bucket_meta(const std::string &key, bucket *b, const swarm::http_request &request,
		const boost::asio::const_buffer &buffer, const continue_handler_t &continue_handler) : m_bucket(b)
{
	m_raw.key = key;
	m_bucket->add_action(std::bind(&bucket_meta::update, this));

	update_and_check(request, buffer, continue_handler);
}

void bucket_meta::check_and_run_raw(const swarm::http_request &request, const boost::asio::const_buffer &buffer,
		const continue_handler_t &continue_handler, bool uptodate)
{
	std::unique_lock<std::mutex> guard(m_lock);
	auto v = verdict(request);
	guard.unlock();

	std::ostringstream ss;
	std::copy(m_raw.groups.begin(), m_raw.groups.end(), std::ostream_iterator<int>(ss, ":"));

	m_bucket->logger().log(swarm::SWARM_LOG_INFO,
			"bucket: check-and-run-raw: bucket: %s, groups: %s, uptodate: %d, req: %s, verdict: %d",
			m_raw.key.c_str(), ss.str().c_str(), uptodate, request.url().query().to_string().c_str(), v);

	if ((v != swarm::http_response::ok) && !uptodate) {
		update_and_check(request, buffer, continue_handler);
	} else {
		continue_handler(request, buffer, m_raw, v);
	}
}

void bucket_meta::check_and_run(const swarm::http_request &request, const boost::asio::const_buffer &buffer,
		const continue_handler_t &continue_handler)
{
	check_and_run_raw(request, buffer, continue_handler, false);
}

void bucket_meta::update(void)
{
	// metadata_session() clones metadata session
	elliptics::session sess = m_bucket->metadata_session();

	sess.read_data(m_raw.key, 0, 0).connect(std::bind(&bucket_meta::update_finished, this,
				std::placeholders::_1, std::placeholders::_2));
}

void bucket_meta::update_and_check(const swarm::http_request &request, const boost::asio::const_buffer &buffer,
		const continue_handler_t &continue_handler)
{
	// metadata_session() clones metadata session
	elliptics::session sess = m_bucket->metadata_session();

	sess.read_data(m_raw.key, 0, 0).connect(std::bind(&bucket_meta::update_and_check_completed, this,
				request, buffer, continue_handler, std::placeholders::_1, std::placeholders::_2));
}

swarm::http_response::status_type bucket_meta::verdict(const swarm::http_request &request)
{
	// if no groups exist, then given bucket is 'empty', or basically it was not written into the storage
	if (m_raw.groups.empty())
		return swarm::http_response::not_found;

	// if no token was set, 'succeed' verification
	if (m_raw.token.empty())
		return swarm::http_response::ok;

	auto verdict = swarm::http_response::bad_request;

	auto auth = request.headers().get("Authorization");
	if (!auth)
		return verdict;

	auto key = http_auth::generate_signature(request, m_raw.token);
	if (key == *auth)
		verdict = swarm::http_response::ok;
	else
		verdict = swarm::http_response::forbidden;

	return verdict;
}

void bucket_meta::update_finished(const ioremap::elliptics::sync_read_result &result,
			const ioremap::elliptics::error_info &error)
{
	if (error) {
		m_bucket->logger().log(swarm::SWARM_LOG_ERROR, "bucket-update-failed: bucket: %s, error: %s",
				m_raw.key.c_str(), error.message().c_str());
	} else {
		try {
			const elliptics::read_result_entry &entry = result[0];
			auto file = entry.file();

			msgpack::unpacked msg;
			msgpack::unpack(&msg, file.data<char>(), file.size());

			std::lock_guard<std::mutex> guard(m_lock);
			msg.get().convert(&m_raw);

			std::ostringstream ss;
			std::copy(m_raw.groups.begin(), m_raw.groups.end(), std::ostream_iterator<int>(ss, ":"));

			m_bucket->logger().log(swarm::SWARM_LOG_NOTICE,
					"bucket-update: bucket: %s, token: '%s', flags: 0x%lx, groups: %s",
					m_raw.key.c_str(), m_raw.token.c_str(), m_raw.flags, ss.str().c_str());

		} catch (const std::exception &e) {
			m_bucket->logger().log(swarm::SWARM_LOG_ERROR, "bucket-update-failed: read exception: "
					"bucket: %s, exception: %s",
					m_raw.key.c_str(), e.what());
		}
	}
}

void bucket_meta::update_and_check_completed(const swarm::http_request &request, const boost::asio::const_buffer &buffer,
		const continue_handler_t &continue_handler, const ioremap::elliptics::sync_read_result &result,
			const ioremap::elliptics::error_info &error)
{
	update_finished(result, error);

	if (error) {
		bucket_meta_raw meta;
		continue_handler(request, buffer, meta, swarm::http_response::forbidden);
	} else {
		check_and_run_raw(request, buffer, continue_handler, true);
	}
}

bucket::bucket()
{
}

bool bucket::initialize(const rapidjson::Value &config, const elliptics_base &base, async_performer *async)
{
	if (!metadata_updater::initialize(config, base.node(), base.logger(), async, base.metadata_groups())) {
		return false;
	}

	return true;
}

void bucket::check(const std::string &ns, const swarm::http_request &request, const boost::asio::const_buffer &buffer,
		const continue_handler_t &continue_handler)
{
	std::unique_lock<std::mutex> guard(m_lock);

	auto lookup = m_meta.find(ns);
	if (lookup == m_meta.end()) {
		auto meta = std::make_shared<bucket_meta>(ns, this, request, buffer, continue_handler);
		m_meta[ns] = meta;
	} else {
		guard.unlock();

		lookup->second->check_and_run(request, buffer, continue_handler);
	}
}
