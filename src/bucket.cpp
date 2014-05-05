#include "rift/bucket.hpp"
#include "rift/server.hpp"
#include "rift/url.hpp"

using namespace ioremap;
using namespace ioremap::rift;

bucket_meta::bucket_meta(bucket *b, const swarm::http_request &request,
		const boost::asio::const_buffer &buffer, const continue_handler_t &continue_handler) : m_bucket(b)
{
	m_raw.key = url::bucket(request);
	m_bucket->add_action(std::bind(&bucket_meta::update, this));

	update_and_check(request, buffer, continue_handler);
}

void bucket_meta::check_and_run_raw(const swarm::http_request &request, const boost::asio::const_buffer &buffer,
		const continue_handler_t &continue_handler, bool uptodate)
{
	bucket_acl acl;

	std::unique_lock<std::mutex> guard(m_lock);
	auto v = bucket_meta::verdict(m_bucket->logger(), m_raw, request, acl);
	guard.unlock();

	std::ostringstream ss;
	std::copy(m_raw.groups.begin(), m_raw.groups.end(), std::ostream_iterator<int>(ss, ":"));

	m_bucket->logger().log(swarm::SWARM_LOG_NOTICE,
			"bucket: check-and-run-raw: bucket: %s, groups: %s, uptodate: %d, req: %s, acl: '%s', verdict: %d",
			m_raw.key.c_str(), ss.str().c_str(), uptodate, request.url().query().to_string().c_str(),
			acl.to_string().c_str(), v);

	if ((v != swarm::http_response::ok) && !uptodate) {
		update_and_check(request, buffer, continue_handler);
	} else {
		continue_handler(request, buffer, m_raw, acl, v);
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
	std::string ns = "bucket";
	sess.set_namespace(ns.c_str(), ns.size());

	sess.read_data(m_raw.key, 0, 0).connect(std::bind(&bucket_meta::update_finished, this,
				std::placeholders::_1, std::placeholders::_2));
}

void bucket_meta::update_and_check(const swarm::http_request &request, const boost::asio::const_buffer &buffer,
		const continue_handler_t &continue_handler)
{
	// metadata_session() clones metadata session
	elliptics::session sess = m_bucket->metadata_session();
	std::string ns = "bucket";
	sess.set_namespace(ns.c_str(), ns.size());

	sess.read_data(m_raw.key, 0, 0).connect(std::bind(&bucket_meta::update_and_check_completed, this,
				request, buffer, continue_handler, std::placeholders::_1, std::placeholders::_2));
}

swarm::http_response::status_type bucket_meta::verdict(const swarm::logger &logger,
		const bucket_meta_raw &meta, const swarm::http_request &request, bucket_acl &acl)
{
	auto verdict = swarm::http_response::not_found;
	const auto &query = request.url().query();

	// if no groups exist, then given bucket is 'empty', or basically it was not written into the storage
	if (meta.groups.empty()) {
		logger.log(swarm::SWARM_LOG_ERROR, "verdict: url: %s, bucket: %s: no groups in bucket -> %d",
				query.to_string().c_str(), meta.key.c_str(), verdict);
		return verdict;
	}

	if (meta.acl.empty()) {
		// acl list is empty, nothing to check
		verdict = swarm::http_response::ok;

		logger.log(swarm::SWARM_LOG_ERROR, "verdict: url: %s, bucket: %s: acls: %zd: acl list is empty -> %d",
				query.to_string().c_str(), meta.key.c_str(), meta.acl.size(), verdict);
		return verdict;
	}

	auto user = query.item_value("user");
	if (!user) {
		user = "*";

		logger.log(swarm::SWARM_LOG_NOTICE, "verdict: url: %s, bucket: %s: acls: %zd: no user in URI -> "
				"searching for '*' wildcard",
				query.to_string().c_str(), meta.key.c_str(), meta.acl.size());
	}

	auto it = meta.acl.find(*user);
	if (it == meta.acl.end()) {
		// no username found, return error
		verdict = swarm::http_response::forbidden;

		logger.log(swarm::SWARM_LOG_ERROR, "verdict: url: %s, bucket: %s: user: %s, acls: %zd: "
				"no user in acl list -> %d",
				query.to_string().c_str(), meta.key.c_str(), (*user).c_str(),
				meta.acl.size(), verdict);
		return verdict;
	}

	acl = it->second;

	if (acl.noauth_all()) {
		// noauth check passed
		verdict = swarm::http_response::ok;

		logger.log(swarm::SWARM_LOG_INFO, "verdict: url: %s, bucket: %s: user: %s, acls: %zd: "
				"passed total noauth check -> %d",
				query.to_string().c_str(), meta.key.c_str(), (*user).c_str(), meta.acl.size(), verdict);
		return verdict;
	}

	auto auth = request.headers().get("Authorization");
	if (!auth) {
		verdict = swarm::http_response::unauthorized;

		logger.log(swarm::SWARM_LOG_ERROR, "verdict: url: %s, bucket: %s: user: %s, acls: %zd: "
				"no 'Authorization' header -> %d",
				query.to_string().c_str(), meta.key.c_str(), (*user).c_str(),
				meta.acl.size(), verdict);
		return verdict;
	}

	auto key = http_auth::generate_signature(request, acl.token);
	if (key != *auth) {
		verdict = swarm::http_response::forbidden;

		logger.log(swarm::SWARM_LOG_ERROR, "verdict: url: %s, bucket: %s: user: %s, acls: %zd: "
				"calculated-key: %s, auth-header: %s: incorrect auth header -> %d",
				query.to_string().c_str(), meta.key.c_str(), (*user).c_str(), meta.acl.size(),
				key.c_str(), (*auth).c_str(), verdict);
		return verdict;
	}

	verdict = swarm::http_response::ok;

	logger.log(swarm::SWARM_LOG_INFO, "verdict: url: %s, bucket: %s: user: %s, acls: %zd: auth-header: %s: OK -> %d",
			query.to_string().c_str(), meta.key.c_str(), (*user).c_str(), meta.acl.size(), key.c_str(), verdict);

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
					"bucket-update: bucket: %s, acls: %zd, flags: 0x%lx, groups: %s",
					m_raw.key.c_str(), m_raw.acl.size(), m_raw.flags, ss.str().c_str());

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
		auto code = swarm::http_response::forbidden;

		if (error.code() == -ENOENT)
			code = swarm::http_response::not_found;

		bucket_meta_raw meta;
		bucket_acl acl;
		continue_handler(request, buffer, meta, acl, code);
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

void bucket::check(const swarm::http_request &request, const boost::asio::const_buffer &buffer,
		const continue_handler_t &continue_handler)
{
	std::string bucket_name = url::bucket(request);

	std::unique_lock<std::mutex> guard(m_lock);
	auto lookup = m_meta.find(bucket_name);

	if (lookup == m_meta.end()) {
		auto meta = std::make_shared<bucket_meta>(this, request, buffer, continue_handler);
		m_meta[bucket_name] = meta;
	} else {
		guard.unlock();

		lookup->second->check_and_run(request, buffer, continue_handler);
	}
}
