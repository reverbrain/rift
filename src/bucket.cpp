#include "rift/bucket.hpp"
#include "rift/server.hpp"
#include "rift/url.hpp"

using namespace ioremap;
using namespace ioremap::rift;

bucket_meta::bucket_meta(bucket *b, const std::string &bucket_name, const authorization_info &info) : m_bucket(b)
{
	m_raw.key = bucket_name;
	m_bucket->add_action(std::bind(&bucket_meta::update, this));

	update_and_check(info);
}

static std::string groups_to_string(const std::vector<int> &groups)
{
	std::ostringstream ss;
	std::copy(groups.begin(), groups.end(), std::ostream_iterator<int>(ss, ":"));
	return ss.str();
}

void bucket_meta::check_and_run_raw(const authorization_info &info, bool uptodate)
{
	rift::authorization_check_result result;
	result.meta = raw();

	if (result.meta.groups.empty()) {
		// if no groups exist, then given bucket is 'empty', or basically it was not written into the storage
		result.verdict = thevoid::http_response::not_found;
		result.stream = info.stream;

		BH_LOG(*info.logger, SWARM_LOG_ERROR, "verdict: url: %s, bucket: %s: no groups in bucket -> %d",
				info.request->url().to_human_readable(), result.meta.key, result.verdict);
	} else if (result.meta.acl.empty()) {
		// acl list is empty, nothing to check
		result.verdict = thevoid::http_response::ok;
		result.stream = info.stream;
		result.acl.flags = bucket_acl::auth_all;

		BH_LOG(*info.logger, SWARM_LOG_ERROR, "verdict: url: %s, bucket: %s: acls: %lld: acl list is empty -> %d",
				info.request->url().to_human_readable(), result.meta.key, result.meta.acl.size(), result.verdict);
	} else {
		std::tie(result.verdict, result.stream, result.acl) = info.checker->check_permission(info.stream, *info.request, result.meta, *info.logger);
	}

	BH_LOG(*info.logger, SWARM_LOG_NOTICE,
		"bucket: check-and-run-raw: bucket: %s, groups: %s, uptodate: %d, req: %s, acl: '%s', verdict: %d",
		result.meta.key, groups_to_string(result.meta.groups), uptodate, info.request->url().to_human_readable(),
		result.acl.to_string(), result.verdict);

	if ((result.verdict != thevoid::http_response::ok) && !uptodate) {
		update_and_check(info);
	} else {
		info.handler(result);
	}
}

void bucket_meta::check_and_run(const authorization_info &info)
{
	check_and_run_raw(info, false);
}

void bucket_meta::lock()
{
	m_lock.lock();
}

void bucket_meta::unlock()
{
	m_lock.unlock();
}

bucket_meta_raw bucket_meta::raw() const
{
	std::unique_lock<std::mutex> guard(m_lock);
	return m_raw;
}

void bucket_meta::update()
{
	// metadata_session() clones metadata session
	elliptics::session sess = m_bucket->metadata_session();
	std::string ns = "bucket";
	sess.set_namespace(ns);

	sess.read_data(m_raw.key, 0, 0).connect(std::bind(&bucket_meta::update_finished, this,
				&m_bucket->logger(), std::placeholders::_1, std::placeholders::_2));
}

void bucket_meta::update_and_check(const authorization_info &info)
{
	// metadata_session() clones metadata session
	elliptics::session sess = m_bucket->metadata_session();
	std::string ns = "bucket";
	sess.set_namespace(ns);

	sess.read_data(m_raw.key, 0, 0).connect(std::bind(&bucket_meta::update_and_check_completed, this,
				info, std::placeholders::_1, std::placeholders::_2));
}

void bucket_meta::update_finished(const swarm::logger *logger, const ioremap::elliptics::sync_read_result &result,
			const ioremap::elliptics::error_info &error)
{
	if (error) {
		BH_LOG(*logger, SWARM_LOG_ERROR, "bucket-update-failed: bucket: %s, error: %s",
				m_raw.key, error.message());
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

			BH_LOG(*logger, SWARM_LOG_NOTICE,
					"bucket-update: bucket: %s, acls: %lld, flags: 0x%lx, groups: %s",
					m_raw.key, m_raw.acl.size(), m_raw.flags, ss.str());

		} catch (const std::exception &e) {
			BH_LOG(*logger, SWARM_LOG_ERROR, "bucket-update-failed: read exception: "
					"bucket: %s, exception: %s",
					m_raw.key, e.what());
		}
	}
}

void bucket_meta::update_and_check_completed(const authorization_info &info,
			const ioremap::elliptics::sync_read_result &result, const ioremap::elliptics::error_info &error)
{
	update_finished(info.logger, result, error);

	if (error) {
		rift::authorization_check_result check_result;

		check_result.verdict = thevoid::http_response::forbidden;
		if (error.code() == -ENOENT)
			check_result.verdict = thevoid::http_response::not_found;

		check_result.stream = info.stream;

		info.handler(check_result);
	} else {
		check_and_run_raw(info, true);
	}
}

bucket::bucket(const swarm::logger &logger) :
	metadata_updater(swarm::logger(logger, blackhole::log::attributes_t({ swarm::keyword::source() = "bucket" })))
{
}

bool bucket::initialize(const rapidjson::Value &config, const elliptics_base &base, async_performer *async)
{
	if (!metadata_updater::initialize(config, base.node(), async, base.metadata_groups())) {
		return false;
	}

	return true;
}

void bucket::check(const std::string &bucket_name, const authorization_info &info)
{
	std::unique_lock<std::mutex> guard(m_lock);
	auto lookup = m_meta.find(bucket_name);

	if (lookup == m_meta.end()) {
		auto meta = std::make_shared<bucket_meta>(this, bucket_name, info);
		m_meta[bucket_name] = meta;
	} else {
		guard.unlock();

		lookup->second->check_and_run(info);
	}
}
