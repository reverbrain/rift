#include "rift/bucket.hpp"

#include <msgpack.hpp>

using namespace ioremap;
using namespace ioremap::rift;

namespace msgpack
{

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const bucket_meta_raw &m)
{
	o.pack_array(5);
	o.pack(bucket_meta_raw::serialization_version);
	o.pack(m.key);
	o.pack(m.token);
	o.pack(m.groups);
	o.pack(m.flags);

	return o;
}

inline bucket_meta_raw &operator >>(msgpack::object o, bucket_meta_raw &m)
{
	if (o.type != msgpack::type::ARRAY || o.via.array.size < 5) {
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
		if (size != 5) {
			std::ostringstream ss;
			ss << "bucket unpack: array size mismatch: read: " << size << ", must be: 5";
			throw std::runtime_error(ss.str());
		}

		p[1].convert(&m.key);
		p[2].convert(&m.token);
		p[3].convert(&m.groups);
		p[4].convert(&m.flags);
		break;
	}
	default: {
		std::ostringstream ss;
		ss << "bucket unpack: version mismatch: read: " << version <<
			", must be: <= " << bucket_meta_raw::serialization_version;
		throw std::runtime_error(ss.str());
	}
	}

	return m;
}

} // namespace msgpack

bucket_meta::bucket_meta(const std::string &key, bucket *b, const swarm::http_request &request, const boost::asio::const_buffer &buffer,
				const continue_handler_t &continue_handler) : m_bucket(b)
{
	m_raw.key = key;
	m_bucket->add_action(std::bind(&bucket_meta::update_and_check, this, request, buffer, continue_handler));
}

void bucket_meta::check_and_run_raw(const swarm::http_request &request, const boost::asio::const_buffer &buffer,
		const continue_handler_t &continue_handler, bool uptodate)
{
	std::unique_lock<std::mutex> guard(m_lock);
	auto v = verdict(request);
	guard.unlock();

	m_bucket->logger().log(swarm::SWARM_LOG_INFO, "bucket: check-and-run-raw: bucket: %s, uptodate: %d, req: %s, verdict: %d",
			m_raw.key.c_str(), uptodate, request.url().query().to_string().c_str(), v);

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

	sess.read_data(m_raw.key, 0, 0).connect(std::bind(&bucket_meta::update_finished, this, std::placeholders::_1, std::placeholders::_2));
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
