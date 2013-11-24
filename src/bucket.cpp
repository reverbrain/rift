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

bucket_meta::bucket_meta(const std::string &key, bucket *b) : m_bucket(b)
{
	m_raw.key = key;
}

void bucket_meta::check_and_run(const swarm::http_request &request, const continue_handler_t &handler)
{

	m_request = request;
	m_continue = handler;

	std::unique_lock<std::mutex> guard(m_lock);
	bool verdict = this->verdict();
	guard.unlock();

	if (!verdict) {
		update();
	} else {
		handler(m_request, true);
	}
}

void bucket_meta::update()
{
	elliptics::session session = m_bucket->create_session();

	session.read_data(m_raw.key, 0, 0).connect(std::bind(
		&bucket_meta::update_finished, this, std::placeholders::_1, std::placeholders::_2));
}

bool bucket_meta::verdict()
{
	bool verdict = false;

	auto auth = m_request.headers().get("Authorization");
	if (!auth)
		return verdict;

	auto key = http_auth::generate_signature(m_request, m_raw.token);
	if (key == *auth)
		verdict = true;

	return verdict;
}

void bucket_meta::update_finished(const ioremap::elliptics::sync_read_result &result,
				const ioremap::elliptics::error_info &error)
{
	bool verdict = false;

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

			verdict = this->verdict();

		} catch (const std::exception &e) {
			m_bucket->logger().log(swarm::SWARM_LOG_ERROR, "bucket-update-failed: read exception: "
					"bucket: %s, exception: %s",
					m_raw.key.c_str(), e.what());
		}
	}

	m_continue(m_request, verdict);
}

bucket::bucket() : m_noauth_allowed(false)
{
}

bool bucket::initialize(const rapidjson::Value &config, const ioremap::elliptics::node &node,
			const swarm::logger &logger, async_performer *async, const std::vector<int> &groups)
{
	if (!metadata_updater::initialize(config, node, logger, async, groups)) {
		return false;
	}

	if (config.HasMember("noauth")) {
		m_noauth_allowed = std::string(config["noauth"].GetString()) == "allowed";
	}

	return true;
}

void bucket::check(const swarm::http_request &request, const continue_handler_t &continue_handler)
{
	auto ns = request.url().query().item_value("namespace");

	if (!ns) {
		continue_handler(request, m_noauth_allowed);
		return;
	}

	std::lock_guard<std::mutex> guard(m_lock);

	auto lookup = m_meta.find(*ns);
	if (lookup == m_meta.end()) {
		auto meta = std::make_shared<bucket_meta>(*ns, this);
		m_meta[*ns] = meta;
		meta->check_and_run(request, continue_handler);

		add_action(std::bind(&bucket_meta::update, meta));
	} else {
		lookup->second->check_and_run(request, continue_handler);
	}
}
