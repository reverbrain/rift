#ifndef __IOREMAP_RIFT_BUCKET_CTL_HPP
#define __IOREMAP_RIFT_BUCKET_CTL_HPP

#include "rift/bucket.hpp"
#include "rift/io.hpp"

namespace ioremap { namespace rift { namespace bucket_ctl {

template <typename Server>
class meta_create : public io::on_upload<Server>
{
public:
	std::shared_ptr<meta_create> shared_from_this() {
		return std::static_pointer_cast<meta_create>(io::on_upload<Server>::shared_from_this());
	}

	virtual void on_request(const swarm::http_request &req, const boost::asio::const_buffer &buffer) {
		const auto &pc = req.url().path_components();
		if (pc.size() != 2) {
			const auto &query = req.url().query();
			this->log(swarm::SWARM_LOG_ERROR, "bucket-meta-create: url: %s: path format: /meta-create/name, you have no name",
					query.to_string().c_str());
			this->send_reply(swarm::http_response::bad_request);
			return;

			elliptics::throw_error(swarm::http_response::bad_request, "bucket-meta-create: url: %s: path format: /meta-create/name, you have no name",
					query.to_string().c_str());
		}

		try {
			parse_request(req, buffer, m_meta);
			m_request = req;

			check_bucket_directory();
		} catch (const elliptics::error &e) {
			this->log(swarm::SWARM_LOG_ERROR, "%s: code: %d", e.what(), e.error_code());
			this->send_reply(e.error_code());
		}
	}
private:
	bucket_meta_raw m_meta;
	std::string m_parent;
	swarm::http_request m_request;

	std::string meta_key_from_session(const elliptics::key &key) {
		const auto &pc = m_request.url().path_components();
		if (pc[0] == "update-bucket-directory") {
			// URL format: /bucket-directory/unused
			return "bucket-directories.1";
		} else {
			// URL format: /bucket/bucket-directory-name-with-slashes/like/this
			return key.remote();
		}
	}

	void check_bucket_directory() {
		elliptics::key key;
		elliptics::session session = this->server()->elliptics()->read_metadata_session(m_request, m_meta, key);

		m_parent = meta_key_from_session(key);

		this->log(swarm::SWARM_LOG_NOTICE, "%s: reading meta key '%s', parent: '%s'",
				m_request.url().to_string().c_str(), m_meta.key.c_str(), m_parent.c_str());

		session.read_data(m_meta.key, 0, 0).connect(
				std::bind(&meta_create::check_completion, this->shared_from_this(),
					std::placeholders::_1, std::placeholders::_2));
	}

	void check_completion(const elliptics::sync_read_result &result, const elliptics::error_info &error) {
		this->log(swarm::SWARM_LOG_NOTICE, "%s: read meta key '%s', parent: '%s', error-code: %d",
				m_request.url().to_string().c_str(), m_meta.key.c_str(), m_parent.c_str(), error.code());
		if (error.code() == -ENOENT) {
			// there is no metadata object with given name, just create a new one
			write_metadata();
			return;
		}

		if (error) {
			this->log(swarm::SWARM_LOG_ERROR, "bucket-meta-create: url: %s: metadata read error: %s",
					m_request.url().to_string().c_str(), error.message().c_str());
			this->send_reply(swarm::http_response::bad_request);
			return;

			elliptics::throw_error(swarm::http_response::bad_request, "bucket-meta-create: url: %s: metadata read error: %s",
					m_request.url().to_string().c_str(), error.message().c_str());
		}

		// we read some metadata from the storage, let's check if provided security credentials allow us to update it
		const elliptics::read_result_entry &entry = result[0];
		const auto &file = entry.file();

		msgpack::unpacked msg;
		msgpack::unpack(&msg, file.data<char>(), file.size());

		bucket_meta_raw read_meta;
		msg.get().convert(&read_meta);

		bucket_acl acl;
		auto v = bucket_meta::verdict(this->logger(), read_meta, m_request, acl);

		this->log(swarm::SWARM_LOG_NOTICE, "%s: read meta key '%s', parent: '%s', security verdict: %d",
				m_request.url().to_string().c_str(), m_meta.key.c_str(), m_parent.c_str(), v);

		if (v != swarm::http_response::ok) {
			this->log(swarm::SWARM_LOG_ERROR, "bucket-meta-create: url: %s, parent: '%s', verdict: %d: read metadata doesn't allow update",
					m_request.url().to_string().c_str(), m_parent.c_str(), v);
			this->send_reply(v);
			return;

			elliptics::throw_error(v, "bucket-meta-create: url: %s, parent: '%s', verdict: %d: read metadata doesn't allow update",
					m_request.url().to_string().c_str(), m_parent.c_str(), v);
		}

		write_metadata();
	}

	void write_metadata(void) {
		elliptics::key unused;
		elliptics::session session = this->server()->elliptics()->write_metadata_session(m_request, m_meta, unused);

		msgpack::sbuffer buf;
		msgpack::pack(buf, m_meta);

		bucket_meta_raw tmp;
		tmp.key = m_parent;

		this->log(swarm::SWARM_LOG_NOTICE, "%s: write meta key '%s', parent: '%s'",
				m_request.url().to_string().c_str(), m_meta.key.c_str(), m_parent.c_str());

		meta_create::set_meta(tmp);
		meta_create::set_key(m_meta.key);
		meta_create::set_session(session);

		session.write_data(m_meta.key, elliptics::data_pointer::copy(buf.data(), buf.size()), 0).connect(
			std::bind(&meta_create::on_write_finished, this->shared_from_this(),
				std::placeholders::_1, std::placeholders::_2));
	}

	void parse_request(const swarm::http_request &request, const boost::asio::const_buffer &buffer, bucket_meta_raw &meta) {
		const auto &query = request.url().query();

		rapidjson::Document doc;
		doc.Parse<0>(boost::asio::buffer_cast<const char*>(buffer));

		if (doc.HasParseError()) {
			elliptics::throw_error(swarm::http_response::bad_request, "bucket-meta-create: url: %s: request parsing error offset: %zd, message: %s",
					query.to_string().c_str(), doc.GetErrorOffset(), doc.GetParseError());
		}

		const char *mandatory_members[] = {"key", "groups", NULL};
		for (auto ptr = mandatory_members; *ptr != NULL; ++ptr) {
			if (!doc.HasMember(*ptr)) {
				elliptics::throw_error(swarm::http_response::bad_request, "bucket-meta-create: url: %s: request doesn't have '%s' member",
						query.to_string().c_str(), *ptr);
			}
		}

		meta.key = doc["key"].GetString();

		auto & groups = doc["groups"];
		if (!groups.IsArray()) {
			elliptics::throw_error(swarm::http_response::bad_request, "bucket-meta-create: url: %s: 'groups' member is not array",
					query.to_string().c_str());
		}
		for (auto it = groups.Begin(); it != groups.End(); ++it) {
			meta.groups.push_back(it->GetInt());
		}

		const char *optional_members[] = {"acl", "flags", "max-size", "max-key-num", NULL};
		for (auto ptr = optional_members; *ptr != NULL; ++ptr) {
			if (!doc.HasMember(*ptr)) {
				this->log(swarm::SWARM_LOG_NOTICE, "bucket-meta-create: url: %s: (warning) request doesn't have '%s' member",
						query.to_string().c_str(), *ptr);
			}
		}

		if (doc.HasMember("acl")) {
			auto & acl_array = doc["acl"];
			if (!acl_array.IsArray()) {
				elliptics::throw_error(swarm::http_response::bad_request, "bucket-meta-create: url: %s: 'acl' member is not array",
						query.to_string().c_str());
			}

			const char *acl_members[] = {"user", "token", "flags", NULL};

			for (auto it = acl_array.Begin(); it != acl_array.End(); ++it) {
				if (!it->IsObject()) {
					elliptics::throw_error(swarm::http_response::bad_request,
							"bucket-meta-create: url: %s: %zd'th ACL member array isnt't valid object, but has type %d",
							query.to_string().c_str(), it - acl_array.Begin(), it->GetType());
				}

				auto & acl_obj = *it;
				for (auto ptr = acl_members; *ptr != NULL; ++ptr) {
					if (!acl_obj.HasMember(*ptr)) {
						elliptics::throw_error(swarm::http_response::bad_request,
								"bucket-meta-create: url: %s: %zd'th ACL member doesn't contain '%s' member",
								query.to_string().c_str(), it - acl_array.Begin(), *ptr);
					}
				}

				bucket_acl acl;
				acl.user = acl_obj["user"].GetString();
				acl.token = acl_obj["token"].GetString();
				acl.flags = acl_obj["flags"].GetInt64();

				meta.acl[acl.user] = acl;

				this->log(swarm::SWARM_LOG_DEBUG, "bucket-meta-create: url: %s: found acl '%s:%s:%llx'",
						query.to_string().c_str(), acl.user.c_str(), acl.token.c_str(), (unsigned long long)acl.flags);
			}
		}

		if (doc.HasMember("flags"))
			meta.flags = doc["flags"].GetInt64();
		if (doc.HasMember("max-size"))
			meta.max_size = doc["max-size"].GetInt64();
		if (doc.HasMember("max-key-num"))
			meta.max_key_num = doc["max-key-num"].GetInt64();
	}
};

template <typename Server>
class meta_create1: public io::on_upload<Server>
{
public:
};

}}} // namespace ioremap::rift::bucket_ctl

#endif /* __IOREMAP_RIFT_BUCKET_CTL_HPP */
