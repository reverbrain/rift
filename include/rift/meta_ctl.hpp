#ifndef __IOREMAP_RIFT_BUCKET_CTL_HPP
#define __IOREMAP_RIFT_BUCKET_CTL_HPP

#include "rift/bucket.hpp"
#include "rift/io.hpp"

namespace ioremap { namespace rift { namespace bucket_ctl {

template <typename Server>
class meta_create : public io::on_upload<Server>
{
public:
	virtual void on_request(const swarm::http_request &req, const boost::asio::const_buffer &buffer) {
		bucket_meta_raw meta;

		try {
			parse_request(req, buffer, meta);

			elliptics::key key;
			elliptics::session session = this->server()->elliptics()->write_metadata_session(req, meta, key);

			msgpack::sbuffer buf;
			msgpack::pack(buf, meta);

			{
				bucket_meta_raw tmp;
				tmp.key = "user.XXX";
				meta_create::set_meta(tmp);
				meta_create::set_key(meta.key);
				meta_create::set_session(session);
			}

			session.write_data(meta.key, elliptics::data_pointer::copy(buf.data(), buf.size()), 0).connect(
				std::bind(&meta_create::on_write_finished, this->shared_from_this(),
					std::placeholders::_1, std::placeholders::_2));
		} catch (const elliptics::error &e) {
			this->log(swarm::SWARM_LOG_ERROR, "%s: code: %d", e.what(), e.error_code());
			this->send_reply(e.error_code());
		}
	}
private:
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
					elliptics::throw_error(swarm::http_response::bad_request, "bucket-meta-create: url: %s: %zd'th ACL member array isnt't valid object, but has type %d",
							query.to_string().c_str(), it - acl_array.Begin(), it->GetType());
				}

				auto & acl_obj = *it;
				for (auto ptr = acl_members; *ptr != NULL; ++ptr) {
					if (!acl_obj.HasMember(*ptr)) {
						elliptics::throw_error(swarm::http_response::bad_request, "bucket-meta-create: url: %s: %zd'th ACL member doesn't contain '%s' member",
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

}}} // namesapce ioremap::rift::bucket_ctl

#endif /* __IOREMAP_RIFT_BUCKET_CTL_HPP */
