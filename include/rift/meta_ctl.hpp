#ifndef __IOREMAP_RIFT_BUCKET_CTL_HPP
#define __IOREMAP_RIFT_BUCKET_CTL_HPP

#include "rift/bucket.hpp"
#include "rift/io.hpp"
#include "rift/url.hpp"

namespace ioremap { namespace rift { namespace bucket_ctl {

enum meta_create_type {
	update_bucket,
	update_bucket_directory
};

template <typename Server, typename Stream, meta_create_type Type>
class meta_create_base :
	public rift::bucket_mixin<thevoid::simple_request_stream<Server>, rift::bucket_acl::handler_bucket | rift::bucket_acl::handler_not_found_is_ok>,
	public std::enable_shared_from_this<Stream>
{
public:
	meta_create_base() : m_meta(this->bucket_mixin_meta)
	{
	}

	virtual void on_request(const swarm::http_request &req, const boost::asio::const_buffer &buffer) {
		const auto &pc = req.url().path_components();
		if (pc.size() < 2) {
			this->log(swarm::SWARM_LOG_ERROR, "bucket-meta-create: url: %s: path format: /update-bucket/bucket-directory-name/bucket-name or "
					"/update-bucket-directory/bucket-directory-name",
					req.url().path().c_str());
			this->send_reply(swarm::http_response::bad_request);
			return;
		}

		if (Type == update_bucket_directory) {
			if (pc.size() != 2) {
				this->log(swarm::SWARM_LOG_ERROR, "bucket-meta-create: url: %s: path format: /update-bucket-directory/bucket-directory-name",
						req.url().path().c_str());
				this->send_reply(swarm::http_response::bad_request);
				return;
			}
			m_parent = "bucket-directories.1";
			m_ctl_meta.key = pc[1];
		} else if (Type == update_bucket) {
			if (pc.size() != 3) {
				this->log(swarm::SWARM_LOG_ERROR, "bucket-meta-create: url: %s: path format: /update-bucket/bucket-directory-name/bucket-name",
						req.url().path().c_str());
				this->send_reply(swarm::http_response::bad_request);
				return;
			}
			m_parent = pc[1];
			m_ctl_meta.key = pc[2];
		}

		try {
			m_ctl_meta_namespace = "bucket";

			parse_request(req, buffer, m_ctl_meta);
			m_request = req;

			write_metadata();
		} catch (const elliptics::error &e) {
			this->log(swarm::SWARM_LOG_ERROR, "%s: code: %d", e.what(), e.error_code());
			this->send_reply(e.error_code());
		}
	}

	void set_key(const elliptics::key &key) {
		m_key = key;
	}

	void set_meta(const bucket_meta_raw &meta) {
		m_meta = meta;
	}

	void set_session(const elliptics::session &session) {
		m_session.reset(new elliptics::session(session));
	}

	virtual void on_write_finished(const elliptics::sync_write_result &result,
			const elliptics::error_info &error) = 0;

protected:
	std::string m_ctl_meta_namespace;
	bucket_meta_raw m_ctl_meta;
	elliptics::key m_key;
	bucket_meta_raw &m_meta;
	std::unique_ptr<elliptics::session> m_session;
	// this index will be updated when new bucket or bucket directory has been created
	std::string m_parent;
	swarm::http_request m_request;

	void write_metadata(void) {
		bucket_meta_raw meta;

		elliptics::session session = this->server()->elliptics()->write_metadata_session(m_request, meta);
		session.set_namespace(m_ctl_meta_namespace.c_str(), m_ctl_meta_namespace.size());

		msgpack::sbuffer buf;
		msgpack::pack(buf, m_ctl_meta);

		bucket_meta_raw tmp;
		tmp.key = m_parent;
		tmp.groups = session.get_groups();

		this->log(swarm::SWARM_LOG_NOTICE, "%s: write meta key '%s', namespace: '%s', parent: '%s'",
				m_request.url().to_human_readable().c_str(), m_ctl_meta.key.c_str(), m_ctl_meta_namespace.c_str(), m_parent.c_str());

		meta_create_base::set_meta(tmp);
		meta_create_base::set_key(m_ctl_meta.key);
		meta_create_base::set_session(session);

		session.write_data(m_ctl_meta.key, elliptics::data_pointer::copy(buf.data(), buf.size()), 0).connect(
			std::bind(&meta_create_base::on_write_finished, this->shared_from_this(),
				std::placeholders::_1, std::placeholders::_2));
	}

	void parse_request(const swarm::http_request &request, const boost::asio::const_buffer &buffer, bucket_meta_raw &meta) {
		std::string buf(boost::asio::buffer_cast<const char*>(buffer), boost::asio::buffer_size(buffer));
		rapidjson::Document doc;
		doc.Parse<0>(buf.c_str());

		if (doc.HasParseError()) {
			elliptics::throw_error(swarm::http_response::bad_request, "bucket-meta-create: url: %s: request parsing error offset: %zd, message: %s",
					request.url().to_human_readable().c_str(), doc.GetErrorOffset(), doc.GetParseError());
		}

		const char *mandatory_members[] = {"groups", NULL};
		for (auto ptr = mandatory_members; *ptr != NULL; ++ptr) {
			if (!doc.HasMember(*ptr)) {
				elliptics::throw_error(swarm::http_response::bad_request, "bucket-meta-create: url: %s: request doesn't have '%s' member",
						request.url().to_human_readable().c_str(), *ptr);
			}
		}

		auto & groups = doc["groups"];
		if (!groups.IsArray()) {
			elliptics::throw_error(swarm::http_response::bad_request, "bucket-meta-create: url: %s: 'groups' member is not array",
					request.url().to_human_readable().c_str());
		}
		for (auto it = groups.Begin(); it != groups.End(); ++it) {
			meta.groups.push_back(it->GetInt());
		}

		const char *optional_members[] = {"acl", "flags", "max-size", "max-key-num", NULL};
		for (auto ptr = optional_members; *ptr != NULL; ++ptr) {
			if (!doc.HasMember(*ptr)) {
				this->log(swarm::SWARM_LOG_NOTICE, "bucket-meta-create: url: %s: (warning) request doesn't have '%s' member",
						request.url().to_human_readable().c_str(), *ptr);
			}
		}

		if (doc.HasMember("acl")) {
			auto & acl_array = doc["acl"];
			if (!acl_array.IsArray()) {
				elliptics::throw_error(swarm::http_response::bad_request, "bucket-meta-create: url: %s: 'acl' member is not array",
						request.url().to_human_readable().c_str());
			}

			const char *acl_members[] = {"user", "token", "flags", NULL};

			for (auto it = acl_array.Begin(); it != acl_array.End(); ++it) {
				if (!it->IsObject()) {
					elliptics::throw_error(swarm::http_response::bad_request,
							"bucket-meta-create: url: %s: %zd'th ACL member array isnt't valid object, but has type %d",
							request.url().to_human_readable().c_str(), it - acl_array.Begin(), it->GetType());
				}

				auto & acl_obj = *it;
				for (auto ptr = acl_members; *ptr != NULL; ++ptr) {
					if (!acl_obj.HasMember(*ptr)) {
						elliptics::throw_error(swarm::http_response::bad_request,
								"bucket-meta-create: url: %s: %zd'th ACL member doesn't contain '%s' member",
								request.url().to_human_readable().c_str(), it - acl_array.Begin(), *ptr);
					}
				}

				bucket_acl acl;
				acl.user = acl_obj["user"].GetString();
				acl.token = acl_obj["token"].GetString();
				acl.flags = acl_obj["flags"].GetInt64();

				meta.acl[acl.user] = acl;

				this->log(swarm::SWARM_LOG_DEBUG, "bucket-meta-create: url: %s: found acl '%s:%s:%llx'",
						request.url().to_human_readable().c_str(), acl.user.c_str(), acl.token.c_str(), (unsigned long long)acl.flags);
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

template <typename Server, meta_create_type Type>
class meta_create : public rift::indexed_upload_mixin<meta_create_base<Server, meta_create<Server, Type>, Type>>
{
public:
};

// remove bucket and all objects within
template <typename Server, typename Stream>
class on_delete_base : public bucket_mixin<thevoid::simple_request_stream<Server>, rift::bucket_acl::handler_bucket>, public std::enable_shared_from_this<Stream>
{
public:
	virtual void on_request(const swarm::http_request &req, const boost::asio::const_buffer &buffer) {
		(void) buffer;

		elliptics::session session = this->server()->elliptics()->write_metadata_session(req, this->bucket_mixin_meta);

		this->log(swarm::SWARM_LOG_NOTICE, "delete-base: checked: url: %s, removing: %s: using data session",
				req.url().to_human_readable().c_str(), this->bucket_mixin_meta.key.c_str());
		session.remove_index(this->bucket_mixin_meta.key + ".index", true).connect(std::bind(&on_delete_base::on_delete_finished, this->shared_from_this(),
					std::placeholders::_1, std::placeholders::_2));

		std::string bucket_namespace = "bucket";

		elliptics::session metadata_session = this->server()->elliptics()->write_metadata_session(req, this->bucket_mixin_meta);
		metadata_session.set_namespace(bucket_namespace.c_str(), bucket_namespace.size());

		this->log(swarm::SWARM_LOG_NOTICE, "delete-base: checked: url: %s, removing: %s: using metadata session in '%s' namespace",
				req.url().path().c_str(), this->bucket_mixin_meta.key.c_str(), bucket_namespace.c_str());
		metadata_session.clone().remove(this->bucket_mixin_meta.key);

		std::vector<elliptics::index_entry> parent_indexes;

		this->log(swarm::SWARM_LOG_NOTICE, "delete-base: checked: url: %s, removing: %s: clearing its indexes in '%s' namespace",
				req.url().path().c_str(), this->bucket_mixin_meta.key.c_str(), bucket_namespace.c_str());

		metadata_session.clone().set_indexes(this->bucket_mixin_meta.key, parent_indexes).connect([this] (elliptics::sync_set_indexes_result result, elliptics::error_info error) {
			this->log(swarm::SWARM_LOG_ERROR, "FINISHED set_indexes, result.size: %zu, error: '%s'", result.size(), error.message().c_str());
			for (auto it = result.begin(); it != result.end(); ++it) {
				this->log(swarm::SWARM_LOG_ERROR, "FINISHED command: %s, error: '%s'", dnet_cmd_string(it->command()->cmd), it->error().message().c_str());
			}
		});
	}

	virtual void on_delete_finished(const elliptics::sync_generic_result &result, const elliptics::error_info &error) {
		(void) result;

		if (error.code() == -ENOENT) {
			this->send_reply(swarm::http_response::ok);
		} else if (error) {
			this->send_reply(swarm::http_response::bad_request);
		}
		this->send_reply(swarm::http_response::ok);
	}
};

template <typename Server>
class on_delete : public on_delete_base<Server, on_delete<Server>>
{
public:
};

template <typename Server, typename Stream>
class meta_read_base : public bucket_mixin<thevoid::simple_request_stream<Server>, rift::bucket_acl::handler_bucket>, public std::enable_shared_from_this<Stream>
{
public:
	virtual void on_request(const swarm::http_request &req, const boost::asio::const_buffer &buffer) {
		(void) buffer;

		const bucket_meta_raw &meta = this->bucket_mixin_meta;

		std::string ns = "bucket";
		elliptics::session session = this->server()->elliptics()->read_metadata_session(req, this->bucket_mixin_meta);
		session.set_namespace(ns.c_str(), ns.size());

		rift::JsonValue result_object;

		auto & allocator = result_object.GetAllocator();

		this->log(swarm::SWARM_LOG_NOTICE, "meta-read-base: checked: url: %s, meta: '%s'",
				req.url().to_human_readable().c_str(), meta.key.c_str());


		rapidjson::Value jkey(meta.key.c_str(), meta.key.size(), allocator);
		result_object.AddMember("key", jkey, allocator);


		rapidjson::Value jacls;
		jacls.SetArray();

		for (auto acl = meta.acl.begin(); acl != meta.acl.end(); ++acl) {
			rapidjson::Value jacl;
			jacl.SetObject();

			rapidjson::Value user(acl->second.user.c_str(), acl->second.user.size(), allocator);
			rapidjson::Value token(acl->second.token.c_str(), acl->second.token.size(), allocator);

			jacl.AddMember("user", user, allocator);
			jacl.AddMember("token", token, allocator);
			jacl.AddMember("flags", acl->second.flags, allocator);

			jacls.PushBack(jacl, allocator);
		}
		result_object.AddMember("acl", jacls, allocator);


		rapidjson::Value jgroups;
		jgroups.SetArray();

		for (auto group = meta.groups.begin(); group != meta.groups.end(); ++group) {
			jgroups.PushBack(*group, allocator);
		}
		result_object.AddMember("groups", jgroups, allocator);


		result_object.AddMember("flags", meta.flags, allocator);
		result_object.AddMember("max_size", meta.max_size, allocator);
		result_object.AddMember("max_key_num", meta.max_key_num, allocator);


		auto data = result_object.ToString();

		swarm::http_response reply;

		reply.set_code(swarm::http_response::ok);
		reply.headers().set_content_type("text/json; charset=utf-8");
		reply.headers().set_content_length(data.size());

		this->send_reply(std::move(reply), std::move(data));
	}
};

template <typename Server>
class meta_read : public meta_read_base<Server, meta_read<Server>>
{
public:
};

}}} // namespace ioremap::rift::bucket_ctl

#endif /* __IOREMAP_RIFT_BUCKET_CTL_HPP */
