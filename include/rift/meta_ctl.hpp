#ifndef __IOREMAP_RIFT_BUCKET_CTL_HPP
#define __IOREMAP_RIFT_BUCKET_CTL_HPP

#include "rift/bucket.hpp"
#include "rift/io.hpp"

namespace ioremap { namespace rift { namespace bucket_ctl {

static std::string meta_from_key(const swarm::http_request &request, const elliptics::key &key) {
	const auto &pc = request.url().path_components();
	if ((pc[0] == "update-bucket-directory") || (pc[0] == "delete-bucket-directory")) {
		// URL format: /update-bucket-directory/unused
		return "bucket-directories.1";
	} else {
		// URL format: /update-bucket/bucket-directory-name-with-slashes/like/this
		return key.remote();
	}
}

template <typename Server>
class meta_create : public thevoid::simple_request_stream<Server>, public std::enable_shared_from_this<meta_create<Server>>
{
public:
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
			parse_request(req, buffer, m_ctl_meta);
			m_request = req;

			check_bucket_directory();
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

private:
	std::string m_ctl_meta_namespace;
	bucket_meta_raw m_ctl_meta;
	elliptics::key m_key;
	bucket_meta_raw m_meta;
	std::unique_ptr<elliptics::session> m_session;
	std::string m_parent;
	swarm::http_request m_request;

	void check_bucket_directory() {
		// use empty meta - we use metadata groups and empty this hardcoded namespace
		bucket_meta_raw meta;

		m_ctl_meta_namespace = "bucket";

		elliptics::key key;
		elliptics::session session = this->server()->elliptics()->read_metadata_session(m_request, meta, key);
		session.set_namespace(m_ctl_meta_namespace.c_str(), m_ctl_meta_namespace.size());

		// this index will be updated when new bucket or bucket directory has been created
		m_parent = meta_from_key(m_request, key);

		this->log(swarm::SWARM_LOG_NOTICE, "%s: reading meta key '%s', namespace: '%s', parent: '%s'",
				m_request.url().to_string().c_str(), m_ctl_meta.key.c_str(), m_ctl_meta_namespace.c_str(), m_parent.c_str());

		session.read_data(m_ctl_meta.key, 0, 0).connect(
				std::bind(&meta_create::check_completion, this->shared_from_this(),
					std::placeholders::_1, std::placeholders::_2));
	}

	void check_completion(const elliptics::sync_read_result &result, const elliptics::error_info &error) {
		this->log(swarm::SWARM_LOG_NOTICE, "%s: read meta key '%s', namespace: '%s', parent: '%s', error-code: %d",
				m_request.url().to_string().c_str(), m_ctl_meta.key.c_str(), m_ctl_meta_namespace.c_str(), m_parent.c_str(), error.code());
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

		this->log(swarm::SWARM_LOG_NOTICE, "%s: read meta key '%s', namespace: '%s', parent: '%s', security verdict: %d",
				m_request.url().to_string().c_str(), m_ctl_meta.key.c_str(), m_ctl_meta_namespace.c_str(), m_parent.c_str(), v);

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
		bucket_meta_raw meta;

		elliptics::key unused;
		elliptics::session session = this->server()->elliptics()->write_metadata_session(m_request, meta, unused);
		session.set_namespace(m_ctl_meta_namespace.c_str(), m_ctl_meta_namespace.size());

		msgpack::sbuffer buf;
		msgpack::pack(buf, m_ctl_meta);

		bucket_meta_raw tmp;
		tmp.key = m_parent;
		tmp.groups = session.get_groups();

		this->log(swarm::SWARM_LOG_NOTICE, "%s: write meta key '%s', namespace: '%s', parent: '%s'",
				m_request.url().to_string().c_str(), m_ctl_meta.key.c_str(), m_ctl_meta_namespace.c_str(), m_parent.c_str());

		meta_create::set_meta(tmp);
		meta_create::set_key(m_ctl_meta.key);
		meta_create::set_session(session);

		session.write_data(m_ctl_meta.key, elliptics::data_pointer::copy(buf.data(), buf.size()), 0).connect(
			std::bind(&meta_create::on_write_finished, this->shared_from_this(),
				std::placeholders::_1, std::placeholders::_2));
	}

	void parse_request(const swarm::http_request &request, const boost::asio::const_buffer &buffer, bucket_meta_raw &meta) {
		const auto &query = request.url().query();

		std::string buf(boost::asio::buffer_cast<const char*>(buffer), boost::asio::buffer_size(buffer));
		rapidjson::Document doc;
		doc.Parse<0>(buf.c_str());

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

	void completion(const swarm::http_response::status_type &status, const std::string &data) {
		if (status != swarm::http_response::ok) {
			this->send_reply(status);
			return;
		}

		swarm::http_response reply;

		reply.set_code(swarm::http_response::ok);
		reply.headers().set_content_type("text/json");
		reply.headers().set_content_length(data.size());

		this->send_reply(std::move(reply), std::move(data));
	}

	virtual void on_write_finished(const elliptics::sync_write_result &result,
			const elliptics::error_info &error) {
		if (error) {
			this->send_reply(swarm::http_response::service_unavailable);
			return;
		}

		try {
			io::upload_completion::upload_update_indexes(*m_session, m_meta, m_key, result,
					std::bind(&meta_create::completion, this->shared_from_this(),
						std::placeholders::_1, std::placeholders::_2));
		} catch (std::exception &e) {
			this->log(swarm::SWARM_LOG_ERROR, "post-base: write_finished: key: %s, namespace: %s, exception: %s",
					m_key.to_string().c_str(), m_meta.key.c_str(), e.what());
			m_session->remove(m_key);
			this->send_reply(swarm::http_response::bad_request);
		}
	}
};

// remove bucket and all objects within
template <typename Server, typename Stream>
class on_delete_base : public bucket_processing<Server, Stream>
{
public:
	virtual void checked(const swarm::http_request &req, const boost::asio::const_buffer &buffer,
			const bucket_meta_raw &meta, const bucket_acl &acl, swarm::http_response::status_type verdict) {
		const auto &query = req.url().query();

		if ((verdict != swarm::http_response::ok) && !acl.noauth_all()) {
			this->log(swarm::SWARM_LOG_ERROR, "delete-base: checked: url: %s, verdict: %d, did-not-pass-noauth-check",
					query.to_string().c_str(), verdict);

			this->send_reply(verdict);
			return;
		}

		this->log(swarm::SWARM_LOG_NOTICE, "delete-base: checked: url: %s, verdict: %d, removing: %s, passed-no-auth-check",
				query.to_string().c_str(), verdict, meta.key.c_str());

		(void) buffer;

		elliptics::key key;
		elliptics::session session = this->server()->elliptics()->write_data_session(req, meta, key);

		std::string parent = meta_from_key(req, key);
		if (parent.size() == 0) {
			this->log(swarm::SWARM_LOG_ERROR, "delete-base: checked: url: %s, there is no bucket directory name, URL must be /delete-bucket/directory_name",
					query.to_string().c_str());

			this->send_reply(swarm::http_response::bad_request);
			return;
		}


		this->log(swarm::SWARM_LOG_NOTICE, "delete-base: checked: url: %s, removing: %s: using data session",
				query.to_string().c_str(), meta.key.c_str());
		session.remove_index(meta.key + ".index", true).connect(std::bind(&on_delete_base::on_delete_finished, this->shared_from_this(),
					std::placeholders::_1, std::placeholders::_2));

		std::string bucket_namespace = "bucket";

		elliptics::key unused;
		elliptics::session metadata_session = this->server()->elliptics()->write_metadata_session(req, meta, unused);
		metadata_session.set_namespace(bucket_namespace.c_str(), bucket_namespace.size());

		this->log(swarm::SWARM_LOG_NOTICE, "delete-base: checked: url: %s, removing: %s: using metadata session in '%s' namespace",
				query.to_string().c_str(), meta.key.c_str(), bucket_namespace.c_str());
		metadata_session.remove(meta.key);

		parent += ".index";
		std::vector<std::string> parent_indexes;
		parent_indexes.push_back(parent);

		this->log(swarm::SWARM_LOG_NOTICE, "delete-base: checked: url: %s, removing: %s: from index: '%s' using metadata session in '%s' namespace",
				query.to_string().c_str(), meta.key.c_str(), parent.c_str(), bucket_namespace.c_str());
		metadata_session.remove_indexes(meta.key, parent_indexes);
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

}}} // namespace ioremap::rift::bucket_ctl

#endif /* __IOREMAP_RIFT_BUCKET_CTL_HPP */
