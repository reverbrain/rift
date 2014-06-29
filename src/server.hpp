#ifndef RIFT_SERVER_SERVER_HPP
#define RIFT_SERVER_SERVER_HPP

#include "rift/bucket.hpp"
#include "rift/cache.hpp"
#include "rift/common.hpp"
#include "rift/index.hpp"
#include "rift/io.hpp"
#include "rift/list.hpp"
#include "rift/meta_ctl.hpp"
#include "rift/server.hpp"
#include "rift/url.hpp"

#include <boost/algorithm/string.hpp>

namespace rift_server {

using namespace ioremap;

class example_server : public thevoid::server<example_server>
{
public:
	struct signature_info {
		std::string key;
		std::string path;
	};

	example_server();
	~example_server();

	virtual bool initialize(const rapidjson::Value &config);

	swarm::url generate_url_base(dnet_addr *addr, const std::string &path, swarm::http_response::status_type *type);

	template <typename BaseStream, uint64_t Flags>
	std::string signature_token(rift::bucket_mixin<BaseStream, Flags> &mixin) const;

	const rift::elliptics_base *elliptics() const;

	bool process(const rift::authorization_info &info) const;
	void check_cache(const elliptics::key &key, elliptics::session &sess) const;
	bool query_ok(const swarm::http_request &request) const;

	template <typename BaseStream, uint64_t Flags>
	elliptics::session create_session(rift::bucket_mixin<BaseStream, Flags> &mixin, const swarm::http_request &req, elliptics::key &key) const;

	/*!
	 * \brief on_upload class provides HTTP API for requesting data from Elliptics storage
	 *
	 * It inherits bucket_mixin to have authorization support.
	 *
	 * It inherits indexed_upload_mixin to be able to add file to secondary indexes after succesfull write.
	 */
	class on_upload : public rift::indexed_upload_mixin<rift::bucket_mixin<rift::io::on_upload_base<example_server, on_upload>, rift::bucket_acl::handler_write>>
	{
	public:
	};

	class on_get : public rift::bucket_mixin<rift::io::on_get_base<example_server, on_get>, rift::bucket_acl::handler_read>
	{
	};

	class on_download_info : public rift::bucket_mixin<rift::io::on_download_info_base<example_server, on_download_info>, rift::bucket_acl::handler_read>
	{
	};

	class on_redirectable_get : public rift::bucket_mixin<rift::io::on_redirectable_get_base<example_server, on_redirectable_get>, rift::bucket_acl::handler_read>
	{
	};

	class on_delete : public rift::bucket_mixin<rift::io::on_delete_base<example_server, on_delete>, rift::bucket_acl::handler_write>
	{
	public:
		virtual void on_delete_finished(const elliptics::sync_remove_result &result,
				const elliptics::error_info &error) {
			elliptics::key key;
			elliptics::session session = this->server()->create_session(*this, this->request(), key);

			std::vector<std::string> indexes;
			indexes.push_back(this->bucket_mixin_meta.key + ".index");

			session.remove_indexes(key, indexes);

			rift::io::on_delete_base<example_server, on_delete>::on_delete_finished(result, error);
		}
	};

	class on_update : public rift::bucket_mixin<rift::index::on_update_base<example_server, on_update>, rift::bucket_acl::handler_write>
	{
	};

	class on_find : public rift::bucket_mixin<rift::index::on_find_base<example_server, on_find>, rift::bucket_acl::handler_read>
	{
	};

private:
	int m_redirect_port;
	bool m_secured_http;
	bool m_use_hostname;
	std::string m_path_prefix;
	rift::elliptics_base m_elliptics;
	std::shared_ptr<rift::cache> m_cache;
	std::shared_ptr<rift::bucket> m_bucket;
	rift::async_performer m_async;
	std::map<std::string, rift::authorization_checker_base::ptr> m_auth;
};

} // namespace rift_server

#endif // RIFT_SERVER_SERVER_HPP
