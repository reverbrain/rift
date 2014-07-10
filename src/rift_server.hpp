#ifndef RIFT_SERVER_SERVER_HPP
#define RIFT_SERVER_SERVER_HPP

#include "base_server.h"

namespace rift_server {

using namespace ioremap;

class example_server : public base_server<example_server>
{
public:
	struct signature_info {
		std::string key;
		std::string path;
	};

	example_server();
	~example_server();

	virtual bool initialize(const rapidjson::Value &config);

	bool check_query(const swarm::http_request &request) const;

	std::string extract_key(const swarm::http_request &request) const;
	std::string extract_bucket(const swarm::http_request &request) const;

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
};

} // namespace rift_server

#endif // RIFT_SERVER_SERVER_HPP
