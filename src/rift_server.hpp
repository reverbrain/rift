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

	bool check_query(const thevoid::http_request &request) const;

	template <typename Stream>
	std::string extract_key(Stream &, const thevoid::http_request &request) const;
	template <typename Stream>
	std::string extract_bucket(Stream &, const thevoid::http_request &request) const;

	/*!
	 * \brief on_upload class provides HTTP API for requesting data from Elliptics storage
	 *
	 * It inherits bucket_mixin to have authorization support.
	 *
	 * It inherits indexed_upload_mixin to be able to add file to secondary indexes after succesfull write.
	 *
	 * Temporarily we do not update indexes.
	 * Current implementation is slow and doesn't scale.
	 *
	 * Previously it used @indexed_upload_mixin wrapper to rewrite virtual on_write_finished() to force
	 * it sending indexes update
	 */
	class on_upload : public rift::bucket_mixin<rift::io::on_upload_base<example_server, on_upload>, rift::bucket_acl::handler_write>
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
		// Indexes in current elliptics implementation are slow and do not scale
		// Drop it for now, they do harm
		//
		// meta_ctl::on_delete is used for bucket/bucket directory removal operations
		// Rift server used this on_delete handler with virual on_delete_finished() method, which was translate
		// to method below which deleted indexes.
		virtual void on_delete_finished1(const elliptics::sync_remove_result &result,
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
