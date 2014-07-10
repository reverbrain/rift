#ifndef S3_S3_SERVER_H
#define S3_S3_SERVER_H

#include "base_server.h"
#include <rift/crypto.hpp>

namespace s3 {

using namespace ioremap;

class s3_server : public rift_server::base_server<s3_server>
{
public:
	s3_server();
	~s3_server();

	virtual bool initialize(const rapidjson::Value &config);

	bool check_query(const swarm::http_request &request) const;

	std::string extract_key(const swarm::http_request &request) const;
	std::string extract_bucket(const swarm::http_request &request) const;

	class on_upload : public rift::indexed_upload_mixin<rift::bucket_mixin<rift::io::on_upload_base<s3_server, on_upload>, rift::bucket_acl::handler_write>>
	{
	public:
		void on_chunk(const boost::asio::const_buffer &buffer, unsigned int flags) {
			m_md5.Update(boost::asio::buffer_cast<const byte *>(buffer), boost::asio::buffer_size(buffer));

			rift::indexed_upload_mixin<rift::bucket_mixin<rift::io::on_upload_base<s3_server, on_upload>, rift::bucket_acl::handler_write>>::on_chunk(buffer, flags);
		}

		void on_write_finished(const elliptics::sync_write_result &,
				const elliptics::error_info &error) {
			if (error) {
				this->send_reply(swarm::http_response::service_unavailable);
				return;
			}

			byte digest[CryptoPP::MD5::DIGESTSIZE];
			m_md5.Final(digest);

			std::string etag = "\"";
			etag += rift::crypto::to_hex(digest);
			etag += "\"";

			swarm::http_response reply;
			reply.set_code(swarm::http_response::ok);
			reply.headers().set_content_length(0);
			reply.headers().add("ETag", etag);

			this->send_reply(std::move(reply));
		}

	private:
		CryptoPP::MD5 m_md5;
	};

	class on_get : public rift::bucket_mixin<rift::io::on_get_base<s3_server, on_get>, rift::bucket_acl::handler_read>
	{
	};
};

} // namespace s3

#endif // S3_S3_SERVER_H
