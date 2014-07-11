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

	template <typename Stream>
	std::string extract_key(Stream &stream, const swarm::http_request &request) const;
	template <typename Stream>
	std::string extract_bucket(Stream &stream, const swarm::http_request &request) const;

	enum calling_format {
		subdomain_format,
		ordinary_format
	};

	template <calling_format Format>
	class calling_format_mixin
	{
	public:
		enum {
			s3_calling_format = Format
		};
	};

	class runtime_calling_format
	{
	public:
		calling_format mixin_s3_calling_format;
	};

	template <typename Stream, calling_format Format>
	class runtime_calling_format_mixin : public Stream, public calling_format_mixin<Format>
	{
	public:
		runtime_calling_format_mixin()
		{
			Stream::mixin_s3_calling_format = Format;
		}
	};

	template <typename BaseStream, calling_format Format>
	class bucket_processor :
		public rift::bucket_processor_base<
			s3_server,
			bucket_processor<BaseStream, Format>,
			runtime_calling_format_mixin<BaseStream, Format>
		>,
		public calling_format_mixin<Format>
	{
	public:
	};

	class meta_head : public rift::bucket_ctl::meta_head_base<s3_server, meta_head>, public runtime_calling_format
	{
	public:
	};

	class on_upload : public rift::indexed_upload_mixin<rift::bucket_mixin<rift::io::on_upload_base<s3_server, on_upload>, rift::bucket_acl::handler_write>>, public runtime_calling_format
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

			byte digest[CryptoPP::Weak::MD5::DIGESTSIZE];
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
		CryptoPP::Weak::MD5 m_md5;
	};

	class on_get : public rift::bucket_mixin<rift::io::on_get_base<s3_server, on_get>, rift::bucket_acl::handler_read>, public runtime_calling_format
	{
	};

	template <typename T, typename... Args>
	void on_object(Args &&...args);
	template <typename T, typename... Args>
	void on_bucket(Args &&...args);

protected:
	std::string m_host;
};

} // namespace s3

#endif // S3_S3_SERVER_H
