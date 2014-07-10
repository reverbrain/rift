#ifndef S3_S3_SERVER_H
#define S3_S3_SERVER_H

#include "base_server.h"

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

	class on_get : public rift::bucket_mixin<rift::io::on_get_base<s3_server, on_get>, rift::bucket_acl::handler_read>
	{
	};
};

} // namespace s3

#endif // S3_S3_SERVER_H
