#ifndef __IOREMAP_RIFT_STAT_HPP
#define __IOREMAP_RIFT_STAT_HPP

#include "rift/jsonvalue.hpp"
#include "rift/server.hpp"

#include <thevoid/server.hpp>

namespace ioremap { namespace rift { namespace stat {

template <typename T>
struct on_stat : public thevoid::simple_request_stream<T> {
	virtual void on_request(const swarm::http_request &req, const boost::asio::const_buffer &buffer) {
		(void) req;
		(void) buffer;

		rift::JsonValue ret;
		const_cast<ioremap::rift::elliptics_base *>(this->server()->elliptics())->stat(ret, ret.GetAllocator());
		std::string data = ret.ToString();

		swarm::http_response reply;
		reply.set_code(swarm::http_response::ok);
		reply.headers().set_content_type("text/json; charset=utf-8");
		reply.headers().set_content_length(data.size());

		this->send_reply(std::move(reply), std::move(data));
	}
};

}}} // namespace ioremap::rift::stat

#endif /*__IOREMAP_RIFT_STAT_HPP */
