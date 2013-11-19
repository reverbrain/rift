#ifndef __IOREMAP_RIFT_COMMON_HPP
#define __IOREMAP_RIFT_COMMON_HPP

#include <thevoid/server.hpp>

namespace ioremap { namespace rift { namespace common {

template <typename T>
struct on_ping : public thevoid::simple_request_stream<T>, public std::enable_shared_from_this<on_ping<T>> {
	virtual void on_request(const swarm::http_request &req, const boost::asio::const_buffer &buffer) {
		(void) buffer;
		(void) req;

		this->send_reply(swarm::http_response::ok);
	}
};

template <typename T>
struct on_echo : public thevoid::simple_request_stream<T>, public std::enable_shared_from_this<on_echo<T>> {
	virtual void on_request(const swarm::http_request &req, const boost::asio::const_buffer &buffer) {
		auto data = boost::asio::buffer_cast<const char*>(buffer);
		auto size = boost::asio::buffer_size(buffer);

		swarm::http_response reply;
		reply.set_code(swarm::http_response::ok);
		reply.set_headers(req.headers());
		reply.headers().set_content_length(size);

		this->send_reply(std::move(reply), std::string(data, size));
	}
};

}}} /* namespace ioremap::rift::common */

#endif /*__IOREMAP_RIFT_COMMON_HPP */
