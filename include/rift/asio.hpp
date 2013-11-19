#ifndef __IOREMAP_RIFT_ASIO_HPP
#define __IOREMAP_RIFT_ASIO_HPP

#include <boost/asio.hpp>
#include <elliptics/session.hpp>

// must be the first header, since thevoid internally uses X->boost::buffer conversion,
// which must be present at compile time

namespace boost { namespace asio {

inline const_buffer buffer(const ioremap::elliptics::data_pointer &data)
{
	return buffer(data.data(), data.size());
}

}}

#endif /* __IOREMAP_RIFT_ASIO_HPP */
