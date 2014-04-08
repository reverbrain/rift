#ifndef __IOREMAP_RIFT_ASIO_HPP
#define __IOREMAP_RIFT_ASIO_HPP

#include <thevoid/stream.hpp>
#include <elliptics/utils.hpp>

namespace ioremap { namespace thevoid {
template <>
struct buffer_traits<elliptics::data_pointer>
{
	static boost::asio::const_buffer convert(const elliptics::data_pointer &data)
	{
		return boost::asio::const_buffer(data.data(), data.size());
	}
};
}} // namespace ioremap::thevoid

#endif /* __IOREMAP_RIFT_ASIO_HPP */
