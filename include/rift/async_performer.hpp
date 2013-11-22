#ifndef __IOREMAP_RIFT_ASYNC_HPP
#define __IOREMAP_RIFT_ASYNC_HPP

// must be the first, since thevoid internally uses X->boost::buffer conversion,
// which must be present at compile time
#include "asio.hpp"

#include <boost/thread.hpp>
#include <swarm/logger.hpp>
#include <functional>
#include <memory>
#include <mutex>
#include <set>

namespace ioremap {
namespace rift {

class async_performer
{
public:
	async_performer();
	~async_performer();

	void initialize(const swarm::logger &logger);

	/*!
	 * Invoke \a handler every \a timeout seconds. First call will be done
	 * right now from another thread.
	 */
	void add_action(const std::function<void ()> &handler, int timeout);

protected:
	void action_thread();

	struct info
	{
		typedef std::shared_ptr<info> ptr;

		std::function<void ()> handler;
		int timeout;
		time_t time;
	};

	struct info_less_then
	{
		bool operator ()(const info::ptr &first, const info::ptr &second) const
		{
			return first->time < second->time
				|| (first->time == second->time && first < second);
		}
	};

	swarm::logger m_logger;
	boost::thread m_thread;
	std::mutex m_lock;
	bool m_need_exit;
	std::set<info::ptr, info_less_then> m_set;
};

}} // ioremap::rift

#endif /* __IOREMAP_RIFT_ASYNC_HPP */
