#include "rift/async_performer.hpp"
#include <elliptics/interface.h>

namespace ioremap { namespace rift {

async_performer::async_performer(const swarm::logger &logger) :
	m_logger(logger, blackhole::log::attributes_t({ swarm::keyword::source() = "async_performer" })),
	m_need_exit(false)
{
	m_thread = boost::thread(std::bind(&async_performer::action_thread, this));
}

async_performer::~async_performer()
{
	std::lock_guard<std::mutex> guard(m_lock);
	m_set.clear();
}

void async_performer::stop()
{
	m_need_exit = true;
	m_thread.join();
}

void async_performer::add_action(const std::function<void ()> &handler, int timeout)
{
	BH_LOG(m_logger, SWARM_LOG_DEBUG, "add_action: timeout: %d secs", timeout);

	auto action = std::make_shared<info>();
	action->handler = handler;
	action->timeout = timeout;
	action->time = std::time(NULL);

	std::lock_guard<std::mutex> guard(m_lock);
	m_set.insert(action);
}

void async_performer::action_thread()
{
	while (!m_need_exit) {
		while (!m_need_exit && !m_set.empty()) {
			time_t time = ::time(NULL);

			std::unique_lock<std::mutex> guard(m_lock);
			if (m_set.empty())
				break;

			auto it = m_set.begin();
			auto info = *it;
			if (info->time > time)
				break;

			m_set.erase(it);

			guard.unlock();

			BH_LOG(m_logger, SWARM_LOG_DEBUG, "action: %p, time: %llu sec", info.get(), time);

			info->handler();
			info->time = time + info->timeout;
			guard.lock();

			m_set.insert(info);
		}

		sleep(1);
	}
}

}} // ioremap::rift
