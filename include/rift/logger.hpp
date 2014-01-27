#ifndef __IOREMAP_RIFT_LOGGER_HPP
#define __IOREMAP_RIFT_LOGGER_HPP

#include <swarm/logger.hpp>
#include <elliptics/session.hpp>

namespace ioremap {
namespace rift {

class swarm_logger_interface : public elliptics::logger_interface
{
public:
	swarm_logger_interface(const swarm::logger &logger) : m_logger(logger)
	{
	}
	~swarm_logger_interface()
	{
	}

	virtual void log(const int level, const char *msg)
	{
		m_logger.log(level, "%s", msg);
	}

private:
	swarm::logger m_logger;
};

class swarm_logger : public elliptics::logger
{
public:
	swarm_logger(const swarm::logger &logger) : elliptics::logger(new swarm_logger_interface(logger), logger.level()) {}
};

}} // namespace ioremap::rift

#endif // __IOREMAP_RIFT_LOGGER_HPP
