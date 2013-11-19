/*
 * 2013+ Copyright (c) Ruslan Nigatullin <euroelessar@yandex.ru>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __IOREMAP_RIFT_SERVER_HPP
#define __IOREMAP_RIFT_SERVER_HPP

// must be the first, since thevoid internally uses X->boost::buffer conversion,
// which must be present at compile time
#include "asio.hpp"

#include "rift/common.hpp"
#include "rift/io.hpp"
#include "rift/index.hpp"

#include <thevoid/server.hpp>
#include <swarm/logger.hpp>
#include <elliptics/session.hpp>

namespace ioremap {
namespace rift {

class auth_interface;

class elliptics_base
{
public:
	elliptics_base();

	bool initialize(const rapidjson::Value &config, const swarm::logger &logger);
	void set_auth(auth_interface *auth);

	elliptics::node node() const;
	elliptics::session session() const;
	virtual swarm::http_response::status_type process(const swarm::http_request &request, elliptics::key &key, elliptics::session &session) const;

protected:
	virtual bool prepare_config(const rapidjson::Value &config, dnet_config &node_config);
	virtual bool prepare_node(const rapidjson::Value &config, elliptics::node &node);
	virtual bool prepare_session(const rapidjson::Value &config, elliptics::session &session);

	swarm::logger logger() const;

private:
	swarm::logger m_logger;
	auth_interface *m_auth;
	std::unique_ptr<elliptics::node> m_node;
	std::unique_ptr<elliptics::session> m_session;
};

}} // namespace ioremap::rift

#endif /*__IOREMAP_RIFT_SERVER_HPP */
