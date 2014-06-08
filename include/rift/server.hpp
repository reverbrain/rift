#ifndef __IOREMAP_RIFT_SERVER_HPP
#define __IOREMAP_RIFT_SERVER_HPP

#include "rift/bucket.hpp"
#include "rift/logger.hpp"
#include "rift/timer.hpp"

#include <thevoid/server.hpp>
#include <swarm/logger.hpp>
#include <elliptics/session.hpp>

#include <atomic>

namespace ioremap {
namespace rift {

class elliptics_base
{
public:
	elliptics_base() : m_read_timeout(0), m_write_timeout(0), m_generation(0) {}

	bool initialize(const rapidjson::Value &config, const swarm::logger &logger) {
		m_logger = logger;

		dnet_config node_config;
		memset(&node_config, 0, sizeof(node_config));

		if (!prepare_config(config, node_config)) {
			return false;
		}

		m_node.reset(new elliptics::node(swarm_logger(logger), node_config));

		if (!prepare_node(config, *m_node)) {
			return false;
		}

		m_session.reset(new elliptics::session(*m_node));

		if (!prepare_session(config, *m_session)) {
			return false;
		}

		return true;
	}

	elliptics::node node() const {
		return *m_node;
	}

	elliptics::session read_data_session(const swarm::http_request &req, const bucket_meta_raw &meta) const {
		auto session = m_session->clone();
		session.set_timeout(m_read_timeout);

		if (meta.key.size() && meta.groups.size()) {
			session.set_namespace(meta.key.c_str(), meta.key.size());
			session.set_groups(meta.groups);
		}

		try {
			const auto &query = req.url().query();
			uint32_t ioflags = query.item_value("ioflags", 0u);
			uint64_t cflags = query.item_value("cflags", 0llu);
			uint64_t trace_id = query.item_value("trace_id", 0llu);

			session.set_ioflags(ioflags);
			session.set_cflags(cflags);
			session.set_trace_id(trace_id);

		} catch (const std::exception &e) {
			m_logger.log(swarm::SWARM_LOG_ERROR, "data-session: url: %s: invalid ioflags/cflags parameters: %s",
					req.url().to_string().c_str(), e.what());
		}

		return session;
	}

	elliptics::session write_data_session(const swarm::http_request &req, const bucket_meta_raw &meta) const {
		auto session = read_data_session(req, meta);
		session.set_timeout(m_write_timeout);

		return session;
	}

	elliptics::session read_metadata_session(const swarm::http_request &req, const bucket_meta_raw &meta) const {
		auto session = read_data_session(req, meta);
		session.set_groups(m_metadata_groups);

		return session;
	}

	elliptics::session write_metadata_session(const swarm::http_request &req, const bucket_meta_raw &meta) const {
		auto session = write_data_session(req, meta);
		session.set_groups(m_metadata_groups);

		return session;
	}

	swarm::logger logger() const {
		return m_logger;
	}

	const std::vector<int> metadata_groups(void) const {
		return m_metadata_groups;
	}

	void stat_update() {
		m_generation++;

		m_session->monitor_stat(DNET_MONITOR_BACKEND).connect(
				std::bind(&elliptics_base::monitor_stat_result, this, std::placeholders::_1),
				std::bind(&elliptics_base::monitor_stat_complete, this, std::placeholders::_1));
		m_session->stat_log().connect(
				std::bind(&elliptics_base::vfs_stat_result, this, std::placeholders::_1),
				std::bind(&elliptics_base::vfs_stat_complete, this, std::placeholders::_1));
	}

protected:
	virtual bool prepare_config(const rapidjson::Value &config, dnet_config &node_config) {
		(void) config;
		(void) node_config;
		return true;
	}

	virtual bool prepare_node(const rapidjson::Value &config, elliptics::node &node) {
		if (!config.HasMember("remotes")) {
			m_logger.log(swarm::SWARM_LOG_ERROR, "\"remotes\" field is missed");
			return false;
		}

		std::vector<std::string> remotes;

		auto &remotesArray = config["remotes"];
		std::transform(remotesArray.Begin(), remotesArray.End(),
			std::back_inserter(remotes),
			std::bind(&rapidjson::Value::GetString, std::placeholders::_1));

		bool any_added = false;
		for (auto it = remotes.begin(); it != remotes.end(); ++it) {
			try {
				node.add_remote(it->c_str());
				any_added = true;
			} catch (...) {
				// do nothing - its ok not to add some nodes
			}
		}

		if (!any_added) {
			m_logger.log(swarm::SWARM_LOG_ERROR, "Didn't add any remote node, exiting.");
			return false;
		}

		return true;
	}

	virtual bool prepare_session(const rapidjson::Value &config, elliptics::session &session) {
		if (!config.HasMember("groups")) {
			m_logger.log(swarm::SWARM_LOG_ERROR, "\"application.groups\" field is missed");
			return false;
		}

		if (!config.HasMember("metadata-groups")) {
			m_logger.log(swarm::SWARM_LOG_ERROR, "\"application.metadata-groups\" field is missed");
			return false;
		}

		if (config.HasMember("read-timeout")) {
			m_read_timeout = config["read-timeout"].GetInt();
		}

		if (config.HasMember("write-timeout")) {
			m_write_timeout = config["write-timeout"].GetInt();
		}

		std::vector<int> groups;

		auto &groups_array = config["groups"];
		std::transform(groups_array.Begin(), groups_array.End(),
			std::back_inserter(groups),
			std::bind(&rapidjson::Value::GetInt, std::placeholders::_1));

		session.set_groups(groups);

		auto &groups_meta_array = config["metadata-groups"];
		std::transform(groups_meta_array.Begin(), groups_meta_array.End(),
			std::back_inserter(m_metadata_groups),
			std::bind(&rapidjson::Value::GetInt, std::placeholders::_1));

		return true;
	}

private:
	swarm::logger m_logger;
	std::unique_ptr<elliptics::node> m_node;
	std::unique_ptr<elliptics::session> m_session;
	std::vector<int> m_metadata_groups;

	long m_read_timeout;
	long m_write_timeout;

	struct host_stat {
		struct dnet_time	vfs_update_time;
		struct dnet_stat	vfs;

		struct dnet_time	monitor_update_time;
		std::string		monitor;

		// base_size from backend monitor output
		// it should be equal to data + all indexes size
		uint64_t		used_size;

		int			generation;

		host_stat() : used_size(0), generation(0) {
			memset(&vfs, 0, sizeof(struct dnet_stat));
			memset(&vfs_update_time, 0, sizeof(struct dnet_time));
			memset(&monitor_update_time, 0, sizeof(struct dnet_time));
		}
	};

	struct group_meta {
		uint64_t				total_size, free_size, used_size;
		std::map<std::string, host_stat>	hosts;

		group_meta() : total_size(0), free_size(0), used_size(0) {}
	};

	std::map<int, group_meta> m_group_meta;
	std::mutex m_lock;

	int m_generation;

	/*!
	 * This functions returns reference to host statistics structure with already updated generation counter.
	 * If there is no stat structure for given group and address, it will be created.
	 *
	 * This function MUST be called under m_lock locked. The same applies to returned host statistics reference.
	 */
	host_stat &get_host_stat(const int group_id, const std::string &addr) {
		auto group_it = m_group_meta.find(group_id);
		if (group_it == m_group_meta.end()) {
			group_it = m_group_meta.insert(std::make_pair(group_id, group_meta())).first;
		}

		auto & hosts = group_it->second.hosts;
		auto it = hosts.find(addr);
		if (it == hosts.end()) {
			struct host_stat st;

			it = hosts.insert(std::make_pair(addr, st)).first;
		}

		// this is a bit racy - rift could send multiple stat requests before this reply has been received
		// but we do not really care - next replies will overwrite it with more recent data when arrived
		it->second.generation = m_generation;
		return it->second;
	}

	void vfs_stat_result(const elliptics::stat_result_entry &res) {
		int group_id = res.command()->id.group_id;
		std::string addr(dnet_server_convert_dnet_addr(res.address()));

		std::unique_lock<std::mutex> guard(m_lock);
		auto & host = get_host_stat(group_id, addr);

		dnet_current_time(&host.vfs_update_time);
		host.vfs = *res.statistics();

		m_logger.log(swarm::SWARM_LOG_NOTICE, "%s: VFS statistics updated, generation: %d", addr.c_str(), host.generation);
	}

	void vfs_stat_complete(const elliptics::error_info &error) {
		if (error) {
			m_logger.log(swarm::SWARM_LOG_ERROR, "vfs-stat-completion: error: %d: %s", error.code(), error.message().c_str());
			return;
		}

		std::unique_lock<std::mutex> guard(m_lock);

		for (auto group = m_group_meta.begin(); group != m_group_meta.end(); ++group) {
			auto & group_meta = group->second;

			uint64_t total_size = 0;
			uint64_t used_size = 0;
			uint64_t free_size = 0;
			size_t hosts = 0;

			for (auto it = group_meta.hosts.begin(); it != group_meta.hosts.end(); ++it) {
				auto & host = it->second;

				int diff = m_generation - host.generation;
				if (diff <= 1) {
					hosts++;
					free_size += host.vfs.bsize * host.vfs.bavail;
					total_size += host.vfs.frsize * host.vfs.blocks;
					used_size += host.used_size;
				}
			}

			group_meta.total_size = total_size;
			group_meta.used_size = used_size;
			group_meta.free_size = free_size;

			m_logger.log(swarm::SWARM_LOG_INFO, "statistics: group: %d, total-size: %llu, used-size: %llu, free-size: %llu, "
					"generation: %d, hosts: %zd/%zd",
					group->first, (unsigned long long)total_size, (unsigned long long)used_size, (unsigned long long)free_size,
					m_generation, hosts, group_meta.hosts.size());
		}
	}

	void monitor_stat_result(const elliptics::monitor_stat_result_entry &res) {
		int group_id = res.command()->id.group_id;
		std::string addr(dnet_server_convert_dnet_addr(res.address()));

		rapidjson::Document doc;
		doc.Parse<0>(res.statistics().c_str());

		uint64_t base_size = 0;

		if (doc.HasMember("backend")) {
			const auto & backend = doc["backend"];
			if (backend.IsObject()) {
				if (backend.HasMember("base_stats")) {
					const auto & base = backend["base_stats"];
					if (base.IsObject()) {
						for (rapidjson::Value::ConstMemberIterator it = base.MemberBegin(); it != base.MemberEnd(); ++it) {
							const auto & blob = it->value;

							if (blob.HasMember("base_size")) {
								const auto & bsize = blob["base_size"];
								if (bsize.IsNumber()) {
									base_size = bsize.GetUint64();
								}
							}
						}
					}
				}
			}
		}

		std::unique_lock<std::mutex> guard(m_lock);
		auto & host = get_host_stat(group_id, addr);

		dnet_current_time(&host.monitor_update_time);
		host.monitor = res.statistics();
		host.used_size = base_size;

		m_logger.log(swarm::SWARM_LOG_NOTICE, "%s: MONITOR statistics updated, generation: %d, base-size: %zd", addr.c_str(), host.generation, base_size);
	}

	void monitor_stat_complete(const elliptics::error_info &error) {
		if (error) {
			m_logger.log(swarm::SWARM_LOG_ERROR, "monitor-stat-completion: error: %d: %s", error.code(), error.message().c_str());
		}
	}

};

}} // namespace ioremap::rift

#endif /*__IOREMAP_RIFT_SERVER_HPP */
