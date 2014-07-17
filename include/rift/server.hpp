#ifndef __IOREMAP_RIFT_SERVER_HPP
#define __IOREMAP_RIFT_SERVER_HPP

#include "rift/bucket.hpp"
#include "rift/logger.hpp"
#include "rift/timer.hpp"

#include <thevoid/server.hpp>
#include <swarm/logger.hpp>
#include <elliptics/session.hpp>

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

		// do not throw session exceptions, in particular TIMEOUT error forces rift to terminate
		m_session->set_exceptions_policy(elliptics::session::no_exceptions);

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
					req.url().to_human_readable().c_str(), e.what());
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

	template <typename Allocator>
	void stat(rapidjson::Value &ret, Allocator &allocator) {
		std::unique_lock<std::mutex> guard(m_lock);

		for (auto it = m_group_meta.begin(); it != m_group_meta.end(); ++it) {
			rapidjson::Value g(rapidjson::kObjectType);

			it->second.stat(g, allocator);

			ret.AddMember(std::to_string(it->first).c_str(), allocator, g, allocator);
		}
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

		try {
			node.add_remote(remotes);
			elliptics::session session(node);

			if (!session.get_routes().size()) {
				m_logger.log(swarm::SWARM_LOG_ERROR, "Didn't add any remote node, exiting.");
				return false;
			}
		} catch (const std::exception &e) {
			m_logger.log(swarm::SWARM_LOG_ERROR, "Could not add any out of %zd nodes.", remotes.size());
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

	struct node_stat {
		struct dnet_stat	vfs;

		// 'backend' monitoring output (json) from elliptics node
		rapidjson::Value	doc_backend;

		// base_size from backend monitor output
		// it should be equal to data + all indexes size
		uint64_t		used_size;

		int			generation;

		node_stat(node_stat &&orig) : used_size(orig.used_size), generation(orig.generation) {
			doc_backend = orig.doc_backend;
		}

		node_stat() : used_size(0), generation(0) {
			memset(&vfs, 0, sizeof(struct dnet_stat));
		}

		template <typename Allocator>
		void stat(rapidjson::Value &ret, Allocator &allocator) {
			rapidjson::Value v(rapidjson::kObjectType);
			v.AddMember("bsize", vfs.bsize, allocator);

			ret.AddMember("vfs", v, allocator);
			ret.AddMember("backend", doc_backend, allocator);
		}
	};

	struct group_meta {
		uint64_t				total_size, free_size, used_size;

		/*!
		 * address string to per-host statistics map
		 */
		std::map<std::string, node_stat>	nodes;

		group_meta() : total_size(0), free_size(0), used_size(0) {}

		template <typename Allocator>
		void stat(rapidjson::Value &g, Allocator &allocator) {
			g.AddMember("total-size", total_size, allocator);
			g.AddMember("free-size", free_size, allocator);
			g.AddMember("used-size", used_size, allocator);

			for (auto it = nodes.begin(); it != nodes.end(); ++it) {
				rapidjson::Value n(rapidjson::kObjectType);

				it->second.stat(n, allocator);
				g.AddMember(it->first.c_str(), allocator, n, allocator);
			}
		}
	};

	/*!
	 *
	 * group_id to group metadata map, must be accessed under @m_lock
	 */
	std::map<int, group_meta> m_group_meta;
	std::mutex m_lock;

	/*!
	 * Generation is increased for every stat request, it is needed to detect nodes which
	 * were updated long ago (much smaller generation number). We only account nodes
	 * whose generation number is at most 1 generation ago from the last one, i.e.
	 * m_generation - host.generation <= 1
	 */
	int m_generation;

	/*!
	 * This functions returns reference to host statistics structure with already updated generation counter.
	 * If there is no stat structure for given group and address, it will be created.
	 *
	 * This function MUST be called under m_lock locked. The same applies to returned host statistics reference.
	 */
	node_stat &get_host_stat(const int group_id, const std::string &addr) {
		auto group_it = m_group_meta.find(group_id);
		if (group_it == m_group_meta.end()) {
			group_it = m_group_meta.insert(std::make_pair(group_id, group_meta())).first;
		}

		auto & nodes = group_it->second.nodes;
		auto it = nodes.find(addr);
		if (it == nodes.end()) {
			struct node_stat st;

			it = nodes.emplace(std::make_pair(addr, std::move(st))).first;
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

		host.vfs = *res.statistics();

		m_logger.log(swarm::SWARM_LOG_NOTICE, "%s: VFS statistics updated, generation: %d", addr.c_str(), host.generation);
	}

	void vfs_stat_complete(const elliptics::error_info &error) {
		if (error) {
			m_logger.log(swarm::SWARM_LOG_ERROR, "vfs-stat-completion: error: %d: %s", error.code(), error.message().c_str());
		}

		// iterate over all groups and nodes and sum up size statistics
		// we do this in VFS completion callback, since this command was started after monitor request,
		// this doesn't mean vfs stat command will be completed after monitor one, but its probability is rather high
		//
		// If vfs stat command comes before monitor one, it is possible, that we will account previous generation of the monitor data
		// This is not a huge problem (stats are updated periodically, so error will not accumulate) though.
		std::unique_lock<std::mutex> guard(m_lock);

		for (auto group = m_group_meta.begin(); group != m_group_meta.end(); ++group) {
			auto & group_meta = group->second;

			uint64_t total_size = 0;
			uint64_t used_size = 0;
			uint64_t free_size = 0;
			size_t nodes = 0;

			for (auto it = group_meta.nodes.begin(); it != group_meta.nodes.end(); ++it) {
				auto & host = it->second;

				int diff = m_generation - host.generation;
				if (diff <= 1) {
					nodes++;
					free_size += host.vfs.bsize * host.vfs.bavail;
					total_size += host.vfs.frsize * host.vfs.blocks;
					used_size += host.used_size;
				}
			}

			group_meta.total_size = total_size;
			group_meta.used_size = used_size;
			group_meta.free_size = free_size;

			// Only write size summary into the log, eventually we will export it to clients and/or some other monitoring
			// tool, which will provide per-bucket statistics
			m_logger.log(swarm::SWARM_LOG_INFO, "statistics: group: %d, total-size: %llu, used-size: %llu, free-size: %llu, "
					"generation: %d, nodes: %zd/%zd",
					group->first, (unsigned long long)total_size, (unsigned long long)used_size, (unsigned long long)free_size,
					m_generation, nodes, group_meta.nodes.size());
		}
	}

	void monitor_stat_result(const elliptics::monitor_stat_result_entry &res) {
		int group_id = res.command()->id.group_id;
		std::string addr(dnet_server_convert_dnet_addr(res.address()));

		// parse 'backend' monitoring stats
		// we want to sum up all blob sizes (data and indexes)
		rapidjson::Document doc;
		doc.Parse<0>(res.statistics().c_str());

		uint64_t base_size = 0;
		int generation = 0;

		if (doc.HasMember("backend")) {
			// Right now we only support one backend per elliptics node, after this is changed,
			// we must account backend array/map here
			auto & backend = doc["backend"];
			if (backend.IsObject()) {
				if (backend.HasMember("base_stats")) {
					const auto & base = backend["base_stats"];
					if (base.IsObject()) {
						// Iterate over blob data
						for (rapidjson::Value::ConstMemberIterator it = base.MemberBegin(); it != base.MemberEnd(); ++it) {
							const auto & blob = it->value;

							// base_size contains summed up size of the data and all indexes
							if (blob.HasMember("base_size")) {
								const auto & bsize = blob["base_size"];
								if (bsize.IsNumber()) {
									base_size += bsize.GetUint64();
								}
							}
						}
					}
				}
			}

			std::unique_lock<std::mutex> guard(m_lock);
			auto & host = get_host_stat(group_id, addr);

			host.doc_backend = backend;
			host.used_size = base_size;

			generation = host.generation;
		}

		m_logger.log(swarm::SWARM_LOG_NOTICE, "%s: MONITOR statistics updated, generation: %d, base-size: %zd", addr.c_str(), generation, base_size);
	}

	void monitor_stat_complete(const elliptics::error_info &error) {
		if (error) {
			m_logger.log(swarm::SWARM_LOG_ERROR, "monitor-stat-completion: error: %d: %s", error.code(), error.message().c_str());
		}
	}
};

}} // namespace ioremap::rift

#endif /*__IOREMAP_RIFT_SERVER_HPP */
