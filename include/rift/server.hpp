#ifndef __IOREMAP_RIFT_SERVER_HPP
#define __IOREMAP_RIFT_SERVER_HPP

#include "rift/bucket.hpp"
#include "rift/timer.hpp"

#include <thevoid/server.hpp>
#include <swarm/logger.hpp>
#include <elliptics/session.hpp>

namespace ioremap {
namespace rift {

class elliptics_base
{
public:
	elliptics_base(const swarm::logger &logger) :
		m_logger(logger, blackhole::log::attributes_t({ swarm::keyword::source() = "elliptics" })),
		m_read_timeout(0),
		m_write_timeout(0),
		m_generation(0)
	{
	}

	~elliptics_base()
	{
	}

	bool initialize(const rapidjson::Value &config) {
		dnet_config node_config;
		memset(&node_config, 0, sizeof(node_config));

		if (!prepare_config(config, node_config)) {
			return false;
		}

		m_node.reset(new elliptics::node(swarm::logger(m_logger, blackhole::log::attributes_t()), node_config));

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

	elliptics::session read_data_session(const thevoid::http_request &req, const bucket_meta_raw &meta) const {
		auto session = m_session->clone();
		session.set_timeout(m_read_timeout);

		if (meta.key.size() && meta.groups.size()) {
			session.set_namespace(meta.key.c_str(), meta.key.size());
			session.set_groups(meta.groups);
		}

		session.set_trace_id(req.request_id());
		session.set_trace_bit(req.trace_bit());

		try {
			const auto &query = req.url().query();
			uint32_t ioflags = query.item_value("ioflags", 0u);
			uint64_t cflags = query.item_value("cflags", 0llu);

			session.set_ioflags(ioflags);
			session.set_cflags(cflags);

		} catch (const std::exception &e) {
			BH_LOG(m_logger, SWARM_LOG_ERROR, "data-session: url: %s: invalid ioflags/cflags parameters: %s",
					req.url().to_human_readable().c_str(), e.what());
		}

		return session;
	}

	elliptics::session write_data_session(const thevoid::http_request &req, const bucket_meta_raw &meta) const {
		auto session = read_data_session(req, meta);
		session.set_timeout(m_write_timeout);

		return session;
	}

	elliptics::session read_metadata_session(const thevoid::http_request &req, const bucket_meta_raw &meta) const {
		auto session = read_data_session(req, meta);
		session.set_groups(m_metadata_groups);

		return session;
	}

	elliptics::session write_metadata_session(const thevoid::http_request &req, const bucket_meta_raw &meta) const {
		auto session = write_data_session(req, meta);
		session.set_groups(m_metadata_groups);

		return session;
	}

	const std::vector<int> metadata_groups(void) const {
		return m_metadata_groups;
	}

	void stat_update() {
		m_generation++;

		m_session->monitor_stat(DNET_MONITOR_BACKEND).connect(
				std::bind(&elliptics_base::monitor_stat_result, this, std::placeholders::_1),
				std::bind(&elliptics_base::monitor_stat_complete, this, std::placeholders::_1));
	}

	template <typename Allocator>
	void stat(rapidjson::Value &ret, Allocator &allocator) {
		std::unique_lock<std::mutex> guard(m_lock);

		for (auto it = m_group_meta.begin(); it != m_group_meta.end(); ++it) {
			rapidjson::Value g(rapidjson::kObjectType);

			it->second.stat(g, allocator);

			ret.AddMember(std::to_string(static_cast<unsigned long long>(it->first)).c_str(),
					allocator, g, allocator);
		}
	}

protected:
	virtual bool prepare_config(const rapidjson::Value &config, dnet_config &node_config) {
		if (config.HasMember("io-thread-num")) {
			node_config.io_thread_num = config["io-thread-num"].GetInt();
		}
		if (config.HasMember("nonblocking-io-thread-num")) {
			node_config.nonblocking_io_thread_num = config["nonblocking-io-thread-num"].GetInt();
		}
		if (config.HasMember("net-thread-num")) {
			node_config.net_thread_num = config["net-thread-num"].GetInt();
		}

		return true;
	}

	virtual bool prepare_node(const rapidjson::Value &config, elliptics::node &node) {
		if (!config.HasMember("remotes")) {
			BH_LOG(m_logger, SWARM_LOG_ERROR, "\"remotes\" field is missed");
			return false;
		}

		std::vector<elliptics::address> remotes;

		auto &remotesArray = config["remotes"];
		for (auto it = remotesArray.Begin(); it != remotesArray.End(); ++it) {
			remotes.emplace_back(std::string(it->GetString(), it->GetStringLength()));
		}

		node.add_remote(remotes);

		return true;
	}

	virtual bool prepare_session(const rapidjson::Value &config, elliptics::session &session) {
		if (!config.HasMember("groups")) {
			BH_LOG(m_logger, SWARM_LOG_ERROR, "\"application.groups\" field is missed");
			return false;
		}

		if (!config.HasMember("metadata-groups")) {
			BH_LOG(m_logger, SWARM_LOG_ERROR, "\"application.metadata-groups\" field is missed");
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
		std::vector<dnet_raw_id>	ids;

		// 'backend' monitoring output (json) from elliptics node
		// this json string *always* contain 'backend' section, otherwise it is empty
		// periodic stat update receives monitoring data, parses json and only
		// assign this string if 'backend' object is present
		std::string		doc_backend;

		// base_size from backend monitor output
		// it should be equal to data + all indexes size
		uint64_t		used_size;

		int			generation;

		node_stat() : used_size(0), generation(0) {
		}

		template <typename Allocator>
		void stat(rapidjson::Value &ret, Allocator &allocator) {
			rapidjson::Value v(rapidjson::kObjectType);

			if (doc_backend.size()) {
				rapidjson::Document doc(&allocator);
				doc.Parse<0>(doc_backend.c_str());
				ret.AddMember("backend", doc["backend"], allocator);
			}

			rapidjson::Value ids_json(rapidjson::kArrayType);
			char id_str[2*DNET_ID_SIZE + 1];
			for (auto id = ids.begin(); id != ids.end(); ++id) {
				dnet_dump_id_len_raw(id->id, DNET_ID_SIZE, id_str);
				rapidjson::Value id_val(id_str, DNET_ID_SIZE*2, allocator);

				ids_json.PushBack(id_val, allocator);
			}

			ret.AddMember("ids", ids_json, allocator);
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

			it = nodes.insert(std::make_pair(addr, std::move(st))).first;
		}

		// this is a bit racy - rift could send multiple stat requests before this reply has been received
		// but we do not really care - next replies will overwrite it with more recent data when arrived
		it->second.generation = m_generation;
		return it->second;
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
						for (rapidjson::Value::ConstMemberIterator it = base.MemberBegin();
								it != base.MemberEnd(); ++it) {
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

				std::unique_lock<std::mutex> guard(m_lock);
				auto & host = get_host_stat(group_id, addr);

				host.doc_backend = res.statistics();
				host.used_size = base_size;

				generation = host.generation;
			}

			// this function parses current route table and updates list of IDs under @m_lock
			route_update();

		}

		BH_LOG(m_logger, SWARM_LOG_NOTICE, "%s: MONITOR statistics updated, generation: %d, base-size: %lld",
				addr.c_str(), generation, base_size);
	}

	void monitor_stat_complete(const elliptics::error_info &error) {
		if (error) {
			BH_LOG(m_logger, SWARM_LOG_ERROR, "monitor-stat-completion: error: %d: %s",
					error.code(), error.message().c_str());
		}
	}

	void route_update() {
		auto routes = m_session->get_routes();

		std::map<int, std::map<std::string, std::vector<dnet_raw_id>>> group_addrs;
		for (auto it = routes.begin(); it != routes.end(); ++it) {
			const dnet_route_entry &entry = *it;
			const dnet_addr &addr = entry.addr;
			const dnet_raw_id id = entry.id;
			const int group_id = entry.group_id;

			auto group_it = group_addrs.find(group_id);
			if (group_it == group_addrs.end()) {
				group_addrs[group_id] = std::map<std::string, std::vector<dnet_raw_id>>();
				group_it = group_addrs.find(group_id);
			}

			auto & addrs = group_it->second;

			std::string addr_string(dnet_server_convert_dnet_addr(&addr));

			auto tmp = addrs.find(addr_string);
			if (tmp == addrs.end()) {
				tmp = addrs.insert(std::make_pair(addr_string, std::vector<dnet_raw_id>())).first;
			}

			tmp->second.emplace_back(id);
		}

		struct id_comp {
			bool operator() (const dnet_raw_id &id1, const dnet_raw_id &id2) const {
				return dnet_id_cmp_str(id1.id, id2.id) < 0;
			}
		};

		for (auto group_it = group_addrs.begin(); group_it != group_addrs.end(); ++group_it) {
			auto & addrs = group_it->second;

			for (auto addr_it = addrs.begin(); addr_it != addrs.end(); ++addr_it) {
				std::sort(addr_it->second.begin(), addr_it->second.end(), id_comp());
			}
		}

		std::unique_lock<std::mutex> guard(m_lock);

		for (auto group_it = group_addrs.begin(); group_it != group_addrs.end(); ++group_it) {
			int group_id = group_it->first;
			auto & addrs = group_it->second;

			for (auto addr_it = addrs.begin(); addr_it != addrs.end(); ++addr_it) {
				auto &node = get_host_stat(group_id, addr_it->first);
				node.ids.swap(addr_it->second);
			}
		}
	}
};

}} // namespace ioremap::rift

#endif /*__IOREMAP_RIFT_SERVER_HPP */
