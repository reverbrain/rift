#include "rift/bucket.hpp"

#include <iostream>

#include <elliptics/session.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>

using namespace ioremap;

namespace {

struct digitizer {
	int operator() (const std::string &str) {
		return atoi(str.c_str());
	}
};

}

int main(int argc, char *argv[])
{
	struct rift::bucket_meta_raw meta;
	std::vector<int> groups;
	std::string remote;
	std::string metadata_groups_str;
	std::string data_groups_str;
	std::string noauth;
	int log_level;

	std::vector<std::string> acl_str;

	namespace bpo = boost::program_options;

	bpo::variables_map vm;
	bpo::options_description generic("Bucket control options");

	generic.add_options()
		("help", "This help message")
		("remote", bpo::value<std::string>(&remote), "Remote elliptics server address")
		("log-level", bpo::value<int>(&log_level)->default_value(DNET_LOG_ERROR),
		 	"Elliptics message log level (messages will be written into stdout)")
		("bucket", bpo::value<std::string>(&meta.key), "Bucket (namespace) name")
		("metadata-groups", bpo::value<std::string>(&metadata_groups_str),
		 	"Metadata groups string (colon separated). These groups are used to store bucket info")
		("read", "Read and print bucket metadata, all options below will be ignored\n")
		("acl", bpo::value<std::vector<std::string>>(&acl_str)->multitoken(),
		 	"Access control list with the following format: username:token:flags (can be empty for no authorization). "
			"Flags: 1 - bypass auth check for read requests (get, lookup, download-info and so on), 2 - bypass auth check for write requests")
		("data-groups", bpo::value<std::string>(&data_groups_str),
		 	"Data groups string (colon separated). "
			"These groups are used to store real data written into this namespace/bucket")
		("max-size", bpo::value<uint64_t>(&meta.max_size)->default_value(0),
		 	"Maximum object size (unsupported yet) in given bucket")
		("max-key-num", bpo::value<uint64_t>(&meta.max_key_num)->default_value(0),
		 	"Maximum number of objects in given bucket (unsupported yet)")
		 ;

	try {
		bpo::store(bpo::parse_command_line(argc, argv, generic), vm);
		bpo::notify(vm);
	} catch (const std::exception &e) {
		std::cerr << "Command line parsing error\n" << generic;
		return -1;
	}

	if (vm.count("help")) {
		std::cerr << generic;
		return -1;
	}

	if (!vm.count("metadata-groups") || !vm.count("bucket") || !vm.count("remote")) {
		std::cerr << "Remote server address, bucket name and metadata groups are required\n" << generic;
		return -1;
	}

	std::vector<std::string> gr;

	boost::split(gr, metadata_groups_str, boost::is_any_of(":"));
	std::transform(gr.begin(), gr.end(), std::back_inserter(groups), digitizer());


	try {
		elliptics::file_logger log("/dev/stdout", log_level);
		elliptics::node node(log);
		node.add_remote(remote.c_str());

		elliptics::session session(node);
		session.set_groups(groups);

		if (vm.count("read")) {
			try {
				elliptics::data_pointer data = session.read_data(meta.key, 0, 0).get_one().file();

				msgpack::unpacked msg;
				msgpack::unpack(&msg, data.data<char>(), data.size());

				msg.get().convert(&meta);

				std::ostringstream ss;
				for (auto gr = meta.groups.begin(); gr != meta.groups.end();) {
					ss << *gr;
					++gr;

					if (gr != meta.groups.end())
						ss << ":";
				}
				data_groups_str = ss.str();

			} catch (const std::exception &e) {
				std::cout << "Could not read bucket metadata: " << e.what() << std::endl;
				return -1;
			}
		} else {

			if (!vm.count("data-groups")) {
				std::cerr << "Data groups are required\n" << generic;
				return -1;
			}

			gr.clear();
			boost::split(gr, data_groups_str, boost::is_any_of(":"));
			std::transform(gr.begin(), gr.end(), std::back_inserter(meta.groups), digitizer());

			for (auto it = acl_str.begin(); it != acl_str.end(); ++it) {
				std::vector<std::string> tmp;
				boost::split(tmp, *it, boost::is_any_of(":"));

				if (tmp.size() != 3) {
					std::cerr << "Invalid ACL string '" << *it << "'" << std::endl;
					continue;
				}

				rift::bucket_acl acl;
				acl.user = tmp[0];
				acl.token = tmp[1];
				acl.flags = strtoul(tmp[2].c_str(), NULL, 0);

				meta.acl[acl.user] = acl;
			}

			msgpack::sbuffer buf;
			msgpack::pack(buf, meta);

			try {
				session.write_data(meta.key, elliptics::data_pointer::copy(buf.data(), buf.size()), 0).wait();
			} catch (const std::exception &e) {
				std::cout << "Could not write bucket metadata: " << e.what() << std::endl;
				return -1;
			}

			printf("Successfully written bucket metadata\n");
		}
	} catch (const std::exception &e) {
		std::cout << "Failed to create elliptics client node and session: " << e.what() << std::endl;
		return -1;
	}

	std::ostringstream ss;
	for (auto it = meta.acl.begin(); it != meta.acl.end(); ++it) {
		const auto & acl = it->second;

		ss << acl.user << ":" << acl.token << ":0x" << std::hex << acl.flags << " ";
	}

	printf("Metadata info:\n"
		"  bucket: %s\n"
		"  acl: %s\n"
		"  data groups: %s\n"
		"  flags: 0x%lx\n"
		"  maximum record size: %ld\n"
		"  maximum number of keys: %ld\n"
		"  metadata stored in the following groups: %s\n",
		meta.key.c_str(), ss.str().c_str(), data_groups_str.c_str(), meta.flags,
		meta.max_size, meta.max_key_num, metadata_groups_str.c_str());

	return 0;
}
