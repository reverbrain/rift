#include "rift/bucket.hpp"

#include <elliptics/session.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>

using namespace ioremap;

int main(int argc, char *argv[])
{
	struct rift::bucket_meta_raw meta;
	std::vector<int> groups;
	std::string metadata_groups_str;
	std::string data_groups_str;
	std::string noauth;
	int log_level;

	namespace bpo = boost::program_options;

	bpo::variables_map vm;
	bpo::options_description generic("Bucket control options");

	generic.add_options()
		("help", "This help message")
		("log-level", bpo::value<int>(&log_level)->default_value(DNET_LOG_ERROR),
		 	"Elliptics message log level (messages will be written into stdout)")
		("bucket", bpo::value<std::string>(&meta.key), "Bucket (namespace) name")
		("token", bpo::value<std::string>(&meta.token), "Secure token (can be empty for no authorization)")
		("metadata-groups", bpo::value<std::string>(&metadata_groups_str),
		 	"Metadata groups string (colon separated). These groups are used to store bucket info")
		("data-groups", bpo::value<std::string>(&data_groups_str),
		 	"Data groups string (colon separated). "
			"These groups are used to store real data written into this namespace/bucket")
		("noauth", bpo::value<std::string>(&noauth),
		 	"Noauth option:\n"
			"  'read' means read requests (read, download-info, lookup and other GET requests) "
			"will bypass authentication check, POST upload requests will pass through proper auth check\n"
			"  'all' - all requests for this bucket will bypass auth checks")
		("max-size", bpo::value<uint64_t>(&meta.max_size)->default_value(0),
		 	"Maximum object size (unsupported yet) in given bucket")
		("max-key-num", bpo::value<uint64_t>(&meta.max_key_num)->default_value(0),
		 	"Maximum number of objects in given bucket (unsupported yet)")
		 ;

	try {
		bpo::store(bpo::parse_command_line(argc, argv, generic), vm);
		bpo::notify(vm);
	} catch (const std::exception &e) {
		std::cerr << "Command line parser: " << generic;
		return -1;
	}

	if (vm.count("help")) {
		std::cerr << generic;
		return -1;
	}

	if (!vm.count("metadata-groups") || !vm.count("data-groups") || !vm.count("bucket")) {
		std::cerr << "Bucket name, data and metadata groups are required" << generic;
		return -1;
	}

	if (noauth == "read")
		meta.flags |= rift::bucket_meta_raw::flags_noauth_read;
	else if (noauth == "all")
		meta.flags |= rift::bucket_meta_raw::flags_noauth_all;

	struct digitizer {
		int operator() (const std::string &str) {
			return atoi(str.c_str());
		}
	};

	std::vector<std::string> gr;

	boost::split(gr, metadata_groups_str, boost::is_any_of(":"));
	std::transform(gr.begin(), gr.end(), std::back_inserter<std::vector<int>>(groups), digitizer());

	gr.clear();
	boost::split(gr, data_groups_str, boost::is_any_of(":"));
	std::transform(gr.begin(), gr.end(), std::back_inserter<std::vector<int>>(meta.groups), digitizer());

	msgpack::sbuffer buf;
	msgpack::pack(buf, meta);

	elliptics::file_logger log("/dev/stdout", log_level);
	elliptics::node node(log);
	elliptics::session session(node);

	session.set_groups(groups);

	try {
		session.write_data(meta.key, elliptics::data_pointer(buf.data(), buf.size()), 0).wait();
	} catch (const std::exception &e) {
		std::cout << "Could not write bucket metadata: " << e.what() << std::endl;
		return -1;
	}

	printf("Successfully written bucket metadata\n"
		"  bucket: %s\n"
		"  token: %s\n"
		"  data groups: %s\n"
		"  flags: 0x%lx\n"
		"  maximum record size: %ld\n"
		"  maximum number of keys: %ld\n"
		"  metadata stored in the following groups: %s\n",
		meta.key.c_str(), meta.token.c_str(), data_groups_str.c_str(), meta.flags,
		meta.max_size, meta.max_key_num, metadata_groups_str.c_str());

	return 0;
}
