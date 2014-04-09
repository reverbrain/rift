#include "server.hpp"

		on<rift::io::on_delete<example_server>>(
			options::prefix_match("/delete/"),
			options::methods("POST")
		);

		on<rift::bucket_ctl::on_delete<example_server>>(
			options::prefix_match("/delete-bucket-directory/"),
			options::methods("POST")
		);
		on<rift::bucket_ctl::on_delete<example_server>>(
			options::prefix_match("/delete-bucket/"),
			options::methods("POST")
		);

int main(int argc, char **argv)
{
	return ioremap::thevoid::run_server<rift_server::example_server>(argc, argv);
}
