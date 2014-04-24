#include "server.hpp"

int main(int argc, char **argv)
{
	return ioremap::thevoid::run_server<rift_server::example_server>(argc, argv);
}
