#include <swarm/urlfetcher/url_fetcher.hpp>
#include <swarm/urlfetcher/boost_event_loop.hpp>
#include <swarm/urlfetcher/stream.hpp>

#include <thevoid/rapidjson/document.h>

#include <rift/auth.hpp>

#define BOOST_TEST_NO_MAIN
#include <boost/test/included/unit_test.hpp>
#include <boost/thread.hpp>
#include <boost/program_options.hpp>

#include <thread>
#include <mutex>
#include <condition_variable>

#include "server.hpp"

using namespace rift_server;

using namespace boost::unit_test;
using namespace ioremap;

namespace tests {

struct response_data
{
	swarm::url_fetcher::response response;
	std::string data;
	boost::system::error_code error;
};

struct server_runner
{
	server_runner(int argc, char **argv) :
		argc(argc), argv(argv), result(0), arguments_parsed(false)
	{
	}

	int argc;
	char **argv;
	std::shared_ptr<example_server> server;
	int result;
	bool arguments_parsed;
	std::mutex mutex;
	std::condition_variable condition;

	void operator() ()
	{
		server = thevoid::create_server<example_server>();
		result = server->parse_arguments(argc, argv);
		{
			std::unique_lock<std::mutex> lock(mutex);
			arguments_parsed = true;
			condition.notify_all();
		}
		if (result != 0)
			return;

		server->run();
	}
};

struct data_container
{
	data_container(int argc, char **argv) :
		work(new boost::asio::io_service::work(service)),
		loop(service),
		fetcher(loop, logger),
		thread(boost::bind(&data_container::run, this)),
		runner(argc, argv),
		server_thread(std::ref(runner))
	{
	}

	~data_container()
	{
		delete work;
		service.stop();
		runner.server->stop();
		thread.join();
		server_thread.join();
	}

	void run()
	{
		service.run();
	}

	struct sync_handler
	{
		response_data result;
		bool ready;
		std::mutex mutex;
		std::condition_variable condition;

		sync_handler() : ready(false)
		{
		}

		void operator ()(const swarm::url_fetcher::response &response, const std::string &data, const boost::system::error_code &error)
		{
			std::unique_lock<std::mutex> lock(mutex);

			result.response = response;
			result.data = data;
			result.error = error;
			ready = true;

			condition.notify_all();
		}

		response_data get()
		{
			std::unique_lock<std::mutex> lock(mutex);
			while (!ready)
				condition.wait(lock);

			return std::move(result);
		}
	};

	void add_authorization(swarm::url_fetcher::request &request)
	{
		auto auth = rift::http_auth::generate_signature(request, bucket_token);
		request.headers().add("Authorization", auth);
	}

	response_data get(swarm::url_fetcher::request &&request)
	{
		sync_handler handler;
		request.set_method("GET");
		add_authorization(request);
		fetcher.get(swarm::simple_stream::create(std::ref(handler)), std::move(request));
		return handler.get();
	}

	response_data post(swarm::url_fetcher::request &&request, std::string &&body)
	{
		sync_handler handler;
		request.set_method("POST");
		add_authorization(request);
		fetcher.post(swarm::simple_stream::create(std::ref(handler)), std::move(request), std::move(body));
		return handler.get();
	}

	swarm::url base_url;
	boost::asio::io_service service;
	boost::asio::io_service::work *work;
	swarm::boost_event_loop loop;
	swarm::logger logger;
	swarm::url_fetcher fetcher;
	boost::thread thread;
	std::string bucket_name;
	std::string bucket_token;
	server_runner runner;
	boost::thread server_thread;
} static *helper = NULL;

#define RIFT_TEST_CASE(M, C...) do { suite->add(BOOST_TEST_CASE(std::bind( M, ##C ))); } while (false)
#define RIFT_TEST_CASE_NOARGS(M) do { suite->add(BOOST_TEST_CASE(std::bind( M ))); } while (false)

static swarm::url create_url(const std::string &base_path, const std::string &key, std::initializer_list<std::pair<std::string, std::string>> query)
{
	swarm::url url = helper->base_url;
	std::string path = base_path + "/" + helper->bucket_name + "/" + key;
	url.set_path(path);
	for (auto it = query.begin(); it != query.end(); ++it)
		url.query().add_item(it->first, it->second);
	return url;
}

void test_ping()
{
	swarm::url_fetcher::request request;
	request.set_url(create_url("/ping", "", {}));

	response_data response = helper->get(std::move(request));
	BOOST_REQUIRE_MESSAGE(!response.error, response.error.message());
	BOOST_REQUIRE_EQUAL(response.response.code(), swarm::http_response::ok);
}

void test_echo()
{
	swarm::url_fetcher::request request;
	request.set_url(create_url("/echo", "", {}));
	request.headers().add({ "X-UNIQUE-HEADER", "some-value"});

	response_data response = helper->get(std::move(request));
	BOOST_REQUIRE_MESSAGE(!response.error, response.error.message());
	BOOST_REQUIRE_EQUAL(response.response.code(), swarm::http_response::ok);
	BOOST_REQUIRE(response.response.headers().has("X-UNIQUE-HEADER"));
	BOOST_REQUIRE_EQUAL(*response.response.headers().get("X-UNIQUE-HEADER"), "some-value");
}

void test_upload(const std::string &name, const std::string &data)
{
	swarm::url_fetcher::request request;
	request.set_url(create_url("/upload", name, {}));

	response_data response = helper->post(std::move(request), std::string(data));
	BOOST_REQUIRE_MESSAGE(!response.error, response.error.message());
	BOOST_REQUIRE_EQUAL(response.response.code(), swarm::http_response::ok);
}

void test_get(const std::string &name, const std::string &data)
{
	swarm::url_fetcher::request request;
	request.set_url(create_url("/get", name, {}));

	response_data response = helper->get(std::move(request));
	BOOST_REQUIRE_MESSAGE(!response.error, response.error.message());
	BOOST_REQUIRE_EQUAL(response.response.code(), swarm::http_response::ok);
	BOOST_REQUIRE_EQUAL(response.data, data);
}

void test_download_info(const std::string &name, const std::string &data)
{
	swarm::url_fetcher::request request;
	request.set_url(create_url("/download-info", name, {}));

	response_data response = helper->get(std::move(request));
	BOOST_REQUIRE_MESSAGE(!response.error, response.error.message());
	BOOST_REQUIRE_EQUAL(response.response.code(), swarm::http_response::ok);

	rapidjson::Document doc;
	doc.Parse<0>(response.data.c_str());
	std::cerr << response.data;

	BOOST_REQUIRE_MESSAGE(!doc.HasParseError(), doc.GetParseError());
	BOOST_REQUIRE(doc.HasMember("size"));
	BOOST_REQUIRE(doc.HasMember("csum"));
	BOOST_REQUIRE(doc.HasMember("id"));
	BOOST_REQUIRE(doc.HasMember("server"));
	BOOST_REQUIRE(doc["size"].IsInt64());
	BOOST_REQUIRE_EQUAL(doc["size"].GetInt64(), data.size());
	BOOST_REQUIRE(doc["csum"].IsString());
}

boost::unit_test::test_suite *register_tests(int argc, char *argv[])
{
	test_suite *suite = new test_suite("Local Test Suite");

	helper = new data_container(argc, argv);
	helper->base_url.set_scheme("http");
	helper->base_url.set_host("localhost");
	helper->base_url.set_port(8080);
	helper->bucket_name = "rift_test";
	helper->bucket_token = "rift_password";

	{
		std::unique_lock<std::mutex> lock(helper->runner.mutex);
		while (!helper->runner.arguments_parsed)
			helper->runner.condition.wait(lock);
	}

	if (helper->runner.result != 0) {
		throw std::runtime_error("failed to start the server");
	}

	RIFT_TEST_CASE_NOARGS(test_ping);
	RIFT_TEST_CASE_NOARGS(test_echo);
	RIFT_TEST_CASE(test_upload, "test", "test-data");
	RIFT_TEST_CASE(test_get, "test", "test-data");
	RIFT_TEST_CASE(test_download_info, "test", "test-data");

	return suite;
}

}

int main(int argc, char *argv[])
{
	int err = unit_test_main(tests::register_tests, argc, argv);
	delete tests::helper;
	return err;
}
