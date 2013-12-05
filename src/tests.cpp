#include <swarm/urlfetcher/url_fetcher.hpp>
#include <swarm/urlfetcher/boost_event_loop.hpp>
#include <swarm/urlfetcher/stream.hpp>

#include <thevoid/rapidjson/document.h>

#include <rift/auth.hpp>

#define BOOST_TEST_DYN_LINK
#include <boost/test/included/unit_test.hpp>
#include <boost/thread.hpp>

#include <mutex>
#include <condition_variable>

using namespace boost::unit_test;
using namespace ioremap;

namespace tests {

struct response_data
{
	swarm::url_fetcher::response response;
	std::string data;
	boost::system::error_code error;
};

struct data_container
{
	data_container() :
		work(new boost::asio::io_service::work(service)),
		loop(service),
		fetcher(loop, logger),
		thread(boost::bind(&data_container::run, this))
	{
	}

	~data_container()
	{
		delete work;
		service.stop();
		thread.join();
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
} static *helper = NULL;

#define RIFT_TEST_CASE(M, C...) do { framework::master_test_suite().add(BOOST_TEST_CASE(std::bind( M, ##C ))); } while (false)
#define RIFT_TEST_CASE_NOARGS(M) do { framework::master_test_suite().add(BOOST_TEST_CASE(std::bind( M ))); } while (false)

static swarm::url create_url(const std::string &path, std::initializer_list<std::pair<std::string, std::string>> query)
{
	swarm::url url = helper->base_url;
	url.set_path(path);
	for (auto it = query.begin(); it != query.end(); ++it)
		url.query().add_item(it->first, it->second);
	url.query().add_item("namespace", helper->bucket_name);
	return url;
}

void test_ping()
{
	swarm::url_fetcher::request request;
	request.set_url(create_url("/ping", {}));

	response_data response = helper->get(std::move(request));
	BOOST_REQUIRE_MESSAGE(!response.error, response.error.message());
	BOOST_REQUIRE_EQUAL(response.response.code(), swarm::http_response::ok);
}

void test_echo()
{
	swarm::url_fetcher::request request;
	request.set_url(create_url("/echo", {}));
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
	request.set_url(create_url("/upload", {
		{ "name", name }
	}));

	response_data response = helper->post(std::move(request), std::string(data));
	BOOST_REQUIRE_MESSAGE(!response.error, response.error.message());
	BOOST_REQUIRE_EQUAL(response.response.code(), swarm::http_response::ok);
}

void test_get(const std::string &name, const std::string &data)
{
	swarm::url_fetcher::request request;
	request.set_url(create_url("/get", {
		{ "name", name }
	}));

	response_data response = helper->get(std::move(request));
	BOOST_REQUIRE_MESSAGE(!response.error, response.error.message());
	BOOST_REQUIRE_EQUAL(response.response.code(), swarm::http_response::ok);
	BOOST_REQUIRE_EQUAL(response.data, data);
}

void test_download_info(const std::string &name, const std::string &data)
{
	swarm::url_fetcher::request request;
	request.set_url(create_url("/download-info", {
		{ "name", name }
	}));

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

bool register_tests()
{
	helper = new data_container();
	helper->base_url.set_scheme("http");
	helper->base_url.set_host("localhost");
	helper->base_url.set_port(8080);
	helper->bucket_name = "rift_test";
	helper->bucket_token = "rift_password";

	RIFT_TEST_CASE_NOARGS(test_ping);
	RIFT_TEST_CASE_NOARGS(test_echo);
	RIFT_TEST_CASE(test_upload, "test", "test-data");
	RIFT_TEST_CASE(test_get, "test", "test-data");
	RIFT_TEST_CASE(test_download_info, "test", "test-data");

	return true;
}

}

int main(int argc, char *argv[])
{
	int err = unit_test_main(tests::register_tests, argc, argv);
	delete tests::helper;
	return err;
}
