import server
import rift_server
import rift_client
import pytest

def pytest_addoption(parser):
    parser.addoption("--server", action="store", help="path to rift_server binary")
    parser.addoption("--s3server", action="store", help="path to s3_server binary")
    parser.addoption("--remotes", action="store", help="comma-separated list of remote nodes")
    parser.addoption("--bucket", action="store", help="name of bucket")


def server_nodes(request):
    if request.config.option.remotes:
        return None

    servers = server.Server(xrange(1, 7))

    request.config.option.remotes = servers.remotes
    request.config.option.temporary_path = servers.path

    def fin():
        print("Stopping servers")
        servers.stop()
    request.addfinalizer(fin)

    return servers


def server_proxy(request, binary, port):
    proxy = rift_server.Server(request.config.option, binary, port)

    def fin():
        print("Stopping rift")
        proxy.stop()
    request.addfinalizer(fin)

    return proxy

@pytest.fixture(scope="session")
def client(request):
    server_nodes(request)
    server_proxy(request, request.config.option.server, 8080)
    if request.config.option.bucket:
        server_proxy(request, request.config.option.s3server, 8081)

    return rift_client.Client(request.config.option)