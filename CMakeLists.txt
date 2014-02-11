project(rift)
cmake_minimum_required(VERSION 2.6)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x -W -Wall -Wextra -fstack-protector-all")

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/debian/changelog" DEBCHANGELOG)

string(REGEX MATCH "([0-9]+\\.[0-9]+\\.[0-9]+)" DEBFULLVERSION "${DEBCHANGELOG}")
string(REGEX MATCH "([0-9]+\\.[0-9]+)" RIFT_VERSION_ABI "${DEBFULLVERSION}")
string(REGEX MATCH "([0-9]+$)" RIFT_VERSION_MINOR "${DEBFULLVERSION}")

include(cmake/locate_library.cmake)

LOCATE_LIBRARY(THEVOID "thevoid/server.hpp" "thevoid")
LOCATE_LIBRARY(SWARM "swarm/http_response.hpp" "swarm")
LOCATE_LIBRARY(SWARM_URLFETCHER "swarm/http_response.hpp" "swarm_urlfetcher")
LOCATE_LIBRARY(MSGPACK "msgpack.hpp" "msgpack")

find_package(Boost COMPONENTS system thread program_options REQUIRED)
find_package(Elliptics 2.25 REQUIRED)

include_directories(
	"${CMAKE_CURRENT_SOURCE_DIR}/include"
	${Boost_INCLUDE_DIRS}
	${MSGPACK_INCLUDE_DIRS}
	${THEVOID_INCLUDE_DIRS}
	${SWARM_INCLUDE_DIRS}
	${ELLIPTICS_INCLUDE_DIRS}
)

link_directories(
	${Boost_LIBRARY_DIRS}
	${MSGPACK_LIBRARY_DIRS}
	${THEVOID_LIBRARY_DIRS}
)

add_subdirectory(src)

file(GLOB headers "${CMAKE_CURRENT_SOURCE_DIR}/include/rift/*.hpp")
install(FILES ${headers} DESTINATION include/rift)
