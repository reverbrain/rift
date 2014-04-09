set(RIFT_SOURCES
        async_performer.cpp
	auth.cpp
	bucket.cpp
	cache.cpp
        metadata_updater.cpp
	signature.cpp
)
file(GLOB RIFT_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/../include/rift/*.hpp")

add_library(rift SHARED ${RIFT_SOURCES} ${RIFT_HEADERS})
target_link_libraries(rift
	${ELLIPTICS_LIBRARIES}
	${THEVOID_LIBRARIES}
	${SWARM_LIBRARIES}
	${SWARM_URLFETCHER_LIBRARIES}
	${Boost_LIBRARIES}
)

add_library(rift_server_common STATIC
	server.hpp
	server.cpp
)
target_link_libraries(rift_server_common
	rift
)

set_target_properties(rift PROPERTIES
	VERSION ${DEBFULLVERSION}
	SOVERSION ${RIFT_VERSION_ABI}
)

add_executable(rift_server main.cpp)
target_link_libraries(rift_server rift rift_server_common ${Boost_LIBRARIES})

add_executable(rift_tests tests.cpp)
target_link_libraries(rift_tests rift rift_server_common ${SWARM_LIBRARIES} ${SWARM_URLFETCHER_LIBRARIES} ${Boost_LIBRARIES})

install(TARGETS rift_server
	RUNTIME DESTINATION bin
	COMPONENT runtime
)

install(TARGETS rift
	LIBRARY DESTINATION lib${LIB_SUFFIX}
	ARCHIVE DESTINATION lib${LIB_SUFFIX}
	BUNDLE DESTINATION library
)
