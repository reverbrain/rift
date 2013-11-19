set(RIFT_SOURCES
	auth.cpp
	cache.cpp
	server.cpp
	signature.cpp
)

add_library(rift SHARED ${RIFT_SOURCES})
target_link_libraries(rift
	${ELLIPTICS_LIBRARIES}
	${THEVOID_LIBRARIES}
	${SWARM_LIBRARIES}
	${SWARM_URLFETCHER_LIBRARIES}
)

set_target_properties(rift PROPERTIES
	VERSION ${DEBFULLVERSION}
	SOVERSION ${RIFT_VERSION_ABI}
)

add_executable(rift_server main.cpp)
target_link_libraries(rift_server rift)

install(TARGETS rift_server
	RUNTIME DESTINATION bin
	COMPONENT runtime
)

install(TARGETS rift
	LIBRARY DESTINATION lib${LIB_SUFFIX}
	ARCHIVE DESTINATION lib${LIB_SUFFIX}
	BUNDLE DESTINATION library
)
