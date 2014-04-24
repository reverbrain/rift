set(ENV{LD_LIBRARY_PATH} "$ENV{LD_LIBRARY_PATH}:${CMAKE_CURRENT_BINARY_DIR}/../src")

add_custom_target(test
    COMMAND py.test "${CMAKE_CURRENT_SOURCE_DIR}/tests.py" "--server=${CMAKE_CURRENT_BINARY_DIR}/../src/rift_server"
    COMMAND py.test "${CMAKE_CURRENT_SOURCE_DIR}/tests.py" --bucket=xxx "--server=${CMAKE_CURRENT_BINARY_DIR}/../src/rift_server"
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    DEPENDS rift_server)
