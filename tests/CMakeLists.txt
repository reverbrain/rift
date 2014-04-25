find_package(PythonInterp REQUIRED)

add_custom_target(test
    COMMAND virtualenv -p "${PYTHON_EXECUTABLE}" "${CMAKE_CURRENT_BINARY_DIR}" &&
    . "${CMAKE_CURRENT_BINARY_DIR}/bin/activate" &&
    pip install pytest requests &&
    export LD_LIBRARY_PATH="$ENV{LD_LIBRARY_PATH}:${CMAKE_CURRENT_BINARY_DIR}/../src" &&
    py.test "${CMAKE_CURRENT_SOURCE_DIR}/tests.py" "--server=${CMAKE_CURRENT_BINARY_DIR}/../src/rift_server" &&
    py.test "${CMAKE_CURRENT_SOURCE_DIR}/tests.py" --bucket=xxx "--server=${CMAKE_CURRENT_BINARY_DIR}/../src/rift_server"
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    DEPENDS rift_server
)
