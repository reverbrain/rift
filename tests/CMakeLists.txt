find_package(PythonInterp REQUIRED)

set(RIFT_SERVER "${CMAKE_CURRENT_BINARY_DIR}/../src/rift_server")
set(S3_SERVER "${CMAKE_CURRENT_BINARY_DIR}/../src/s3_server")

add_custom_target(test
    COMMAND virtualenv -p "${PYTHON_EXECUTABLE}" "${CMAKE_CURRENT_BINARY_DIR}" &&
    . "${CMAKE_CURRENT_BINARY_DIR}/bin/activate" &&
    pip install pytest requests boto &&
    export LD_LIBRARY_PATH="\${LD_LIBRARY_PATH}:${CMAKE_CURRENT_BINARY_DIR}/../src" &&
    py.test -x "${CMAKE_CURRENT_SOURCE_DIR}/tests.py" "--server=${RIFT_SERVER}" -v &&
    py.test -x "${CMAKE_CURRENT_SOURCE_DIR}/tests.py" --bucket=xxx "--server=${RIFT_SERVER}" "--s3server=${S3_SERVER}" -v
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    DEPENDS rift_server s3_server
)
