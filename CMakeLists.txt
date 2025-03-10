cmake_minimum_required(VERSION 3.10)

# Project metadata.
project(libp2p
    VERSION 0.1
    DESCRIPTION "C Libp2p implementation"
    LANGUAGES C
)

# Set the C standard.
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Set output directories for executables, libraries, and archives.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include public headers.
include_directories(${PROJECT_SOURCE_DIR}/include)

# ---------------------------------------------
# Build the unsigned_varint library.
# ---------------------------------------------
add_library(unsigned_varint
    src/multiformats/unsigned_varint/unsigned_varint.c
)
target_include_directories(unsigned_varint PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)
target_include_directories(unsigned_varint PRIVATE
    ${PROJECT_SOURCE_DIR}/src/multiformats/unsigned_varint
)

# Build the test executable for unsigned_varint.
add_executable(test_unsigned_varint
    tests/multiformats/unsigned_varint/test_unsigned_varint.c
)
target_link_libraries(test_unsigned_varint PRIVATE unsigned_varint)
set_target_properties(test_unsigned_varint PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)

# Build the benchmark executable for unsigned_varint.
add_executable(bench_unsigned_varint
    benchmarks/multiformats/unsigned_varint/bench_unsigned_varint.c
)
target_link_libraries(bench_unsigned_varint PRIVATE unsigned_varint)
set_target_properties(bench_unsigned_varint PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/benchmarks
)

# ---------------------------------------------
# Build the multicodec library.
# ---------------------------------------------
add_library(multicodec
    src/multiformats/multicodec/multicodec.c
)
target_include_directories(multicodec PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

# Build the test executable for multicodec.
add_executable(test_multicodec
    tests/multiformats/multicodec/test_multicodec.c
)
target_link_libraries(test_multicodec PRIVATE multicodec)
set_target_properties(test_multicodec PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)

# ---------------------------------------------
# Enable testing with CTest.
# ---------------------------------------------
enable_testing()
add_test(NAME TestUnsignedVarint COMMAND test_unsigned_varint)
add_test(NAME TestMulticodec COMMAND test_multicodec)
set_tests_properties(TestUnsignedVarint PROPERTIES TIMEOUT 10)
set_tests_properties(TestMulticodec PROPERTIES TIMEOUT 10)