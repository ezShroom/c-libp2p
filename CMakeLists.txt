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

# Include directories: system/standard headers come first, then internal.
include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/src)

# Build the multiaddr library from its source files.
add_library(multiaddr
    src/multiformats/multiaddr/multiaddr.c
    src/multiformats/multiaddr/multiaddr_helpers.c
)

# Specify public include directories for the multiaddr library.
target_include_directories(multiaddr PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

# Build the test executable.
add_executable(test_multiaddr
    tests/multiformats/multiaddr/test_multiaddr.c
)

# Link the test executable with the multiaddr library.
target_link_libraries(test_multiaddr PRIVATE multiaddr)

# Organize test executables into a dedicated "tests" subdirectory in the build folder.
set_target_properties(test_multiaddr PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)

# Enable testing with CTest.
enable_testing()

# Register the test executable with CTest.
add_test(NAME TestMultiaddr COMMAND test_multiaddr)

# Optionally, set a timeout for tests (in seconds).
set_tests_properties(TestMultiaddr PROPERTIES TIMEOUT 10)