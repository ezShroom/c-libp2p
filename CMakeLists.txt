# CMake minimum required version.
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

# Add secp256k1 submodule.
add_subdirectory(lib/secp256k1)

# ---------------------------------------------
# Helper function for adding a module.
# ---------------------------------------------
#
# Parameters:
#   MODULE_NAME   - Name of the library target.
#   MODULE_SOURCE - Source file for the library.
#   TEST_SOURCE   - Source file for the test executable.
#   BENCH_SOURCE  - (Optional) Source file for the benchmark executable.
#   PRIVATE_DIR   - (Optional) Relative path for additional private include directories.
#
function(add_module MODULE_NAME MODULE_SOURCE TEST_SOURCE BENCH_SOURCE PRIVATE_DIR)
    # Create the library.
    add_library(${MODULE_NAME} ${MODULE_SOURCE})
    target_include_directories(${MODULE_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include)
    if(NOT "${PRIVATE_DIR}" STREQUAL "")
        target_include_directories(${MODULE_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/${PRIVATE_DIR})
    endif()

    # Create the test executable.
    if(NOT "${TEST_SOURCE}" STREQUAL "")
        add_executable(test_${MODULE_NAME} ${TEST_SOURCE})
        target_link_libraries(test_${MODULE_NAME} PRIVATE ${MODULE_NAME})
        set_target_properties(test_${MODULE_NAME} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
        )
        add_test(NAME Test${MODULE_NAME} COMMAND test_${MODULE_NAME})
        set_tests_properties(Test${MODULE_NAME} PROPERTIES TIMEOUT 10)
    endif()

    # Create the benchmark executable if provided.
    if(NOT "${BENCH_SOURCE}" STREQUAL "")
        add_executable(bench_${MODULE_NAME} ${BENCH_SOURCE})
        target_link_libraries(bench_${MODULE_NAME} PRIVATE ${MODULE_NAME})
        set_target_properties(bench_${MODULE_NAME} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/benchmarks
        )
    endif()
endfunction()

# Enable testing with CTest.
enable_testing()

# ---------------------------------------------
# multiformats/unsigned_varint
# ---------------------------------------------
add_module(
    unsigned_varint
    src/multiformats/unsigned_varint/unsigned_varint.c
    tests/multiformats/unsigned_varint/test_unsigned_varint.c
    benchmarks/multiformats/unsigned_varint/bench_unsigned_varint.c
    src/multiformats/unsigned_varint
)

# ---------------------------------------------
# multiformats/multicodec
# ---------------------------------------------
add_module(
    multicodec
    src/multiformats/multicodec/multicodec.c
    tests/multiformats/multicodec/test_multicodec.c
    ""
    ""
)

# ---------------------------------------------
# multiformats/multibase/encoding/base16
# ---------------------------------------------
add_module(
    base16
    src/multiformats/multibase/encoding/base16.c
    tests/multiformats/multibase/test_base16.c
    benchmarks/multiformats/multibase/bench_base16.c
    src/multiformats/multibase
)

# ---------------------------------------------
# multiformats/multibase/encoding/base16_upper
# ---------------------------------------------
add_module(
    base16_upper
    src/multiformats/multibase/encoding/base16_upper.c
    tests/multiformats/multibase/test_base16_upper.c
    benchmarks/multiformats/multibase/bench_base16_upper.c
    src/multiformats/multibase
)

# ---------------------------------------------
# multiformats/multibase/encoding/base32
# ---------------------------------------------
add_module(
    base32
    src/multiformats/multibase/encoding/base32.c
    tests/multiformats/multibase/test_base32.c
    ""
    ""
)

# ---------------------------------------------
# multiformats/multibase/encoding/base32_upper
# ---------------------------------------------
add_module(
    base32_upper
    src/multiformats/multibase/encoding/base32_upper.c
    tests/multiformats/multibase/test_base32_upper.c
    ""
    ""
)

# ---------------------------------------------
# multiformats/multibase/encoding/base58_btc
# ---------------------------------------------
add_module(
    base58_btc
    src/multiformats/multibase/encoding/base58_btc.c
    tests/multiformats/multibase/test_base58_btc.c
    ""
    ""
)

# ---------------------------------------------
# multiformats/multibase/encoding/base64
# ---------------------------------------------
add_module(
    base64
    src/multiformats/multibase/encoding/base64.c
    tests/multiformats/multibase/test_base64.c
    ""
    ""
)

# ---------------------------------------------
# multiformats/multibase/encoding/base64_url
# ---------------------------------------------
add_module(
    base64_url
    src/multiformats/multibase/encoding/base64_url.c
    tests/multiformats/multibase/test_base64_url.c
    ""
    ""
)

# ---------------------------------------------
# multiformats/multibase/encoding/base64_url_pad
# ---------------------------------------------
add_module(
    base64_url_pad
    src/multiformats/multibase/encoding/base64_url_pad.c
    tests/multiformats/multibase/test_base64_url_pad.c
    ""
    ""
)

# ---------------------------------------------
# multiformats/multibase/multibase
# ---------------------------------------------
add_module(
    multibase
    src/multiformats/multibase/multibase.c
    tests/multiformats/multibase/test_multibase.c
    ""
    ""
)
target_link_libraries(multibase PRIVATE base16 base16_upper base32 base32_upper base58_btc base64 base64_url base64_url_pad)

# ---------------------------------------------
# wjcryptlib
# ---------------------------------------------
add_library(wjcryptlib
    lib/wjcryptlib/lib/WjCryptLib_Sha256.c
    lib/wjcryptlib/lib/WjCryptLib_Sha512.c
)
target_include_directories(wjcryptlib PUBLIC ${PROJECT_SOURCE_DIR}/lib/wjcryptlib/lib)

# ---------------------------------------------
# sha3
# ---------------------------------------------
add_library(sha3
    lib/sha3/sha3.c
)
target_include_directories(sha3 PUBLIC ${PROJECT_SOURCE_DIR}/lib/sha3/lib)

# ---------------------------------------------
# multiformats/multihash
# ---------------------------------------------
add_module(
    multihash
    src/multiformats/multihash/multihash.c
    tests/multiformats/multihash/test_multihash.c
    ""
    ""
)
target_link_libraries(multihash PRIVATE multicodec unsigned_varint wjcryptlib sha3)

# ---------------------------------------------
# peer_id/peer_id_secp256k1
# ---------------------------------------------
add_module(
    peer_id_secp256k1
    src/peer_id/peer_id_secp256k1.c
    ""
    ""
    src/peer_id
)
target_link_libraries(peer_id_secp256k1 PRIVATE secp256k1)

# ---------------------------------------------
# multiformats/cid_v0
# ---------------------------------------------
add_module(
    cid_v0
    src/multiformats/cid/cid_v0.c
    tests/multiformats/cid/test_cid_v0.c
    ""
    ""
)
target_link_libraries(cid_v0 PRIVATE base58_btc multicodec unsigned_varint)

# ---------------------------------------------
# multiformats/cid_v1
# ---------------------------------------------
add_module(
    cid_v1
    src/multiformats/cid/cid_v1.c
    tests/multiformats/cid/test_cid_v1.c
    ""
    ""
)
target_link_libraries(cid_v1 PRIVATE multibase multicodec unsigned_varint)

# ---------------------------------------------
# multiformats/multiaddr
# ---------------------------------------------
add_module(
    multiaddr
    src/multiformats/multiaddr/multiaddr.c
    tests/multiformats/multiaddr/test_multiaddr.c
    ""
    ""
)
target_link_libraries(multiaddr PRIVATE multibase multicodec unsigned_varint)

