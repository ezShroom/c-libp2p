# CMake minimum required version.
cmake_minimum_required(VERSION 3.10)

# Build using shared libraries by default
option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

# Project metadata.
project(libp2p
    VERSION 0.1
    DESCRIPTION "C Libp2p implementation"
    LANGUAGES C
)

if(APPLE)
  if("${CMAKE_OSX_ARCHITECTURES}" STREQUAL "")
    set(CMAKE_OSX_ARCHITECTURES "${CMAKE_SYSTEM_PROCESSOR}" CACHE STRING "Build architectures for macOS" FORCE)
    message(STATUS "Building for macOS architecture: ${CMAKE_OSX_ARCHITECTURES}")
  endif()
endif()

option(ENABLE_SANITIZERS "Enable Address, UndefinedBehavior, Thread, etc. Sanitizers" OFF)
set(SANITIZERS "address;undefined" CACHE STRING "List of sanitizers to enable (semicolon-separated)")

# ---------------------------------------------------------------------
# Static‑analysis / coverage options
# ---------------------------------------------------------------------
option(ENABLE_CLANG_TIDY "Run clang‑tidy static analysis" OFF)
option(ENABLE_CPPCHECK   "Run cppcheck static analysis"  OFF)
option(ENABLE_IWYU       "Run include‑what‑you‑use"      OFF)
option(ENABLE_COVERAGE   "Enable code‑coverage flags"    OFF)
option(ENABLE_STRESS_TESTS "Build and run high‑load stress tests" OFF)

if(ENABLE_SANITIZERS)
    set(_sanitizers ${SANITIZERS})
    list(JOIN _sanitizers "," _san_opt)
    message(STATUS "Building with sanitizers: ${_san_opt}")

    add_compile_options(-fsanitize=${_san_opt} -fno-omit-frame-pointer)
    add_link_options(-fsanitize=${_san_opt})
endif()

# ---------------------------------------------------------------------
# Static analysis integrations
# ---------------------------------------------------------------------
if(ENABLE_CLANG_TIDY)
    find_program(CLANG_TIDY_EXE NAMES clang-tidy)
    if(CLANG_TIDY_EXE)
        set(CMAKE_C_CLANG_TIDY "${CLANG_TIDY_EXE};--quiet")
        message(STATUS "clang-tidy enabled: ${CLANG_TIDY_EXE}")
    else()
        message(WARNING "clang-tidy requested but not found – disabling")
    endif()
endif()

if(ENABLE_CPPCHECK)
    find_program(CPPCHECK_EXE NAMES cppcheck)
    if(CPPCHECK_EXE)
        set(CMAKE_C_CPPCHECK "${CPPCHECK_EXE};--enable=all;--inconclusive;--std=c99;--quiet;--error-exitcode=1")
        message(STATUS "cppcheck enabled: ${CPPCHECK_EXE}")
    else()
        message(WARNING "cppcheck requested but not found – disabling")
    endif()
endif()

if(ENABLE_IWYU)
    find_program(IWYU_EXE NAMES include-what-you-use iwyu)
    if(IWYU_EXE)
        set(CMAKE_C_INCLUDE_WHAT_YOU_USE "${IWYU_EXE}")
        message(STATUS "include-what-you-use enabled: ${IWYU_EXE}")
    else()
        message(WARNING "include-what-you-use requested but not found – disabling")
    endif()
endif()

# ---------------------------------------------------------------------
# Code coverage
# ---------------------------------------------------------------------
if(ENABLE_COVERAGE)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(-O0 --coverage)
        add_link_options(--coverage)
        message(STATUS "Code coverage instrumentation enabled")
    else()
        message(WARNING "Code coverage currently supported only with GCC or Clang")
    endif()
endif()

# Pull in pthread/C11‐threads
find_package(Threads REQUIRED)

# ------------------------------------------------
# detect explicit_bzero() in <string.h>
# ------------------------------------------------
include(CheckFunctionExists)
check_function_exists(explicit_bzero HAVE_EXPLICIT_BZERO)

if(HAVE_EXPLICIT_BZERO)
  # system has it—tell the compiler to skip our fallback
  add_compile_definitions(HAVE_EXPLICIT_BZERO=1)
endif()

# Add the cmake directory to the module path
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

# Set the C standard.
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_definitions(_GNU_SOURCE)

# Set output directories for executables, libraries, and archives.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include public headers.
include_directories(BEFORE ${PROJECT_SOURCE_DIR}/include/protocol/tcp)
include_directories(${PROJECT_SOURCE_DIR}/include)

# (force the cache so that the secp256k1 CMakeLists picks them up as OFF)
set(SECP256K1_BUILD_TESTS            OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCHMARK        OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_CTIME_TESTS      OFF CACHE BOOL "" FORCE)

# Add secp256k1 submodule.
add_subdirectory(lib/secp256k1)

# Add libtommath submodule.
add_subdirectory(lib/libtommath)
set(libtommath_DIR "${CMAKE_BINARY_DIR}/lib/libtommath")

# Add libtomcrypt submodule.
add_subdirectory(lib/libtomcrypt)
target_compile_definitions(libtomcrypt PRIVATE USE_LTM LTM_DESC)

# Add noise-c submodule with crypto backends disabled.
set(USE_LIBSODIUM OFF CACHE BOOL "" FORCE)
set(USE_OPENSSL OFF CACHE BOOL "" FORCE)
add_subdirectory(lib/noise-c)
set_target_properties(noiseprotocol PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_sources(noiseprotocol PRIVATE ${CMAKE_SOURCE_DIR}/cmake/newhope_abs_shim.c)

# ---------------------------------------------------------------------------
# Workaround: MinGW/Windows build failure in Noise-C's NewHope implementation
# ---------------------------------------------------------------------------
# The file `error_correction.c` inside the Noise-C submodule defines a local
#   static int32_t abs(int32_t v)
# which collides with the standard C `abs()` declared in <math.h> on Windows
# (and pulled in indirectly by system headers).  We cannot patch the submodule
# in-place, so instead rename the local symbol *only for that translation
# unit*.  Using a per-source compile definition avoids side-effects elsewhere.

if (TARGET noiseprotocol)
    # Inject helper header globally (provides macro + inline impl)
    target_compile_options(noiseprotocol PRIVATE
        "-include${CMAKE_SOURCE_DIR}/cmake/noise_newhope_abs_fix.h")

    # Rename curve25519-donna helper fmul() to avoid libc conflict
    target_compile_options(noiseprotocol PRIVATE
        "-include${CMAKE_SOURCE_DIR}/cmake/noise_fmul_fix.h")

    # For the original NewHope source file, keep the macro but suppress the
    # inline implementation to avoid duplicate definitions.
    set_source_files_properties(
        ${PROJECT_SOURCE_DIR}/lib/noise-c/src/crypto/newhope/error_correction.c
        PROPERTIES
            COMPILE_DEFINITIONS "NEWHOPE_ABS_NO_IMPL"
    )
endif()

# Add libeddsa submodule.
add_subdirectory(lib/libeddsa)

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
    # Create the library (shared if BUILD_SHARED_LIBS=ON).
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

        # On Windows, copy all produced DLLs from bin/ into the test folder
        if (WIN32 AND BUILD_SHARED_LIBS)
          add_custom_command(TARGET test_${MODULE_NAME}
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_directory
              ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
              $<TARGET_FILE_DIR:test_${MODULE_NAME}>
          )
        endif()
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
# multiformats/multicodec/multicodec_table
# ---------------------------------------------
add_module(
    multicodec_table
    src/multiformats/multicodec/multicodec_table.c
    ""
    ""
    ""
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
target_link_libraries(multicodec PUBLIC multicodec_table)

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
target_link_libraries(multibase PRIVATE
    base16 base16_upper base32 base32_upper
    base58_btc base64 base64_url base64_url_pad
)

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
target_link_libraries(multiaddr PRIVATE multibase multicodec unsigned_varint base58_btc)
if (WIN32)
  target_link_libraries(multiaddr PRIVATE ws2_32)
endif()

# ---------------------------------------------
# peer_id/peer_id_proto
# ---------------------------------------------
add_module(
    peer_id_proto
    src/peer_id/peer_id_proto.c
    ""
    ""
    src/peer_id
)
target_link_libraries(peer_id_proto PRIVATE unsigned_varint)

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
target_link_libraries(peer_id_secp256k1 PRIVATE
    secp256k1 peer_id_proto
)
if (WIN32)
  target_link_libraries(peer_id_secp256k1 PRIVATE advapi32)
endif()

# ---------------------------------------------
# peer_id/peer_id_ed25519
# ---------------------------------------------
add_module(
    peer_id_ed25519
    src/peer_id/peer_id_ed25519.c
    ""
    ""
    src/peer_id
)
target_link_libraries(peer_id_ed25519 PRIVATE
    libtomcrypt peer_id_proto
)

# ---------------------------------------------
# peer_id/peer_id_ecdsa
# ---------------------------------------------
add_module(
    peer_id_ecdsa
    src/peer_id/peer_id_ecdsa.c
    ""
    ""
    src/peer_id
)
target_link_libraries(peer_id_ecdsa PRIVATE
    libtomcrypt peer_id_proto
)

# ---------------------------------------------
# peer_id/peer_id_rsa
# ---------------------------------------------
add_module(
    peer_id_rsa
    src/peer_id/peer_id_rsa.c
    ""
    ""
    src/peer_id
)
target_link_libraries(peer_id_rsa PRIVATE
    libtomcrypt peer_id_proto
)

# ---------------------------------------------
# peer_id
# ---------------------------------------------
add_module(
    peer_id
    src/peer_id/peer_id.c
    tests/peer_id/test_peer_id.c
    ""
    ""
)

target_link_libraries(peer_id
    PRIVATE
      peer_id_secp256k1
      peer_id_ed25519
      peer_id_ecdsa
      peer_id_rsa
      peer_id_proto
      unsigned_varint
      multibase
      multicodec
      multihash

    PUBLIC
      Threads::Threads
)

# ---------------------------------------------
# protocol/protocol_tcp
# ---------------------------------------------

add_module(
    protocol_tcp                              # MODULE_NAME  (library target)
    src/protocol/tcp/protocol_tcp.c            # MODULE_SOURCE
    tests/protocol/tcp/test_protocol_tcp.c     # TEST_SOURCE
    ""                                         # BENCH_SOURCE (none yet)
    src/protocol/tcp                           # PRIVATE_DIR  (extra includes)
)

# Link against multiaddr (which already carries all its deps) and Threads.
target_link_libraries(protocol_tcp
    PUBLIC multiaddr Threads::Threads
)

target_sources(protocol_tcp PRIVATE
    src/protocol/tcp/protocol_tcp_util.c
    src/protocol/tcp/protocol_tcp_conn.c
    src/protocol/tcp/protocol_tcp_queue.c
    src/protocol/tcp/protocol_tcp_poller.c
    src/protocol/tcp/protocol_tcp_dial.c
    src/protocol/tcp/protocol_tcp_listen.c
)


# Windows needs Winsock; *nix already linked via libc.
if (WIN32)
    target_link_libraries(protocol_tcp PRIVATE ws2_32)
endif()

# -----------------------------------------------------------------
# protocol/tcp high‑load stress test (optional)
# -----------------------------------------------------------------
if(ENABLE_STRESS_TESTS)
    add_executable(test_protocol_tcp_stress
        tests/protocol/tcp/test_protocol_tcp_stress.c
    )
    target_link_libraries(test_protocol_tcp_stress
        PRIVATE
            protocol_tcp
            Threads::Threads
    )
    set_target_properties(test_protocol_tcp_stress PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
    )

    add_test(NAME Teststress_protocol_tcp COMMAND test_protocol_tcp_stress)
    # Stress jobs can run for a while – no timeout (0 = infinite)
    set_tests_properties(Teststress_protocol_tcp PROPERTIES TIMEOUT 60)

    # On Windows, copy produced DLLs next to the test binary
    if (WIN32 AND BUILD_SHARED_LIBS)
        add_custom_command(TARGET test_protocol_tcp_stress
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
                $<TARGET_FILE_DIR:test_protocol_tcp_stress>
        )
    endif()
endif()


# ---------------------------------------------
# protocol/protocol_multiselect
# ---------------------------------------------
add_module(
    protocol_multiselect                                   # MODULE_NAME  (library)
    src/protocol/multiselect/protocol_multiselect.c        # MODULE_SOURCE
    tests/protocol/multiselect/test_protocol_multiselect.c  # TEST_SOURCE
    ""                                            # BENCH_SOURCE (none)
    src/protocol/multiselect                      # PRIVATE_DIR
)

target_link_libraries(protocol_multiselect PUBLIC unsigned_varint)

if (TARGET test_protocol_multiselect)
    target_link_libraries(test_protocol_multiselect
        PRIVATE
            protocol_tcp
            Threads::Threads
    )
    # handshake-based tests sometimes take longer than the default
    # timeout, so extend it for reliability
    set_tests_properties(Testprotocol_multiselect PROPERTIES TIMEOUT 20)
endif()

# ---------------------------------------------
# protocol/noise
# ---------------------------------------------
add_module(
    protocol_noise
    "src/protocol/noise/protocol_noise.c;src/protocol/noise/protocol_noise_conn.c;src/protocol/noise/protocol_noise_extensions.c;src/protocol/noise/protocol_noise_multiselect.c"
    tests/protocol/noise/test_protocol_noise.c
    ""
    src/protocol/noise
)

# protocol_noise depends on unsigned varint encoding/decoding helpers as part of
# the handshake payload (see src/protocol/noise/protocol_noise.c).  Without this
# link the final build fails with undefined symbol errors for
# `unsigned_varint_encode`/`unsigned_varint_decode` when creating the shared
# library.  Add the dependency explicitly so the correct archive/dylib is linked
# in.

target_link_libraries(protocol_noise PUBLIC
    libtomcrypt
    wjcryptlib
    sha3
    noiseprotocol
    protocol_multiselect
    eddsa
    peer_id_proto
    peer_id
    peer_id_ecdsa
    peer_id_rsa
    secp256k1
    unsigned_varint
)

# ---------------------------------------------
# protocol/identify
# ---------------------------------------------
add_module(
    protocol_identify
    src/protocol/identify/protocol_identify.c
    tests/protocol/identify/test_protocol_identify.c
    ""
    src/protocol/identify
)
target_link_libraries(protocol_identify PUBLIC unsigned_varint protocol_handler)

# ---------------------------------------------
# protocol/protocol_handler (high-level protocol handler system)
# ---------------------------------------------
add_module(
    protocol_handler
    src/protocol/protocol_handler.c
    ""
    ""
    src/protocol
)
target_link_libraries(protocol_handler PUBLIC protocol_multiselect protocol_mplex protocol_yamux Threads::Threads)

# ---------------------------------------------
# protocol/ping
# ---------------------------------------------
add_module(
    protocol_ping
    src/protocol/ping/protocol_ping.c
    tests/protocol/ping/test_protocol_ping.c
    ""
    src/protocol/ping
)

# ---------------------------------------------
# protocol/mplex
# ---------------------------------------------
add_module(
    protocol_mplex
    "src/protocol/mplex/protocol_mplex.c;src/protocol/mplex/protocol_mplex_queue.c;src/protocol/mplex/protocol_mplex_codec.c;src/protocol/mplex/protocol_mplex_handshake.c;src/protocol/mplex/protocol_mplex_stream_array.c"
    tests/protocol/mplex/test_protocol_mplex.c
    ""
    src/protocol/mplex
)
target_link_libraries(protocol_mplex
    PUBLIC
        protocol_multiselect
        protocol_tcp
)
target_sources(protocol_mplex PRIVATE src/transport/conn_util.c)

if (TARGET test_protocol_mplex)
    target_link_libraries(test_protocol_mplex
        PRIVATE
            protocol_tcp
            Threads::Threads
    )
    # negotiation and frame roundtrip may take slightly longer on
    # slower systems, so allow a bit more time
    set_tests_properties(Testprotocol_mplex PROPERTIES TIMEOUT 20)
endif()

# ---------------------------------------------
# protocol/yamux
# ---------------------------------------------
add_module(
    protocol_yamux
    "src/protocol/yamux/protocol_yamux.c;src/protocol/yamux/protocol_yamux_queue.c"
    tests/protocol/yamux/test_protocol_yamux.c
    ""
    src/protocol/yamux
)
target_link_libraries(protocol_yamux
    PUBLIC
        protocol_multiselect
        protocol_tcp
)

target_sources(protocol_yamux PRIVATE src/transport/conn_util.c)
# Windows needs Winsock for network byte order functions
if (WIN32)
    target_link_libraries(protocol_yamux PRIVATE ws2_32)
endif()

if (TARGET test_protocol_yamux)
    target_link_libraries(test_protocol_yamux
        PRIVATE
            protocol_tcp
            Threads::Threads
    )
    set_tests_properties(Testprotocol_yamux PROPERTIES TIMEOUT 60)
endif()

if (TARGET test_protocol_noise)
    target_link_libraries(test_protocol_noise
        PRIVATE
            protocol_tcp
            protocol_mplex
            multiaddr
            secp256k1
            unsigned_varint
            eddsa
            peer_id_ed25519
            peer_id_ecdsa
            peer_id_rsa
            Threads::Threads
    )
    # Provide access to eddsa public headers for the test source
    target_include_directories(test_protocol_noise PRIVATE ${PROJECT_SOURCE_DIR}/lib/libeddsa/lib)

    # Noise handshake test suite can take a while on Windows CI – allow 60 s.
    set_tests_properties(Testprotocol_noise PROPERTIES TIMEOUT 60)
endif()

# ---------------------------------------------
# transport/upgrader
# ---------------------------------------------
add_module(
    transport_upgrader
    src/transport/upgrader.c
    tests/transport/test_upgrader.c
    ""
    src/transport
)

target_link_libraries(transport_upgrader PUBLIC protocol_noise protocol_mplex)

if (TARGET test_transport_upgrader)
    target_link_libraries(test_transport_upgrader
        PRIVATE
            protocol_tcp
            multiaddr
            eddsa
            peer_id
            peer_id_ed25519
            Threads::Threads
    )
    target_include_directories(test_transport_upgrader PRIVATE ${PROJECT_SOURCE_DIR}/lib/libeddsa/lib)
endif()

# -----------------------------------------------------------------
# Example dial for identify protocol
# -----------------------------------------------------------------

add_executable(example_identify_dial
    examples/example_identify_dial.c
)
target_link_libraries(example_identify_dial
    PRIVATE
        protocol_tcp
        protocol_noise
        protocol_mplex
        protocol_yamux
        protocol_identify
        protocol_handler
        transport_upgrader
        multiaddr
        unsigned_varint
        peer_id
        peer_id_secp256k1
        Threads::Threads
)
set_target_properties(example_identify_dial PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/examples
)

# On Windows, copy all produced DLLs from bin/ into the examples folder
if (WIN32 AND BUILD_SHARED_LIBS)
  add_custom_command(TARGET example_identify_dial
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
      ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
      $<TARGET_FILE_DIR:example_identify_dial>
  )
endif()

# -----------------------------------------------------------------
# interop binary
# -----------------------------------------------------------------
add_executable(interop-c
    src/interop/interop.c
)
target_link_libraries(interop-c
    PRIVATE
        protocol_tcp
        protocol_noise
        protocol_yamux
        protocol_mplex
        protocol_ping
        transport_upgrader
        multiaddr
        peer_id
        peer_id_ed25519
        protocol_handler
        Threads::Threads
)
set_target_properties(interop-c PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)
add_executable(test_interop tests/interop/test_interop.c)
target_link_libraries(test_interop PRIVATE Threads::Threads)
set_target_properties(test_interop PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)
add_test(NAME Testinterop COMMAND test_interop)