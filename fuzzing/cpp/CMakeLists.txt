# libFuzzer harnesses for the C++ server.
#
# Requires a Clang toolchain (libFuzzer ships with clang).  Configure with:
#
#   CC=clang CXX=clang++ cmake -S fuzzing/cpp -B build-fuzz-cpp -DCMAKE_BUILD_TYPE=Debug
#   cmake --build build-fuzz-cpp
#
# Each target is a standalone libFuzzer binary built with AddressSanitizer +
# UndefinedBehaviorSanitizer.  Targets whose dependencies (Qt6 / protobuf) are
# not found are skipped with a message rather than failing the whole configure.

cmake_minimum_required(VERSION 3.20)
project(mumble_fuzz_cpp CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR
        "The C++ fuzz harnesses require Clang (libFuzzer). "
        "Re-run with: CC=clang CXX=clang++ cmake ...")
endif()

# Repo roots relative to this file (fuzzing/cpp).
get_filename_component(REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
set(SRC_DIR "${REPO_ROOT}/src")
set(MURMUR_DIR "${SRC_DIR}/murmur")

# Sanitizer + libFuzzer flags shared by every target.
set(FUZZ_FLAGS
    -g -O1 -fno-omit-frame-pointer
    -fsanitize=fuzzer,address,undefined
    -fno-sanitize-recover=undefined)

function(add_fuzz_target name)
    # Remaining args are extra source files.
    add_executable(${name} ${ARGN})
    target_compile_options(${name} PRIVATE ${FUZZ_FLAGS})
    target_link_options(${name} PRIVATE ${FUZZ_FLAGS})
endfunction()

# --- Qt-based harnesses (SSRF classifier, OpenGraph HTML parser, HTMLFilter) -
find_package(Qt6 COMPONENTS Core Network QUIET)
if(Qt6_FOUND)
    add_fuzz_target(fuzz_ssrf
        fuzz_ssrf.cpp
        "${MURMUR_DIR}/LinkPreviewPlugin.cpp")
    target_include_directories(fuzz_ssrf PRIVATE "${MURMUR_DIR}")
    target_link_libraries(fuzz_ssrf PRIVATE Qt6::Core Qt6::Network)

    add_fuzz_target(fuzz_opengraph
        fuzz_opengraph.cpp
        "${MURMUR_DIR}/OpenGraphPlugin.cpp"
        "${MURMUR_DIR}/LinkPreviewPlugin.cpp")
    target_include_directories(fuzz_opengraph PRIVATE "${MURMUR_DIR}")
    target_link_libraries(fuzz_opengraph PRIVATE Qt6::Core Qt6::Network)

    add_fuzz_target(fuzz_htmlfilter
        fuzz_htmlfilter.cpp
        "${SRC_DIR}/HTMLFilter.cpp")
    target_include_directories(fuzz_htmlfilter PRIVATE "${SRC_DIR}")
    target_link_libraries(fuzz_htmlfilter PRIVATE Qt6::Core)

    message(STATUS "fuzzing: Qt6 found - building fuzz_ssrf, fuzz_opengraph, fuzz_htmlfilter")
else()
    message(WARNING "fuzzing: Qt6 not found - skipping SSRF/OpenGraph/HTMLFilter harnesses")
endif()

# --- protobuf protocol harness ---------------------------------------------
find_package(Protobuf QUIET)
if(Protobuf_FOUND)
    set(PROTO_FILE "${SRC_DIR}/Mumble.proto")
    protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS "${PROTO_FILE}")
    add_fuzz_target(fuzz_protocol fuzz_protocol.cpp ${PROTO_SRCS})
    # Generated headers land in the build dir.
    target_include_directories(fuzz_protocol PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
    target_link_libraries(fuzz_protocol PRIVATE protobuf::libprotobuf)
    message(STATUS "fuzzing: protobuf found - building fuzz_protocol")
else()
    message(WARNING "fuzzing: protobuf not found - skipping protocol harness")
endif()
