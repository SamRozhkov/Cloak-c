cmake_minimum_required(VERSION 3.16)
project(cloak-c C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

add_compile_options(-Wall -Wextra)

enable_testing()

add_subdirectory(third_party/cjson)
add_subdirectory(third_party/sqlite)
add_subdirectory(libcloak-common)
add_subdirectory(libcloak-mux)
add_subdirectory(libcloak-server)
add_subdirectory(libcloak-client)

# The binaries. Appended rather than folded into the list above so this
# file's existing content stays byte-identical; the libraries must be
# declared first either way, since an executable links them.
add_subdirectory(cmd/ck-server)

# ck-client comes after ck-server because its test drives BOTH binaries
# and names ck-server as a target dependency.
add_subdirectory(cmd/ck-client)

# ---------------------------------------------------------------------------
# The interoperability test's two outside dependencies.
#
# APPENDED here, after both add_subdirectory calls above, because
# test_ws_interop needs a target declared in libcloak-server/tests and two
# things that only exist further down this file: the ck-server EXECUTABLE
# it drives as a subprocess, and a Go toolchain.
#
# THE GO ORACLE IS BUILT AT BUILD TIME, NOT AT TEST TIME. `go build` warms
# a cache the first time and costs milliseconds afterwards, but doing it
# inside the test would put a compiler on the test's clock -- and this
# project's test bounds are set from the worst FAILING run, where a
# toolchain error would be reported as a timeout with its own message cut
# off. Building here reports it as a build failure, which is what it is.
# GOPROXY=off and GOFLAGS=-mod=mod because the image pre-downloads
# gorilla/websocket into its module cache and has no network; GOCACHE is
# left at its default, which the image's HOME provides.
find_program(CLOAK_GO_EXECUTABLE NAMES go HINTS /usr/local/go/bin)
if(NOT CLOAK_GO_EXECUTABLE)
    # Loud rather than silent. A skipped test in a suite whose count is
    # part of its contract (67 -> 68 in this module) is indistinguishable
    # from a passing one in `ctest` output, and this is the ONLY test in
    # the tree whose peer is not our own code -- losing it quietly is
    # exactly the failure mode module 8 exists to close.
    message(FATAL_ERROR
        "test_ws_interop needs a Go toolchain to build its interoperability "
        "oracle (libcloak-server/tests/ws_interop_oracle), and none was found. "
        "Dockerfile.dev installs one at /usr/local/go/bin/go and pre-downloads "
        "github.com/gorilla/websocket into the image's module cache; build in "
        "that image, or put `go` on PATH.")
endif()

set(_cloak_oracle_dir ${CMAKE_SOURCE_DIR}/libcloak-server/tests/ws_interop_oracle)
set(_cloak_oracle_bin ${CMAKE_BINARY_DIR}/ws_interop_oracle)
file(GLOB_RECURSE _cloak_oracle_srcs CONFIGURE_DEPENDS
     ${_cloak_oracle_dir}/*.go ${_cloak_oracle_dir}/go.mod ${_cloak_oracle_dir}/go.sum)
add_custom_command(
    OUTPUT ${_cloak_oracle_bin}
    COMMAND ${CMAKE_COMMAND} -E env GOPROXY=off GOFLAGS=-mod=mod
            ${CLOAK_GO_EXECUTABLE} build -o ${_cloak_oracle_bin} .
    WORKING_DIRECTORY ${_cloak_oracle_dir}
    DEPENDS ${_cloak_oracle_srcs}
    COMMENT "Building the Go interoperability oracle (gorilla/websocket)"
    VERBATIM)
# The target name deliberately differs from the output FILE name: make
# treats a custom target whose name matches a file in the same directory
# as a circular dependency on itself.
add_custom_target(ws_interop_oracle_build ALL DEPENDS ${_cloak_oracle_bin})

add_dependencies(test_ws_interop ck-server ws_interop_oracle_build)
target_compile_definitions(test_ws_interop PRIVATE
    CK_SERVER_PATH="$<TARGET_FILE:ck-server>"
    ORACLE_PATH="${_cloak_oracle_bin}")
