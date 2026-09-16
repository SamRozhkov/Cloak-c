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
# Guarded by CLOAK_REQUIRE_GO, which libcloak-server/tests/CMakeLists.txt
# defines (and documents) -- with it off, test_ws_interop does not exist,
# so neither should the oracle it runs.
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
if(CLOAK_REQUIRE_GO)

set(_cloak_oracle_dir ${CMAKE_SOURCE_DIR}/libcloak-server/tests/ws_interop_oracle)
set(_cloak_oracle_bin ${CMAKE_BINARY_DIR}/ws_interop_oracle)

# THE MESSAGE EVERY FAILURE BELOW ENDS WITH. One string, so a missing
# toolchain and an unpopulated module cache cannot drift into saying
# different things about the same fix.
set(_cloak_go_help
    "Dockerfile.dev installs a Go toolchain at /usr/local/go/bin/go and "
    "pre-downloads github.com/gorilla/websocket into the image's module "
    "cache (GOPATH=/go, GOMODCACHE=/go/pkg/mod), which is what this test "
    "is built and run in. Build in that image, or populate a module cache "
    "yourself, or configure with -DCLOAK_REQUIRE_GO=OFF -- which REMOVES "
    "test_ws_interop and drops the suite from 68 tests to 67.")

# CLEARING `PATH` DOES NOT SIMULATE A MISSING TOOLCHAIN, AND ANYONE WHO
# "VERIFIES" THE DIAGNOSTIC BELOW THAT WAY HAS VERIFIED NOTHING.
# `HINTS /usr/local/go/bin` is not a last resort: find_program searches
# HINTS ahead of the environment, so `env PATH= cmake ...` finds the dev
# image's Go anyway and configure SUCCEEDS. The hint has to stay -- it is
# what makes this configure outside a login shell -- so the escape is an
# explicit switch instead, and it is here ONLY so that the one state this
# guard exists for can be reached without uninstalling Go from the machine:
#
#     cmake -DCLOAK_GO_FORCE_ABSENT=ON ...   -> the FATAL_ERROR below
#
# It is not a way to build without Go. That is -DCLOAK_REQUIRE_GO=OFF, which
# removes test_ws_interop and says so; this one makes the build FAIL, which
# is the whole point of exercising it.
option(CLOAK_GO_FORCE_ABSENT
       "Pretend no Go toolchain exists, to exercise the missing-toolchain diagnostic" OFF)
if(CLOAK_GO_FORCE_ABSENT)
    # A normal variable, shadowing any cache entry a previous configure
    # left behind, so this works in an already-configured build tree too.
    set(CLOAK_GO_EXECUTABLE "")
else()
    find_program(CLOAK_GO_EXECUTABLE NAMES go HINTS /usr/local/go/bin)
endif()
if(NOT CLOAK_GO_EXECUTABLE)
    # Loud rather than silent. A skipped test in a suite whose count is
    # part of its contract (67 -> 68 in this module) is indistinguishable
    # from a passing one in `ctest` output, and this is the ONLY test in
    # the tree whose peer is not our own code -- losing it quietly is
    # exactly the failure mode module 8 exists to close.
    message(FATAL_ERROR
        "test_ws_interop needs a Go toolchain to build its interoperability "
        "oracle (libcloak-server/tests/ws_interop_oracle), and none was found. "
        ${_cloak_go_help})
endif()

# AND THE MODULE, NOT ONLY THE TOOLCHAIN. find_program alone catches a
# machine with no Go; it does NOT catch the likelier failure outside the
# image -- a machine that has Go but no cached gorilla/websocket, which
# under GOPROXY=off dies at BUILD time with a bare
# "module lookup disabled by GOPROXY=off" and never mentions
# Dockerfile.dev. Measured: `cmake --build` with GOMODCACHE pointed at an
# empty directory printed exactly that and nothing else.
#
# `go list -deps .` is the probe rather than `go list -m gorilla/websocket`
# because it resolves EVERY import of the oracle's own packages -- the
# vendored x/crypto/salsa20 copy included -- so it fails for a missing
# module, an unextracted one, or a vendored package that does not compile
# in this toolchain's version. It costs about a third of a second and it
# runs at CONFIGURE time, where a diagnosis is read, rather than at build
# time, where it is buried under four lines of make errors.
execute_process(
    COMMAND ${CMAKE_COMMAND} -E env GOPROXY=off GOFLAGS=-mod=mod
            ${CLOAK_GO_EXECUTABLE} list -deps .
    WORKING_DIRECTORY ${_cloak_oracle_dir}
    RESULT_VARIABLE _cloak_go_deps_rc
    OUTPUT_QUIET
    ERROR_VARIABLE _cloak_go_deps_err)
if(NOT _cloak_go_deps_rc EQUAL 0)
    message(FATAL_ERROR
        "test_ws_interop's Go oracle cannot resolve its dependencies with "
        "${CLOAK_GO_EXECUTABLE} (`go list -deps .` in ${_cloak_oracle_dir} "
        "exited ${_cloak_go_deps_rc}). Go said:\n${_cloak_go_deps_err}\n"
        ${_cloak_go_help})
endif()

file(GLOB_RECURSE _cloak_oracle_srcs CONFIGURE_DEPENDS
     ${_cloak_oracle_dir}/*.go ${_cloak_oracle_dir}/*.s
     ${_cloak_oracle_dir}/go.mod ${_cloak_oracle_dir}/go.sum)
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

endif()
