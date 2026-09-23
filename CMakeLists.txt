cmake_minimum_required(VERSION 3.16)
project(cloak-c C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

add_compile_options(-Wall -Wextra)

# ---------------------------------------------------------------------------
# Version stamping for release artefacts.
#
# `-DCLOAK_VERSION=v1.2.3` makes `ck-server -v` and `ck-client -v` report
# that tag instead of the in-tree default. The release workflow passes the
# tag it was triggered by; nobody else needs to pass anything.
#
# A leading "v" is stripped so that the conventional tag name `v1.2.3`
# produces `cloak-c-1.2.3` rather than the doubled `cloak-c-v1.2.3`.
#
# Left unset -- which is every developer build and every CI run that is not
# a tag -- libcloak-common/src/version.c keeps returning its own literal,
# "cloak-c-0.1.0-dev". That default is load-bearing: test_ck_server_cli.c
# and test_ck_client_cli.c each assert `-v` contains "0.1.0-dev", so a
# build that stamped unconditionally would turn those two red.
# ---------------------------------------------------------------------------
if(CLOAK_VERSION)
    string(REGEX REPLACE "^v" "" CLOAK_VERSION_CLEAN "${CLOAK_VERSION}")
    add_compile_definitions(CLOAK_VERSION_STRING="cloak-c-${CLOAK_VERSION_CLEAN}")
    message(STATUS "cloak-c: version stamped as cloak-c-${CLOAK_VERSION_CLEAN}")
endif()

enable_testing()

# ---------------------------------------------------------------------------
# The fast/slow label split (module 9 task 0).
#
# Module 9 is about to add several tests that fork external processes --
# including two that fork Go binaries and a UDP echo each -- on top of the
# four that already do today (test_proxy_stream and test_ws_interop in
# libcloak-server/tests, test_ck_server_cli and test_ck_client_cli under
# cmd/): every one of the four forks a real child with fork(2), three of the
# four also exec a real binary, and grep across the whole tree for
# fork/vfork/exec*/posix_spawn/system finds no other caller. THIS WAS
# VERIFIED BY READING AND GREPPING THE TESTS, NOT ASSUMED: the inherited
# claim from module 8 that "the four slowest tests all fork processes" does
# NOT hold -- measured before this split (68/68 at -j4, ~24 s), the two
# slowest tests by wall clock were test_adminapi and test_dispatcher_ws
# (~12.5 s and ~12.4 s each), and NEITHER forks a process; of the four tests
# that actually fork, three (test_proxy_stream, test_ws_interop and
# test_ck_server_cli) are among the FASTEST tests in the whole suite in a
# plain Debug build (0.26 s, 0.92 s and 0.32 s) -- the fork/exec cost only
# bites under ASan+UBSan's LeakSanitizer exit scan on every child process,
# per test_ck_server_cli's and test_ck_client_cli's own TIMEOUT comments
# (~40 s and ~53 s under the sanitizer, ~0.2-9 s in Debug). So labelling by
# "is currently slow" would mislabel test_adminapi and test_dispatcher_ws as
# slow (they aren't the target -- they don't fork, and nothing about them
# changes here) while mislabelling three of today's four forking tests as
# fast. Labelling by fork-or-not is the durable split this task asks for:
# it is exactly what module 9's new oracle tests will do, and it is what
# turns brutal under a sanitizer build, which is where an edit loop most
# needs to be cheap.
#
# EVERY TEST NOT EXPLICITLY LABELLED "slow" (at its own add_test site --
# see libcloak-server/tests/CMakeLists.txt, cmd/ck-server/CMakeLists.txt and
# cmd/ck-client/CMakeLists.txt for the four that are today) GETS "fast" via
# a call to this function at the end of its own directory's test list file.
# Defined once, here, and called once per directory rather than duplicated,
# because set_tests_properties() and the TESTS directory property only see
# tests added in the CURRENT directory scope -- a test added under
# libcloak-server/tests cannot be labelled from this top-level file, only
# from within that directory's own CMakeLists.txt (a function's body runs
# in ITS CALLER's directory scope, which is what makes one shared
# definition here reach every directory that calls it, unlike a foreach
# over directory paths written directly in this file, which cannot resolve
# tests belonging to a different directory scope at all).
#
# A test added anywhere in the tree tomorrow with no LABELS call of its own
# is therefore "fast" by default, and a test that forks a process has to
# OPT IN to "slow" explicitly. A directory that forgot to call this
# function would leave its tests with NO label at all, which `ctest -L
# fast` would then silently exclude -- a worse failure than a mislabelled
# test, because it looks like the edit loop still works while it quietly
# runs fewer and fewer tests. That is why every one of the six directories
# that calls add_test also calls cloak_label_fast_tests() at the end of
# its own CMakeLists.txt.
#
# `ctest -L fast` is the edit-loop target this task exists to create.
# `ctest` WITH NO ARGUMENTS is untouched by any of this -- it runs each
# directory's whole TESTS list regardless of label, so the suite's test
# COUNT stays exactly what CLOAK_REQUIRE_GO already made a contract (68
# with a Go toolchain, visibly 67 without one): this split changes what the
# QUICK loop selects, never what the DEFAULT run covers.
#
# AND THE SAME SWEEP SETS A TIMEOUT, IN THE SAME set_tests_properties CALL.
#
# The final whole-branch review of module 9 read the GENERATED
# CTestTestfile.cmake files and found 44 tests at TIMEOUT 60, 8 at 120, 1
# at 150 -- and 20 carrying LABELS and NO TIMEOUT AT ALL, so they ran at
# ctest's default of 1500 s. All 20 were in-process unit tests with no
# fork, no exec and no sleep, so the exposure was small; the SHAPE was
# not. It is the same orphaning that hid a missing TIMEOUT 150 on
# test_unordered_proof one task earlier: a property set in one place and
# a property set in another, with nothing tying them together, so losing
# one looks exactly like never having needed it.
#
# The fix the earlier round chose is generalised here rather than
# re-litigated: LABELS and TIMEOUT go into ONE call, on every test, from
# the one function every directory already calls. A test added tomorrow
# with no properties of its own gets both, or neither and no label --
# which `ctest -L fast` makes loud immediately.
#
# CLOAK_DEFAULT_TEST_TIMEOUT is 60 because 60 is what 44 of the 75 tests
# already chose explicitly; this makes the majority the default instead of
# an accident. A test that sets its own TIMEOUT at its add_test site KEEPS
# it -- the value is read back here and re-applied, never overwritten --
# which is what leaves the 8 at 120 and test_unordered_proof's 150 exactly
# where their own comments say they are, for the reasons those comments
# give.
set(CLOAK_DEFAULT_TEST_TIMEOUT 60)

function(cloak_label_fast_tests)
    get_property(_cloak_dir_tests DIRECTORY PROPERTY TESTS)
    foreach(_cloak_test_name ${_cloak_dir_tests})
        get_test_property(${_cloak_test_name} LABELS _cloak_test_labels)
        if(_cloak_test_labels MATCHES "slow")
            set(_cloak_labels "${_cloak_test_labels}")
        else()
            set(_cloak_labels "fast")
        endif()
        # get_test_property answers NOTFOUND for an unset property, which
        # if() treats as false -- so this is "the test did not set one".
        get_test_property(${_cloak_test_name} TIMEOUT _cloak_test_timeout)
        if(NOT _cloak_test_timeout)
            set(_cloak_test_timeout ${CLOAK_DEFAULT_TEST_TIMEOUT})
        endif()
        set_tests_properties(${_cloak_test_name} PROPERTIES
            LABELS "${_cloak_labels}"
            TIMEOUT ${_cloak_test_timeout})
    endforeach()
endfunction()

# ---------------------------------------------------------------------------
# THE FUZZ BUILD (module 10a), AND THE GUARD THAT KEEPS IT OUT OF
# EVERYTHING ELSE.
#
# OFF by default and it must stay that way. With CLOAK_FUZZ off, no fuzz
# TARGET is configured, compiled or linked, and none of the
# instrumentation below is applied: the libraries and the 75 pre-existing
# test binaries are byte-identical to what they were before this option
# existed. With it ON, the libraries are rebuilt with libFuzzer's
# coverage instrumentation and AddressSanitizer, which is a DIFFERENT
# build of the same sources -- so it gets its own build directory and
# never shares one with a Debug or CI build.
#
# ONE THING UNDER fuzz/ IS CONFIGURED UNCONDITIONALLY, and the count
# changed with it: test_fuzz_corpus_replay, which makes the committed
# corpus a regression rather than an archive (module 10a task 5). It is
# an ordinary C program with a main(), linking the ordinary libraries,
# and it replays every committed unit once and exits -- no libFuzzer, no
# mutation, no time budget. `ctest` is 76 tests, not 75. Module 10a
# settled that shape by measuring the alternative: a 60-second campaign
# per target is eight minutes against a ~102 s ASan suite, while the
# replay is seconds. See fuzz/README.md and fuzz/replay_main.c.
#
# WHY THE INSTRUMENTATION IS SET HERE AND NOT IN fuzz/CMakeLists.txt.
# libFuzzer's feedback comes from SanitizerCoverage compiled into the code
# under test, not into the harness -- a harness built with
# -fsanitize=fuzzer against uninstrumented libraries links and runs
# perfectly and explores nothing, which is exactly the shape of failure
# this module has to avoid (it looks like a working fuzzer). cloak-mux,
# cloak-common and their third-party dependencies are all declared in
# subdirectories added BELOW this point, so add_compile_options here is
# what reaches them.
#
# -fsanitize=fuzzer-no-link, not -fsanitize=fuzzer: the libraries need the
# coverage instrumentation but must NOT pull in libFuzzer's main(); only
# the one executable that defines LLVMFuzzerTestOneInput asks for the full
# -fsanitize=fuzzer, in fuzz/CMakeLists.txt.
option(CLOAK_FUZZ "Build the libFuzzer targets under fuzz/ (never part of the default build or the test suite)" OFF)
if(CLOAK_FUZZ)
    add_compile_options(-fsanitize=fuzzer-no-link,address -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address)
endif()

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

# ---------------------------------------------------------------------------
# test_go_interop's two in-tree dependencies (module 9 task 1).
#
# APPENDED here, after both cmd/ add_subdirectory calls above, for exactly
# the reason the CLOAK_REQUIRE_GO block above is: the test is declared in
# libcloak-server/tests, which is added BEFORE cmd/ck-server and
# cmd/ck-client, so the two executables it drives as subprocesses do not
# exist as targets yet at the point it is declared. $<TARGET_FILE:...>
# resolves at generate time; the add_dependencies edges are what make a
# plain `cmake --build` produce the binaries before the test runs.
#
# NOT inside the CLOAK_REQUIRE_GO guard: test_go_interop needs no Go
# toolchain, only two prebuilt binaries at run time, and it reports their
# absence itself. See its own comment in libcloak-server/tests/CMakeLists.txt.
add_dependencies(test_go_interop ck-server ck-client)
target_compile_definitions(test_go_interop PRIVATE
    CK_SERVER_PATH="$<TARGET_FILE:ck-server>"
    CK_CLIENT_PATH="$<TARGET_FILE:ck-client>")

# test_go_clienthello_matrix's two in-tree dependencies (module 10b task
# 1), appended here for exactly the reason test_go_interop's are: it is
# declared in libcloak-server/tests, which is added BEFORE cmd/ck-server
# and cmd/ck-client. It never runs OUR ck-server -- the far end is always
# Go's -- but it includes the same go_oracle_harness.h, whose four *_PATH
# macros are a #error if any of them is missing, so both are defined here
# and the dependency edge is kept on both.
add_dependencies(test_go_clienthello_matrix ck-server ck-client)
target_compile_definitions(test_go_clienthello_matrix PRIVATE
    CK_SERVER_PATH="$<TARGET_FILE:ck-server>"
    CK_CLIENT_PATH="$<TARGET_FILE:ck-client>")

# test_go_encryption_matrix's two in-tree dependencies (module 10b task
# 2), appended here for exactly the reason test_go_interop's are. Unlike
# test_go_clienthello_matrix it really does run BOTH of ours -- half its
# matrix is Go's ck-client against our ck-server -- so both edges are
# load-bearing here and not merely present to satisfy the harness's
# #error.
add_dependencies(test_go_encryption_matrix ck-server ck-client)
target_compile_definitions(test_go_encryption_matrix PRIVATE
    CK_SERVER_PATH="$<TARGET_FILE:ck-server>"
    CK_CLIENT_PATH="$<TARGET_FILE:ck-client>")

# test_unordered_proof's two in-tree dependencies (module 9 task 8),
# appended here for exactly the reason test_go_interop's are: the test is
# declared in libcloak-server/tests, which is added BEFORE cmd/ck-server
# and cmd/ck-client, so the two executables it drives as subprocesses do
# not exist as targets yet at the point it is declared.
add_dependencies(test_unordered_proof ck-server ck-client)
target_compile_definitions(test_unordered_proof PRIVATE
    CK_SERVER_PATH="$<TARGET_FILE:ck-server>"
    CK_CLIENT_PATH="$<TARGET_FILE:ck-client>")

# fuzz/, added LAST because everything in it links libraries and
# executables declared above -- the four cloak-* libraries for the corpus
# replay, cloak-mux for the first fuzz target.
#
# ADDED UNCONDITIONALLY, unlike every earlier revision of this line. The
# guard moved INTO fuzz/CMakeLists.txt, which declares the corpus replay
# (an ordinary test, always) and then returns early unless CLOAK_FUZZ is
# ON (the eight libFuzzer targets, never in the default build). The
# option is declared above, next to the instrumentation flags it turns
# on, so that a reader who finds this line is one scroll from what it
# does.
add_subdirectory(fuzz)

# The out-of-band growth harness (module 10b task 9). NOT a test and not
# in the default build: tools/soak/CMakeLists.txt is only entered when
# CLOAK_BUILD_SOAK is ON, so `ctest` still runs exactly the tests it ran
# before this line existed, and a default `cmake --build` compiles
# exactly the same objects. The option is declared here rather than in
# that file so it is visible to `cmake -LH` without configuring the
# subdirectory first. See docs/runbooks/soak-growth.md.
option(CLOAK_BUILD_SOAK "Build the long-running growth harness (tools/soak)" OFF)
if(CLOAK_BUILD_SOAK)
    add_subdirectory(tools/soak)
endif()

# The end-to-end benchmark's helpers, off by default for the same reason
# and declared here for the same visibility. Unlike the soak harness these
# link nothing from this project on purpose -- they speak plain TCP from
# outside the tunnel, so the same two programs measure our ck-client and
# ck-server and Go Cloak's, which is the only comparison worth printing.
# See docs/runbooks/bench.md.
option(CLOAK_BUILD_BENCH "Build the end-to-end benchmark helpers (tools/bench)" OFF)
if(CLOAK_BUILD_BENCH)
    add_subdirectory(tools/bench)
endif()
