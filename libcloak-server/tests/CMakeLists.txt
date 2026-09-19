add_executable(test_clienthello_parse test_clienthello_parse.c)
target_include_directories(test_clienthello_parse PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_clienthello_parse PRIVATE cloak-server)
add_test(NAME test_clienthello_parse COMMAND test_clienthello_parse)

add_executable(test_server_auth test_server_auth.c)
target_include_directories(test_server_auth PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_server_auth PRIVATE cloak-server)
add_test(NAME test_server_auth COMMAND test_server_auth)

# -Wl,--wrap lets this binary interpose on cloak_aead_seal -- a function
# of its OWN static archive, which LD_PRELOAD cannot reach (calls between
# objects inside one executable are direct, never through the PLT) and
# which a competing definition in this file cannot override (that is a
# duplicate symbol at link time, not a preemption).
#
# It exists for one test: cloak_aead_seal takes no output capacity, so
# cloak_server_auth_compose_ws_reply's "the sealed length really was 48"
# check can only be exercised by a cipher that reports a different one,
# and no real AES-256-GCM ever does. Without this the check is an
# unreachable line that merely looks like safety -- the thing this tree's
# cloak/http.h argues against -- and the mutation that deletes it is
# indistinguishable from the original.
#
# GNU ld / lld only, which matches this project's GCC-on-Linux build (the
# same assumption the ASan block below already documents). --wrap on a
# symbol nothing references is silently harmless, so a future refactor
# that stops calling cloak_aead_seal here degrades to a no-op rather than
# a build failure; test_compose_ws_reply_round_trips asserts the
# interposition actually fired, which is what catches that.
target_link_options(test_server_auth PRIVATE -Wl,--wrap=cloak_aead_seal)

add_executable(test_replay_cache test_replay_cache.c)
target_include_directories(test_replay_cache PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_replay_cache PRIVATE cloak-server)
add_test(NAME test_replay_cache COMMAND test_replay_cache)

# The adversarial half of the replay cache's coverage, in its own binary
# rather than appended to test_replay_cache.c: that file is the
# functional suite and every one of its assertions passed on the code
# this one's case 1 breaks. Keeping them apart is what makes "the
# functional suite is green and the cache is still broken" a statement
# you can read off the test list.
#
# In-process, no fork, so it stays "fast" by default (see the top-level
# CMakeLists.txt on the fast/slow split). It is not free, though: case 2
# runs 32 floods of ln(2)*C inserts each and case 3 allocates two more
# tables and fills them, so its whole cost is proportional to
# CLOAK_SERVER_STACK_DEFAULT_REPLAY_CACHE_CAPACITY.
#
# THE TIMEOUT MOVED WITH THE SESSION CAP, and this is the record of why.
# When this test was added the capacity was 2^19, case 2 was about 11.6
# million keyed hashes, and it MEASURED at 2.53 s through ctest in a
# Debug build -- TIMEOUT 120, roughly a 47x margin, chosen to leave room
# for the order-of-magnitude ASan+UBSan slowdown the other TIMEOUT
# comments in this file report rather than from a sanitizer number anyone
# had observed. Raising CLOAK_REGISTRY_MAX_SESSIONS from 256 to 1024
# raised the sized handshake rate fourfold and the capacity with it, to
# 2^21; case 2 is now about 46.5 million keyed hashes. MEASURED at
# 14.66 s in a Debug build at that commit, same command.
#
# AND THE SANITIZER BUILD WAS MEASURED THIS TIME, which is worth recording
# because the number the earlier comment reasoned its way to was wrong:
# an ASan+UBSan build of the whole suite ran this test in 23.75 s, a
# slowdown of 1.6x rather than the order of magnitude the other TIMEOUT
# comments in this file assume. The prediction from that assumption was
# ~147 s. TIMEOUT 600 is a 41x margin on the Debug measurement and a 25x
# margin on the sanitizer one; the old 120 would in fact have survived,
# and is being raised anyway because a 5x margin under -j4 on a loaded
# machine is not one.
#
# NOTHING IN THE TEST ITSELF CHANGED SHAPE: every number in it is derived
# from SHIPPED_CAPACITY and REPLAY_WINDOW_SECONDS, and the two literals
# that are not (the insert count the sizing comment quotes, and the
# capacity floor that stops the constant moving DOWN) moved to the values
# the same two constants now produce.
add_executable(test_replay_cache_keyed test_replay_cache_keyed.c)
target_include_directories(test_replay_cache_keyed PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_replay_cache_keyed PRIVATE cloak-server)
add_test(NAME test_replay_cache_keyed COMMAND test_replay_cache_keyed)
set_tests_properties(test_replay_cache_keyed PROPERTIES TIMEOUT 600)

add_executable(test_firstpacket test_firstpacket.c)
target_include_directories(test_firstpacket PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_firstpacket PRIVATE cloak-server)
add_test(NAME test_firstpacket COMMAND test_firstpacket)
set_tests_properties(test_firstpacket PROPERTIES TIMEOUT 60)

add_executable(test_server_state test_server_state.c)
target_include_directories(test_server_state PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_server_state PRIVATE cloak-server)
add_test(NAME test_server_state COMMAND test_server_state)
set_tests_properties(test_server_state PROPERTIES TIMEOUT 60)

# The session cap at its own scale (module 10b task 4): 1024 sessions
# established, the cost of finding one measured at four occupancies, and
# the refusal at the cap held against the cover-site redirect.
#
# NOT labelled "slow": it forks nothing (the fast/slow split in the
# top-level CMakeLists.txt is by fork-or-not, not by duration). It is not
# free either -- case 1 builds 1024 real cloak_session_t's, case 2 builds
# 1345 more across its four measurement points and runs 100k lookups, and
# case 3 drives 242 real TCP probes through a dispatcher at a full
# registry. MEASURED at 0.26 s through ctest in a Debug build at the
# commit that added it (`ctest -R ^test_registry_scale$`), of which case 3
# is most of it, and MEASURED at 1.47 s in an ASan+UBSan build of the same
# tree -- a slowdown of 5.7x, not the order of magnitude the older TIMEOUT
# comments in this file assume. TIMEOUT 300 is a 1150x margin on the first
# number and a 204x margin on the second.
add_executable(test_registry_scale test_registry_scale.c)
target_include_directories(test_registry_scale PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_registry_scale PRIVATE cloak-server cloak-client)
add_test(NAME test_registry_scale COMMAND test_registry_scale)
set_tests_properties(test_registry_scale PROPERTIES TIMEOUT 300)

add_executable(test_registry test_registry.c)
target_include_directories(test_registry PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_registry PRIVATE cloak-server)
add_test(NAME test_registry COMMAND test_registry)
set_tests_properties(test_registry PROPERTIES TIMEOUT 60)

add_executable(test_dispatcher_redirect test_dispatcher_redirect.c)
target_include_directories(test_dispatcher_redirect PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_dispatcher_redirect PRIVATE cloak-server)
add_test(NAME test_dispatcher_redirect COMMAND test_dispatcher_redirect)
set_tests_properties(test_dispatcher_redirect PROPERTIES TIMEOUT 60)

add_executable(test_dispatcher_auth test_dispatcher_auth.c)
target_include_directories(test_dispatcher_auth PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_dispatcher_auth PRIVATE cloak-server)
add_test(NAME test_dispatcher_auth COMMAND test_dispatcher_auth)
set_tests_properties(test_dispatcher_auth PROPERTIES TIMEOUT 60)

# Test-only LD_PRELOAD shim (see test_write_shim.c's own top-of-file
# comment) that lets test_dispatcher_auth deterministically force the
# dispatcher's step-10 reply write to see EAGAIN or a real error, which
# genuine socket-buffer backpressure cannot do for a reply this small.
add_library(cloak_test_write_shim SHARED test_write_shim.c)
target_link_libraries(cloak_test_write_shim PRIVATE ${CMAKE_DL_LIBS})

# Under an ASan-instrumented build (CMAKE_C_FLAGS carries -fsanitize=address
# out of band -- this project has no CMake-level ASan option of its own),
# ASan requires its own runtime to be the FIRST thing LD_PRELOAD loads, or
# it aborts at startup ("ASan runtime does not come first in initial
# library list"): our shim is built and ASan-instrumented too (see its
# target_link_libraries above / CMAKE_SHARED_LINKER_FLAGS), but merely
# preloading it is not enough on its own. Detect that case and preload
# libasan.so first, ahead of our own shim, in LD_PRELOAD's search order
# (space-separated, per LD_PRELOAD's own documented syntax).
set(_cloak_ld_preload "$<TARGET_FILE:cloak_test_write_shim>")
if(CMAKE_C_FLAGS MATCHES "-fsanitize=[^ ]*address")
    # ASSUMPTION: -print-file-name=libasan.so is a GCC-runtime-naming
    # query and only means anything to a GCC ${CMAKE_C_COMPILER}. Under a
    # Clang/compiler-rt toolchain this resolves to the literal string
    # "libasan.so" (compiler-rt's own runtime has a different name and
    # location entirely), the EXISTS check below fails, and this whole
    # block silently no-ops -- LD_PRELOAD then carries only our shim, ASan
    # aborts at startup ("ASan runtime does not come first in initial
    # library list"), and this coverage (the whole of test_dispatcher_auth
    # and test_dispatcher_limits under the sanitizer suite) is lost
    # without any build failure to flag it. This project's own build is
    # GCC-only today, so that gap is not live, but a future Clang CI leg
    # would hit it silently; fixing that is out of scope here (no attempt
    # is made to restructure this build for Clang) -- this comment exists
    # so the assumption is visible instead of implicit.
    execute_process(
        COMMAND ${CMAKE_C_COMPILER} -print-file-name=libasan.so
        OUTPUT_VARIABLE _cloak_asan_rt
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(_cloak_asan_rt AND EXISTS "${_cloak_asan_rt}")
        set(_cloak_ld_preload "${_cloak_asan_rt} ${_cloak_ld_preload}")
    else()
        # The exact silent-loss scenario the comment above warns about:
        # -fsanitize=address is on, but this compiler's own
        # -print-file-name=libasan.so query did not resolve to a real
        # file (a non-GCC/Clang-with-compiler-rt toolchain, most likely).
        # Failing the CMake configure step loudly here is strictly better
        # than letting this silently degrade into a build that reports
        # green while test_dispatcher_auth and test_dispatcher_limits
        # quietly stop exercising the write-shim-dependent paths (steps
        # 10/11's EAGAIN/error/deadline branches, and this plan's own C1
        # regression test) under the sanitizer suite -- exactly the
        # coverage loss a future Clang CI leg would otherwise hit with no
        # signal at all.
        message(FATAL_ERROR
            "cloak-server tests: -fsanitize=address is set in CMAKE_C_FLAGS "
            "but '${CMAKE_C_COMPILER} -print-file-name=libasan.so' did not "
            "resolve to an existing file (got: '${_cloak_asan_rt}'). "
            "test_write_shim.c's LD_PRELOAD interposition requires ASan's "
            "own runtime to be preloaded first, or the sanitizer aborts at "
            "startup with 'ASan runtime does not come first in initial "
            "library list' -- silently continuing here would instead lose "
            "test_dispatcher_auth/test_dispatcher_limits' shim-dependent "
            "coverage with no build failure to flag it. This toolchain's "
            "ASan runtime needs a different lookup (e.g. compiler-rt under "
            "Clang) than the GCC-runtime-naming query this project uses.")
    endif()
endif()
set_tests_properties(test_dispatcher_auth PROPERTIES
    ENVIRONMENT "LD_PRELOAD=${_cloak_ld_preload}")

add_executable(test_dispatcher_limits test_dispatcher_limits.c)
target_include_directories(test_dispatcher_limits PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_dispatcher_limits PRIVATE cloak-server)
add_test(NAME test_dispatcher_limits COMMAND test_dispatcher_limits)
set_tests_properties(test_dispatcher_limits PROPERTIES TIMEOUT 60)

# Reuses cloak_test_write_shim and _cloak_ld_preload (computed above for
# test_dispatcher_auth): test_dispatcher_limits' mid-reply-write and
# reply-write-deadline cases need the exact same LD_PRELOAD interposition,
# for the exact same reason -- see test_write_shim.c's own top-of-file
# comment.
set_tests_properties(test_dispatcher_limits PROPERTIES
    ENVIRONMENT "LD_PRELOAD=${_cloak_ld_preload}")

add_executable(test_proxy_stream test_proxy_stream.c)
target_include_directories(test_proxy_stream PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_proxy_stream PRIVATE cloak-server)
add_test(NAME test_proxy_stream COMMAND test_proxy_stream)
set_tests_properties(test_proxy_stream PROPERTIES TIMEOUT 60)

# LABELS "slow" (module 9 task 0's fast/slow split): this file's
# test_total_cap_is_derived_from_rlimit calls fork(2) to lower
# RLIMIT_NOFILE in a child without disturbing the parent's own
# descriptor table. `ctest -L fast` (the edit-loop target) excludes
# anything carrying this label; the default `ctest` with no arguments
# still runs it -- the split changes what the QUICK loop runs, never
# what the full suite runs, exactly as CLOAK_REQUIRE_GO's 67 -> 68
# stays a build-time choice, not a per-run skip.
set_tests_properties(test_proxy_stream PROPERTIES LABELS "slow")

# The server's DATAGRAM upstream (module 9 task 6). NOT labelled "slow":
# it forks nothing -- its "upstream" is one bound AF_INET SOCK_DGRAM
# socket driven by the same reactor as everything else -- so it belongs in
# the `ctest -L fast` edit loop, which is where a relay this fiddly most
# needs to be re-run.
add_executable(test_proxy_udp test_proxy_udp.c)
target_include_directories(test_proxy_udp PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_proxy_udp PRIVATE cloak-server)
add_test(NAME test_proxy_udp COMMAND test_proxy_udp)
# 60 s matches every other end-to-end file in this directory and is a
# BACKSTOP, not the mechanism: every wait inside the file is a
# clock-bounded pump_until of 4 s, so a wholly unresponsive run still
# reports its own named assertion rather than being truncated by ctest.
set_tests_properties(test_proxy_udp PROPERTIES TIMEOUT 60)

add_executable(test_proxy_teardown test_proxy_teardown.c)
target_include_directories(test_proxy_teardown PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_proxy_teardown PRIVATE cloak-server)
add_test(NAME test_proxy_teardown COMMAND test_proxy_teardown)
set_tests_properties(test_proxy_teardown PROPERTIES TIMEOUT 60)

# Reuses cloak_test_write_shim and _cloak_ld_preload (computed above for
# test_dispatcher_auth), for the same reason test_dispatcher_limits does:
# this file's site-C case needs the dispatcher's step-10 reply write to
# fail deterministically, and the reply is far smaller than any socket
# buffer floor, so genuine backpressure cannot produce that failure.
set_tests_properties(test_proxy_teardown PROPERTIES
    ENVIRONMENT "LD_PRELOAD=${_cloak_ld_preload}")

add_executable(test_server_e2e test_server_e2e.c)
target_include_directories(test_server_e2e PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_server_e2e PRIVATE cloak-server)
add_test(NAME test_server_e2e COMMAND test_server_e2e)
set_tests_properties(test_server_e2e PROPERTIES TIMEOUT 60)

# Reuses cloak_test_write_shim and _cloak_ld_preload (computed above for
# test_dispatcher_auth), for the same reason test_dispatcher_limits and
# test_proxy_teardown do: this file's buffered-frame case needs the
# dispatcher's step-10 reply write to take the EAGAIN path deterministically,
# which defers conn_handoff to a later reactor turn -- and the reply is far
# smaller than any socket buffer floor, so genuine backpressure cannot
# produce that EAGAIN. See test_write_shim.c's own top-of-file comment.
set_tests_properties(test_server_e2e PROPERTIES
    ENVIRONMENT "LD_PRELOAD=${_cloak_ld_preload}")

# Links sqlite3 directly, on top of the transitive link cloak-server
# already provides: case 12 opens a second sqlite3 handle of its own to
# prove the schema refuses a wrong-length UID no matter who writes it,
# and that needs sqlite3.h on the include path, which cloak-server's
# PRIVATE link deliberately does not propagate.
add_executable(test_usermanager test_usermanager.c)
target_include_directories(test_usermanager PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_usermanager PRIVATE cloak-server sqlite3)
add_test(NAME test_usermanager COMMAND test_usermanager)
set_tests_properties(test_usermanager PROPERTIES TIMEOUT 60)

# Reuses cloak_test_write_shim and _cloak_ld_preload (computed above for
# test_dispatcher_auth), for a different one of the shim's two protocols:
# this file's rollback case needs a genuine mid-batch SQLITE_IOERR, and no
# legitimate use of the database can make an sqlite3_step fail partway.
# The shim fails write(2)/pwrite(2) against the one temp database that
# case names. Preloading also brings the ASan-runtime-first ordering
# requirement the block above handles.
set_tests_properties(test_usermanager PROPERTIES
    ENVIRONMENT "LD_PRELOAD=${_cloak_ld_preload}")

# Links sqlite3 directly, on top of the transitive link cloak-server
# already provides, for the same reason test_usermanager does: the
# retry-on-failed-upload case opens a second sqlite3 connection of its own
# and holds a BEGIN IMMEDIATE write lock, which is the only way to make
# cloak_usermanager_upload_status fail the way a real second writer makes
# it fail (busy_timeout is 0 by design).
add_executable(test_userpanel test_userpanel.c)
target_include_directories(test_userpanel PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_userpanel PRIVATE cloak-server sqlite3)
add_test(NAME test_userpanel COMMAND test_userpanel)
set_tests_properties(test_userpanel PROPERTIES TIMEOUT 60)

# Links sqlite3 directly, on top of the transitive link cloak-server
# already provides, for the same reason test_usermanager.c and
# test_userpanel.c do: this file writes user rows and reads credits back
# through cloak_usermanager_write/get, which needs cloak/usermanager.h's
# own types -- and cloak-server's PRIVATE sqlite3 link deliberately does
# not propagate the include path its implementation uses.
add_executable(test_dispatcher_users test_dispatcher_users.c)
target_include_directories(test_dispatcher_users PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_dispatcher_users PRIVATE cloak-server sqlite3)
add_test(NAME test_dispatcher_users COMMAND test_dispatcher_users)
set_tests_properties(test_dispatcher_users PROPERTIES TIMEOUT 60)

# Reuses cloak_test_write_shim and _cloak_ld_preload (computed above for
# test_dispatcher_auth), for the same reason test_dispatcher_limits,
# test_proxy_teardown and test_server_e2e do: this file's
# test_reply_write_failure_releases_the_user needs the dispatcher's
# step-10 reply write to fail deterministically, which is the only way to
# reach conn_teardown's auth_created unwind -- and the reply is far
# smaller than any socket buffer floor, so genuine backpressure cannot
# produce that failure. See test_write_shim.c's own top-of-file comment.
set_tests_properties(test_dispatcher_users PROPERTIES
    ENVIRONMENT "LD_PRELOAD=${_cloak_ld_preload}")

add_executable(test_http_parse test_http_parse.c)
target_include_directories(test_http_parse PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_http_parse PRIVATE cloak-server)
add_test(NAME test_http_parse COMMAND test_http_parse)
set_tests_properties(test_http_parse PROPERTIES TIMEOUT 60)

add_executable(test_user_json test_user_json.c)
target_include_directories(test_user_json PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_user_json PRIVATE cloak-server)
add_test(NAME test_user_json COMMAND test_user_json)
set_tests_properties(test_user_json PROPERTIES TIMEOUT 60)

# Links sqlite3 directly, on top of the transitive link cloak-server
# already provides, for the same reason test_usermanager.c and
# test_userpanel.c do: every case here asserts the DATABASE and not just
# the status code, through cloak_usermanager_write/get/list, and
# cloak-server's PRIVATE sqlite3 link deliberately does not propagate the
# include path its implementation uses.
add_executable(test_adminapi test_adminapi.c)
target_include_directories(test_adminapi PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_adminapi PRIVATE cloak-server sqlite3)
add_test(NAME test_adminapi COMMAND test_adminapi)
set_tests_properties(test_adminapi PROPERTIES TIMEOUT 60)

# Links sqlite3 directly, on top of the transitive link cloak-server
# already provides, for the same reason test_dispatcher_users.c and
# test_adminapi.c do: this file seeds and reads user rows through
# cloak_usermanager_write/get to assert that an admin session leaves the
# database untouched, and cloak-server's PRIVATE sqlite3 link deliberately
# does not propagate the include path its implementation uses.
add_executable(test_dispatcher_admin test_dispatcher_admin.c)
target_include_directories(test_dispatcher_admin PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_dispatcher_admin PRIVATE cloak-server sqlite3)
add_test(NAME test_dispatcher_admin COMMAND test_dispatcher_admin)
set_tests_properties(test_dispatcher_admin PROPERTIES TIMEOUT 60)

# Links sqlite3 directly, on top of the transitive link cloak-server
# already provides, for the same reason test_adminapi.c and
# test_dispatcher_admin.c do -- and for one more: this file's
# second-writer case opens a second sqlite3 connection of its own and
# holds a BEGIN IMMEDIATE write lock, which is the only way to make the
# admin API's write fail the way a real second writer makes it fail
# (busy_timeout is 0 by design).
add_executable(test_admin_e2e test_admin_e2e.c)
target_include_directories(test_admin_e2e PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_admin_e2e PRIVATE cloak-server sqlite3)
add_test(NAME test_admin_e2e COMMAND test_admin_e2e)
set_tests_properties(test_admin_e2e PROPERTIES TIMEOUT 60)

# ---------------------------------------------------------------------------
# cloak-client, for the nine test binaries that include client_harness.h.
#
# That header's good-path handshake (client_session_open) now drives the
# real cloak_client_handshake_t instead of assembling a ClientHello and
# un-splicing the reply itself -- see the header's own top-of-file note for
# what converted and what deliberately did not. The link is what that
# needs, and the include directory cloak-client exports is what the
# header's `#include "cloak/client_transport.h"` needs even in the two
# includers that never call the converted helper.
#
# THIS IS NOT A LIBRARY DEPENDENCY AND DOES NOT MAKE ONE. cloak-server
# still links only cloak-common and cloak-mux (plus its private sqlite3
# and cjson); nothing in libcloak-server/src references libcloak-client,
# and nothing will. This is the exact mirror of
# libcloak-client/tests/CMakeLists.txt, where cloak-server is a test-only
# oracle for the client's tests without the client library depending on
# it.
#
# APPENDED rather than folded into each target's own
# target_link_libraries line above, for the reason this project appends
# everywhere else (libcloak-server/CMakeLists.txt does the same for
# src/http.c, src/user_json.c and src/adminapi.c): the existing content of
# this file stays byte-identical, including the ASan/LD_PRELOAD block that
# several of these targets depend on. CMake applies these to the
# already-declared targets either way, and resolves `cloak-client` at
# generate time even though libcloak-client is add_subdirectory'd after
# this directory.
foreach(_cloak_harness_test
        test_dispatcher_auth
        test_dispatcher_limits
        test_proxy_stream
        test_proxy_udp
        test_proxy_teardown
        test_server_e2e
        test_dispatcher_users
        test_adminapi
        test_dispatcher_admin
        test_admin_e2e)
    target_link_libraries(${_cloak_harness_test} PRIVATE cloak-client)
endforeach()

# Links sqlite3 directly, on top of the transitive link cloak-server
# already provides, for the same reason test_adminapi.c and
# test_admin_e2e.c do: this file builds a stack over a REAL user database
# (so the manager, the panel and the admin API are all the production
# objects) and cloak-server's PRIVATE sqlite3 link deliberately does not
# propagate the include path its implementation uses.
add_executable(test_server_stack test_server_stack.c)
target_include_directories(test_server_stack PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_server_stack PRIVATE cloak-server sqlite3)
add_test(NAME test_server_stack COMMAND test_server_stack)
set_tests_properties(test_server_stack PROPERTIES TIMEOUT 60)

# client_harness.h, for the same reason the nine tests in the foreach
# above need it: this file drives the real cloak_client_handshake_t.
target_link_libraries(test_server_stack PRIVATE cloak-client)

# Reuses cloak_test_write_shim and _cloak_ld_preload (computed above for
# test_dispatcher_auth), for the same reason test_dispatcher_limits,
# test_proxy_teardown, test_server_e2e and test_dispatcher_users do: this
# file's abandoned-handshake case needs the dispatcher's step-10 reply
# write to fail deterministically, which is the only way to reach the
# post-creation unwind that fires session_aborted -- and the reply is far
# smaller than any socket buffer floor, so genuine backpressure cannot
# produce that failure. See test_write_shim.c's own top-of-file comment.
set_tests_properties(test_server_stack PROPERTIES
    ENVIRONMENT "LD_PRELOAD=${_cloak_ld_preload}")

# The CDN upgrade parser. No sqlite3 and no client_harness.h: this is a
# pure function over a byte buffer with no session, no reactor and no
# socket anywhere near it, which is the same shape (and the same reason)
# as libcloak-mux's test_ws_frame.
add_executable(test_ws_handshake test_ws_handshake.c)
target_include_directories(test_ws_handshake PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_ws_handshake PRIVATE cloak-server)
add_test(NAME test_ws_handshake COMMAND test_ws_handshake)
set_tests_properties(test_ws_handshake PROPERTIES TIMEOUT 120)

# The CDN transport's dispatcher branch: the first test in this tree that
# drives a real socket through cloak_dispatcher_accept carrying an HTTP
# GET and gets a cloak_session_t out the other end. Links sqlite3
# directly, on top of the transitive link cloak-server already provides,
# for the same reason test_dispatcher_users.c and test_adminapi.c do: it
# seeds a user row through cloak_usermanager_write so that "the panel was
# not touched" is a claim about a user the server WOULD have authorised,
# and cloak-server's PRIVATE sqlite3 link deliberately does not propagate
# the include path its implementation uses.
#
# No client_harness.h and therefore no cloak-client: every request here is
# an HTTP GET this file builds itself, and the one client-side
# cloak_session_t it raises is built directly on cloak-mux's
# cloak_session_add_conn_framed -- there is no CDN client transport to
# drive until module 8's client half exists.
add_executable(test_dispatcher_ws test_dispatcher_ws.c)
target_include_directories(test_dispatcher_ws PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_dispatcher_ws PRIVATE cloak-server sqlite3)
add_test(NAME test_dispatcher_ws COMMAND test_dispatcher_ws)
set_tests_properties(test_dispatcher_ws PROPERTIES TIMEOUT 120)

# The interoperability suite: the first test in this tree whose PEER was
# not written by this project. It drives a real ck-server binary, a real
# gorilla/websocket client, a gorilla server, and a hand-written
# fragmenting proxy between the Go client and the C server.
#
# Declared here with the rest of libcloak-server's tests, but the two
# things it needs that this directory cannot give it -- the ck-server
# binary's path, and the Go oracle built from
# tests/ws_interop_oracle/ -- are APPENDED at the end of the top-level
# CMakeLists.txt, after cmd/ck-server has been added. Same reason this
# file appends cloak-client below rather than folding it in: the existing
# content stays byte-identical, and CMake resolves both at generate time.

# CLOAK_REQUIRE_GO IS DEFINED HERE, NOT AT THE TOP OF THE ROOT LIST FILE,
# because this is the first place that needs it and because the root file
# is only ever appended to in this tree. An option() call defines a cache
# entry that every later directory can read -- and a `-DCLOAK_REQUIRE_GO=OFF`
# on the command line sets that entry before any option() runs, so where
# the call sits does not change what the user gets.
#
# WHEN IT IS OFF, THE TEST IS REMOVED, NOT SKIPPED. `ctest` prints a
# skipped test and a passing test the same way, and this project has been
# burned by exactly that: a skip branch is indistinguishable from
# coverage. Turning this off drops the suite from 68 tests to 67, visibly,
# which is a contract change a reader can see in one line of output. It
# exists because a top-level FATAL_ERROR means a C library project cannot
# be CONFIGURED at all without a Go toolchain, which blocks packagers and
# minimal CI images; ON remains the default because the 67 -> 68 count is
# part of module 8's contract and this is the only test in the tree whose
# peer is not our own code.
option(CLOAK_REQUIRE_GO
       "Build test_ws_interop, which needs a Go toolchain and gorilla/websocket. \
Turning this OFF removes that test: the suite becomes 67 tests, not 68." ON)

if(CLOAK_REQUIRE_GO)
    # Links sqlite3 directly, on top of the transitive link cloak-server
    # already provides, for the same reason test_dispatcher_ws.c does: the
    # two in-process cases raise a real cloak_userpanel_t over a real
    # cloak_usermanager_t, and cloak-server's PRIVATE sqlite3 link
    # deliberately does not propagate the include path.
    add_executable(test_ws_interop test_ws_interop.c)
    target_include_directories(test_ws_interop PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
    target_link_libraries(test_ws_interop PRIVATE cloak-server sqlite3)
    add_test(NAME test_ws_interop COMMAND test_ws_interop)

    # THE BOUND IS SET FROM THE WORST FAILING RUN, NOT THE PASSING ONE.
    # A passing run is ~1 s in Debug and ~3 s under ASan+UBSan (one
    # ASan-instrumented ck-server plus seven short-lived Go processes, and
    # ~335 in-process handshakes for the split-point case). What the number
    # has to accommodate is a run in which something never answers: every
    # wait inside the file is bounded by CLOCK_MONOTONIC, the longest
    # single one being CHILD_MS, which test_ws_interop.c sets to 10 s
    # against seven children -- so even a wholly unresponsive run finishes
    # inside this timeout and reports its own named assertions rather than
    # being truncated as "***Timeout" with the diagnosis cut off. This is a
    # backstop, not the mechanism.
    set_tests_properties(test_ws_interop PROPERTIES TIMEOUT 120)

    # LABELS "slow" (module 9 task 0's fast/slow split): this is "the
    # first test in this tree whose PEER was not written by this
    # project" (see above) -- it forks and execs a real ck-server
    # binary and the Go oracle (github.com/gorilla/websocket) as real
    # child processes. `ctest -L fast` (the edit-loop target) excludes
    # it; the default `ctest` still runs it, same as every other label
    # in this split -- the suite's test COUNT stays untouched, only the
    # quick loop's SELECTION shrinks.
    set_tests_properties(test_ws_interop PROPERTIES LABELS "slow")
else()
    message(WARNING
        "CLOAK_REQUIRE_GO=OFF: test_ws_interop is NOT built. The suite is 67 "
        "tests, not 68, and NOTHING then measures this port against an "
        "implementation it did not write -- which is how it once shipped a "
        "frame format no Go peer could read. Turn this back on to restore it.")
endif()

# ---------------------------------------------------------------------------
# The DIRECT path's interoperability suite (module 9 task 1).
#
# test_ws_interop, above, put a foreign implementation in front of the
# server's WEBSOCKET leg. The direct (TLS-shaped) leg and the whole C
# CLIENT had never met foreign code at all -- eight modules in, both ends
# of every one of their tests were our own -- which is exactly the
# condition under which this port once shipped a frame format no Go peer
# could read. test_go_interop closes that: it drives Go Cloak's own
# ck-client and ck-server BINARIES as subprocesses, in both roles.
#
# NOT GUARDED BY CLOAK_REQUIRE_GO, deliberately. That option is about a Go
# TOOLCHAIN, because ws_interop_oracle is Go source this build compiles.
# This test compiles nothing: it execs two prebuilt binaries that
# Dockerfile.dev's `gobuild` stage puts in the image, so a machine with no
# Go toolchain at all can still run it, and tying it to CLOAK_REQUIRE_GO
# would remove coverage for a dependency it does not have. The suite is
# therefore 69 tests with a Go toolchain and 68 with -DCLOAK_REQUIRE_GO=OFF.
#
# A MISSING BINARY IS A NAMED FAILURE, NOT A CONFIGURE ERROR AND NOT A
# TIMEOUT. The paths below are resolved here if they exist and defaulted
# to where Dockerfile.dev puts them if they do not, so the TEST reports
# the absence in milliseconds, naming the file and the image that builds
# it. Making this a configure-time FATAL_ERROR would mean a C library
# cannot be configured without Go binaries present; making it a skip would
# be invisible in ctest output, which this tree has been burned by.
find_program(CLOAK_GO_CK_CLIENT NAMES go-ck-client HINTS /usr/local/bin)
find_program(CLOAK_GO_CK_SERVER NAMES go-ck-server HINTS /usr/local/bin)
if(NOT CLOAK_GO_CK_CLIENT)
    set(CLOAK_GO_CK_CLIENT "/usr/local/bin/go-ck-client")
endif()
if(NOT CLOAK_GO_CK_SERVER)
    set(CLOAK_GO_CK_SERVER "/usr/local/bin/go-ck-server")
endif()

add_executable(test_go_interop test_go_interop.c)
target_include_directories(test_go_interop PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
# cloak-server for cloak_clienthello_parse (case 4 reads the relayed
# ClientHello itself); cloak-common for base64, X25519 and the AEAD it
# then decrypts the authentication payload with.
target_link_libraries(test_go_interop PRIVATE cloak-server cloak-common)
target_compile_definitions(test_go_interop PRIVATE
    GO_CK_CLIENT_PATH="${CLOAK_GO_CK_CLIENT}"
    GO_CK_SERVER_PATH="${CLOAK_GO_CK_SERVER}")
add_test(NAME test_go_interop COMMAND test_go_interop)

# The two things this directory cannot give it -- the paths of OUR
# ck-client and ck-server binaries -- are APPENDED at the end of the
# top-level CMakeLists.txt, after cmd/ck-client and cmd/ck-server have
# been added, exactly as test_ws_interop's ck-server path already is.

# TIMEOUT 120, the bound this project uses for anything that forks real
# binaries, and set from the worst FAILING run rather than the passing
# one. MEASURED: a passing run is 2.2 s in Debug (four cases, six child
# processes, 128 KiB each way through two of them).
#
# What the number has to accommodate is a run where the two ends cannot
# read each other's frames -- the exact shape of the defect this file
# exists to catch, and one this file was actually run against by
# mutation. Every wait inside the test is bounded by CLOCK_MONOTONIC, and
# the file's own budget comment works the arithmetic out to ~77 s for the
# worst failing path (XFER_MS 15 s per stalled transfer, EXIT_MS 5 s per
# child that ignores SIGTERM, HANDSHAKE_FAIL_MS 15 s for the negative
# control). That leaves ~40 s of headroom, so even a wholly unresponsive
# run finishes inside this timeout and prints its own named assertion
# instead of being truncated as "***Timeout" with the diagnosis cut off.
#
# The first draft of those budgets did NOT fit: at XFER_MS 30 s the two
# positive cases alone burned 60 s of the 120 under the frame-AEAD
# mutation. They were cut after measuring that, not before.
set_tests_properties(test_go_interop PROPERTIES TIMEOUT 120)

# LABELS "slow" (module 9 task 0's fast/slow split): this file forks and
# execs six real Cloak binaries -- two of them Go's -- which is precisely
# the cost that split exists to keep out of the edit loop, and which turns
# brutal under ASan's per-child LeakSanitizer exit scan. `ctest -L fast`
# excludes it; the default `ctest` still runs it.
set_tests_properties(test_go_interop PROPERTIES LABELS "slow")

# ---------------------------------------------------------------------------
# THE CLIENTHELLO MATRIX (module 10b task 1).
#
# A SECOND binary rather than more cases in test_go_interop, for two
# reasons and neither is tidiness. test_go_interop's TIMEOUT 120 is
# already sized for a worst FAILING run of roughly 90 s (its own budget
# comment does the arithmetic); six more forking scenarios would not fit,
# and a bound that cannot cover its own failure mode reports "***Timeout"
# instead of the assertion that diagnoses it. And the two files ask
# different questions -- one asks whether the direct path interoperates at
# all, this one asks whether all three ClientHello templates do -- so a
# failure in one should not hide the other behind a single ctest row.
#
# The harness both share is go_oracle_harness.h, extracted verbatim from
# test_go_interop.c when this file was written; see its own header.
#
# cloak-server for cloak_clienthello_parse (the relay locates the X25519
# key share it corrupts by parsing the record that arrived, not by
# reading a template table); cloak-common for base64, X25519 and the AEAD
# the shared harness uses.
add_executable(test_go_clienthello_matrix test_go_clienthello_matrix.c)
target_include_directories(test_go_clienthello_matrix PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_go_clienthello_matrix PRIVATE cloak-server cloak-common)
target_compile_definitions(test_go_clienthello_matrix PRIVATE
    GO_CK_CLIENT_PATH="${CLOAK_GO_CK_CLIENT}"
    GO_CK_SERVER_PATH="${CLOAK_GO_CK_SERVER}")
add_test(NAME test_go_clienthello_matrix COMMAND test_go_clienthello_matrix)

# The paths of OUR ck-client and ck-server are APPENDED at the end of the
# top-level CMakeLists.txt, after cmd/ck-client and cmd/ck-server have
# been added, exactly as test_go_interop's are.

# TIMEOUT AND LABELS IN ONE CALL, AT THE SOURCE SITE. Task 8 of this
# module found that "every test carries both" was true of the GENERATED
# CTestTestfile.cmake and not of the source -- cloak_label_fast_tests()
# was merging two adjacent calls after the fact, so the discipline was
# the sweep's and not the file's. This is one call. (The older tests in
# this file, test_go_interop and test_unordered_proof among them, still
# use two adjacent calls; that is recorded rather than quietly fixed,
# because changing them is not this task's work.)
#
# LABELS "slow": six scenarios, twelve forked children, four of them Go's
# own binaries. That is exactly the cost module 9 task 0's split exists to
# keep out of the `ctest -L fast` edit loop; the default `ctest` still
# runs it.
#
# TIMEOUT 150, set from the worst FAILING run and not the passing one.
# MEASURED in Debug: a passing run is ~14 s (twelve children, 128 KiB
# each way through six of them). The bound has to cover a run where the
# two ends cannot read each other's frames -- the shape of defect this
# file exists to catch -- which is the shared harness's own arithmetic:
# three positive scenarios stalling for XFER_MS (15 s) each, plus three
# negative ones at HANDSHAKE_FAIL_MS + QUIET_MS (10 s) each, i.e. 75 s
# before any child that also ignores SIGTERM adds EXIT_MS. 150 leaves
# room for that and still fails loudly rather than being truncated.
set_tests_properties(test_go_clienthello_matrix PROPERTIES
    TIMEOUT 150
    LABELS "slow")

# ---------------------------------------------------------------------------
# THE ENCRYPTION MATRIX (module 10b task 2).
#
# A THIRD binary rather than more cases in either of the two above, for
# the same reason task 1 gave for splitting off the second and one more.
# test_go_clienthello_matrix's TIMEOUT 150 is sized for a worst FAILING
# run of six scenarios; twelve more would not fit under it, and a bound
# that cannot cover its own failure mode reports "***Timeout" instead of
# the assertion that diagnoses it. The three files also ask three
# different questions -- does the direct path interoperate at all, do all
# three ClientHello templates, do all four encryption methods -- so a
# failure in one should not hide the others behind a single ctest row.
# And at -j4 three rows run beside each other where one long row cannot.
#
# The harness all three share is go_oracle_harness.h. This task added the
# post-handshake wire capture and the numbered-record corruption to it;
# every existing scenario in the other two files is unchanged, because
# both are opt-in fields that default to off.
#
# cloak-server for cloak_clienthello_parse (the ClientHello is parsed to
# find the client's ephemeral key, which is what the session key is
# recovered through); cloak-mux for nothing linked but CLOAK_FRAME_* and
# CLOAK_CONN_MAX_FRAME_LEN, which are header constants -- the frame layer
# is re-implemented in the test rather than called, deliberately, so the
# assertion does not inherit the code it is judging; cloak-common for
# base64, X25519, Salsa20 and the AEAD.
add_executable(test_go_encryption_matrix test_go_encryption_matrix.c)
target_include_directories(test_go_encryption_matrix PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_go_encryption_matrix PRIVATE cloak-server cloak-mux cloak-common)
target_compile_definitions(test_go_encryption_matrix PRIVATE
    GO_CK_CLIENT_PATH="${CLOAK_GO_CK_CLIENT}"
    GO_CK_SERVER_PATH="${CLOAK_GO_CK_SERVER}")
add_test(NAME test_go_encryption_matrix COMMAND test_go_encryption_matrix)

# The paths of OUR ck-client and ck-server are APPENDED at the end of the
# top-level CMakeLists.txt, after cmd/ck-client and cmd/ck-server have
# been added, exactly as test_go_interop's are.

# TIMEOUT AND LABELS IN ONE CALL, AT THE SOURCE SITE -- the discipline
# task 8 of this module established and task 1 kept. (The older tests in
# this file, test_go_interop and test_unordered_proof among them, still
# use two adjacent calls merged after the fact by cloak_label_fast_tests();
# that is recorded rather than quietly fixed, because changing them is
# not this task's work either.)
#
# LABELS "slow": twelve scenarios, twenty-four forked children, twelve of
# them Go's own binaries.
#
# TIMEOUT 300, set from the worst FAILING run and not the passing one.
# MEASURED in Debug: a passing run is 6.9 s -- cheaper than its twelve
# scenarios suggest, because three of the four corrupting ones end on
# STALL_QUIET_MS (2 s of silence) rather than on XFER_MS. The bound has to
# cover a run where the two ends cannot read each other's frames -- the shape of defect this file exists to catch -- which is the
# shared harness's own arithmetic: eight positive scenarios stalling for
# XFER_MS (15 s) each is 120 s, and four frame-corrupting scenarios that
# never see their flipped bit land would also run to XFER_MS, 60 s more.
# 180 s of stalling plus twenty-four child spawns and teardowns; 300
# leaves room for that and still fails loudly rather than being
# truncated.
set_tests_properties(test_go_encryption_matrix PROPERTIES
    TIMEOUT 300
    LABELS "slow")

# ---------------------------------------------------------------------------
# UNORDERED MODE, PROVED (module 9 task 8).
#
# Five cases in one binary: the Go oracle in UDP mode (both roles), a
# deliberate-reordering middle box, sequence-number generation read off a
# captured connection with our own deobfuscator, two distributions, and a
# frame-replaying middle box. See the file's own header for why three of
# those are things no oracle can see.
#
# The same find_program pair as test_go_interop above resolves the Go
# binaries, and the same reasoning applies to why a missing one is a named
# runtime failure rather than a configure error or a skip.
add_executable(test_unordered_proof test_unordered_proof.c)
target_include_directories(test_unordered_proof PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
# cloak-server for cloak_clienthello_parse (case 3 recovers the session key
# from the relayed handshake itself); cloak-mux for the frame, stream,
# session and switchboard objects cases 2-5 drive directly; cloak-common
# for base64, X25519 and the AEAD.
target_link_libraries(test_unordered_proof PRIVATE cloak-server cloak-mux cloak-common)
target_compile_definitions(test_unordered_proof PRIVATE
    GO_CK_CLIENT_PATH="${CLOAK_GO_CK_CLIENT}"
    GO_CK_SERVER_PATH="${CLOAK_GO_CK_SERVER}")
add_test(NAME test_unordered_proof COMMAND test_unordered_proof)

# TIMEOUT 150, set from the worst FAILING run and not the passing one.
#
# MEASURED, idle, on the dev image, AT THIS COMMIT: a passing run is
# 3.68-3.83 s in Debug (5 consecutive runs) and 7.18-7.40 s under
# ASan+UBSan (3 consecutive runs). Four child processes, 24 datagram
# probes, 200000 padded frames and 48000 switchboard picks -- the padded
# frames went up 8x in this round (see PAD_STREAMS in the test file) and
# the wall time went DOWN, because case 5 stopped spending two fixed
# 200 ms budgets and now waits on events.
#
# What the number has to cover is a run where the two ends cannot exchange
# a datagram at all, which is the defect this file exists to catch and
# which its mutation campaign actually produced. Each oracle role then
# spends BOOT_MS (15 s, the warm-up retry window, which is where a wholly
# dead tunnel burns its time) plus three QUIET_MS windows plus two
# EXIT_MS teardowns -- about 27 s -- so both roles are ~54 s. A run whose
# LADDER stalls instead costs nine PROBE_MS (2 s each) per role on top,
# i.e. ~36 s more. The white-box cases fork nothing and every one of their
# loops is clock-bounded at 1 s or less, and their measured cost is 0.63 s
# (Debug). The worst failing path is therefore ~95 s,
# inside this timeout with enough room that even a wholly unresponsive run
# prints its own named assertion instead of being truncated as
# "***Timeout".
#
# 150 rather than the 120 this directory uses elsewhere, for one reason:
# that 120 covers ONE stalled transfer, and this file has TWO stalled
# roles plus a nine-rung ladder in each of them.
#
# LABELS "slow": this file forks and execs four real Cloak binaries, two of
# them Go's. `ctest -L fast` excludes it; the default `ctest` still runs it.
#
# THE TWO PROPERTIES ARE SET IN ONE CALL, DELIBERATELY, AND THAT IS A
# REPAIR RATHER THAN A STYLE CHOICE. They were two calls separated by the
# comment above, and a later edit that rewrote the comment took the
# TIMEOUT call with it -- leaving thirty lines deriving 150 from a ~95 s
# worst failing path, and a generated CTestTestfile.cmake carrying only
#     set_tests_properties(test_unordered_proof PROPERTIES  LABELS "slow" ...)
# so the test ran at ctest's DEFAULT 1500 s. A justification for a number
# that is not in the build is worse than no justification, because it
# stops the next reader from checking; the two oracle roles this comment
# reasons about would have hung the suite for 25 minutes instead of
# failing at 150 s with a named assertion. One call means a future comment
# rewrite cannot orphan one property without orphaning the other, and the
# check that matters is on the GENERATED file:
#     grep test_unordered_proof build/libcloak-server/tests/CTestTestfile.cmake
set_tests_properties(test_unordered_proof PROPERTIES TIMEOUT 150 LABELS "slow")

# Module 9 task 0's fast/slow split (see the top-level CMakeLists.txt's own
# comment on cloak_label_fast_tests() for what this call does and why it
# has to be made from here rather than from that file). Placed after the
# CLOAK_REQUIRE_GO block above, not before it, so that test_ws_interop
# already carries its "slow" label (or does not exist at all, with
# CLOAK_REQUIRE_GO=OFF) by the time this runs -- every OTHER test in this
# directory ends up labelled "fast" except test_proxy_stream, which was
# labelled "slow" directly at its own set_tests_properties call above.
cloak_label_fast_tests()
