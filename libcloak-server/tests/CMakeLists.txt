add_executable(test_clienthello_parse test_clienthello_parse.c)
target_include_directories(test_clienthello_parse PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_clienthello_parse PRIVATE cloak-server)
add_test(NAME test_clienthello_parse COMMAND test_clienthello_parse)

add_executable(test_server_auth test_server_auth.c)
target_include_directories(test_server_auth PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_server_auth PRIVATE cloak-server)
add_test(NAME test_server_auth COMMAND test_server_auth)

add_executable(test_replay_cache test_replay_cache.c)
target_include_directories(test_replay_cache PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_replay_cache PRIVATE cloak-server)
add_test(NAME test_replay_cache COMMAND test_replay_cache)

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
