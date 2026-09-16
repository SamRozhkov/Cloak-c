# cloak-server is a TEST-ONLY dependency here, not a dependency of the
# cloak-client library itself (see libcloak-client/CMakeLists.txt, which
# links only cloak-common) -- linking it in would be circular, since
# libcloak-server has no reason to depend on the client library and never
# will. It is the merged, well-tested decrypting half of this handshake
# (cloak_server_auth_decrypt, cloak/server_auth.h) and therefore the
# correct oracle for these tests: a payload the real verifier accepts is
# stronger evidence than a hand-computed literal, and unlike a literal it
# cannot drift if either side changes.
add_executable(test_client_auth test_client_auth.c)
target_include_directories(test_client_auth PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_client_auth PRIVATE cloak-client cloak-server)
add_test(NAME test_client_auth COMMAND test_client_auth)
set_tests_properties(test_client_auth PROPERTIES TIMEOUT 60)

# cloak-server is a TEST-ONLY dependency here for the same reason
# test_client_auth uses it (see above): the handshake's counterpart is the
# real, merged server, so these tests drive an actual cloak_dispatcher_t
# rather than a mock -- and the scripted server in this file composes its
# replies with cloak_server_auth_compose_reply itself, so the bytes it
# dribbles out one at a time cannot drift from what a real server sends.
add_executable(test_client_transport test_client_transport.c)
target_include_directories(test_client_transport PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_client_transport PRIVATE cloak-client cloak-server)
add_test(NAME test_client_transport COMMAND test_client_transport)
set_tests_properties(test_client_transport PROPERTIES TIMEOUT 60)

# cloak-server is a TEST-ONLY dependency here for the same reason
# test_client_auth and test_client_transport use it (see above), taken to
# its conclusion: this file drives the WHOLE merged server -- server
# state, user manager, user panel, registry, proxy, dispatcher and a
# listener -- against a real cloak_client_handshake_t and a real
# client-side cloak_session_t, so both halves of the protocol are library
# code for the first time. No sqlite3 link of its own is needed on top of
# the transitive one cloak-server already provides: cloak/usermanager.h
# keeps cloak_usermanager_t opaque and never includes sqlite3.h, and this
# file only opens and closes the manager.
add_executable(test_client_e2e test_client_e2e.c)
target_include_directories(test_client_e2e PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_client_e2e PRIVATE cloak-client cloak-server)
add_test(NAME test_client_e2e COMMAND test_client_e2e)
set_tests_properties(test_client_e2e PROPERTIES TIMEOUT 60)

# cloak-server is a TEST-ONLY dependency here for the same reason every
# other file in this directory uses it (see above): cloak_client_connector_t
# brings up a REAL session, so the far end has to be a real dispatcher,
# registry, panel and proxy -- a mock could not tell the difference between
# "four connections joined one session" and "four sessions were created",
# which is the single assertion this file most depends on. The library
# itself still links only cloak-common and cloak-mux.
# test_client_connector.c #includes ../src/client_connector.c directly, so
# that D4's key check can be forced from INSIDE the implementation's own
# translation unit rather than through a hook in the shipped config struct
# -- see that file's own top-of-file comment. The cloak-client link still
# supplies client_transport.c and client_auth.c; it does not supply
# client_connector.c.o, because an archive member is only pulled in to
# resolve an undefined symbol and every connector symbol is already
# defined in this executable.
add_executable(test_client_connector test_client_connector.c)
target_include_directories(test_client_connector PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_client_connector PRIVATE cloak-client cloak-server)
add_test(NAME test_client_connector COMMAND test_client_connector)
set_tests_properties(test_client_connector PROPERTIES TIMEOUT 60)

# cloak-server is a TEST-ONLY dependency here for the same reason every
# other file in this directory uses it (see above), and for this file it
# is the sharpest form of it: cloak_client_piper_t is the exact mirror of
# cloak_proxy_t, so the assertions that actually carry these cases are
# read off the SERVER -- cloak_proxy_stream_count and the upstream
# socket's own byte count. A mock could not tell "the piper opened a
# stream before any byte arrived" (D6's whole point) from "it waited",
# because both look the same from the local peer's side; only the
# server's stream context count separates them. The library itself still
# links only cloak-common and cloak-mux.
add_executable(test_client_piper test_client_piper.c)
target_include_directories(test_client_piper PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_client_piper PRIVATE cloak-client cloak-server)
add_test(NAME test_client_piper COMMAND test_client_piper)
set_tests_properties(test_client_piper PROPERTIES TIMEOUT 60)

# cloak-server is a TEST-ONLY dependency here for the same reason every
# other file in this directory uses it (see above), and singleplex is the
# case where a mock would be least able to stand in: the single assertion
# this file is built around is "two local connections produced TWO
# sessions on the server, not one", read off cloak_server_registry_count
# and the dispatcher's own created-session count. Only a real registry
# distinguishes two sessions from one session carrying two streams, and
# only a real dispatcher can refuse the deliberately-unauthenticatable
# handshake case 3 needs. The library itself still links only
# cloak-common and cloak-mux.
add_executable(test_client_singleplex test_client_singleplex.c)
target_include_directories(test_client_singleplex PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_client_singleplex PRIVATE cloak-client cloak-server)
add_test(NAME test_client_singleplex COMMAND test_client_singleplex)
set_tests_properties(test_client_singleplex PROPERTIES TIMEOUT 60)

# cloak-server is a TEST-ONLY dependency here for the same reason every
# other file in this directory uses it (see above), and this file is the
# end of that line: it wires a real cloak_client_piper_t over a real
# cloak_client_connector_t against the WHOLE merged server -- server
# state, user manager, user panel, registry, proxy, dispatcher and a
# listener -- with a fake upstream beyond it and an application socket at
# the near end, which is exactly how ck-client and ck-server will face
# each other. Nothing about these cases is checkable against a mock: case
# 2 reads "four local connections produced ONE session" off
# cloak_server_registry_count, case 3 needs a REAL user row, a real
# credit and a real cloak_userpanel_upload_now cycle to terminate a user
# out from under the client, and case 4 needs a real switchboard to
# answer what happens when one of several underlying connections dies.
# No sqlite3 link of its own is needed on top of the transitive one
# cloak-server already provides: cloak/usermanager.h keeps
# cloak_usermanager_t opaque and never includes sqlite3.h, and this file
# only opens, writes one user to, and closes the manager. The library
# itself still links only cloak-common and cloak-mux.
add_executable(test_client_full_e2e test_client_full_e2e.c)
target_include_directories(test_client_full_e2e PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_client_full_e2e PRIVATE cloak-client cloak-server)
add_test(NAME test_client_full_e2e COMMAND test_client_full_e2e)
set_tests_properties(test_client_full_e2e PROPERTIES TIMEOUT 60)

# cloak-server is a TEST-ONLY dependency here for the same reason every
# other file in this directory uses it (see above), and this file takes it
# one step further: the far end is assembled by cloak/server_stack.h, the
# sibling helper, so the two stacks face each other exactly as ck-client
# and ck-server will. That is not convenience -- case 2's whole claim is
# that a replacement session uses a DIFFERENT id, and the only trustworthy
# witness is the id the SERVER gave the session it created, read off the
# dispatcher's attach callback that cloak_server_stack_config_t exposes.
# A mock could report whatever the client asked for. No sqlite3 link of
# its own is needed on top of the transitive one cloak-server already
# provides: this file uses the VOID user manager (no DatabasePath) and
# never includes sqlite3.h.
# test_client_stack.c #includes ../src/client_stack.c directly, as
# test_client_connector.c does, so that the backoff ladder and the
# session-id predicate can be evaluated as the functions of numbers they
# are rather than inferred from how long something took -- see that file's
# own top-of-file comment. The cloak-client link still supplies the rest
# of the library; it does not supply client_stack.c.o, because an archive
# member is only pulled in to resolve an undefined symbol and every stack
# symbol is already defined in this executable.
add_executable(test_client_stack test_client_stack.c)
target_include_directories(test_client_stack PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_client_stack PRIVATE cloak-client cloak-server)
add_test(NAME test_client_stack COMMAND test_client_stack)
set_tests_properties(test_client_stack PROPERTIES TIMEOUT 60)
