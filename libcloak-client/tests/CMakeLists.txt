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
