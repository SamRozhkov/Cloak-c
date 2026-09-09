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
