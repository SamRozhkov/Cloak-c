add_executable(test_version test_version.c)
target_include_directories(test_version PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_version PRIVATE cloak-common)
add_test(NAME test_version COMMAND test_version)

add_executable(test_random test_random.c)
target_link_libraries(test_random PRIVATE cloak-common)
add_test(NAME test_random COMMAND test_random)

add_executable(test_aead test_aead.c)
target_link_libraries(test_aead PRIVATE cloak-common)
add_test(NAME test_aead COMMAND test_aead)

add_executable(test_salsa20 test_salsa20.c)
target_link_libraries(test_salsa20 PRIVATE cloak-common)
add_test(NAME test_salsa20 COMMAND test_salsa20)

add_executable(test_x25519 test_x25519.c)
target_link_libraries(test_x25519 PRIVATE cloak-common)
add_test(NAME test_x25519 COMMAND test_x25519)

add_executable(test_reactor test_reactor.c)
target_link_libraries(test_reactor PRIVATE cloak-common)
add_test(NAME test_reactor COMMAND test_reactor)

add_executable(test_reactor_once test_reactor_once.c)
target_link_libraries(test_reactor_once PRIVATE cloak-common)
add_test(NAME test_reactor_once COMMAND test_reactor_once)
set_tests_properties(test_reactor_once PROPERTIES TIMEOUT 60)

add_executable(test_clienthello test_clienthello.c)
target_link_libraries(test_clienthello PRIVATE cloak-common)
add_test(NAME test_clienthello COMMAND test_clienthello)

add_executable(test_base64 test_base64.c)
target_include_directories(test_base64 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_base64 PRIVATE cloak-common)
add_test(NAME test_base64 COMMAND test_base64)

add_executable(test_log test_log.c)
target_include_directories(test_log PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_log PRIVATE cloak-common)
add_test(NAME test_log COMMAND test_log)

add_executable(test_cjson_link test_cjson_link.c)
target_include_directories(test_cjson_link PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_cjson_link PRIVATE cloak-common cjson)
add_test(NAME test_cjson_link COMMAND test_cjson_link)

add_executable(test_config_client test_config_client.c)
target_include_directories(test_config_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_config_client PRIVATE cloak-common)
add_test(NAME test_config_client COMMAND test_config_client)

add_executable(test_config_server test_config_server.c)
target_include_directories(test_config_server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_config_server PRIVATE cloak-common)
add_test(NAME test_config_server COMMAND test_config_server)

add_executable(test_config_ssv test_config_ssv.c)
target_include_directories(test_config_ssv PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_config_ssv PRIVATE cloak-common)
add_test(NAME test_config_ssv COMMAND test_config_ssv)

add_executable(test_bytequeue test_bytequeue.c)
target_include_directories(test_bytequeue PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_bytequeue PRIVATE cloak-common)
add_test(NAME test_bytequeue COMMAND test_bytequeue)

add_executable(test_listener test_listener.c)
target_include_directories(test_listener PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_listener PRIVATE cloak-common)
add_test(NAME test_listener COMMAND test_listener)
set_tests_properties(test_listener PROPERTIES TIMEOUT 60)

add_executable(test_dial test_dial.c)
target_include_directories(test_dial PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_dial PRIVATE cloak-common)
add_test(NAME test_dial COMMAND test_dial)
set_tests_properties(test_dial PROPERTIES TIMEOUT 60)

add_executable(test_relay test_relay.c)
target_include_directories(test_relay PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_relay PRIVATE cloak-common)
add_test(NAME test_relay COMMAND test_relay)
set_tests_properties(test_relay PROPERTIES TIMEOUT 60)

add_executable(test_sqlite_link test_sqlite_link.c)
target_include_directories(test_sqlite_link PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_sqlite_link PRIVATE cloak-common sqlite3)
add_test(NAME test_sqlite_link COMMAND test_sqlite_link)
set_tests_properties(test_sqlite_link PROPERTIES TIMEOUT 60)

add_executable(test_signals test_signals.c)
target_include_directories(test_signals PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_signals PRIVATE cloak-common)
add_test(NAME test_signals COMMAND test_signals)
set_tests_properties(test_signals PROPERTIES TIMEOUT 60)

# None of this directory's tests fork a process (module 9 task 0's
# fast/slow split; see the top-level CMakeLists.txt's own comment on
# cloak_label_fast_tests() for what this call does and why it has to be
# made from here rather than from that file). Every test above ends up
# labelled "fast".
cloak_label_fast_tests()
