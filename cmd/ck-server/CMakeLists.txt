# The server, as a program. Everything it needs is already a library:
# cloak-server carries the stack, cloak-common the reactor, the config
# parsers, the signalfd and the key generation. cjson is linked directly
# because main.c edits the configuration DOCUMENT before handing it to
# cloak_server_config_parse_json -- the BindAddr defaulting and the plugin
# mode's ProxyBook injection are Go's main() work, not the parser's --
# and cloak-common links cjson PRIVATE, so it does not propagate.
add_executable(ck-server main.c)
target_link_libraries(ck-server PRIVATE cloak-server cloak-common cjson)

# Driven as a subprocess, so the test needs the binary's path and an
# ordering edge against it. It borrows libcloak-common's test_framework.h
# rather than growing a second copy.
add_executable(test_ck_server_cli tests/test_ck_server_cli.c)
target_include_directories(test_ck_server_cli
    PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_ck_server_cli PRIVATE cloak-common)
target_compile_definitions(test_ck_server_cli
    PRIVATE CK_SERVER_PATH="$<TARGET_FILE:ck-server>")
add_dependencies(test_ck_server_cli ck-server)
add_test(NAME test_ck_server_cli COMMAND test_ck_server_cli)
set_tests_properties(test_ck_server_cli PROPERTIES TIMEOUT 60)
