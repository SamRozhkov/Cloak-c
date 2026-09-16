# The client, as a program. Everything it needs is already a library:
# cloak-client carries the stack, cloak-common the reactor, the config
# parsers and the signalfd. cjson is linked directly because main.c edits
# the configuration DOCUMENT before handing it to the parser -- the flag
# overrides and the plugin mode's SS_* fill-ins are Go's main() work, not
# the parser's, and they have to happen before a parser that validates as
# it parses sees the document -- and cloak-common links cjson PRIVATE, so
# it does not propagate.
add_executable(ck-client main.c)
target_link_libraries(ck-client PRIVATE cloak-client cloak-common cjson)

# Driven as a subprocess, and so is ck-server: cases 5 and 7 are the
# first tests in this project where the two BINARIES talk to each other,
# so this test needs both paths and an ordering edge against both. It
# borrows libcloak-common's test_framework.h rather than growing a second
# copy.
add_executable(test_ck_client_cli tests/test_ck_client_cli.c)
target_include_directories(test_ck_client_cli
    PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_ck_client_cli PRIVATE cloak-common)
target_compile_definitions(test_ck_client_cli
    PRIVATE CK_CLIENT_PATH="$<TARGET_FILE:ck-client>"
            CK_SERVER_PATH="$<TARGET_FILE:ck-server>")
add_dependencies(test_ck_client_cli ck-client ck-server)
add_test(NAME test_ck_client_cli COMMAND test_ck_client_cli)
set_tests_properties(test_ck_client_cli PROPERTIES TIMEOUT 60)
