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

# THE BOUND IS SET FROM THE WORST *FAILING* RUN, NOT THE PASSING ONE.
# This case forks ~40 real processes, and under ASan each one pays about
# 0.9 s for LeakSanitizer's exit scan (measured: 5 runs of `-u` take 4.6 s
# with leak detection and 0.11 s without). A passing run is therefore ~0.2 s
# in Debug and ~40 s under ASan.
#
# RE-MEASURED AFTER THE FINAL FIX WAVE: 39.8 s under ASan+UBSan, against
# ~38.9 s before it. Case 5 no longer binds the global ports 443 and 80 (it
# runs one descriptor short of the listener instead), so two concurrent
# runs of this suite on one host no longer collide and the file is safe
# under `ctest -j`.
#
# What this number has to accommodate is a run in which the shutdown path
# is broken: thirteen cases signal a child and reap it, each bounded by the
# test's own SHUTDOWN_MS of 2 s, so the worst failing run is ~40 + 26 s.
# At TIMEOUT 60 that run was reported as "***Timeout", truncated, with its
# named assertions cut off -- which is exactly how a removed
# cloak_reactor_stop presented before SHUTDOWN_MS existed. 120 s leaves the
# failing run room to finish and SAY WHAT BROKE. Every wait inside the test
# is bounded by CLOCK_MONOTONIC, so this is a backstop and not the
# mechanism.
set_tests_properties(test_ck_server_cli PROPERTIES TIMEOUT 120)
