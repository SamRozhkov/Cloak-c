# The server, as a program. Everything it needs is already a library:
# cloak-server carries the stack, cloak-common the reactor, the config
# parsers, the signalfd and the key generation. cjson is linked directly
# because main.c edits the configuration DOCUMENT before handing it to
# cloak_server_config_parse_json -- the BindAddr defaulting and the plugin
# mode's ProxyBook injection are Go's main() work, not the parser's --
# and cloak-common links cjson PRIVATE, so it does not propagate.
add_executable(ck-server main.c)
target_link_libraries(ck-server PRIVATE cloak-server cloak-common cjson)

# ---------------------------------------------------------------------------
# ONE SOURCE FILE, TWO TEST BINARIES (module 10b task 8).
#
# tests/test_ck_server_cli.c is compiled twice, with -DCK_CLI_PART=1 and
# -DCK_CLI_PART=2; both objects contain EVERY case and the table at the
# bottom of that file decides which half each process RUNS. A case left
# out of that table is a static function nobody calls -- a
# -Wunused-function warning -- so a split that drops a case cannot
# compile. cmd/ck-client/CMakeLists.txt carries the long version of the
# runtime argument; what is specific to this file is below.
#
# WHY THIS FILE WAS SPLIT TOO. It was test_ck_client_cli that crossed its
# margin (63.07 s warm at -j4 under ASan+UBSan against TIMEOUT 120 =
# 1.90x, under module 9's declared 1.91x floor). But this file measured
# 41.44 s in the same paired control run and was the SECOND-longest test
# in the suite, so splitting only the client would have promoted this one
# straight to the floor and bought one module of room instead of a floor
# that stays down. Splitting both is the answer to that. Measured after:
# 19.5-19.6 s (config) and 23.6-23.8 s (runtime) warm at -j4, i.e. 6.1x
# and 5.1x against TIMEOUT 120 where the single binary had 2.9x.
#
# Measured per-case, serial, ASan+UBSan: the whole file is 38.6 s across
# 23 cases, and FIFTEEN of them cost between 901 and 916 ms each and fork
# exactly one child. THE UNIT OF COST IS A FORKED CHILD, ~0.9 s under
# LeakSanitizer's exit scan -- the two expensive cases here are
# test_uid_and_key_generation (7321 ms) and test_exit_codes_are_distinct
# (4541 ms), and they are expensive because they fork eight and five
# children, not because of what they assert.
#
# THE BOUND IS STILL SET FROM THE WORST *FAILING* RUN, NOT THE PASSING
# ONE, and TIMEOUT 120 is therefore kept on both halves rather than
# re-derived: thirteen cases signal a child and reap it, each bounded by
# the test's own SHUTDOWN_MS of 2 s, so a run in which the shutdown path
# is broken costs the passing time plus that. At TIMEOUT 60 such a run
# was reported as "***Timeout", truncated, with its named assertions cut
# off -- which is exactly how a removed cloak_reactor_stop presented
# before SHUTDOWN_MS existed. Splitting halves both terms, so 120 now
# leaves the worse half a MEASURED 5.1x instead of 2.9x. Every wait inside
# the test is bounded by CLOCK_MONOTONIC; this is a backstop, not the
# mechanism.
#
# Case 5 still runs one descriptor short of the listener rather than
# binding the global ports 443 and 80, so the two halves running
# CONCURRENTLY under -j4 collide with each other no more than two
# concurrent runs of the old single binary did. The relative-path files
# the cases write (ck_server_test_config.json, "1234567") were checked
# before the split: each is written and removed inside ONE case, so no
# filename is now live in two processes at once.
foreach(_part config runtime)
    if(_part STREQUAL "config")
        set(_part_id 1)
    else()
        set(_part_id 2)
    endif()
    set(_tgt test_ck_server_cli_${_part})

    # Driven as a subprocess, so the test needs the binary's path and an
    # ordering edge against it. It borrows libcloak-common's
    # test_framework.h rather than growing a second copy.
    add_executable(${_tgt} tests/test_ck_server_cli.c)
    target_include_directories(${_tgt}
        PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
    target_link_libraries(${_tgt} PRIVATE cloak-common)
    target_compile_definitions(${_tgt}
        PRIVATE CK_SERVER_PATH="$<TARGET_FILE:ck-server>"
                CK_CLI_PART=${_part_id})
    add_dependencies(${_tgt} ck-server)
    add_test(NAME ${_tgt} COMMAND ${_tgt})

    # LABELS "slow" (module 9 task 0's fast/slow split): both halves fork
    # and exec real ck-server processes -- 19 children in config and 23 in
    # runtime, counted, not estimated -- which is nearly free in Debug
    # (0.04 s and 0.31 s) and 19.5 s / 23.6 s under ASan+UBSan purely from
    # LeakSanitizer's exit scan on each child. That scan is exactly the
    # cost an edit loop cannot afford on every keystroke.
    # `ctest -L fast` excludes them;
    # the default `ctest` with no arguments still runs them. LABELS and
    # TIMEOUT are set in ONE call here and merged into one generated call
    # by cloak_label_fast_tests() below -- see the top-level
    # CMakeLists.txt for why they never travel apart.
    set_tests_properties(${_tgt} PROPERTIES TIMEOUT 120 LABELS "slow")
endforeach()
unset(_part_id)
unset(_tgt)

# Module 9 task 0's fast/slow split (see the top-level CMakeLists.txt's
# own comment on cloak_label_fast_tests() for what this call does and why
# it has to be made from here rather than from that file). Both tests in
# this directory are already labelled "slow" above, so this call has
# nothing left to label -- it is here anyway, for the same reason every
# directory that calls add_test has it: a test added to this file later
# with no LABELS call of its own must not end up with no label at all.
cloak_label_fast_tests()
