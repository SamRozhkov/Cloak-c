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
# cloak-server, for cloak_usermanager_* ONLY. The billing case
# (test_shutdown_bills_the_last_interval) reads the user database back out
# after ck-server has exited, through the same API the server wrote it
# with, rather than re-implementing the SQLite schema in the test or
# standing up a second server and an admin request to ask.
target_link_libraries(test_ck_client_cli PRIVATE cloak-common cloak-server)
target_include_directories(test_ck_client_cli
    PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-server/include)
target_compile_definitions(test_ck_client_cli
    PRIVATE CK_CLIENT_PATH="$<TARGET_FILE:ck-client>"
            CK_SERVER_PATH="$<TARGET_FILE:ck-server>")
add_dependencies(test_ck_client_cli ck-client ck-server)
add_test(NAME test_ck_client_cli COMMAND test_ck_client_cli)
# TIMEOUT 120, not 60, and the number is measured rather than guessed.
# At TIMEOUT 60 an independent reviewer measured this file under
# ASan+UBSan at 33.5 s idle, 43.9 s with the machine 50% oversubscribed,
# and TIMING OUT at 60.04 s under 2x oversubscription -- and ctest reported
# that timeout as "<end of output>", because the test's stdout was
# block-buffered to a pipe. A flake with no diagnostic is a flake nobody
# can act on, so the test now line-buffers stdout and this bound is 120.
#
# Almost all of the runtime is process startup and LeakSanitizer's exit
# scan across the ck-server and ck-client processes this file spawns, not
# the transfers it measures. 120 also matches test_ck_server_cli, which was
# raised for the same reason, so the two binaries' tests carry one bound
# and not two.
#
# RE-MEASURED AGAIN AFTER MODULE 9 TASK 7 (the -u/"UDP" wiring): 60.2 s
# idle under ASan+UBSan, against 53.1 s before it. That task replaced case
# 4's two subprocesses with eleven -- the -h run, the three listener runs
# (with -u, without it, and by config key), -u=false, -u=perhaps, the two
# NumConn runs and case 4b's two ClientHello captures -- and the margin
# against TIMEOUT 120 is therefore 2.0x, not 2.3x.
#
# HELD ACROSS TASK 7'S FIX ROUND, and the mechanism is worth copying: case
# 4 gained a leg (the ssv option-string path, whose conf_set_bool branch was
# measured to drop -u silently with all 73 green) and PAID FOR IT by
# deleting the "same configuration without the flag" run, every assertion of
# which -- the TCP log line, can_connect, tcp_port_is_free, on the same port
# -- moved into the -u=false run that was already there. Net subprocess
# count unchanged; measured 60.5 s at -j2, against 60.2 s before. A new leg
# here has to arrive with a trade like that one.
#
# THE BOUND WAS STILL NOT RAISED, for the reason below, and the win named
# at the end of this comment was still not taken: ASAN_OPTIONS=detect_leaks=0
# on the children would remove most of this number AND the only leak check
# that ever runs against the two BINARIES, which is coverage this project
# has no other source for. Whoever adds the next case here should take
# that trade deliberately rather than by arriving at it.
#
# THE MEASUREMENT BEFORE THAT: 53.1 s idle under ASan+UBSan
# (39.8 s for test_ck_server_cli), against 45.0 s before it -- the wave
# added seven subprocesses across the SIGPIPE, ServerName, admin-singleplex,
# plugin-detection and billing cases. The margin is therefore 2.3x, not
# 2.7x, and THE BOUND WAS DELIBERATELY NOT RAISED AGAIN: a third raise
# would be the point at which nobody runs the sanitizer build before
# pushing. The next module that wants to add cases to this file should
# first take the win the whole-branch review measured and costed --
# ASAN_OPTIONS=detect_leaks=0 on the forked CHILDREN only, which is most
# of this number and which the parent's own check does not need.
set_tests_properties(test_ck_client_cli PROPERTIES TIMEOUT 120)

# LABELS "slow" (module 9 task 0's fast/slow split): this file forks
# and execs both real binaries repeatedly (see above) -- 8.6 s in
# Debug, 53 s under ASan+UBSan idle, almost all of it process startup
# and LeakSanitizer's exit scan. `ctest -L fast` excludes it; the
# default `ctest` with no arguments still runs it.
set_tests_properties(test_ck_client_cli PROPERTIES LABELS "slow")

# Module 9 task 0's fast/slow split (see the top-level CMakeLists.txt's
# own comment on cloak_label_fast_tests() for what this call does and why
# it has to be made from here rather than from that file). This directory
# has exactly one test, already labelled "slow" above, so this call has
# nothing left to label -- it is here anyway, for the same reason every
# directory that calls add_test has it: a test added to this file later
# with no LABELS call of its own must not end up with no label at all.
cloak_label_fast_tests()
