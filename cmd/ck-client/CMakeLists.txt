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

# ---------------------------------------------------------------------------
# ONE SOURCE FILE, TWO TEST BINARIES (module 10b task 8).
#
# tests/test_ck_client_cli.c is compiled twice, with -DCK_CLI_PART=1 and
# -DCK_CLI_PART=2. Both objects contain EVERY case; the table at the
# bottom of that file decides which half each process RUNS. See that
# file's own comment for why it is a table and not an #if -- the short
# version is that a case left out of the table is a static function
# nobody calls, which is a -Wunused-function warning, so a split that
# drops a case cannot compile.
#
# WHY IT WAS SPLIT, in measured numbers rather than remembered ones.
# Warm (NOT cold -- the ~102 s figure quoted through module 10a was a
# cold-cache reading; warm runs of this suite are 67-71 s), ASan+UBSan,
# ctest -j4, paired against a control run of the same build:
#
#   test_ck_client_cli   63.07 s   against TIMEOUT 120 = 1.90x
#   test_ck_server_cli   41.44 s
#   suite (76 tests)     68.51 s
#
# 1.90x is UNDER the 1.91x floor module 9 declared, and the trick that
# funded the last addition here -- deleting a subprocess run and merging
# its assertions into a neighbour -- is spent. So the file was split
# rather than trimmed, and the three tasks in this module that each add a
# forking case have room measured for them rather than argued.
#
# AND WHAT IT MEASURED AFTERWARDS, same build, same machine, same session:
#
#   test_ck_client_cli_config    31.2 - 32.0 s   = 3.8x - 3.7x
#   test_ck_client_cli_runtime   32.0 - 32.3 s   = 3.7x
#   test_ck_server_cli_config    19.5 - 19.6 s   = 6.1x
#   test_ck_server_cli_runtime   23.6 - 23.8 s   = 5.1x
#   suite (78 tests)             67.19 s, 68.81 s
#
# THE SPLIT BOUGHT TIMEOUT MARGIN AND NOT WALL CLOCK, and that second
# half is the part the plan needs to hear. 68.5 s (control) against 67.2
# and 68.8 s (treatment) is no change at all: the suite's serial work is
# 247 s before and 255 s after, and at -j4 it CANNOT go below 255/4 =
# 63.8 s no matter how finely any single test is divided. The control was
# already within 11% of its own such bound. THE SUITE IS WORK-BOUND, NOT
# LATENCY-BOUND -- so the next task that adds 30 s of forking cases pays
# about 7.5 s of wall clock wherever it puts them, and the question its
# sizing has to answer is the TIMEOUT one, which this split just reopened
# from 1.90x to 3.7x.
#
# The split also COST 8 s of serial work (247 -> 255): two extra
# processes, two extra ASan startups, two extra LeakSanitizer scans of
# the parent. That is the price of the margin and it is paid in a
# dimension that is not the critical path.
#
# THE REMAINING WALL-CLOCK LEVER is the one both CLI test files have
# recorded and deliberately not taken for two modules now: ASAN_OPTIONS=
# detect_leaks=0 on the forked CHILDREN. The measurement below prices it:
# this file forks 56 children and the server file 42, at ~0.92 s each, so
# roughly 90 s of the suite's 255 s is LeakSanitizer scanning children --
# which would take the -j4 bound from 63.8 s to about 41 s. It is not
# taken here because it would also remove the only leak check that ever
# runs against the two real BINARIES, which this project has no other
# source for. Whoever takes it should take it deliberately.
#
# THE UNIT OF COST IS A FORKED CHILD, 918 ms each, measured with a
# counter on the test's fork() site rather than inferred: 54 of this
# file's 56 children account for 49.6 s of its run, and the same counter
# reads 919 ms/child across the server file's 42. The exception is
# test_proxy_flag_overrides_json -- two children, 9503 ms, the most
# expensive case in either file -- where the other ~8.6 s is the client
# stack's RETRY BACKOFF while it waits for the server to refuse the
# flag's proxy method. So: size a forking case at ~0.92 s per child, and
# MEASURE any case that waits on a real protocol event.
#
# THE SPLIT IS SAFE UNDER -j4, which was checked BEFORE splitting and not
# after. Cases that shared a process now run concurrently, so anything
# implicitly serialised by living in one binary is now a race. The two
# shapes that exist here:
#   - Every port comes from free_port(), never a constant, and
#     test_udp_is_honoured's `tcp_port_is_free(local) == 1` is the known
#     shape module 9 investigated -- a TCP bind to a UDP listener's
#     ephemeral port, defeatable by any concurrent process because
#     ephemeral ranges are shared across protocol families. It is NOT made
#     worse by this split: it was already concurrent with 75 other tests
#     at -j4, and no OTHER case in this file derives a port from it.
#   - Three cases write RELATIVE-path files into the ctest working
#     directory: ck_client_test_admin.db, ck_client_test_billing.db and
#     ck_client_test_config.json. Each name is written and unlinked inside
#     ONE case, so no filename is now live in two processes at once. A new
#     case that adds a relative-path file has to keep that property or
#     name the file after its half.
#
# TIMEOUT STAYS 120 on both halves, deliberately, and the value is NOT
# re-derived here: it is the bound the single binary carried, for the
# reasons module 9 measured and wrote down -- a run in which the shutdown
# path is broken pays every case's bounded wait, and at TIMEOUT 60 such a
# run was reported as "***Timeout" with its named assertions cut off.
# Halving the work halves that failing run too, so 120 is now a MEASURED
# margin of 3.7x on the worse half instead of 1.90x. Lowering it would
# spend the room this task exists to create.
foreach(_part config runtime)
    if(_part STREQUAL "config")
        set(_part_id 1)
    else()
        set(_part_id 2)
    endif()
    set(_tgt test_ck_client_cli_${_part})

    # Driven as a subprocess, and so is ck-server: the end-to-end and
    # admin cases are the first tests in this project where the two
    # BINARIES talk to each other, so this test needs both paths and an
    # ordering edge against both. It borrows libcloak-common's
    # test_framework.h rather than growing a second copy.
    add_executable(${_tgt} tests/test_ck_client_cli.c)
    target_include_directories(${_tgt}
        PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
    # cloak-server, for cloak_usermanager_* ONLY. The billing case
    # (test_shutdown_bills_the_last_interval) reads the user database back
    # out after ck-server has exited, through the same API the server
    # wrote it with, rather than re-implementing the SQLite schema in the
    # test or standing up a second server and an admin request to ask.
    target_link_libraries(${_tgt} PRIVATE cloak-common cloak-server)
    target_include_directories(${_tgt}
        PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-server/include)
    target_compile_definitions(${_tgt}
        PRIVATE CK_CLIENT_PATH="$<TARGET_FILE:ck-client>"
                CK_SERVER_PATH="$<TARGET_FILE:ck-server>"
                CK_CLI_PART=${_part_id})
    add_dependencies(${_tgt} ck-client ck-server)
    add_test(NAME ${_tgt} COMMAND ${_tgt})

    # LABELS "slow" (module 9 task 0's fast/slow split): both halves fork
    # and exec both real binaries repeatedly -- config forks 24 children
    # and runtime 32 -- so both are ~31-32 s under ASan+UBSan, almost all
    # of it process startup and LeakSanitizer's exit scan. IN DEBUG THE
    # TWO ARE NOT BALANCED (7.15 s and 0.60 s) and that is expected, not a
    # bug in the split: with no sanitizer a fork is nearly free, so Debug
    # cost is dominated by test_proxy_flag_overrides_json's ~8.6 s of
    # protocol retry backoff instead of by fork count. The halves are
    # balanced against the build the TIMEOUT protects, which is the
    # sanitizer one; Debug's whole suite is 22.5 s and its critical path
    # is test_adminapi and test_dispatcher_ws, not this file.
    # `ctest -L fast` excludes them; the
    # default `ctest` with no arguments still runs them. TIMEOUT is NOT
    # set here: cloak_label_fast_tests() below writes LABELS and TIMEOUT
    # in ONE set_tests_properties call, defaulting the timeout only where
    # a test set none -- and 120 is what this pair needs, so it is set
    # here and read back there. See the top-level CMakeLists.txt for why
    # the two properties travel together and never apart.
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
# It is also what merges the LABELS and TIMEOUT above into the ONE
# generated set_tests_properties call the whole tree is verified against.
cloak_label_fast_tests()
