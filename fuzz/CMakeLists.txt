# THE fuzz/ CONVENTION, established here and followed by every later
# target in this module.
#
#   * ONE FILE PER TARGET, named fuzz_<what it drives>.c, defining exactly
#     one LLVMFuzzerTestOneInput and nothing else that another target
#     links. No shared harness library: a fuzz target's whole value is
#     that you can read it top to bottom and know precisely what it feeds
#     the code under test, and the moment two targets share a helper that
#     stops being true of either.
#   * ONE committed seed corpus per target, at fuzz/corpus/<target name>/,
#     kept minimised with `-merge=1` (Ruling 2 caps the whole fuzz/
#     corpus at 1 MiB across all targets).
#   * A target that needs its seeds GENERATED -- because a gate in the
#     code is one the mutator cannot pass blind -- gets one companion
#     generator, gen_seeds_<target name>.c, built here alongside it. That
#     is an exception to "one file per target" and it needs the
#     justification fuzz_session_envelope.c's own generator gives; a
#     target whose seeds can be typed by hand should not have one.
#   * NO FUZZ TARGET IS add_test()ED, ever. These are not tests: they
#     have no expected output and they run for as long as you give them.
#     EXACTLY ONE TEST LIVES IN THIS DIRECTORY and it is not a fuzz
#     target: test_fuzz_corpus_replay (module 10a task 5, declared at the
#     bottom of the always-configured section below) feeds every
#     committed corpus unit to the harness that produced it, once, in
#     sorted order, and exits. That test -- and only that test -- is
#     configured with CLOAK_FUZZ OFF; the eight libFuzzer targets still
#     are not. The suite's count is a contract and this is the one thing
#     in module 10a that changes it: 75 -> 76.
#
# HOW TO BUILD AND RUN (from the repo root, in the cloak-c-dev image):
#
#   CC=clang cmake -S . -B /tmp/fuzzbuild -DCMAKE_BUILD_TYPE=Debug \
#         -DCLOAK_FUZZ=ON -DCLOAK_REQUIRE_GO=OFF
#   cmake --build /tmp/fuzzbuild --target fuzz_session_envelope -j4
#   /tmp/fuzzbuild/fuzz/fuzz_session_envelope \
#         fuzz/corpus/session_envelope -max_len=4096 -max_total_time=60
#
# CC=clang IS REQUIRED and was missing from this recipe until module 10a
# task 3 tripped over it: the dev image's default compiler is gcc, which
# has no libFuzzer, so a plain `cmake -S . -B ...` configures cleanly and
# then fails every compile in this directory with
#   cc: error: unrecognized argument to '-fsanitize=' option: 'fuzzer-no-link'
# A build directory already configured with gcc must be DELETED, not
# reconfigured: CMake caches the compiler.
#
# -DCLOAK_REQUIRE_GO=OFF is not required, only cheap: it skips the Go
# oracle's configure-time dependency probe and build, neither of which a
# fuzz build has any use for. --target names ONE executable so the 75 test
# binaries are not also built under ASan; measured on the commit that
# added this, a build directory holding only fuzz_session_envelope and
# gen_seeds_session_envelope plus the libraries they need is 12 MB,
# against the ~760 MB a full sanitizer build of the whole tree costs
# (that 760 MB figure is READ from module 10a task 0's report, not
# re-measured here).
#
# WHAT ONE MINUTE OF fuzz_session_envelope LOOKS LIKE, measured on the
# commit that added it (Docker cloak-c-dev, arm64, clang 14.0.6,
# -max_len=4096, starting from the committed corpus): 761,045 executions,
# 12,476 exec/s, 269 new units, 453 MB peak RSS, 288 coverage edges at
# corpus load, zero findings. A later task comparing against this should
# compare EXEC/S CAUTIOUSLY: module 10's scouting baseline of 185,590
# exec/s was one parse of one buffer per execution, while one execution
# here constructs a session and a reactor and then drives every envelope
# the input encodes, so the per-envelope rates are far closer than the
# per-execution ones. Peak RSS is directly comparable and is well under
# the scout's 732 MB.
#
# -max_len MATTERS HERE AND SHOULD BE PASSED EVERY TIME. Without a corpus
# libFuzzer starts at a 4096-byte ceiling but with a corpus it silently
# adopts the longest seed as the limit, so a minimised corpus can shrink
# the search space without anybody choosing to.

# ---------------------------------------------------------------------------
# THE ONE TEST IN THIS DIRECTORY, AND THE ONLY THING HERE THAT IS
# CONFIGURED WITH CLOAK_FUZZ OFF (module 10a task 5).
#
# Everything below the `if(NOT CLOAK_FUZZ) return()` further down is the
# libFuzzer build proper and is unchanged. This section is above it
# because it is what an ordinary `cmake -S . -B build` sees: one
# executable, one add_test, no libFuzzer, no -fsanitize=fuzzer, no seed
# generators. See replay_main.c's own header for what the test is for and
# why a replay rather than a campaign runs in the suite.
#
# WHY THE HARNESSES ARE COMPILED TWICE. Each fuzz_*.c defines exactly one
# LLVMFuzzerTestOneInput, so all eight cannot be linked into one program
# as written. Each gets its own OBJECT library here with the entry point
# renamed by the preprocessor, which means the replay links the SAME
# SOURCE the campaign fuzzes -- not a copy, not a subset, not a
# re-implementation of the oracles. A harness edit reaches both or
# neither. The cost is eight extra object files in the default build,
# measured at the commit that added this.
#
# THESE OBJECT LIBRARIES NAME THEIR INCLUDE DIRECTORIES but link nothing:
# an OBJECT library is only compiled here, and the executable below
# resolves every symbol. It links the four libraries rather than naming
# the ~12 source files the eight harnesses between them drive, which is
# the opposite of what each fuzz target below does -- and deliberately.
# A fuzz target names sources to keep an instrumented, ASan-built SQLite
# out of a build directory that exists to be small and fast to rebuild;
# this executable is part of the ordinary suite, where cloak-server,
# cloak-client, cloak-mux and cloak-common are already built for the
# other 75 tests and linking them costs a link rather than a compile.
# Naming sources here would instead risk duplicate symbols, since
# ws_frame.c and clienthello.c are members of libraries two other
# harnesses pull in whole.
find_package(OpenSSL REQUIRED)

# Every target with a committed corpus. A name here must match both
# fuzz_<name>.c and fuzz/corpus/<name>/, and must have a row in
# replay_main.c's g_targets -- the replay fails on a corpus directory it
# cannot open, so a name added here and forgotten there is loud.
set(CLOAK_REPLAY_TARGETS base64 client_reply clienthello firstpacket http
                         session_envelope ws_frame ws_handshake)

set(_cloak_replay_objects "")
foreach(_cloak_t IN LISTS CLOAK_REPLAY_TARGETS)
    add_library(fuzz_replay_${_cloak_t} OBJECT fuzz_${_cloak_t}.c)
    # LLVMFuzzerInitialize is renamed too, even though only
    # fuzz_client_reply.c defines one today: the rename has to be
    # unconditional so that a harness which grows one later is picked up
    # by adding a single table row in replay_main.c rather than by also
    # remembering to change this loop.
    target_compile_definitions(fuzz_replay_${_cloak_t} PRIVATE
        LLVMFuzzerTestOneInput=cloak_replay_${_cloak_t}
        LLVMFuzzerInitialize=cloak_replay_init_${_cloak_t})
    target_include_directories(fuzz_replay_${_cloak_t} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../libcloak-common/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../libcloak-mux/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../libcloak-server/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../libcloak-client/include)
    list(APPEND _cloak_replay_objects $<TARGET_OBJECTS:fuzz_replay_${_cloak_t}>)
endforeach()

add_executable(test_fuzz_corpus_replay replay_main.c ${_cloak_replay_objects})
# The corpus is read from the SOURCE tree, not copied into the build
# directory: it is the committed artefact, and a test that replays a copy
# would keep passing after somebody deleted the original.
target_compile_definitions(test_fuzz_corpus_replay PRIVATE
    CLOAK_FUZZ_CORPUS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/corpus")
target_link_libraries(test_fuzz_corpus_replay PRIVATE
    cloak-client cloak-server cloak-mux cloak-common OpenSSL::Crypto)
add_test(NAME test_fuzz_corpus_replay COMMAND test_fuzz_corpus_replay)

# LABELS AND TIMEOUT IN ONE CALL. Module 9 shipped a TIMEOUT 150
# documented in a thirty-line comment and never actually set, because a
# comment rewrite swallowed the set_tests_properties call that set it,
# and the test then ran at ctest's default of 1500 s while its own
# comment said 150. One call is the fix, here as in
# cloak_label_fast_tests(), and it is verified by reading the GENERATED
# fuzz/CTestTestfile.cmake rather than this file.
#
# "fast": the split is fork-or-not, not slow-or-not (see the root
# CMakeLists.txt), and this test forks nothing and execs nothing -- it is
# one process feeding 1,094 buffers to eight in-process entry points.
#
# TIMEOUT 60 is the project default and is not a placeholder: measured at
# the commit that added this file (Docker cloak-c-dev, arm64, ctest -j4),
# the replay runs in 0.32 s in a Debug build and 1.33-1.39 s under
# ASan+UBSan, so 60 is a 43x margin on the slower of the two -- far wider
# than the 1.89-2.02x the suite's longest test lives at. It is a
# MEASUREMENT, and `ctest -R test_fuzz_corpus_replay` in a sanitizer
# build is the command that would fail if it stopped being true.
set_tests_properties(test_fuzz_corpus_replay PROPERTIES
    LABELS "fast"
    TIMEOUT 60)

# Called for the reason every other directory that adds a test calls it
# (root CMakeLists.txt): a directory that forgets leaves its tests with
# no label at all, which `ctest -L fast` then silently excludes. It reads
# the LABELS and TIMEOUT set above back and re-applies them, so the two
# cannot disagree.
cloak_label_fast_tests()

# ---------------------------------------------------------------------------
# EVERYTHING BELOW THIS LINE IS THE libFuzzer BUILD, and is configured
# only with -DCLOAK_FUZZ=ON. return() at directory scope stops CMake
# reading the rest of this file, which is why the eight targets below
# stay byte-identical to what tasks 1-4 wrote rather than being wrapped
# in an if() that would re-indent all of them.
if(NOT CLOAK_FUZZ)
    return()
endif()

# Every target in this directory is built and sanitized identically; what
# differs between them is only WHICH code they drive, which is why the
# sanitizer options live in this function and the sources and libraries do
# not. ARGN is any extra source the target compiles in directly (see the
# note above targets #2 and #3), and each target names its own libraries
# below.
function(cloak_add_fuzz_target name)
    add_executable(${name} ${name}.c ${ARGN})
    # fuzzer (not fuzzer-no-link) only on the target that defines
    # LLVMFuzzerTestOneInput: this is what pulls in libFuzzer's own main.
    # The instrumentation of the LIBRARIES is set once, in the root
    # CMakeLists.txt's CLOAK_FUZZ block, because it has to apply to code
    # compiled there rather than here.
    target_compile_options(${name} PRIVATE -fsanitize=fuzzer,address)
    target_link_options(${name} PRIVATE -fsanitize=fuzzer,address)
endfunction()

cloak_add_fuzz_target(fuzz_session_envelope)
target_link_libraries(fuzz_session_envelope PRIVATE cloak-mux)

# The seed generator for target #1. Not a fuzz target -- an ordinary
# program with a main() that writes fuzz/corpus/session_envelope/. See
# its own file header for why this target cannot reach its own interesting
# state from a corpus of random bytes.
add_executable(gen_seeds_session_envelope gen_seeds_session_envelope.c)
target_link_libraries(gen_seeds_session_envelope PRIVATE cloak-mux)

# Targets #2 and #3: the server's front door. Both are unauthenticated --
# anything that can open a TCP connection reaches them -- and both live in
# libcloak-server.
#
# WHY THESE TWO NAME A SOURCE FILE RATHER THAN LINKING cloak-server. Both
# drive a self-contained parser with no dependency on anything else in
# that library, while `cloak-server` as a target drags in sqlite3 and
# cJSON (see libcloak-server/CMakeLists.txt) -- a large, instrumented,
# ASan-built amalgamation that nothing here feeds a single byte to, paid
# for in build time and in a fuzz build directory this module has to keep
# small on a nearly full disk. Naming the one .c file keeps each target's
# build to its harness plus the code under test, and it keeps the
# convention's promise intact: you can still read the target top to bottom
# and know exactly what is being fuzzed. If either parser ever grows a
# dependency on another translation unit, this breaks at link time, loudly,
# which is the right way for it to be noticed. The instrumentation is
# unaffected: the root CMakeLists.txt's CLOAK_FUZZ block sets
# -fsanitize=fuzzer-no-link,address via add_compile_options before this
# directory is added, so a source compiled here is instrumented exactly as
# it would be inside the library.
cloak_add_fuzz_target(fuzz_firstpacket ../libcloak-server/src/firstpacket.c)
target_include_directories(fuzz_firstpacket PRIVATE ../libcloak-server/include)

cloak_add_fuzz_target(fuzz_clienthello ../libcloak-server/src/clienthello_parse.c)
target_include_directories(fuzz_clienthello PRIVATE ../libcloak-server/include)

# ---------------------------------------------------------------------------
# Task 3's four targets. Same convention as everything above: one file per
# target, one LLVMFuzzerTestOneInput each, no shared harness, nothing
# add_test()ed.
#
# EACH OF THESE NAMES ITS SOURCE FILES rather than linking a library, for
# exactly the reason targets #2 and #3 do (see the note above them):
# `cloak-server` drags in an instrumented, ASan-built SQLite amalgamation
# and cJSON that none of these targets feeds a byte to, and `cloak-common`
# drags in cJSON, the reactor and the config readers for the same nothing.
# Naming the .c files keeps each build to the harness plus the code under
# test, and it keeps the convention's promise that a target can be read
# top to bottom. If any of these parsers grows a dependency on another
# translation unit this breaks at link time, loudly, which is the right
# way for it to be noticed.

# OpenSSL::Crypto, which two of the targets below need by name, is
# already in scope: find_package(OpenSSL REQUIRED) runs at the top of
# this file, in the replay section. It has to run HERE rather than be
# relied on from libcloak-common because find_package's IMPORTED targets
# are directory-scoped and this directory is a sibling of that one, not a
# child.

# Target #4: the CDN front door's WebSocket upgrade. Unauthenticated.
# ws_handshake.c uses cloak/base64.h (compiled in here) and OpenSSL's
# EVP_Digest for the SHA-1 in Sec-WebSocket-Accept, which is why this is
# the one target in this group that links anything at all.
cloak_add_fuzz_target(fuzz_ws_handshake ../libcloak-server/src/ws_handshake.c
                                        ../libcloak-common/src/base64.c)
target_include_directories(fuzz_ws_handshake PRIVATE ../libcloak-server/include
                                                     ../libcloak-common/include)
target_link_libraries(fuzz_ws_handshake PRIVATE OpenSSL::Crypto)

# Target #5: the RFC 6455 frame header decoder on the CDN data path.
# ws_frame.c references cloak_random_bytes (from cloak_ws_frame_mask_key,
# which this target never calls) so random.c comes along to satisfy the
# link; it is 34 lines and pulls in only OpenSSL's RAND.
cloak_add_fuzz_target(fuzz_ws_frame ../libcloak-mux/src/ws_frame.c
                                    ../libcloak-common/src/random.c)
target_include_directories(fuzz_ws_frame PRIVATE ../libcloak-mux/include
                                                 ../libcloak-common/include)
target_link_libraries(fuzz_ws_frame PRIVATE OpenSSL::Crypto)

# Target #9: base64, both alphabets, both directions. No dependencies at
# all -- base64.c includes only <string.h>.
cloak_add_fuzz_target(fuzz_base64 ../libcloak-common/src/base64.c)
target_include_directories(fuzz_base64 PRIVATE ../libcloak-common/include)

# Target #6: the admin API's HTTP/1.1 request parser. The highest per-bug
# cost in the tree (cloak/http.h:19-27) and the only target in this group
# that is stateful and allocates. http.c includes only <stdlib.h> and
# <string.h>, so nothing is linked.
cloak_add_fuzz_target(fuzz_http ../libcloak-server/src/http.c)
target_include_directories(fuzz_http PRIVATE ../libcloak-server/include)

# ---------------------------------------------------------------------------
# Target #7: the CLIENT's handshake-reply reader. The first client-side
# target in this directory, and the first one whose subject is reached by
# ANSWERING a connection rather than by opening one -- see the file's own
# header for why nine modules of fuzz lists missed it.
#
# NAMES ITS SOURCES rather than linking cloak-client, for the reason
# every target above it does: `cloak-client` drags in the connector, both
# pipers and the whole client stack -- and, through cloak-mux, the
# session and relay layers -- none of which this target feeds a byte to,
# all of them built instrumented and under ASan. The seven files below
# are exactly the transitive closure of what the reply reader needs:
# client_transport.c itself, client_auth.c for the shared secret the
# reply is sealed under, and from libcloak-common the four primitives
# (aead, x25519, random, clienthello) plus the reactor that actually
# dispatches the reads. If the reader grows a dependency on anything
# else this breaks at link time, loudly, which is the right way for it to
# be noticed.
#
# OpenSSL::Crypto: aead.c, x25519.c and random.c are all EVP/RAND.
cloak_add_fuzz_target(fuzz_client_reply ../libcloak-client/src/client_transport.c
                                        ../libcloak-client/src/client_auth.c
                                        ../libcloak-common/src/aead.c
                                        ../libcloak-common/src/x25519.c
                                        ../libcloak-common/src/random.c
                                        ../libcloak-common/src/clienthello.c
                                        ../libcloak-common/src/reactor.c)
target_include_directories(fuzz_client_reply PRIVATE ../libcloak-client/include
                                                     ../libcloak-common/include)
target_link_libraries(fuzz_client_reply PRIVATE OpenSSL::Crypto)
#
# RUN IT WITH -max_len=1024, not the 4096 the recipe at the top of this
# file uses. This target's cost is dominated by SETUP, not by parsing: a
# fresh ephemeral X25519 key, an ECDH, a ClientHello and a socketpair per
# execution, which is why it runs at ~490 exec/s where a pure parser
# target in this directory runs at six figures. Longer inputs buy nothing
# -- a real reply is ~165-206 bytes and the record-length ceiling is
# tripped by two header bytes, not by delivering 16640 of body -- and
# cost linearly, since a chunk size of 1 turns each input byte into its
# own write and its own reactor turn.
#
# WHAT ONE MINUTE LOOKS LIKE, measured on the commit that added it
# (Docker cloak-c-dev, arm64, clang 14.0.6, -max_len=1024, starting from
# the committed 65-file corpus): 29,871 executions, 489 exec/s, 33 new
# units, 388 MB peak RSS, 267 coverage edges, zero findings.
