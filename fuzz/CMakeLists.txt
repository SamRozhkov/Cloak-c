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
#   * NOTHING HERE IS add_test()ED, ever. These are not tests: they have
#     no expected output, they run for as long as you give them, and the
#     suite's count is a contract (75). See the root CMakeLists.txt guard
#     that keeps this whole directory out of the default build.
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

# OpenSSL is found again here rather than relied on from libcloak-common:
# find_package's IMPORTED targets are directory-scoped, and this directory
# is a sibling of that one, not a child. Two of the targets below need
# OpenSSL::Crypto by name.
find_package(OpenSSL REQUIRED)

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
