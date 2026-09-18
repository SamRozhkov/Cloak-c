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
#   cmake -S . -B /tmp/fuzzbuild -DCMAKE_BUILD_TYPE=Debug \
#         -DCLOAK_FUZZ=ON -DCLOAK_REQUIRE_GO=OFF
#   cmake --build /tmp/fuzzbuild --target fuzz_session_envelope -j4
#   /tmp/fuzzbuild/fuzz/fuzz_session_envelope \
#         fuzz/corpus/session_envelope -max_len=4096 -max_total_time=60
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

# Every target in this directory links the same libraries and the same
# sanitizer runtime; the differences between targets belong in their .c
# files, not here.
function(cloak_add_fuzz_target name)
    add_executable(${name} ${name}.c)
    target_link_libraries(${name} PRIVATE cloak-mux)
    # fuzzer (not fuzzer-no-link) only on the target that defines
    # LLVMFuzzerTestOneInput: this is what pulls in libFuzzer's own main.
    # The instrumentation of the LIBRARIES is set once, in the root
    # CMakeLists.txt's CLOAK_FUZZ block, because it has to apply to code
    # compiled there rather than here.
    target_compile_options(${name} PRIVATE -fsanitize=fuzzer,address)
    target_link_options(${name} PRIVATE -fsanitize=fuzzer,address)
endfunction()

cloak_add_fuzz_target(fuzz_session_envelope)

# The seed generator for target #1. Not a fuzz target -- an ordinary
# program with a main() that writes fuzz/corpus/session_envelope/. See
# its own file header for why this target cannot reach its own interesting
# state from a corpus of random bytes.
add_executable(gen_seeds_session_envelope gen_seeds_session_envelope.c)
target_link_libraries(gen_seeds_session_envelope PRIVATE cloak-mux)
