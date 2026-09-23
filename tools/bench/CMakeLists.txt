# The end-to-end benchmark's two helper programs -- OFF by default, and
# never add_test()ed.
#
# WHY THEY ARE NOT TESTS. A benchmark answers "how fast", and `ctest`
# answers "is it correct". A timing number that gates a merge is a flake
# generator on shared CI hardware, and this project has already paid for
# three wall-clock assertions that were true on one machine and false on
# another. bench.sh prints numbers; nothing here asserts one.
#
# WHY THEY ARE SEPARATE PROGRAMS AND NOT PART OF THE SUITE'S HARNESSES.
# Both link nothing from this project. That is the point: they sit
# OUTSIDE the tunnel, speak plain TCP to whatever is listening, and so
# measure ck-client and ck-server exactly as an operator's traffic would
# -- including Go Cloak's own binaries, which is the only comparison
# that means anything. A helper that linked libcloak would be measuring
# a second implementation of the client instead of the shipped one.
#
# Turn them on explicitly:
#
#   cmake -S . -B build -DCLOAK_BUILD_BENCH=ON
#   cmake --build build --target bench_upstream bench_load
#
# Then drive them with tools/bench/bench.sh; see docs/runbooks/bench.md.
add_executable(bench_upstream upstream.c)
add_executable(bench_load load.c)
