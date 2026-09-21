# The long-running growth harness -- OFF by default, and never an
# add_test.
#
# WHY IT IS NOT REGISTERED WITH ctest. Module 10b task 9 decided this
# with a measurement, not a preference: the standard error of a fitted
# slope falls as T^(-3/2), so a case sized to fit this suite's budget
# resolves only slopes so coarse that a server losing a gigabyte a day
# would pass it green. The numbers, and the procedure that reproduces
# them, are in docs/runbooks/soak-growth.md. A "no growth detected" from
# a sixty-second run is a green light nobody should trust, and putting
# one in ctest is how it would get trusted.
#
# WHY IT IS OFF BY DEFAULT rather than merely unregistered: an extra
# executable in every build costs compile time and disk on a host this
# project has repeatedly found at 99% full, for a target nobody runs in
# an edit loop. Turn it on explicitly:
#
#   cmake -S . -B build -DCLOAK_BUILD_SOAK=ON
#   cmake --build build --target soak_growth
#
# It links cloak-client for the same reason the nine test binaries that
# include client_harness.h do -- the harness drives the SHIPPED client
# handshake rather than a second implementation of the wire format --
# and that dependency is test/tool-only in exactly the same way:
# libcloak-server does not and must not depend on libcloak-client.
add_executable(soak_growth soak_growth.c)
target_include_directories(soak_growth PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests
                                               ${CMAKE_SOURCE_DIR}/libcloak-server/tests)
target_link_libraries(soak_growth PRIVATE cloak-server cloak-client)
