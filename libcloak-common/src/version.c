#include "cloak/common.h"

/* The version string is baked in at configure time so that a release
 * artefact can say which tag produced it. `-DCLOAK_VERSION=v1.2.3` on the
 * CMake line sets it; nothing else in the tree reads it.
 *
 * The default is deliberately unchanged from what this file has always
 * returned, because two tests pin it by content --
 * test_ck_server_cli.c:587 and test_ck_client_cli.c:853 both assert that
 * `-v` contains "0.1.0-dev". A developer build must keep saying that, or
 * those two go red for a reason that has nothing to do with the code they
 * guard. So the override is opt-in: absent the flag, this is the same
 * literal it was before.
 *
 * The stamping happens in the top-level CMakeLists.txt, which also
 * strips a leading "v" so that the tag `v1.2.3` yields `cloak-c-1.2.3`
 * rather than `cloak-c-v1.2.3`. */
#ifndef CLOAK_VERSION_STRING
#define CLOAK_VERSION_STRING "cloak-c-0.1.0-dev"
#endif

const char *cloak_common_version(void) {
    return CLOAK_VERSION_STRING;
}
