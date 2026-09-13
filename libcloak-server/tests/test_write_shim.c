/* Test-only LD_PRELOAD shim for test_dispatcher_auth: intercepts write(2)
 * so a test can deterministically force the dispatcher's step-10 reply
 * write to see EAGAIN or a real error, without needing genuine kernel
 * socket-buffer backpressure -- which is not achievable for a reply this
 * small (CLOAK_SERVER_AUTH_REPLY_MAX_BYTES is 256 bytes; this container's
 * (and any ordinary Linux system's) minimum SO_RCVBUF/SO_SNDBUF floors are
 * in the low kilobytes, comfortably larger than any single write this
 * module ever makes, so no combination of tiny-receive-buffer-plus-
 * non-reading-peer can ever produce a short write or EAGAIN for it; this
 * was confirmed empirically before writing this shim, not assumed).
 *
 * Unlike the rest of this project, this file is deliberately
 * Linux+glibc-specific (RTLD_NEXT, LD_PRELOAD symbol interposition) rather
 * than POSIX-portable -- that's an acceptable trade here since it is
 * test-support code, never shipped, and the project's own global
 * constraints are already Linux-only.
 *
 * Protocol: a test sets the CLOAK_TEST_FORCE_PEER_PORT environment
 * variable (via setenv, from the test process itself -- this shim and the
 * test it serves always run in the very same process, since the
 * dispatcher-under-test and the test's own "client" socket both live in
 * this one executable) to the TCP port number of the client-side socket
 * whose CORRESPONDING SERVER-SIDE accepted fd's next write() call should
 * be faked, and optionally CLOAK_TEST_FORCE_MODE to "error" (the default,
 * absent or anything else, is "eagain"). The FIRST write() call this
 * process makes on any fd whose peer port matches is faked (errno set to
 * ECONNRESET for "error", EAGAIN otherwise; -1 returned either way) and
 * CLOAK_TEST_FORCE_PEER_PORT is immediately unset -- so only that one
 * call is affected, and every other write() everywhere else in the
 * process (including the client's own send of its ClientHello, and every
 * other test in this same binary that never sets this variable) passes
 * straight through to the real write(). */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

typedef ssize_t (*cloak_real_write_fn)(int, const void *, size_t);

ssize_t write(int fd, const void *buf, size_t count) {
    static cloak_real_write_fn real_write = NULL;
    if (real_write == NULL) {
        real_write = (cloak_real_write_fn)dlsym(RTLD_NEXT, "write");
    }

    const char *port_str = getenv("CLOAK_TEST_FORCE_PEER_PORT");
    if (port_str != NULL && *port_str != '\0') {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        if (getpeername(fd, (struct sockaddr *)&peer, &plen) == 0 && peer.sin_family == AF_INET &&
            ntohs(peer.sin_port) == (uint16_t)atoi(port_str)) {
            /* Consume the trigger before returning, so a retry on this
             * same fd (the whole point of the resume path under test)
             * goes through to the real write() rather than looping
             * forever on the fake failure. */
            unsetenv("CLOAK_TEST_FORCE_PEER_PORT");

            const char *mode = getenv("CLOAK_TEST_FORCE_MODE");
            errno = (mode != NULL && strcmp(mode, "error") == 0) ? ECONNRESET : EAGAIN;
            return -1;
        }
    }

    return real_write(fd, buf, count);
}
