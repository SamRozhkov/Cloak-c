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
 * straight through to the real write().
 *
 * Optionally, CLOAK_TEST_FORCE_STICKY=1 keeps CLOAK_TEST_FORCE_PEER_PORT
 * set across a forced failure instead of consuming it, so EVERY
 * subsequent write() to the matching peer keeps failing (CLOAK_TEST_
 * FORCE_MODE still governs which errno) until the test itself calls
 * unsetenv on it. This exists for one reason: proving a bounded deadline
 * actually fires against a reply write that never drains, which requires
 * a write that can never succeed -- and genuine socket-buffer
 * backpressure cannot do that for a reply this small either (same
 * reasoning as above, repeated indefinitely instead of once). Without
 * CLOAK_TEST_FORCE_STICKY set to exactly "1", behaviour is unchanged from
 * the one-shot protocol above.
 *
 * SECOND, INDEPENDENT PROTOCOL -- disk I/O failure, for
 * test_usermanager's rollback case. A test sets CLOAK_TEST_FAIL_WRITE_PATH
 * to a substring of a FILE path; every write(2)/pwrite(2) this process
 * makes to a file descriptor whose path contains that substring then
 * fails with EIO until the test unsets it. That is what lets a test drive
 * a genuine SQLITE_IOERR out of a commit, which no amount of legitimate
 * database usage can be made to do on demand. The substring should name
 * the test's own unique temp database, so the matching also covers
 * SQLite's `-wal` and `-shm` sidecars -- which, in WAL mode, are where a
 * COMMIT actually writes.
 *
 * All of write, pwrite and pwrite64 are interposed. SQLite's unix VFS
 * picks between them at compile time (os_unix.c selects USE_PREAD on
 * Linux, making pwrite the one seekAndWrite uses) but reaches the disk
 * through more than one of them in practice: interposing either write or
 * pwrite alone was MEASURED to be sufficient to fail a commit here, so
 * covering all three is what keeps this from depending on a selection
 * that could change under a different build.
 *
 * CLOAK_TEST_FAIL_WRITE_AFTER (optional, default 0) lets the first N
 * matching writes land before the failures begin -- see cloak_fail_this_fd.
 *
 * The two protocols are keyed by different environment variables and do
 * not interact: a test setting neither is completely unaffected, which is
 * what keeps this shim safe to preload into every test that already
 * uses it. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

typedef ssize_t (*cloak_real_write_fn)(int, const void *, size_t);
typedef ssize_t (*cloak_real_pwrite_fn)(int, const void *, size_t, off_t);

/* True when CLOAK_TEST_FAIL_WRITE_PATH is set and fd names a file whose
 * path contains it. Resolved through /proc/self/fd rather than tracked
 * from open(2), so it works regardless of which of SQLite's several open
 * paths produced the descriptor, and costs nothing when the variable is
 * unset (the common case: every other test in every binary). */
static int cloak_fail_this_fd(int fd) {
    static long seen = 0;
    const char *pat = getenv("CLOAK_TEST_FAIL_WRITE_PATH");
    const char *after;
    char link[64];
    char path[4096];
    ssize_t n;

    if (pat == NULL || *pat == '\0') {
        /* Disabled: also the reset point for the counter below, so a test
         * that unsets the variable leaves no state for the next one. */
        seen = 0;
        return 0;
    }
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    n = readlink(link, path, sizeof(path) - 1);
    if (n < 0) {
        return 0;
    }
    path[n] = '\0';
    if (strstr(path, pat) == NULL) {
        return 0;
    }

    /* CLOAK_TEST_FAIL_WRITE_AFTER lets the first N matching writes
     * through before failing everything after them. Failing from the very
     * first write is useless for testing a transaction, because then
     * NOTHING reaches the disk whether the writer batched its work or not
     * -- the two are indistinguishable. Letting a few writes land first is
     * what makes an unbatched writer leave some of its rows committed and
     * a batched one leave none. */
    after = getenv("CLOAK_TEST_FAIL_WRITE_AFTER");
    if (after != NULL && *after != '\0' && seen++ < atol(after)) {
        return 0;
    }
    return 1;
}

ssize_t write(int fd, const void *buf, size_t count) {
    static cloak_real_write_fn real_write = NULL;

    if (cloak_fail_this_fd(fd)) {
        errno = EIO;
        return -1;
    }
    if (real_write == NULL) {
        real_write = (cloak_real_write_fn)dlsym(RTLD_NEXT, "write");
        if (real_write == NULL) {
            /* dlsym itself failed (e.g. a libc that does not export a
             * plain "write" symbol under this name) -- there is no real
             * write() left to fall back to, and returning without
             * writing anything would make every caller in this process
             * see a silent no-op rather than an honest failure. Fail
             * loudly instead of leaving real_write NULL and crashing on
             * the next call below. */
            errno = ENOSYS;
            return -1;
        }
    }

    const char *port_str = getenv("CLOAK_TEST_FORCE_PEER_PORT");
    if (port_str != NULL && *port_str != '\0') {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        if (getpeername(fd, (struct sockaddr *)&peer, &plen) == 0 && peer.sin_family == AF_INET &&
            ntohs(peer.sin_port) == (uint16_t)atoi(port_str)) {
            const char *sticky = getenv("CLOAK_TEST_FORCE_STICKY");
            if (sticky == NULL || strcmp(sticky, "1") != 0) {
                /* One-shot (default): consume the trigger before
                 * returning, so a retry on this same fd (the whole point
                 * of the resume path under test) goes through to the real
                 * write() rather than looping forever on the fake
                 * failure. */
                unsetenv("CLOAK_TEST_FORCE_PEER_PORT");
            }
            /* Sticky: CLOAK_TEST_FORCE_PEER_PORT stays set, so every
             * subsequent write() to this same peer keeps failing until
             * the test itself clears it -- see this file's own
             * top-of-file comment. */

            const char *mode = getenv("CLOAK_TEST_FORCE_MODE");
            errno = (mode != NULL && strcmp(mode, "error") == 0) ? ECONNRESET : EAGAIN;
            return -1;
        }
    }

    return real_write(fd, buf, count);
}

/* pwrite is the call SQLite's unix VFS names on Linux (os_unix.c's
 * seekAndWrite under USE_PREAD); pwrite64 is covered as well so this does
 * not silently stop working if the amalgamation is ever built with
 * _FILE_OFFSET_BITS=64 or HAVE_PWRITE64. Neither is affected by the
 * socket protocol above. */
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) {
    static cloak_real_pwrite_fn real_pwrite = NULL;

    if (cloak_fail_this_fd(fd)) {
        errno = EIO;
        return -1;
    }
    if (real_pwrite == NULL) {
        real_pwrite = (cloak_real_pwrite_fn)dlsym(RTLD_NEXT, "pwrite");
        if (real_pwrite == NULL) {
            errno = ENOSYS;
            return -1;
        }
    }
    return real_pwrite(fd, buf, count, offset);
}

ssize_t pwrite64(int fd, const void *buf, size_t count, off64_t offset);

ssize_t pwrite64(int fd, const void *buf, size_t count, off64_t offset) {
    typedef ssize_t (*real_fn)(int, const void *, size_t, off64_t);
    static real_fn real_pwrite64 = NULL;

    if (cloak_fail_this_fd(fd)) {
        errno = EIO;
        return -1;
    }
    if (real_pwrite64 == NULL) {
        real_pwrite64 = (real_fn)dlsym(RTLD_NEXT, "pwrite64");
        if (real_pwrite64 == NULL) {
            errno = ENOSYS;
            return -1;
        }
    }
    return real_pwrite64(fd, buf, count, offset);
}
