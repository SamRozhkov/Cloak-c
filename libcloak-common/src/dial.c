#define _POSIX_C_SOURCE 200809L
#include "cloak/net.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int set_err(char *err, size_t err_cap, const char *fmt, ...) {
    if (err != NULL && err_cap > 0) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, err_cap, fmt, ap);
        va_end(ap);
    }
    return -1;
}

/* See cloak/net.h for why this exists and why its result is ignored. */
void cloak_net_set_tcp_nodelay(int fd, int socktype) {
    if (fd < 0 || socktype != SOCK_STREAM) {
        return;
    }
    int one = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

int cloak_net_resolve(const char *addr, int is_udp, cloak_addr_t *out,
                      char *err, size_t err_cap) {
    if (addr == NULL || out == NULL) {
        return set_err(err, err_cap, "resolve: invalid argument");
    }

    char host[256];
    char port[16];
    if (cloak_net_split_hostport(addr, host, sizeof(host), port, sizeof(port)) != 0) {
        return set_err(err, err_cap, "resolve: malformed address %s", addr);
    }
    if (host[0] == '\0') {
        return set_err(err, err_cap, "resolve: %s has no host to connect to", addr);
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = is_udp ? SOCK_DGRAM : SOCK_STREAM;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        return set_err(err, err_cap, "resolve: cannot resolve %s: %s", addr,
                       gai_strerror(rc));
    }
    if (res == NULL) {
        /* Not reachable per POSIX (rc == 0 guarantees at least one result),
         * but checked separately regardless -- folding this into the rc != 0
         * branch above would hand gai_strerror(0) ("Success") to the caller
         * as the reason a resolve failed, which is worse than no reason. */
        return set_err(err, err_cap, "resolve: %s resolved to no addresses", addr);
    }

    memset(out, 0, sizeof(*out));
    memcpy(&out->ss, res->ai_addr, res->ai_addrlen);
    out->len = res->ai_addrlen;
    out->socktype = res->ai_socktype;
    out->protocol = res->ai_protocol;
    freeaddrinfo(res);
    return 0;
}

/* Single exit point: unregisters, cancels timers, and fires cb exactly
 * once. fd is handed to cb on success (ownership passes) or closed here on
 * failure. */
static void dial_finish(cloak_dial_t *d, int success) {
    if (d->finished) {
        return;
    }
    d->finished = 1;

    if (d->timeout_timer != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(d->reactor, d->timeout_timer);
        d->timeout_timer = CLOAK_TIMER_INVALID;
    }
    if (d->immediate_timer != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(d->reactor, d->immediate_timer);
        d->immediate_timer = CLOAK_TIMER_INVALID;
    }

    int fd = d->fd;
    d->fd = -1;
    if (fd >= 0) {
        cloak_reactor_remove_fd(d->reactor, fd);
    }

    if (success) {
        d->cb(d, fd, d->userdata);
    } else {
        if (fd >= 0) {
            close(fd);
        }
        d->cb(d, -1, d->userdata);
    }
}

static void dial_on_event(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    (void)events;
    cloak_dial_t *d = userdata;

    /* The reactor folds HUP/ERR into READABLE regardless of the registered
     * interest, so never infer success from the event mask -- ask the
     * socket. */
    int soerr = 0;
    socklen_t len = sizeof(soerr);
    if (getsockopt(d->fd, SOL_SOCKET, SO_ERROR, &soerr, &len) != 0 || soerr != 0) {
        dial_finish(d, 0);
        return;
    }
    dial_finish(d, 1);
}

static void dial_on_timeout(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_dial_t *d = userdata;
    d->timeout_timer = CLOAK_TIMER_INVALID;
    dial_finish(d, 0);
}

/* Used when connect() succeeded synchronously: defers the callback to the
 * reactor's next turn so it never fires before cloak_dial_start returns. */
static void dial_on_immediate(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_dial_t *d = userdata;
    d->immediate_timer = CLOAK_TIMER_INVALID;
    dial_finish(d, 1);
}

int cloak_dial_start(cloak_dial_t *d, cloak_reactor_t *r, const cloak_addr_t *addr,
                     uint64_t timeout_ms, cloak_dial_cb cb, void *userdata,
                     char *err, size_t err_cap) {
    /* Initialize before validating anything else, so that on any failure
     * below -- including a NULL r/addr/cb -- d is already in the state
     * cloak_dial_cancel expects (the finished/fd/timer sentinels), not
     * only once every check has passed. Matches the ordering already used
     * by cloak_listener_open and cloak_relay_start. Only d itself being
     * NULL is exempt, since there is nothing to initialize. */
    if (d != NULL) {
        memset(d, 0, sizeof(*d));
        d->fd = -1;
        d->timeout_timer = CLOAK_TIMER_INVALID;
        d->immediate_timer = CLOAK_TIMER_INVALID;
    }

    if (d == NULL) {
        return set_err(err, err_cap, "dial: invalid argument");
    }
    if (r == NULL || addr == NULL || cb == NULL || addr->len == 0) {
        return set_err(err, err_cap, "dial: invalid argument");
    }

    d->reactor = r;
    d->cb = cb;
    d->userdata = userdata;

    int fd = socket(((const struct sockaddr *)&addr->ss)->sa_family,
                    addr->socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, addr->protocol);
    if (fd < 0) {
        return set_err(err, err_cap, "dial: socket: %s", strerror(errno));
    }
    d->fd = fd;
    cloak_net_set_tcp_nodelay(fd, addr->socktype);

    int rc = connect(fd, (const struct sockaddr *)&addr->ss, addr->len);
    if (rc == 0) {
        /* completed immediately (loopback, or a datagram socket): defer the
         * callback rather than firing it from inside start */
        d->immediate_timer = cloak_reactor_add_timer(r, 0, dial_on_immediate, d);
        if (d->immediate_timer == CLOAK_TIMER_INVALID) {
            close(fd);
            d->fd = -1;
            return set_err(err, err_cap, "dial: cannot arm completion timer");
        }
        return 0;
    }
    if (errno != EINPROGRESS) {
        int saved_errno = errno;
        close(fd);
        d->fd = -1;
        return set_err(err, err_cap, "dial: connect: %s", strerror(saved_errno));
    }

    if (cloak_reactor_add_fd(r, fd, CLOAK_REACTOR_WRITABLE, dial_on_event, d) != 0) {
        close(fd);
        d->fd = -1;
        return set_err(err, err_cap, "dial: cannot register with the reactor");
    }

    if (timeout_ms > 0) {
        d->timeout_timer = cloak_reactor_add_timer(r, timeout_ms, dial_on_timeout, d);
        if (d->timeout_timer == CLOAK_TIMER_INVALID) {
            cloak_reactor_remove_fd(r, fd);
            close(fd);
            d->fd = -1;
            return set_err(err, err_cap, "dial: cannot arm timeout timer");
        }
    }
    return 0;
}

void cloak_dial_cancel(cloak_dial_t *d) {
    if (d == NULL || d->finished) {
        return;
    }
    d->finished = 1;

    if (d->timeout_timer != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(d->reactor, d->timeout_timer);
        d->timeout_timer = CLOAK_TIMER_INVALID;
    }
    if (d->immediate_timer != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(d->reactor, d->immediate_timer);
        d->immediate_timer = CLOAK_TIMER_INVALID;
    }
    if (d->fd >= 0) {
        cloak_reactor_remove_fd(d->reactor, d->fd);
        close(d->fd);
        d->fd = -1;
    }
}
