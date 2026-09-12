/* _GNU_SOURCE (rather than _POSIX_C_SOURCE) for accept4; it implies the
 * POSIX definitions this file also needs. */
#define _GNU_SOURCE
#include "cloak/net.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdarg.h>
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

int cloak_net_split_hostport(const char *addr, char *host, size_t host_cap,
                             char *port, size_t port_cap) {
    if (addr == NULL || host == NULL || port == NULL || host_cap == 0 || port_cap == 0) {
        return -1;
    }

    const char *host_start;
    size_t host_len;
    const char *colon;

    if (addr[0] == '[') {
        const char *close_bracket = strchr(addr, ']');
        if (close_bracket == NULL || close_bracket[1] != ':') {
            return -1;
        }
        host_start = addr + 1;
        host_len = (size_t)(close_bracket - host_start);
        colon = close_bracket + 1;
    } else {
        colon = strrchr(addr, ':');
        if (colon == NULL) {
            return -1;
        }
        /* an unbracketed address with more than one colon is an ambiguous
         * bare IPv6 literal -- rejected, as Go's net.SplitHostPort does */
        if (memchr(addr, ':', (size_t)(colon - addr)) != NULL) {
            return -1;
        }
        host_start = addr;
        host_len = (size_t)(colon - addr);
    }

    const char *port_start = colon + 1;
    size_t port_len = strlen(port_start);
    if (port_len == 0) {
        return -1;
    }
    if (host_len + 1 > host_cap || port_len + 1 > port_cap) {
        return -1;
    }

    memcpy(host, host_start, host_len);
    host[host_len] = '\0';
    memcpy(port, port_start, port_len + 1);
    return 0;
}

/* Reads back the port the socket is actually bound to, which is the only
 * way to learn it when the caller asked for port 0. */
static int bound_port(int fd) {
    struct sockaddr_storage ss;
    socklen_t len = sizeof(ss);
    if (getsockname(fd, (struct sockaddr *)&ss, &len) != 0) {
        return -1;
    }
    if (ss.ss_family == AF_INET) {
        return ntohs(((struct sockaddr_in *)&ss)->sin_port);
    }
    if (ss.ss_family == AF_INET6) {
        return ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
    }
    return -1;
}

static void listener_on_readable(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    (void)events;
    cloak_listener_t *l = userdata;

    /* Edge-triggered: drain every pending connection, or the ones that
     * arrived within this same edge are never reported again. */
    for (;;) {
        int conn = accept4(l->fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (conn < 0) {
            /* accept(2) NOTES: several errors are already-pending errors on
             * the *next* queued connection, not a reason to stop accepting
             * -- the listening socket can have more connections queued
             * behind the failed one. Portable programs should treat these
             * as EAGAIN and retry the loop. All of the errno names below
             * are defined by glibc on Linux (this project's only target),
             * so no #ifdef guards are needed here.
             *
             * Deliberately NOT included: EMFILE/ENFILE/ENOBUFS/ENOMEM.
             * Those are resource exhaustion, not per-connection errors --
             * retrying immediately would spin the reactor at 100% CPU
             * until a descriptor/buffer frees (the classic epoll-accept
             * EMFILE trap). Do not "simplify" this into retrying on
             * anything but EAGAIN/EWOULDBLOCK; that reintroduces the trap. */
            if (errno == EINTR || errno == ECONNABORTED || errno == EPROTO ||
                errno == ENETDOWN || errno == ENOPROTOOPT || errno == EHOSTDOWN ||
                errno == ENONET || errno == EHOSTUNREACH || errno == EOPNOTSUPP ||
                errno == ENETUNREACH) {
                continue;
            }
            /* EAGAIN/EWOULDBLOCK: drained. Anything else (a resource
             * exhaustion error, or something unexpected) is also not fatal
             * to the listener -- stop draining and wait for the next edge. */
            return;
        }
        /* cloak_listener_open rejects cb == NULL, so on_accept is always
         * set on a listener that made it this far -- no NULL fallback
         * needed here. */
        l->on_accept(l, conn, l->on_accept_userdata);
    }
}

int cloak_listener_open(cloak_listener_t *l, cloak_reactor_t *r, const char *addr,
                        cloak_listener_accept_cb cb, void *userdata,
                        char *err, size_t err_cap) {
    /* Zero and mark closed before validating anything else, so that on any
     * failure below -- including a NULL r/addr/cb -- l is still left safe
     * to pass to cloak_listener_close, as the header promises. Only l
     * itself being NULL is exempt, since there is nothing to initialize. */
    if (l != NULL) {
        memset(l, 0, sizeof(*l));
        l->fd = -1;
        l->port = -1;
    }

    if (l == NULL || r == NULL || addr == NULL || cb == NULL) {
        return set_err(err, err_cap, "listener: invalid argument");
    }

    char host[256];
    char port[16];
    if (cloak_net_split_hostport(addr, host, sizeof(host), port, sizeof(port)) != 0) {
        return set_err(err, err_cap, "listener: malformed address %s", addr);
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host[0] != '\0' ? host : NULL, port, &hints, &res);
    if (rc != 0) {
        return set_err(err, err_cap, "listener: cannot resolve %s: %s", addr,
                       gai_strerror(rc));
    }

    int last_errno = 0;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        int fd = socket(ai->ai_family, ai->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC,
                        ai->ai_protocol);
        if (fd < 0) {
            last_errno = errno;
            continue;
        }

        int one = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (ai->ai_family == AF_INET6 && host[0] == '\0') {
            /* an empty host means every interface: ask for dual-stack, but
             * carry on with IPv6-only if the kernel refuses */
            int zero = 0;
            (void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
        }

        if (bind(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
            last_errno = errno;
            close(fd);
            continue;
        }
        if (listen(fd, 128) != 0) {
            last_errno = errno;
            close(fd);
            continue;
        }

        int port = bound_port(fd);
        if (port < 0) {
            /* Neither AF_INET nor AF_INET6 -- getaddrinfo shouldn't hand
             * back anything else for SOCK_STREAM here, but if it ever did,
             * succeeding with a listener whose port can never be reported
             * (cloak_listener_port's -1 is defined to mean "not open") is
             * worse than trying the next candidate address, if any. */
            close(fd);
            continue;
        }

        l->reactor = r;
        l->fd = fd;
        l->port = port;
        l->on_accept = cb;
        l->on_accept_userdata = userdata;

        if (cloak_reactor_add_fd(r, fd, CLOAK_REACTOR_READABLE, listener_on_readable, l) != 0) {
            close(fd);
            l->fd = -1;
            l->port = -1;
            freeaddrinfo(res);
            return set_err(err, err_cap, "listener: cannot register %s with the reactor",
                           addr);
        }

        freeaddrinfo(res);
        return 0;
    }

    freeaddrinfo(res);
    return set_err(err, err_cap, "listener: cannot bind %s: %s", addr,
                   last_errno != 0 ? strerror(last_errno) : "no usable address");
}

void cloak_listener_close(cloak_listener_t *l) {
    if (l == NULL || l->fd < 0) {
        return;
    }
    cloak_reactor_remove_fd(l->reactor, l->fd);
    close(l->fd);
    l->fd = -1;
    l->port = -1;
}

int cloak_listener_port(const cloak_listener_t *l) {
    if (l == NULL) {
        return -1;
    }
    return l->port;
}
