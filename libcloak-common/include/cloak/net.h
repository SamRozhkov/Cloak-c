#ifndef CLOAK_NET_H
#define CLOAK_NET_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include "cloak/bytequeue.h"
#include "cloak/reactor.h"

/* Socket primitives shared by both binaries: a listener that turns an
 * address string into accepted connections, a connector that turns one
 * into a connected socket, and a relay that splices two sockets together.
 *
 * All three are reactor-driven and never block (with the single, clearly
 * marked exception of cloak_net_resolve, which performs a synchronous DNS
 * lookup and must therefore be called at startup, not per connection).
 *
 * Failure reporting matches the rest of this library: 0/-1, with a
 * human-readable reason written into a caller-supplied err buffer that may
 * be NULL. */

/* Splits "host:port" into its parts, matching Go's net.SplitHostPort
 * closely enough for the address forms Cloak's configs use:
 *   "127.0.0.1:1984"  -> host "127.0.0.1", port "1984"
 *   ":443"            -> host "",          port "443"   (all interfaces)
 *   "[::1]:443"       -> host "::1",       port "443"
 *   "localhost:51443" -> host "localhost", port "51443"
 * An IPv6 address MUST be bracketed; an unbracketed one is ambiguous and
 * rejected. Returns 0 on success, -1 if there is no port, the port is
 * empty, or either part does not fit its buffer (including the NUL). */
int cloak_net_split_hostport(const char *addr, char *host, size_t host_cap,
                             char *port, size_t port_cap);

typedef struct cloak_listener cloak_listener_t;

/* Fired once per accepted connection. fd is an already-non-blocking,
 * connected socket, and OWNERSHIP OF IT PASSES TO THIS CALLBACK: the
 * listener never closes it, so the callback must either take
 * responsibility for closing it or hand it to something that will (a
 * relay, a session). Losing the fd here leaks a descriptor. */
typedef void (*cloak_listener_accept_cb)(cloak_listener_t *l, int fd, void *userdata);

struct cloak_listener {
    cloak_reactor_t *reactor;
    int fd;
    int port; /* the bound port, resolved even when addr asked for port 0 */
    cloak_listener_accept_cb on_accept;
    void *on_accept_userdata;
};

/* Binds and listens on addr (see cloak_net_split_hostport for the accepted
 * forms), registers the socket with r, and calls cb for every connection
 * accepted from then on. An empty host binds every interface, dual-stack
 * where the kernel allows it. SO_REUSEADDR is always set, so a restart does
 * not have to wait out TIME_WAIT. Port 0 asks the kernel to choose a free
 * port, readable afterwards via cloak_listener_port.
 *
 * Returns 0 on success, -1 with the reason in err on a NULL r/addr/cb, a
 * malformed address, a resolution failure, or a socket/bind/listen
 * failure. cb == NULL is rejected rather than silently accepting and
 * discarding every connection, which is never what a caller wanted. On
 * failure l (when non-NULL) is left safe to pass to cloak_listener_close. */
int cloak_listener_open(cloak_listener_t *l, cloak_reactor_t *r, const char *addr,
                        cloak_listener_accept_cb cb, void *userdata,
                        char *err, size_t err_cap);

/* Unregisters and closes the listening socket. Does NOT touch any fd
 * already handed to the accept callback -- those belong to whoever took
 * them. Idempotent, and safe on a listener left zeroed by a failed open. */
void cloak_listener_close(cloak_listener_t *l);

/* The bound port, or -1 if the listener is not open. */
int cloak_listener_port(const cloak_listener_t *l);

/* A resolved socket address, ready to connect to without another lookup. */
typedef struct {
    struct sockaddr_storage ss;
    socklen_t len;
    int socktype; /* SOCK_STREAM or SOCK_DGRAM */
    int protocol;
} cloak_addr_t;

/* Resolves "host:port" into a connectable address.
 *
 * THIS CALL BLOCKS: it performs a synchronous DNS lookup. Call it at
 * startup (when parsing config, as Go Cloak's InitState does for RedirAddr
 * and ProxyBook), never per connection on the reactor's thread. A numeric
 * address resolves without touching the network.
 *
 * is_udp selects SOCK_DGRAM instead of SOCK_STREAM. Returns 0 on success,
 * -1 with the reason in err on a malformed address or a resolution
 * failure. The first result returned by the resolver is used. */
int cloak_net_resolve(const char *addr, int is_udp, cloak_addr_t *out,
                      char *err, size_t err_cap);

typedef struct cloak_dial cloak_dial_t;

/* Fired exactly once per cloak_dial_start, with a connected, non-blocking
 * socket, or fd < 0 if the connect failed or timed out. OWNERSHIP OF fd
 * PASSES TO THIS CALLBACK (it is already unregistered from the reactor);
 * closing it is the callback's responsibility.
 *
 * Guaranteed never to fire before cloak_dial_start returns -- even when
 * the connect completes immediately, as it does on loopback -- so a caller
 * can finish initializing its own state after calling start without
 * racing its own callback. */
typedef void (*cloak_dial_cb)(int fd, void *userdata);

struct cloak_dial {
    cloak_reactor_t *reactor;
    int fd;
    cloak_timer_id_t timeout_timer;
    cloak_timer_id_t immediate_timer;
    cloak_dial_cb cb;
    void *userdata;
    int finished;
};

/* Starts a non-blocking connect to addr. timeout_ms bounds the attempt (0
 * means no timeout). On completion, success or failure, cb fires exactly
 * once.
 *
 * Returns 0 if the attempt started, -1 if it could not be started at all
 * (bad argument, socket creation failure, or a reactor registration
 * failure) -- in which case cb never fires and the caller owns the
 * failure. */
int cloak_dial_start(cloak_dial_t *d, cloak_reactor_t *r, const cloak_addr_t *addr,
                     uint64_t timeout_ms, cloak_dial_cb cb, void *userdata);

/* Abandons an in-flight dial: closes the socket, cancels the timeout, and
 * guarantees cb will NOT fire. A no-op if the dial already completed.
 * Must not be called from within cb itself. */
void cloak_dial_cancel(cloak_dial_t *d);

typedef struct cloak_relay cloak_relay_t;

/* Fired exactly once, when the relay finishes: either side reaching EOF,
 * or either side erroring. Both file descriptors are already closed by the
 * time this fires. Never fired by cloak_relay_stop (an explicit teardown
 * is not a completion), and never before cloak_relay_start returns. */
typedef void (*cloak_relay_done_cb)(cloak_relay_t *rl, void *userdata);

struct cloak_relay {
    cloak_reactor_t *reactor;
    int fd[2];
    /* q[i] holds bytes read from fd[i] and awaiting write to fd[1 - i]. */
    cloak_bytequeue_t q[2];
    int read_eof[2];
    /* The CLOAK_REACTOR_* mask most recently registered with the reactor
     * for fd[i] -- via cloak_reactor_add_fd's initial registration, or a
     * later cloak_reactor_mod_fd issued by sync_interest. sync_interest
     * reads this to tell "the desired mask is still zero, same as last
     * time" apart from "the desired mask just became zero"; only the
     * former is safe to skip re-registering. Do not delete this as
     * unused dead state -- it is read by exactly that one condition, and
     * that condition is what keeps a full send queue whose peer has gone
     * away from spinning the reactor at 100% CPU forever (see sync_interest
     * in relay.c). */
    uint32_t interest[2];
    int done;
    cloak_relay_done_cb on_done;
    void *on_done_userdata;
};

/* Splices fd_a and fd_b together until one of them ends.
 *
 * Ownership of both descriptors passes to the relay: it closes both when
 * it finishes, and cloak_relay_stop closes both too. Each direction gets
 * its own buf_cap-byte queue; when a queue fills, read interest on its
 * source is deregistered until the destination drains it, which is what
 * keeps a fast producer from growing memory without bound.
 *
 * preload/preload_len is data already read from fd_a before the relay
 * existed, to be written to fd_b ahead of anything else -- the server
 * dispatcher's redirect path, which has already consumed its client's
 * first packet, is what this is for. preload_len must not exceed buf_cap.
 *
 * Teardown is symmetric and immediate, matching Go Cloak's own
 * common.Copy: the first EOF or error on either side ends the whole
 * relay. Before closing, it makes one best-effort non-blocking pass over
 * the data still in flight -- draining whatever the other side has
 * already sent, then flushing both queues -- so a short reply that
 * crossed paths with the EOF still gets delivered. Neither side is
 * half-closed and left running.
 *
 * Returns 0 on success, -1 on invalid arguments (including an oversized
 * preload), allocation failure, or a reactor registration failure. On
 * failure neither descriptor is closed -- the caller still owns them. */
int cloak_relay_start(cloak_relay_t *rl, cloak_reactor_t *r, int fd_a, int fd_b,
                      const uint8_t *preload, size_t preload_len, size_t buf_cap,
                      cloak_relay_done_cb on_done, void *userdata);

/* Tears the relay down without firing on_done: unregisters and closes both
 * descriptors and frees both queues. Idempotent, and safe on a relay left
 * zeroed by a failed start. */
void cloak_relay_stop(cloak_relay_t *rl);

#endif
