#ifndef CLOAK_NET_H
#define CLOAK_NET_H

#include <stddef.h>
#include <stdint.h>

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
 * Returns 0 on success, -1 with the reason in err on a malformed address,
 * a resolution failure, or a socket/bind/listen failure. On failure l is
 * left safe to pass to cloak_listener_close. */
int cloak_listener_open(cloak_listener_t *l, cloak_reactor_t *r, const char *addr,
                        cloak_listener_accept_cb cb, void *userdata,
                        char *err, size_t err_cap);

/* Unregisters and closes the listening socket. Does NOT touch any fd
 * already handed to the accept callback -- those belong to whoever took
 * them. Idempotent, and safe on a listener left zeroed by a failed open. */
void cloak_listener_close(cloak_listener_t *l);

/* The bound port, or -1 if the listener is not open. */
int cloak_listener_port(const cloak_listener_t *l);

#endif
