#ifndef CLOAK_REACTOR_H
#define CLOAK_REACTOR_H

#include <stddef.h>
#include <stdint.h>

/* A cloak_reactor_t is a single-threaded epoll-based event loop: it
 * dispatches readiness callbacks for registered file descriptors and (from
 * a later task) fires timer callbacks after a delay. It is not
 * thread-safe -- every function here must be called from the same thread
 * that calls cloak_reactor_run. */
typedef struct cloak_reactor cloak_reactor_t;

#define CLOAK_REACTOR_READABLE 0x1u
#define CLOAK_REACTOR_WRITABLE 0x2u

/* events is the CLOAK_REACTOR_* bitmask that actually fired (a subset of
 * what the fd was registered/modified for). */
typedef void (*cloak_reactor_fd_cb)(cloak_reactor_t *r, int fd, uint32_t events, void *userdata);

cloak_reactor_t *cloak_reactor_create(void);

/* Frees the reactor and closes its underlying epoll fd. Does not close any
 * fd the caller registered with cloak_reactor_add_fd -- the caller owns
 * those. */
void cloak_reactor_destroy(cloak_reactor_t *r);

/* Registers fd for events (a CLOAK_REACTOR_READABLE/WRITABLE bitmask).
 * Registration is edge-triggered: cb fires once per readiness transition,
 * so on CLOAK_REACTOR_READABLE the caller must read() until EAGAIN (and
 * likewise write() until EAGAIN for CLOAK_REACTOR_WRITABLE), or it will
 * not be notified again for data/space that was already available within
 * the same edge.
 * Returns 0 on success, -1 if fd < 0, cb is NULL, fd is already
 * registered, or the underlying epoll_ctl call fails. */
int cloak_reactor_add_fd(cloak_reactor_t *r, int fd, uint32_t events,
                          cloak_reactor_fd_cb cb, void *userdata);

/* Changes the registered event mask for an already-added fd. Returns 0 on
 * success, -1 if fd isn't registered or epoll_ctl fails. */
int cloak_reactor_mod_fd(cloak_reactor_t *r, int fd, uint32_t events);

/* Deregisters fd. Safe to call from within that fd's own callback, or from
 * another fd's callback during the same dispatch batch -- a removed fd's
 * callback will not fire even if it was already ready in this batch.
 * Returns 0 on success, -1 if fd isn't registered. */
int cloak_reactor_remove_fd(cloak_reactor_t *r, int fd);

/* Blocks, dispatching fd callbacks, until cloak_reactor_stop is called
 * (typically from within a callback). */
void cloak_reactor_run(cloak_reactor_t *r);

/* Requests that the current cloak_reactor_run call return once the
 * in-progress dispatch batch finishes. Must be called from within a
 * callback running on the reactor's own thread during cloak_reactor_run. */
void cloak_reactor_stop(cloak_reactor_t *r);

#endif
