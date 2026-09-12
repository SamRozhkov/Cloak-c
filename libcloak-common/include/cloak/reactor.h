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

/* events is the CLOAK_REACTOR_* bitmask that fired. This is not always a
 * strict subset of what the fd was registered for: the kernel reports
 * EPOLLHUP/EPOLLERR regardless of the registered interest mask, and this
 * reactor folds both into CLOAK_REACTOR_READABLE -- so even a
 * CLOAK_REACTOR_WRITABLE-only registration can be dispatched with
 * CLOAK_REACTOR_READABLE set on hangup or error. Callers must attempt a
 * read (or inspect SO_ERROR via getsockopt) to distinguish a real
 * hangup/error from genuinely readable data. */
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
 * add_fd forces fd into non-blocking mode (O_NONBLOCK) itself and fails if
 * it cannot; a blocking fd combined with the edge-triggered read-until-EAGAIN
 * contract would deadlock the single-threaded reactor.
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
 * Callers must call this before close()ing fd -- closing first leaves a
 * stale registration, and a later cloak_reactor_add_fd for the same
 * (recycled) fd number will then spuriously fail with -1.
 * Returns 0 on success, -1 if fd isn't registered. */
int cloak_reactor_remove_fd(cloak_reactor_t *r, int fd);

/* Blocks, dispatching fd callbacks, until cloak_reactor_stop is called
 * (typically from within a callback). */
void cloak_reactor_run(cloak_reactor_t *r);

/* Requests that the current cloak_reactor_run call return once the
 * in-progress dispatch batch finishes. Must be called from within a
 * callback running on the reactor's own thread during cloak_reactor_run.
 * Sets a sticky stop flag -- see cloak_reactor_run_once for what that
 * means for callers driving the loop directly. */
void cloak_reactor_stop(cloak_reactor_t *r);

/* Runs a single dispatch turn: waits up to timeout_ms for readiness (0
 * returns immediately, -1 waits indefinitely), dispatches whatever fired
 * along with any timers now due, and returns. Returns the number of fd
 * events dispatched, or -1 on a fatal epoll error.
 *
 * cloak_reactor_run is this called in a loop until stopped; tests and
 * callers that need to interleave their own work with the event loop use
 * this directly.
 *
 * run_once OBSERVES THE STOP FLAG BUT DOES NOT CLEAR IT: only
 * cloak_reactor_run resets it (on entry, before its first turn). If any
 * callback calls cloak_reactor_stop while a caller is driving the loop
 * via run_once directly (rather than via cloak_reactor_run), every
 * subsequent run_once call sees the flag still set, dispatches nothing,
 * fires no timers, and returns 0 -- indistinguishable from "nothing was
 * ready yet". A caller writing its own pump loop around run_once that
 * needs to honor stop requests must check for this itself (e.g. by having
 * its own flag set from within a callback, since polling the reactor for
 * "was stop called" is not exposed) rather than relying on run_once's
 * return value to signal it. */
int cloak_reactor_run_once(cloak_reactor_t *r, int timeout_ms);

typedef uint64_t cloak_timer_id_t;
#define CLOAK_TIMER_INVALID ((cloak_timer_id_t)0)

typedef void (*cloak_reactor_timer_cb)(cloak_reactor_t *r, void *userdata);

/* Schedules cb to run once, delay_ms from now (CLOCK_MONOTONIC). Returns a
 * timer id usable with cloak_reactor_cancel_timer, or CLOAK_TIMER_INVALID
 * on failure (cb is NULL, or an allocation failure growing the timer
 * heap). */
cloak_timer_id_t cloak_reactor_add_timer(cloak_reactor_t *r, uint64_t delay_ms,
                                          cloak_reactor_timer_cb cb, void *userdata);

/* Cancels a pending timer. A no-op if id is CLOAK_TIMER_INVALID, already
 * fired, or already cancelled. */
void cloak_reactor_cancel_timer(cloak_reactor_t *r, cloak_timer_id_t id);

#endif
