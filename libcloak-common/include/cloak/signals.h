#ifndef CLOAK_SIGNALS_H
#define CLOAK_SIGNALS_H

#include "cloak/reactor.h"

/* cloak_signalfd_t delivers SIGINT and SIGTERM to a callback running on
 * the reactor's own thread, so a binary's shutdown path is just another
 * reactor callback rather than a second, signal-context, code path.
 *
 * WHY signalfd RATHER THAN A HANDLER: this is a single-threaded
 * epoll-based reactor (see cloak/reactor.h) that only ever calls back into
 * user code from inside cloak_reactor_run/run_once. A traditional
 * sigaction handler runs asynchronously, on whatever the interrupted
 * thread happened to be doing, and is restricted to the small set of
 * async-signal-safe calls (no malloc, no cloak_reactor_stop, no touching
 * the reactor's non-reentrant internal state) -- every one of those
 * restrictions would apply to whatever the caller's callback wanted to do
 * on shutdown. A signalfd turns "a signal happened" into "a file
 * descriptor became readable", which is exactly the event this reactor
 * already knows how to wait for and dispatch on its own thread, at a point
 * where it is safe to call anything, including cloak_reactor_stop.
 *
 * ORDER OF OPERATIONS, AND THE GAP THIS LEAVES: cloak_signalfd_create
 * blocks SIGINT/SIGTERM with sigprocmask *before* calling signalfd(2) to
 * create the fd. Blocking first, rather than creating the fd first and
 * blocking after, closes the only race that matters here: if the signal
 * were still unblocked while the fd did not yet exist, a SIGINT/SIGTERM
 * arriving in that window would run the default disposition and kill the
 * process outright, before this code ever got a chance to run. Once
 * blocked, a signal delivered before signalfd(2) is called is not lost and
 * is not handled by any handler -- the kernel simply records it as
 * pending, exactly as it would for any other blocked signal, and it
 * becomes immediately readable from the fd the moment cloak_signalfd_create
 * creates it (signalfd surfaces whatever of its signal set is already
 * pending, not just what arrives after the fd exists). The only window
 * with no coverage at all is before cloak_signalfd_create is ever called
 * (e.g. very early in main): a caller that wants signals handled from
 * process start must call this as close to the top of main as possible.
 *
 * SECOND-SIGNAL CONTRACT (decided here, not left to the caller to guess):
 * this module does not deduplicate or latch. Every signal instance the
 * kernel actually delivers through the fd produces one callback
 * invocation -- if the reactor has drained the first SIGINT before a
 * second one arrives, the callback fires a second time. This is a
 * deliberate choice: an operator hitting Ctrl-C twice usually means "I
 * meant it, stop now", and a shutdown callback that has to defend itself
 * against being re-entered is a smaller cost than a shutdown path that
 * silently swallows a repeated request. (Note this is subject to a
 * standard, unrelated Linux limitation this module cannot change: ordinary
 * signals are not queued by the kernel, so two SIGINTs sent back-to-back
 * before either is read may already have been collapsed into one pending
 * signal before signalfd ever sees them -- this module's contract is
 * about what it does with what the kernel hands it, not a promise to
 * recover signals the kernel itself merged.) A caller that wants the
 * classic "first press asks nicely, second press kills immediately"
 * behaviour implements that by counting invocations in its own callback;
 * this module supplies the events, not the shutdown policy.
 */
typedef struct cloak_signalfd cloak_signalfd_t;

/* signo is whichever of SIGINT/SIGTERM was delivered. */
typedef void (*cloak_signalfd_cb)(int signo, void *userdata);

/* Blocks SIGINT and SIGTERM (saving the previous mask for
 * cloak_signalfd_destroy to restore), creates a signalfd for them, and
 * registers it with r. cb is invoked with signo and userdata once per
 * signal instance read from the fd, from within cloak_reactor_run /
 * cloak_reactor_run_once on r's own thread -- never from signal context.
 *
 * Returns NULL, leaving the process signal mask untouched, if r or cb is
 * NULL, sigprocmask fails, signalfd(2) fails, or registering the fd with r
 * fails. */
cloak_signalfd_t *cloak_signalfd_create(cloak_reactor_t *r, cloak_signalfd_cb cb, void *userdata);

/* Deregisters the fd from its reactor, closes it, restores the signal
 * mask cloak_signalfd_create saved, and frees sfd. Safe to call with
 * NULL (a no-op). Not safe to call twice on the same non-NULL pointer
 * (as with free(), sfd is invalid after this returns). */
void cloak_signalfd_destroy(cloak_signalfd_t *sfd);

#endif
