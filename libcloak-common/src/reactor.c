#define _POSIX_C_SOURCE 200809L
#include "cloak/reactor.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>

struct watcher {
    int fd;
    uint32_t events;
    cloak_reactor_fd_cb cb;
    void *userdata;
    int dead;
    struct watcher *dead_next;
};

/* THE TIMER HANDLE, AND WHY IT IS NOT JUST A COUNTER ANY MORE.
 *
 * cloak_reactor_cancel_timer used to be a linear scan of the heap looking
 * for a monotonically-issued id: MEASURED at 512 elements examined per
 * cancel at 1024 timers against 1 at a single timer, i.e. O(n), and
 * 1.2 us of wall clock for one cancel at the server's session cap. See
 * libcloak-common/tests/test_reactor_timer_scale.c, whose case 1 asserts
 * the cost bracket that number failed.
 *
 * The cure is the usual one -- the handle names the timer's storage
 * directly instead of being searched for -- and the only thing that
 * needed care is that recycled storage must not make a DEAD handle
 * addressable again. Callers in this tree routinely cancel handles that
 * may already have fired -- libcloak-mux/src/session.c's inactivity
 * re-arm cancels the previous id without knowing whether it fired first,
 * and cloak_session_destroy cancels a teardown timer that usually has --
 * so "cancel an id that is gone" is an ordinary case, not a corner case,
 * and it MUST NOT reach whatever timer inherited that slot.
 *
 * So a handle is a slot index plus that slot's generation:
 *
 *     id = (generation << 20) | (slot + 1)
 *
 * The +1 is what keeps CLOAK_TIMER_INVALID (0) unissuable, and it leaves
 * the first two ids a fresh reactor hands out equal to 1 and 2 exactly as
 * the counter did (test_reactor.c's test_add_timer_returns_correct_id_
 * after_sift_up pins both).
 *
 * THE GENERATION NEVER WRAPS -- it is not a modular counter that could
 * alias an old handle onto a new timer. It is 44 bits, and a slot whose
 * generation reaches the maximum is RETIRED rather than recycled (see
 * timer_slot_free), so an ABA is impossible by construction and not
 * merely improbable. The cost of that guarantee is one 24-byte slot
 * leaked per 1.76e13 cancel/re-arm cycles on the same slot; a reactor
 * doing a million of them a second reaches the first retirement in about
 * 557 days. NOT MEASURED -- that is arithmetic on the field widths, and
 * no test in this tree can reach 2^44 of anything. What IS measured is
 * the mechanism it protects: test_reactor_timer_scale.c case 3 fires a
 * timer, creates a second one that reuses its slot, and asserts the first
 * one's handle does not cancel it.
 *
 * 20 slot bits caps a single reactor at 1048575 SIMULTANEOUSLY PENDING
 * timers -- add_timer returns CLOAK_TIMER_INVALID past that, which is an
 * already-documented failure return. The server's cap is 1024 sessions at
 * roughly three timers each. */
#define TIMER_SLOT_BITS 20
#define TIMER_SLOT_MASK (((uint64_t)1 << TIMER_SLOT_BITS) - 1)
#define TIMER_MAX_SLOTS ((size_t)TIMER_SLOT_MASK)
#define TIMER_GEN_MAX (((uint64_t)1 << (64 - TIMER_SLOT_BITS)) - 1)
#define TIMER_NO_SLOT UINT32_MAX

struct timer_entry {
    uint64_t deadline_ms;
    uint64_t id;
    uint32_t slot; /* index into cloak_reactor::slots; the back-pointer that
                    * makes cancel O(1) instead of a scan */
    cloak_reactor_timer_cb cb;
    void *userdata;
};

struct timer_slot {
    size_t heap_pos;    /* where this timer currently sits in timers[]; kept
                         * correct by timer_place(), which is the ONLY
                         * function that writes timers[] */
    uint64_t gen;
    uint32_t next_free; /* free-list link while !in_use */
    uint8_t in_use;
};

struct cloak_reactor {
    int epoll_fd;
    struct watcher **watchers;
    size_t watchers_cap;
    struct watcher *dead_list;
    int stopped;

    struct timer_entry *timers;
    size_t timer_count;
    size_t timer_cap;

    struct timer_slot *slots;
    size_t slots_count; /* slots ever handed out: in use, free-listed, or retired */
    size_t slots_cap;
    uint32_t free_slot; /* head of the free list, or TIMER_NO_SLOT */

    uint64_t cancel_probe_steps;
};

static uint32_t to_epoll_events(uint32_t events) {
    uint32_t e = EPOLLET;
    if (events & CLOAK_REACTOR_READABLE) {
        e |= EPOLLIN;
    }
    if (events & CLOAK_REACTOR_WRITABLE) {
        e |= EPOLLOUT;
    }
    return e;
}

static int ensure_capacity(cloak_reactor_t *r, int fd) {
    if ((size_t)fd < r->watchers_cap) {
        return 0;
    }
    size_t new_cap = r->watchers_cap == 0 ? 16 : r->watchers_cap * 2;
    while (new_cap <= (size_t)fd) {
        new_cap *= 2;
    }
    struct watcher **grown = realloc(r->watchers, new_cap * sizeof(*grown));
    if (grown == NULL) {
        return -1;
    }
    for (size_t i = r->watchers_cap; i < new_cap; i++) {
        grown[i] = NULL;
    }
    r->watchers = grown;
    r->watchers_cap = new_cap;
    return 0;
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

/* The one place timers[] is written. Every move of an element through the
 * heap goes through here, so a slot's heap_pos cannot drift out of step
 * with where its entry actually is -- which is the whole basis of the O(1)
 * cancel below. */
static void timer_place(cloak_reactor_t *r, size_t i, const struct timer_entry *e) {
    r->timers[i] = *e;
    r->slots[e->slot].heap_pos = i;
}

/* Sift the element currently at i towards the root. Returns the number of
 * OTHER elements it displaced, which cancel charges to its own cost
 * counter; callers that do not measure ignore it. */
static size_t heap_sift_up(cloak_reactor_t *r, size_t i) {
    struct timer_entry e = r->timers[i];
    size_t moves = 0;
    while (i > 0) {
        size_t parent = (i - 1) / 2;
        if (r->timers[parent].deadline_ms <= e.deadline_ms) {
            break;
        }
        timer_place(r, i, &r->timers[parent]);
        moves++;
        i = parent;
    }
    timer_place(r, i, &e);
    return moves;
}

/* Sift the element currently at i away from the root. Returns the number
 * of elements displaced, as heap_sift_up does; 0 means it did not move. */
static size_t heap_sift_down(cloak_reactor_t *r, size_t i) {
    struct timer_entry e = r->timers[i];
    size_t moves = 0;
    for (;;) {
        size_t left = 2 * i + 1;
        size_t right = 2 * i + 2;
        if (left >= r->timer_count) {
            break;
        }
        size_t smallest = left;
        if (right < r->timer_count &&
            r->timers[right].deadline_ms < r->timers[left].deadline_ms) {
            smallest = right;
        }
        if (r->timers[smallest].deadline_ms >= e.deadline_ms) {
            break;
        }
        timer_place(r, i, &r->timers[smallest]);
        moves++;
        i = smallest;
    }
    timer_place(r, i, &e);
    return moves;
}

/* Removes the entry at pos and restores the heap. Returns the number of
 * elements moved. The caller frees pos's slot AFTER this returns -- the
 * entry is still readable until then.
 *
 * Both directions are needed and neither is dead code: the last element
 * moved into an interior hole can be later than the hole's children (sift
 * down) or earlier than its parent (sift up), and which one applies
 * depends on where the hole is. Only one of the two can do any work, so
 * the second is a single comparison when the first moved anything.
 * test_reactor_timer_scale.c case 4 removes 2000 entries from arbitrary
 * positions of a 4000-entry heap and asserts the survivors still come out
 * in deadline order; dropping the sift_up leg fails it. */
static size_t heap_remove_at(cloak_reactor_t *r, size_t pos) {
    size_t last = r->timer_count - 1;
    r->timer_count = last;
    if (pos == last) {
        return 0;
    }
    struct timer_entry moved = r->timers[last];
    timer_place(r, pos, &moved);
    size_t moves = heap_sift_down(r, pos);
    if (moves == 0) {
        moves = heap_sift_up(r, pos);
    }
    return moves + 1;
}

/* Takes a slot for a new timer. Returns -1 when the reactor is out of
 * slots, which is a hard cap of TIMER_MAX_SLOTS pending timers. */
static int timer_slot_alloc(cloak_reactor_t *r, uint32_t *out) {
    if (r->free_slot != TIMER_NO_SLOT) {
        uint32_t s = r->free_slot;
        r->free_slot = r->slots[s].next_free;
        r->slots[s].in_use = 1;
        r->slots[s].next_free = TIMER_NO_SLOT;
        *out = s;
        return 0;
    }
    if (r->slots_count >= TIMER_MAX_SLOTS) {
        return -1;
    }
    if (r->slots_count == r->slots_cap) {
        size_t new_cap = r->slots_cap == 0 ? 8 : r->slots_cap * 2;
        if (new_cap > TIMER_MAX_SLOTS) {
            new_cap = TIMER_MAX_SLOTS;
        }
        struct timer_slot *grown = realloc(r->slots, new_cap * sizeof(*grown));
        if (grown == NULL) {
            return -1;
        }
        r->slots = grown;
        r->slots_cap = new_cap;
    }
    uint32_t s = (uint32_t)r->slots_count++;
    r->slots[s].heap_pos = 0;
    r->slots[s].gen = 0;
    r->slots[s].next_free = TIMER_NO_SLOT;
    r->slots[s].in_use = 1;
    *out = s;
    return 0;
}

/* Gives a slot back. Bumping the generation is what turns every handle
 * ever issued against this slot into a handle cancel will refuse, so a
 * caller holding the id of a timer that has already fired cannot reach
 * the next timer to land here. A slot that has run out of generations is
 * retired instead of recycled -- see TIMER_GEN_MAX above. */
static void timer_slot_free(cloak_reactor_t *r, uint32_t s) {
    r->slots[s].in_use = 0;
    if (r->slots[s].gen < TIMER_GEN_MAX) {
        r->slots[s].gen++;
        r->slots[s].next_free = r->free_slot;
        r->free_slot = s;
    }
}

static int timer_heap_ensure_capacity(cloak_reactor_t *r) {
    if (r->timer_count < r->timer_cap) {
        return 0;
    }
    size_t new_cap = r->timer_cap == 0 ? 8 : r->timer_cap * 2;
    struct timer_entry *grown = realloc(r->timers, new_cap * sizeof(*grown));
    if (grown == NULL) {
        return -1;
    }
    r->timers = grown;
    r->timer_cap = new_cap;
    return 0;
}

/* Fires every timer whose deadline has passed. The heap holds only live
 * timers now -- a cancelled one is removed when it is cancelled, not left
 * behind a `cancelled` flag to be skipped here -- so there is nothing to
 * discard on the way. WHEN a timer fires is unchanged by that: the old
 * code skipped cancelled entries here and popped them in
 * compute_timeout_ms, so the earliest LIVE deadline was already what both
 * functions answered. */
static void process_expired_timers(cloak_reactor_t *r) {
    uint64_t now = now_ms();
    while (r->timer_count > 0 && !r->stopped) {
        if (r->timers[0].deadline_ms > now) {
            break;
        }
        struct timer_entry top = r->timers[0];
        heap_remove_at(r, 0);
        /* Freed BEFORE the callback runs, so that a callback cancelling
         * its own (now fired) id sees a dead handle and does nothing --
         * which is what the header promises and what the scan used to
         * give for free by failing to find the popped entry. */
        timer_slot_free(r, top.slot);
        top.cb(r, top.userdata);
    }
}

/* Returns the epoll_wait timeout in ms: -1 if there are no timers,
 * otherwise the ms remaining until the earliest one (>= 0). */
static int compute_timeout_ms(cloak_reactor_t *r) {
    if (r->timer_count == 0) {
        return -1;
    }
    uint64_t now = now_ms();
    if (r->timers[0].deadline_ms <= now) {
        return 0;
    }
    uint64_t diff = r->timers[0].deadline_ms - now;
    return diff > (uint64_t)2147483647 ? 2147483647 : (int)diff;
}

cloak_reactor_t *cloak_reactor_create(void) {
    cloak_reactor_t *r = calloc(1, sizeof(*r));
    if (r == NULL) {
        return NULL;
    }
    r->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (r->epoll_fd < 0) {
        free(r);
        return NULL;
    }
    r->free_slot = TIMER_NO_SLOT; /* calloc's 0 would mean "slot 0 is free" */
    return r;
}

void cloak_reactor_destroy(cloak_reactor_t *r) {
    if (r == NULL) {
        return;
    }
    for (size_t i = 0; i < r->watchers_cap; i++) {
        free(r->watchers[i]);
    }
    free(r->watchers);
    while (r->dead_list != NULL) {
        struct watcher *dead = r->dead_list;
        r->dead_list = dead->dead_next;
        free(dead);
    }
    free(r->timers);
    free(r->slots);
    close(r->epoll_fd);
    free(r);
}

int cloak_reactor_add_fd(cloak_reactor_t *r, int fd, uint32_t events,
                          cloak_reactor_fd_cb cb, void *userdata) {
    if (fd < 0 || cb == NULL) {
        return -1;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        return -1;
    }
    if (ensure_capacity(r, fd) != 0) {
        return -1;
    }
    if (r->watchers[fd] != NULL) {
        return -1;
    }

    struct watcher *w = malloc(sizeof(*w));
    if (w == NULL) {
        return -1;
    }
    w->fd = fd;
    w->events = events;
    w->cb = cb;
    w->userdata = userdata;
    w->dead = 0;
    w->dead_next = NULL;

    struct epoll_event ev;
    ev.events = to_epoll_events(events);
    ev.data.ptr = w;
    if (epoll_ctl(r->epoll_fd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        free(w);
        return -1;
    }
    r->watchers[fd] = w;
    return 0;
}

int cloak_reactor_mod_fd(cloak_reactor_t *r, int fd, uint32_t events) {
    if (fd < 0 || (size_t)fd >= r->watchers_cap || r->watchers[fd] == NULL) {
        return -1;
    }
    struct watcher *w = r->watchers[fd];
    w->events = events;

    struct epoll_event ev;
    ev.events = to_epoll_events(events);
    ev.data.ptr = w;
    if (epoll_ctl(r->epoll_fd, EPOLL_CTL_MOD, fd, &ev) != 0) {
        return -1;
    }
    return 0;
}

int cloak_reactor_remove_fd(cloak_reactor_t *r, int fd) {
    if (fd < 0 || (size_t)fd >= r->watchers_cap || r->watchers[fd] == NULL) {
        return -1;
    }
    struct watcher *w = r->watchers[fd];
    epoll_ctl(r->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    r->watchers[fd] = NULL;
    w->dead = 1;
    w->dead_next = r->dead_list;
    r->dead_list = w;
    return 0;
}

void cloak_reactor_stop(cloak_reactor_t *r) {
    r->stopped = 1;
}

cloak_timer_id_t cloak_reactor_add_timer(cloak_reactor_t *r, uint64_t delay_ms,
                                          cloak_reactor_timer_cb cb, void *userdata) {
    if (cb == NULL) {
        return CLOAK_TIMER_INVALID;
    }
    if (timer_heap_ensure_capacity(r) != 0) {
        return CLOAK_TIMER_INVALID;
    }
    uint32_t slot;
    if (timer_slot_alloc(r, &slot) != 0) {
        return CLOAK_TIMER_INVALID;
    }
    struct timer_entry e;
    e.deadline_ms = now_ms() + delay_ms;
    e.id = (r->slots[slot].gen << TIMER_SLOT_BITS) | ((uint64_t)slot + 1);
    e.slot = slot;
    e.cb = cb;
    e.userdata = userdata;
    size_t idx = r->timer_count++;
    timer_place(r, idx, &e);
    heap_sift_up(r, idx);
    return e.id;
}

void cloak_reactor_cancel_timer(cloak_reactor_t *r, cloak_timer_id_t id) {
    if (id == CLOAK_TIMER_INVALID) {
        return;
    }
    /* THE LOOKUP, and the whole point of the commit: one step, whatever
     * the occupancy is. What this replaced walked the heap from the front
     * until it matched the id. */
    r->cancel_probe_steps++;
    uint64_t low = id & TIMER_SLOT_MASK;
    if (low == 0) {
        return; /* not a handle this reactor could ever have issued */
    }
    uint64_t slot = low - 1;
    if (slot >= r->slots_count) {
        return;
    }
    struct timer_slot *s = &r->slots[slot];
    if (!s->in_use || s->gen != (id >> TIMER_SLOT_BITS)) {
        return; /* already fired, already cancelled, or a recycled slot */
    }
    r->cancel_probe_steps += heap_remove_at(r, s->heap_pos);
    timer_slot_free(r, (uint32_t)slot);
}

/* INSTRUMENTATION. Elements of the timer structure that
 * cloak_reactor_cancel_timer has examined or moved over this reactor's
 * lifetime: one per handle lookup, plus one per heap element displaced
 * while closing the hole. It exists so that the cost of a cancel can be
 * asserted in units that do not depend on the machine the suite runs on
 * -- see libcloak-common/tests/test_reactor_timer_scale.c, which measures
 * it at 1, 64, 256 and 1024 pending timers and fails if it grows with
 * occupancy. Never read by the reactor itself; monotonic; saturating
 * arithmetic is not needed at 2^64 steps. */
uint64_t cloak_reactor_cancel_probe_steps(const cloak_reactor_t *r) {
    return r->cancel_probe_steps;
}

size_t cloak_reactor_pending_timers(const cloak_reactor_t *r) {
    return r->timer_count;
}

/* Combines the timer heap's own deadline with the caller's requested
 * timeout_ms, honoring the -1-means-no-bound convention on both sides:
 * whichever of the two is finite wins, and the smaller of two finite
 * values wins. */
static int effective_timeout_ms(int timer_timeout_ms, int caller_timeout_ms) {
    if (timer_timeout_ms < 0) {
        return caller_timeout_ms;
    }
    if (caller_timeout_ms < 0) {
        return timer_timeout_ms;
    }
    return timer_timeout_ms < caller_timeout_ms ? timer_timeout_ms : caller_timeout_ms;
}

int cloak_reactor_run_once(cloak_reactor_t *r, int timeout_ms) {
    struct epoll_event events[64];
    int wait_ms = effective_timeout_ms(compute_timeout_ms(r), timeout_ms);
    int n = epoll_wait(r->epoll_fd, events, 64, wait_ms);
    if (n < 0) {
        if (errno == EINTR) {
            return 0;
        }
        return -1;
    }
    int dispatched = 0;
    for (int i = 0; i < n && !r->stopped; i++) {
        struct watcher *w = (struct watcher *)events[i].data.ptr;
        if (w->dead) {
            continue; /* removed earlier in this same batch; the watcher's
                       * memory is kept alive via deferred free below, so
                       * this read is safe -- unlike checking watchers[fd]
                       * against a pointer that may already be freed. */
        }
        int fd = w->fd;

        uint32_t fired = 0;
        if (events[i].events & (EPOLLIN | EPOLLHUP | EPOLLERR)) {
            fired |= CLOAK_REACTOR_READABLE;
        }
        if (events[i].events & EPOLLOUT) {
            fired |= CLOAK_REACTOR_WRITABLE;
        }
        if (fired != 0) {
            w->cb(r, fd, fired, w->userdata);
            dispatched++;
        }
    }
    while (r->dead_list != NULL) {
        struct watcher *dead = r->dead_list;
        r->dead_list = dead->dead_next;
        free(dead);
    }
    if (!r->stopped) {
        process_expired_timers(r);
    }
    return dispatched;
}

void cloak_reactor_run(cloak_reactor_t *r) {
    r->stopped = 0;
    while (!r->stopped) {
        if (cloak_reactor_run_once(r, -1) < 0) {
            return;
        }
    }
}
