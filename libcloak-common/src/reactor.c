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

struct timer_entry {
    uint64_t deadline_ms;
    uint64_t id;
    cloak_reactor_timer_cb cb;
    void *userdata;
    int cancelled;
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
    uint64_t next_timer_id;
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

static void timer_swap(struct timer_entry *a, struct timer_entry *b) {
    struct timer_entry tmp = *a;
    *a = *b;
    *b = tmp;
}

static void heap_sift_up(cloak_reactor_t *r, size_t i) {
    while (i > 0) {
        size_t parent = (i - 1) / 2;
        if (r->timers[parent].deadline_ms <= r->timers[i].deadline_ms) {
            break;
        }
        timer_swap(&r->timers[parent], &r->timers[i]);
        i = parent;
    }
}

static void heap_sift_down(cloak_reactor_t *r, size_t i) {
    for (;;) {
        size_t left = 2 * i + 1;
        size_t right = 2 * i + 2;
        size_t smallest = i;
        if (left < r->timer_count && r->timers[left].deadline_ms < r->timers[smallest].deadline_ms) {
            smallest = left;
        }
        if (right < r->timer_count && r->timers[right].deadline_ms < r->timers[smallest].deadline_ms) {
            smallest = right;
        }
        if (smallest == i) {
            break;
        }
        timer_swap(&r->timers[i], &r->timers[smallest]);
        i = smallest;
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

static void heap_pop(cloak_reactor_t *r) {
    r->timer_count--;
    r->timers[0] = r->timers[r->timer_count];
    if (r->timer_count > 0) {
        heap_sift_down(r, 0);
    }
}

/* Fires all expired (non-cancelled) timers whose deadline has passed,
 * discarding cancelled ones encountered along the way. */
static void process_expired_timers(cloak_reactor_t *r) {
    uint64_t now = now_ms();
    while (r->timer_count > 0 && !r->stopped) {
        struct timer_entry top = r->timers[0];
        if (top.cancelled) {
            heap_pop(r);
            continue;
        }
        if (top.deadline_ms > now) {
            break;
        }
        heap_pop(r);
        top.cb(r, top.userdata);
    }
}

/* Returns the epoll_wait timeout in ms: -1 if there are no live timers,
 * otherwise the ms remaining until the earliest one (>= 0). */
static int compute_timeout_ms(cloak_reactor_t *r) {
    while (r->timer_count > 0 && r->timers[0].cancelled) {
        heap_pop(r);
    }
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
    size_t idx = r->timer_count;
    struct timer_entry *e = &r->timers[idx];
    e->deadline_ms = now_ms() + delay_ms;
    cloak_timer_id_t new_id = ++r->next_timer_id;
    e->id = new_id;
    e->cb = cb;
    e->userdata = userdata;
    e->cancelled = 0;
    r->timer_count++;
    heap_sift_up(r, idx);
    return new_id;
}

void cloak_reactor_cancel_timer(cloak_reactor_t *r, cloak_timer_id_t id) {
    if (id == CLOAK_TIMER_INVALID) {
        return;
    }
    for (size_t i = 0; i < r->timer_count; i++) {
        if (r->timers[i].id == id) {
            r->timers[i].cancelled = 1;
            return;
        }
    }
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
