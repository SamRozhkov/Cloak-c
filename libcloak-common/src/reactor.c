#include "cloak/reactor.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <unistd.h>

struct watcher {
    int fd;
    uint32_t events;
    cloak_reactor_fd_cb cb;
    void *userdata;
};

struct cloak_reactor {
    int epoll_fd;
    struct watcher **watchers;
    size_t watchers_cap;
    int stopped;
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
    close(r->epoll_fd);
    free(r);
}

int cloak_reactor_add_fd(cloak_reactor_t *r, int fd, uint32_t events,
                          cloak_reactor_fd_cb cb, void *userdata) {
    if (fd < 0 || cb == NULL) {
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
    epoll_ctl(r->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    free(r->watchers[fd]);
    r->watchers[fd] = NULL;
    return 0;
}

void cloak_reactor_stop(cloak_reactor_t *r) {
    r->stopped = 1;
}

void cloak_reactor_run(cloak_reactor_t *r) {
    struct epoll_event events[64];

    while (!r->stopped) {
        int n = epoll_wait(r->epoll_fd, events, 64, -1);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        for (int i = 0; i < n && !r->stopped; i++) {
            struct watcher *w = (struct watcher *)events[i].data.ptr;
            int fd = w->fd;
            if ((size_t)fd >= r->watchers_cap || r->watchers[fd] != w) {
                continue; /* removed (or replaced) earlier in this same batch */
            }

            uint32_t fired = 0;
            if (events[i].events & (EPOLLIN | EPOLLHUP | EPOLLERR)) {
                fired |= CLOAK_REACTOR_READABLE;
            }
            if (events[i].events & EPOLLOUT) {
                fired |= CLOAK_REACTOR_WRITABLE;
            }
            if (fired != 0) {
                w->cb(r, fd, fired, w->userdata);
            }
        }
    }
}
