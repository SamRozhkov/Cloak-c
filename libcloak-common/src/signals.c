/* _GNU_SOURCE for signalfd(2)/struct signalfd_siginfo/SFD_NONBLOCK; it
 * implies the POSIX definitions (sigprocmask, sigset_t, ...) this file
 * also needs -- same convention as net.c. */
#define _GNU_SOURCE
#include "cloak/signals.h"

#include <signal.h>
#include <stdlib.h>
#include <sys/signalfd.h>
#include <unistd.h>

struct cloak_signalfd {
    int fd;
    cloak_reactor_t *reactor;
    cloak_signalfd_cb cb;
    void *userdata;
    sigset_t old_mask;
};

static void on_signal_readable(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)events;
    cloak_signalfd_t *sfd = userdata;

    /* Registration is edge-triggered (see cloak/reactor.h): drain every
     * signalfd_siginfo currently queued, invoking cb once per signal
     * instance -- see cloak/signals.h for why a repeat is not
     * deduplicated. */
    for (;;) {
        struct signalfd_siginfo info;
        ssize_t n = read(fd, &info, sizeof(info));
        if (n != (ssize_t)sizeof(info)) {
            break;
        }
        sfd->cb((int)info.ssi_signo, sfd->userdata);
    }
}

cloak_signalfd_t *cloak_signalfd_create(cloak_reactor_t *r, cloak_signalfd_cb cb, void *userdata) {
    if (r == NULL || cb == NULL) {
        return NULL;
    }

    cloak_signalfd_t *sfd = calloc(1, sizeof(*sfd));
    if (sfd == NULL) {
        return NULL;
    }
    sfd->fd = -1;
    sfd->reactor = r;
    sfd->cb = cb;
    sfd->userdata = userdata;

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);

    /* Block before creating the fd -- see cloak/signals.h for why this
     * order matters. sfd->old_mask is filled here regardless of what
     * happens afterward, so any early-return path below that has reached
     * this point restores it before freeing sfd. */
    if (sigprocmask(SIG_BLOCK, &mask, &sfd->old_mask) != 0) {
        free(sfd);
        return NULL;
    }

    int fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (fd < 0) {
        sigprocmask(SIG_SETMASK, &sfd->old_mask, NULL);
        free(sfd);
        return NULL;
    }
    sfd->fd = fd;

    if (cloak_reactor_add_fd(r, fd, CLOAK_REACTOR_READABLE, on_signal_readable, sfd) != 0) {
        close(fd);
        sigprocmask(SIG_SETMASK, &sfd->old_mask, NULL);
        free(sfd);
        return NULL;
    }

    return sfd;
}

void cloak_signalfd_destroy(cloak_signalfd_t *sfd) {
    if (sfd == NULL) {
        return;
    }
    if (sfd->fd >= 0) {
        cloak_reactor_remove_fd(sfd->reactor, sfd->fd);
        close(sfd->fd);
    }
    sigprocmask(SIG_SETMASK, &sfd->old_mask, NULL);
    free(sfd);
}
