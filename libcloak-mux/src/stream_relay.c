#define _POSIX_C_SOURCE 200809L
#include "cloak/stream_relay.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define STREAM_RELAY_CHUNK 16384

static void stream_relay_teardown(cloak_stream_relay_t *sr, int fire_done);

/* True while the session's outbound queue is at or above the watermark,
 * so pushing more into the stream risks overrunning it. An empty pool
 * (capacity 0) counts as backed up: there is nowhere to send. */
static int session_is_backed_up(const cloak_stream_relay_t *sr) {
    size_t cap = cloak_session_send_capacity(sr->sesh);
    if (cap == 0) {
        return 1;
    }
    size_t queued = cloak_session_send_queued(sr->sesh);
    return queued * CLOAK_STREAM_RELAY_HIGH_WATER_DEN >=
           cap * CLOAK_STREAM_RELAY_HIGH_WATER_NUM;
}

/* True once the relay has finished, or has already decided to finish and
 * is only waiting for its deferred zero-delay timer to run the actual
 * teardown (see cloak_stream_relay::finish_timer). Every entry point that
 * could otherwise act on the relay a second time before that teardown
 * runs -- the fd's own reactor callback and both notify functions --
 * checks this first. */
static int stream_relay_is_finishing(const cloak_stream_relay_t *sr) {
    return sr->done || sr->finish_timer != CLOAK_TIMER_INVALID;
}

static uint32_t desired_interest(const cloak_stream_relay_t *sr) {
    uint32_t ev = 0;
    if (!sr->fd_read_paused) {
        ev |= CLOAK_REACTOR_READABLE;
    }
    if (cloak_bytequeue_len(&sr->to_fd) > 0) {
        ev |= CLOAK_REACTOR_WRITABLE;
    }
    return ev;
}

static void sync_interest(cloak_stream_relay_t *sr) {
    if (sr->fd < 0) {
        return;
    }
    uint32_t want = desired_interest(sr);
    /* Suppressing the re-issue only when the mask is zero and was already
     * zero, for the same reason cloak_relay_t does: epoll delivers
     * ERR/HUP regardless of the registered mask, and re-arming a zero
     * mask every turn re-delivers it forever without the read path ever
     * being able to act on it. Any non-zero mask is re-issued
     * unconditionally, because an edge-triggered fd needs the re-arm to
     * re-report data already sitting in the socket buffer. */
    if (want == 0 && sr->interest == 0) {
        return;
    }
    sr->interest = want;
    (void)cloak_reactor_mod_fd(sr->reactor, sr->fd, want);
}

/* Drains the stream into the to_fd queue, then writes the queue out.
 * Returns 0 to continue, -1 if the relay should tear down. */
static int pump_stream_to_fd(cloak_stream_relay_t *sr) {
    uint8_t buf[STREAM_RELAY_CHUNK];

    if (!sr->stream_ended) {
        for (;;) {
            size_t room = cloak_bytequeue_free_space(&sr->to_fd);
            if (room == 0) {
                break; /* backpressure: the fd has not kept up */
            }
            size_t want = room < sizeof(buf) ? room : sizeof(buf);
            long n = cloak_stream_read(sr->stream, buf, want);
            if (n < 0) {
                sr->stream_ended = 1; /* peer closed: flush, then finish */
                break;
            }
            if (n == 0) {
                break; /* nothing ready right now */
            }
            cloak_bytequeue_write(&sr->to_fd, buf, (size_t)n);
        }
    }

    for (;;) {
        size_t have = cloak_bytequeue_peek(&sr->to_fd, buf, sizeof(buf));
        if (have == 0) {
            break;
        }
        ssize_t n = send(sr->fd, buf, have, MSG_NOSIGNAL);
        if (n > 0) {
            cloak_bytequeue_read(&sr->to_fd, buf, (size_t)n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }
        return -1;
    }

    if (sr->stream_ended && cloak_bytequeue_len(&sr->to_fd) == 0) {
        return -1; /* everything the stream ever sent has reached the fd */
    }
    return 0;
}

/* Reads the fd into the stream while the session has room. Returns 0 to
 * continue, -1 if the relay should tear down. */
static int pump_fd_to_stream(cloak_stream_relay_t *sr) {
    uint8_t buf[STREAM_RELAY_CHUNK];
    for (;;) {
        if (session_is_backed_up(sr)) {
            /* Stop reading; cloak_stream_relay_notify_writable re-arms. */
            sr->fd_read_paused = 1;
            return 0;
        }
        ssize_t n = read(sr->fd, buf, sizeof(buf));
        if (n > 0) {
            if (cloak_stream_write(sr->stream, buf, (size_t)n) < 0) {
                return -1;
            }
            continue;
        }
        if (n == 0) {
            return -1; /* the socket peer closed */
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }
}

static void stream_relay_on_event(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    cloak_stream_relay_t *sr = (cloak_stream_relay_t *)userdata;
    if (stream_relay_is_finishing(sr)) {
        return;
    }

    if ((events & CLOAK_REACTOR_WRITABLE) != 0) {
        if (pump_stream_to_fd(sr) != 0) {
            stream_relay_teardown(sr, 1);
            return;
        }
    }
    if ((events & CLOAK_REACTOR_READABLE) != 0) {
        if (pump_fd_to_stream(sr) != 0) {
            /* Best effort: push anything the stream already delivered out
             * to the fd before closing, mirroring cloak_relay_t's
             * teardown drain. */
            (void)pump_stream_to_fd(sr);
            stream_relay_teardown(sr, 1);
            return;
        }
    }
    sync_interest(sr);
}

static void stream_relay_teardown(cloak_stream_relay_t *sr, int fire_done) {
    if (sr->done) {
        return;
    }
    sr->done = 1;

    if (sr->finish_timer != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(sr->reactor, sr->finish_timer);
        sr->finish_timer = CLOAK_TIMER_INVALID;
    }

    if (sr->fd >= 0) {
        cloak_reactor_remove_fd(sr->reactor, sr->fd);
        close(sr->fd);
        sr->fd = -1;
    }
    cloak_bytequeue_destroy(&sr->to_fd);

    /* Tell the peer the stream is over. Never release it -- that is the
     * caller's, per cloak_session_release_stream's contract. A stream
     * that already closed returns -1 here, which is fine. */
    if (sr->sesh != NULL && sr->stream != NULL) {
        (void)cloak_session_close_stream(sr->sesh, sr->stream);
    }

    if (fire_done && sr->on_done != NULL) {
        sr->on_done(sr, sr->on_done_userdata);
    }
}

/* Fires the deferred teardown for a relay that was already finished by
 * the time cloak_stream_relay_start's own initial pump ran. Runs the
 * real, full teardown (not just the on_done call) so it stays exactly
 * one code path -- see stream_relay_teardown -- rather than duplicating
 * its resource-cleanup logic here. */
static void stream_relay_on_finish_timer(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_stream_relay_t *sr = (cloak_stream_relay_t *)userdata;
    sr->finish_timer = CLOAK_TIMER_INVALID;
    stream_relay_teardown(sr, 1);
}

int cloak_stream_relay_start(cloak_stream_relay_t *sr, cloak_reactor_t *r,
                              cloak_session_t *sesh, cloak_stream_t *stream, int fd,
                              size_t buf_cap, cloak_stream_relay_done_cb on_done,
                              void *userdata) {
    if (sr == NULL) {
        return -1;
    }
    /* Initialize before validating anything else, so every failure path
     * leaves a struct cloak_stream_relay_stop can safely be called on --
     * the same ordering cloak_listener_open and cloak_relay_start use. */
    memset(sr, 0, sizeof(*sr));
    sr->fd = -1;
    sr->finish_timer = CLOAK_TIMER_INVALID;

    if (r == NULL || sesh == NULL || stream == NULL || fd < 0 || buf_cap == 0) {
        return -1;
    }

    if (cloak_bytequeue_init(&sr->to_fd, buf_cap) != 0) {
        return -1;
    }
    if (cloak_reactor_add_fd(r, fd, CLOAK_REACTOR_READABLE, stream_relay_on_event, sr) != 0) {
        cloak_bytequeue_destroy(&sr->to_fd);
        return -1;
    }

    sr->reactor = r;
    sr->sesh = sesh;
    sr->stream = stream;
    sr->fd = fd;
    sr->interest = CLOAK_REACTOR_READABLE;
    sr->on_done = on_done;
    sr->on_done_userdata = userdata;

    /* The stream may already hold bytes delivered before this relay
     * existed -- on_new_stream fires with the first frame already fed. */
    if (pump_stream_to_fd(sr) != 0) {
        /* Already finished before this call could even return -- the
         * stream had already ended (or the fd already broke) before the
         * relay ever ran a reactor turn. on_done must never fire before
         * this function returns, so the actual teardown is deferred to a
         * zero-delay reactor timer, exactly like cloak_dial_t's own
         * immediate_timer defers cloak_dial_start's immediate-connect-
         * success case (see libcloak-common/src/dial.c). Until that timer
         * fires, sr->finish_timer being non-invalid makes
         * stream_relay_is_finishing() freeze every other entry point, so
         * nothing else can act on this relay in the meantime. */
        sr->finish_timer = cloak_reactor_add_timer(r, 0, stream_relay_on_finish_timer, sr);
        if (sr->finish_timer == CLOAK_TIMER_INVALID) {
            /* Can't defer -- tear down for real right now rather than
             * leave the relay stuck "finishing" forever with no way left
             * to ever report completion. This can only happen if growing
             * the reactor's own timer heap fails. */
            stream_relay_teardown(sr, 0);
            return -1;
        }
        return 0;
    }
    sync_interest(sr);
    return 0;
}

void cloak_stream_relay_notify_stream_data(cloak_stream_relay_t *sr) {
    if (sr == NULL || stream_relay_is_finishing(sr)) {
        return;
    }
    if (pump_stream_to_fd(sr) != 0) {
        stream_relay_teardown(sr, 1);
        return;
    }
    sync_interest(sr);
}

void cloak_stream_relay_notify_writable(cloak_stream_relay_t *sr) {
    if (sr == NULL || stream_relay_is_finishing(sr) || !sr->fd_read_paused) {
        return;
    }
    if (session_is_backed_up(sr)) {
        return; /* drained, but not below the watermark yet */
    }
    sr->fd_read_paused = 0;
    sync_interest(sr);
}

void cloak_stream_relay_stop(cloak_stream_relay_t *sr) {
    if (sr == NULL) {
        return;
    }
    stream_relay_teardown(sr, 0);
}
