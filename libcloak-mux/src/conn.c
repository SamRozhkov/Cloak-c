#include "cloak/conn.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void conn_set_want_writable(cloak_conn_t *c, int want) {
    if (c->want_writable == want) {
        return;
    }
    c->want_writable = want;
    uint32_t events = CLOAK_REACTOR_READABLE | (want ? CLOAK_REACTOR_WRITABLE : 0);
    cloak_reactor_mod_fd(c->reactor, c->fd, events);
}

static void conn_mark_broken(cloak_conn_t *c) {
    if (c->broken) {
        return; /* idempotent -- already reported */
    }
    c->broken = 1;
    cloak_reactor_remove_fd(c->reactor, c->fd);
    if (c->on_closed) {
        c->on_closed(c, c->on_closed_userdata);
    }
}

/* Attempts to write everything currently buffered in send_q to the fd,
 * non-blocking, looping until either send_q is empty or the kernel
 * reports EAGAIN. Peeks a chunk (never consuming ahead of what the
 * kernel actually accepted), writes it, then discards exactly the number
 * of bytes the kernel took -- so a partial write never loses buffered
 * data, and a full write of one peeked chunk continues the loop to see
 * if more remains. */
static void conn_try_drain_send(cloak_conn_t *c) {
    uint8_t drain_buf[4096];
    for (;;) {
        size_t avail = cloak_bytequeue_len(&c->send_q);
        if (avail == 0) {
            conn_set_want_writable(c, 0);
            return;
        }
        size_t want = avail < sizeof(drain_buf) ? avail : sizeof(drain_buf);
        size_t peeked = cloak_bytequeue_peek(&c->send_q, drain_buf, want);
        ssize_t n = write(c->fd, drain_buf, peeked);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                conn_set_want_writable(c, 1);
                return;
            }
            conn_mark_broken(c);
            return;
        }
        cloak_bytequeue_read(&c->send_q, drain_buf, (size_t)n); /* discard exactly what the kernel took */
        if ((size_t)n < peeked) {
            /* Kernel's send buffer is now full -- stop for now, resume
             * on the next EPOLLWRITABLE. */
            conn_set_want_writable(c, 1);
            return;
        }
        /* Fully wrote this chunk -- loop to see if more remains. */
    }
}

static void conn_extract_and_dispatch(cloak_conn_t *c) {
    uint8_t prefix[CLOAK_CONN_LEN_PREFIX_LEN];
    for (;;) {
        size_t peeked = cloak_bytequeue_peek(&c->recv_acc, prefix, CLOAK_CONN_LEN_PREFIX_LEN);
        if (peeked < CLOAK_CONN_LEN_PREFIX_LEN) {
            return; /* not even the length prefix has fully arrived yet */
        }
        uint16_t frame_len = (uint16_t)(((uint16_t)prefix[0] << 8) | (uint16_t)prefix[1]);
        if ((size_t)frame_len > c->max_frame_len) {
            conn_mark_broken(c); /* protocol violation -- declared length too large for this conn */
            return;
        }
        size_t envelope_len = (size_t)CLOAK_CONN_LEN_PREFIX_LEN + frame_len;
        if (cloak_bytequeue_len(&c->recv_acc) < envelope_len) {
            return; /* full envelope hasn't arrived yet */
        }
        cloak_bytequeue_read(&c->recv_acc, c->recv_scratch, envelope_len);
        if (c->on_envelope) {
            c->on_envelope(c, c->recv_scratch + CLOAK_CONN_LEN_PREFIX_LEN, frame_len, c->on_envelope_userdata);
        }
        if (c->broken) {
            return; /* the callback may have torn c down re-entrantly */
        }
    }
}

static void conn_handle_readable(cloak_conn_t *c) {
    for (;;) {
        size_t room = cloak_bytequeue_free_space(&c->recv_acc);
        if (room == 0) {
            return; /* structurally unreachable given recv_acc's capacity invariant; defensive only */
        }
        uint8_t tmp[4096];
        size_t want = room < sizeof(tmp) ? room : sizeof(tmp);
        ssize_t n = read(c->fd, tmp, want);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            conn_mark_broken(c);
            return;
        }
        if (n == 0) {
            conn_mark_broken(c); /* peer EOF */
            return;
        }
        cloak_bytequeue_write(&c->recv_acc, tmp, (size_t)n); /* always fits: n <= room */
        conn_extract_and_dispatch(c);
        if (c->broken) {
            return;
        }
    }
}

static void conn_reactor_cb(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    cloak_conn_t *c = (cloak_conn_t *)userdata;
    if (c->broken) {
        return;
    }
    if (events & CLOAK_REACTOR_READABLE) {
        conn_handle_readable(c);
        if (c->broken) {
            return;
        }
    }
    if (events & CLOAK_REACTOR_WRITABLE) {
        conn_try_drain_send(c);
    }
}

int cloak_conn_init(cloak_conn_t *c, int fd, cloak_reactor_t *reactor,
                     size_t max_frame_len, size_t send_queue_cap,
                     cloak_conn_envelope_cb on_envelope, void *on_envelope_userdata,
                     cloak_conn_closed_cb on_closed, void *on_closed_userdata) {
    memset(c, 0, sizeof(*c));
    if (max_frame_len == 0 || max_frame_len > 65535 || send_queue_cap == 0) {
        return -1;
    }
    c->fd = fd;
    c->reactor = reactor;
    c->max_frame_len = max_frame_len;
    c->max_envelope_len = (size_t)CLOAK_CONN_LEN_PREFIX_LEN + max_frame_len;
    c->on_envelope = on_envelope;
    c->on_envelope_userdata = on_envelope_userdata;
    c->on_closed = on_closed;
    c->on_closed_userdata = on_closed_userdata;

    if (cloak_bytequeue_init(&c->recv_acc, 2 * c->max_envelope_len) != 0) {
        return -1;
    }
    if (cloak_bytequeue_init(&c->send_q, send_queue_cap) != 0) {
        cloak_bytequeue_destroy(&c->recv_acc);
        return -1;
    }
    c->recv_scratch = (uint8_t *)malloc(c->max_envelope_len);
    if (c->recv_scratch == NULL) {
        cloak_bytequeue_destroy(&c->recv_acc);
        cloak_bytequeue_destroy(&c->send_q);
        return -1;
    }
    if (cloak_reactor_add_fd(reactor, fd, CLOAK_REACTOR_READABLE, conn_reactor_cb, c) != 0) {
        free(c->recv_scratch);
        cloak_bytequeue_destroy(&c->recv_acc);
        cloak_bytequeue_destroy(&c->send_q);
        return -1;
    }
    return 0;
}

void cloak_conn_destroy(cloak_conn_t *c) {
    if (c->reactor != NULL) {
        cloak_reactor_remove_fd(c->reactor, c->fd); /* no-op-with-error-return if already removed */
    }
    free(c->recv_scratch);
    if (c->recv_acc.data != NULL) {
        cloak_bytequeue_destroy(&c->recv_acc);
    }
    if (c->send_q.data != NULL) {
        cloak_bytequeue_destroy(&c->send_q);
    }
    memset(c, 0, sizeof(*c));
}

int cloak_conn_send(cloak_conn_t *c, const uint8_t *frame_bytes, size_t frame_len) {
    if (c->broken) {
        return -1;
    }
    size_t total = (size_t)CLOAK_CONN_LEN_PREFIX_LEN + frame_len;
    if (total > c->max_envelope_len) {
        conn_mark_broken(c); /* caller/config bug: frame too large for this conn */
        return -1;
    }
    if (cloak_bytequeue_free_space(&c->send_q) < total) {
        conn_mark_broken(c); /* send queue's hard cap exceeded -- treated as a connection failure */
        return -1;
    }
    uint8_t prefix[CLOAK_CONN_LEN_PREFIX_LEN];
    prefix[0] = (uint8_t)((frame_len >> 8) & 0xff);
    prefix[1] = (uint8_t)(frame_len & 0xff);
    cloak_bytequeue_write(&c->send_q, prefix, CLOAK_CONN_LEN_PREFIX_LEN);
    cloak_bytequeue_write(&c->send_q, frame_bytes, frame_len);
    conn_try_drain_send(c);
    return 0;
}
