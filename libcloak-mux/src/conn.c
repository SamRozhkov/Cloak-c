#include "cloak/conn.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* The interest mask this connection wants right now.
 *
 * READABLE is dropped for exactly one reason: the user's rx token bucket
 * is empty and the connection has been told to stop pulling bytes off
 * the wire until it refills (see conn_pause_read_for_rate). There is no
 * other recv-side backpressure here and there never was -- recv_acc is
 * sized so it cannot fill (cloak_conn_init). */
static uint32_t conn_desired_interest(const cloak_conn_t *c) {
    uint32_t events = 0;
    if (!c->read_paused) {
        events |= CLOAK_REACTOR_READABLE;
    }
    if (c->want_writable) {
        events |= CLOAK_REACTOR_WRITABLE;
    }
    return events;
}

/* Re-issues the registered mask whenever it differs from what is already
 * registered. The unequal test also means that resuming a paused read
 * takes the mask from (possibly) 0 back to READABLE, and that transition
 * is what RE-ARMS an edge-triggered fd: without it, bytes that arrived
 * while the read was paused would already be past their edge and would
 * never be reported again. */
static void conn_sync_interest(cloak_conn_t *c) {
    uint32_t events = conn_desired_interest(c);
    if (events == c->interest) {
        return;
    }
    c->interest = events;
    cloak_reactor_mod_fd(c->reactor, c->fd, events);
}

static void conn_set_want_writable(cloak_conn_t *c, int want) {
    if (c->want_writable == want) {
        return;
    }
    c->want_writable = want;
    conn_sync_interest(c);
}

static void conn_mark_broken(cloak_conn_t *c) {
    if (c->broken) {
        return; /* idempotent -- already reported */
    }
    c->broken = 1;
    /* The rx resume timer is deliberately NOT cancelled here. Breaking a
     * connection never frees it -- cloak_conn_destroy is the only place
     * this connection's storage is released (cloak/conn.h makes that the
     * owner's obligation, and cloak_switchboard_close_all is the only
     * caller in this tree), and that function cancels before it
     * memsets. So a cancel here could only ever be a second one, and
     * conn_rx_resume_cb's own `if (c->broken) return` already makes a
     * fire in the window between the two harmless. An earlier version
     * did cancel here, with a comment asserting a use-after-free that
     * cannot occur: dead defensive code describing an impossible bug is
     * worse than none, because the next reader has to disprove it. */
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
    /* "Were we in backpressure when this drain began?" -- want_writable
     * is set only when a previous write hit EAGAIN, so it is exactly the
     * state a producer is waiting to see cleared. Deliberately NOT
     * "was anything queued": cloak_conn_send enqueues and then calls this
     * function inline, so a send the kernel swallows whole would look
     * like a queued-then-drained transition and fire the callback on
     * every ordinary write. */
    int was_backpressured = c->want_writable;
    for (;;) {
        size_t avail = cloak_bytequeue_len(&c->send_q);
        if (avail == 0) {
            conn_set_want_writable(c, 0);
            /* The moment a backpressured producer may resume. Fired last,
             * after the interest mask is already correct, so a
             * cloak_conn_send from within the callback sees consistent
             * state. */
            if (was_backpressured && c->on_drained != NULL) {
                c->on_drained(c, c->on_drained_userdata);
            }
            return;
        }
        size_t want = avail < sizeof(drain_buf) ? avail : sizeof(drain_buf);
        size_t peeked = cloak_bytequeue_peek(&c->send_q, drain_buf, want);
        /* send() with MSG_NOSIGNAL, not write() -- writing to a socket
         * whose peer has already closed raises SIGPIPE, which by default
         * terminates the whole process. A proxy server must survive an
         * individual client disconnecting; MSG_NOSIGNAL makes this an
         * ordinary EPIPE error instead (handled below, same as any other
         * write error -- conn_mark_broken). Found during this plan's own
         * design verification while constructing a peer-disconnect
         * regression test for an unrelated bug (see this plan's Global
         * Constraints) -- not a hypothetical. */
        ssize_t n = send(c->fd, drain_buf, peeked, MSG_NOSIGNAL);
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
    uint8_t header[CLOAK_CONN_RECORD_HEADER_LEN];
    for (;;) {
        size_t peeked = cloak_bytequeue_peek(&c->recv_acc, header, CLOAK_CONN_RECORD_HEADER_LEN);
        if (peeked < CLOAK_CONN_RECORD_HEADER_LEN) {
            return; /* not even the record header has fully arrived yet */
        }
        /* Bytes 0-2 (type and version) are read past WITHOUT being
         * validated -- Go's common.TLSConn.Read does exactly the same, and
         * cloak/conn.h gives the two reasons at length: being fussier than
         * the reference implementation is itself a distinguisher, and the
         * frame's own AEAD is the only authenticator that could actually
         * stop anything. Deliberate; pinned by
         * libcloak-mux/tests/test_conn_record.c. */
        uint16_t frame_len = (uint16_t)(((uint16_t)header[3] << 8) | (uint16_t)header[4]);
        if ((size_t)frame_len > c->max_frame_len) {
            conn_mark_broken(c); /* protocol violation -- declared length too large for this conn */
            return;
        }
        size_t envelope_len = (size_t)CLOAK_CONN_RECORD_HEADER_LEN + frame_len;
        if (cloak_bytequeue_len(&c->recv_acc) < envelope_len) {
            return; /* full envelope hasn't arrived yet */
        }
        cloak_bytequeue_read(&c->recv_acc, c->recv_scratch, envelope_len);
        if (c->on_envelope) {
            c->on_envelope(c, c->recv_scratch + CLOAK_CONN_RECORD_HEADER_LEN, frame_len, c->on_envelope_userdata);
        }
        if (c->broken) {
            return; /* the callback may have torn c down re-entrantly */
        }
    }
}

static void conn_rx_resume_cb(cloak_reactor_t *r, void *userdata);

/* Stops pulling bytes off this socket until the user's rx bucket has
 * something to give, and ARMS THE TIMER THAT WILL UNDO THAT before it
 * returns.
 *
 * The arming is not optional and is not a nicety. Every other pause in
 * this codebase is resumed by an event that is already guaranteed to
 * happen (a queue drains, a peer writes). This one is resumed by nothing
 * at all: the bytes are already sitting in the socket, their readiness
 * edge has been consumed, the peer has no reason to send more, and the
 * only thing that will ever change is the clock. A pause here that
 * returned without a timer would be a connection that looks healthy,
 * holds an open fd and a live session, and never moves another byte --
 * see cloak_valve_take_rx's own contract in cloak/valve.h. */
static void conn_pause_read_for_rate(cloak_conn_t *c) {
    if (c->rx_resume_timer == CLOAK_TIMER_INVALID) {
        /* Armed verbatim, with no floor of its own. This is only
         * reached after cloak_valve_take_rx refused a want of at least
         * one byte, which means the valve is non-NULL with a non-zero
         * rate -- and cloak/valve.h guarantees a rate-limited direction
         * never reports 0. The floor that used to be here has moved into
         * bucket_delay_ms; re-adding it would mask the producer's and
         * leave nothing to notice if the producer's were lost. */
        uint64_t delay = cloak_valve_rx_resume_delay_ms(c->valve);
        c->rx_resume_timer = cloak_reactor_add_timer(c->reactor, delay, conn_rx_resume_cb, c);
        if (c->rx_resume_timer == CLOAK_TIMER_INVALID) {
            /* The timer heap could not grow. Pausing now would be the
             * permanent stall described above, so the connection is
             * broken instead: a reported failure the owner can act on
             * beats a silent hang it cannot even detect. */
            conn_mark_broken(c);
            return;
        }
    }
    c->read_paused = 1;
    /* HALF OF A DELIBERATELY REDUNDANT PAIR -- see conn_rx_resume_cb for
     * the other half and for what each one alone would still achieve.
     * Dropping this call alone leaves every test green: the fd simply
     * stays registered for READABLE while paused, and because the
     * registration is edge-triggered nothing is re-delivered unless new
     * data arrives, at which point the read loop takes 0 again and
     * re-pauses against the timer that is already armed. It is kept
     * because an fd registered for a readiness the owner has decided not
     * to act on is a lie about this object's state, not because a stall
     * depends on it. */
    conn_sync_interest(c);
}

static void conn_handle_readable(cloak_conn_t *c);

static void conn_rx_resume_cb(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_conn_t *c = (cloak_conn_t *)userdata;
    c->rx_resume_timer = CLOAK_TIMER_INVALID;
    if (c->broken) {
        return;
    }
    c->read_paused = 0;
    conn_sync_interest(c);
    /* THE OTHER HALF OF THE PAIR, and the redundancy is deliberate and
     * measured: removing either of these two calls alone leaves all 45
     * tests green, and removing both together fails the stall test. Each
     * is independently sufficient to resume the read --
     * conn_sync_interest's 0 -> READABLE transition re-arms an
     * edge-triggered fd and re-reports data already in the socket, and
     * this call pulls it directly -- so neither is individually pinned
     * and no test can pin one without disabling the other.
     *
     * Kept as a pair rather than reduced to one because the two rest on
     * different guarantees: one on an epoll_ctl(EPOLL_CTL_MOD) detail,
     * the other on nothing but this function running. A stall is the one
     * failure this module must not be able to produce, and this is the
     * only place in the file where the cost of belt-and-braces is a
     * single call on a path that runs at most once per pause. */
    conn_handle_readable(c);
}

static void conn_handle_readable(cloak_conn_t *c) {
    for (;;) {
        size_t room = cloak_bytequeue_free_space(&c->recv_acc);
        if (room == 0) {
            return; /* structurally unreachable given recv_acc's capacity invariant; defensive only */
        }
        uint8_t tmp[4096];
        size_t want = room < sizeof(tmp) ? room : sizeof(tmp);
        /* RATE LIMITING POINT, rx half. Go's LimitedValve.rxWait, which
         * BLOCKS the deplexing goroutine until the bucket has n tokens.
         * Nothing here may block, so the shape is inverted: ask how many
         * bytes may move, read at most that many, and when the answer is
         * zero stop reading and let a timer bring us back.
         *
         * Here, on the raw socket read, for the same reason the counter
         * on the next-but-one line is here: these are the bytes the peer
         * makes this host receive, and the only way not to receive them
         * is not to ask for them. There is no point further in that
         * could refuse anything -- by then they are already in.
         *
         * rx/tx here are the SERVER's directions, NOT the user manager's
         * up/down -- see cloak/valve.h before touching this line. */
        int64_t allowed = cloak_valve_take_rx(c->valve, (int64_t)want);
        if (allowed <= 0) {
            conn_pause_read_for_rate(c);
            return;
        }
        if ((size_t)allowed < want) {
            want = (size_t)allowed;
        }
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
        /* RX counting point. Go's switchboard.go:153 -- sb.valve.AddRx(int64(n))
         * in deplex, immediately after conn.Read returns, before the
         * bytes are handed to the session and before the error check (so
         * a read that returned data AND an error still bills that data).
         *
         * Deliberately here, on the raw socket read, and not on the
         * extracted envelope in conn_extract_and_dispatch: these are the
         * bytes the peer actually made this host receive. A peer that
         * streams megabytes which never assemble into a valid frame, or
         * that stalls mid-envelope forever, would be metered as zero by
         * an envelope-level counter -- unmetered traffic is not a
         * cosmetic accounting difference when the counter's purpose is
         * to charge a user's credit. It also means partial frames are
         * counted when they arrive rather than when they complete, which
         * is what Go does too.
         *
         * Wire bytes: this includes each envelope's
         * CLOAK_CONN_RECORD_HEADER_LEN record header, matching what the sending
         * peer's TX side counted for the same envelope.
         *
         * rx/tx here are the SERVER's directions, NOT the user manager's
         * up/down -- see cloak/valve.h before touching this line. */
        cloak_valve_add_rx(c->valve, (int64_t)n);
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
    if (max_frame_len == 0 || max_frame_len > CLOAK_CONN_MAX_FRAME_LEN || send_queue_cap == 0) {
        return -1;
    }
    c->fd = fd;
    c->reactor = reactor;
    c->max_frame_len = max_frame_len;
    c->max_envelope_len = (size_t)CLOAK_CONN_RECORD_HEADER_LEN + max_frame_len;
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
    /* Mirror what was just registered, so conn_sync_interest's
     * "unchanged mask" test starts out telling the truth. */
    c->interest = CLOAK_REACTOR_READABLE;
    return 0;
}

void cloak_conn_destroy(cloak_conn_t *c) {
    if (c->reactor != NULL) {
        /* Before the memset below wipes the id: a resume timer that
         * outlived its connection fires with a dangling userdata. */
        cloak_reactor_cancel_timer(c->reactor, c->rx_resume_timer);
        c->rx_resume_timer = CLOAK_TIMER_INVALID;
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
    /* Checked directly against max_frame_len first, before the addition
     * below -- frame_len is always this module's own bounded chunking in
     * practice (never network-derived), but a caller bug passing a
     * frame_len near SIZE_MAX would otherwise wrap CLOAK_CONN_RECORD_HEADER_LEN
     * + frame_len back into range and silently bypass the size check
     * entirely. Flagged as an open Minor by an earlier task review and
     * triaged (fixed, not deferred) during this plan's final
     * whole-branch review, since it's free and removes the reasoning
     * burden for every future caller of this function. */
    if (frame_len > c->max_frame_len) {
        conn_mark_broken(c); /* caller/config bug: frame too large for this conn */
        return -1;
    }
    size_t total = (size_t)CLOAK_CONN_RECORD_HEADER_LEN + frame_len;
    if (total > c->max_envelope_len) {
        conn_mark_broken(c); /* caller/config bug: frame too large for this conn */
        return -1;
    }
    if (cloak_bytequeue_free_space(&c->send_q) < total) {
        conn_mark_broken(c); /* send queue's hard cap exceeded -- treated as a connection failure */
        return -1;
    }
    /* The five bytes a censor's DPI box sees before every frame. Byte for
     * byte what Go's common.TLSConn.Write emits
     * (/Users/sam/Cloak/internal/common/tls.go): application_data, the
     * legacy record version TLS 1.3 puts on the wire, then the body length
     * big-endian. See cloak/conn.h for why the three constant bytes are
     * the point of this module and not overhead to be trimmed. */
    uint8_t header[CLOAK_CONN_RECORD_HEADER_LEN];
    header[0] = 0x17; /* ContentType application_data */
    header[1] = 0x03; /* legacy_record_version 0x0303, high byte */
    header[2] = 0x03; /* legacy_record_version 0x0303, low byte  */
    header[3] = (uint8_t)((frame_len >> 8) & 0xff);
    header[4] = (uint8_t)(frame_len & 0xff);
    cloak_bytequeue_write(&c->send_q, header, CLOAK_CONN_RECORD_HEADER_LEN);
    cloak_bytequeue_write(&c->send_q, frame_bytes, frame_len);
    conn_try_drain_send(c);
    /* conn_try_drain_send may have discovered a hard write failure (e.g.
     * the peer disconnected) and called conn_mark_broken during THIS
     * call -- in which case the bytes just enqueued above are sitting in
     * a send_q that's about to be destroyed, never actually delivered.
     * Reporting success (0) here would silently drop them, violating
     * this plan's Global Constraints ("never silently drop data"). Found
     * during this plan's own design verification, via a regression test
     * for an unrelated bug (a stream write surviving its own connection
     * dying mid-call -- see the Global Constraints entry on this
     * project's recurring UAF class) that happened to also exercise this
     * return-value path for the first time. */
    return c->broken ? -1 : 0;
}

void cloak_conn_set_valve(cloak_conn_t *c, cloak_valve_t *v) {
    if (c == NULL) {
        return;
    }
    c->valve = v;
}

void cloak_conn_set_drained_cb(cloak_conn_t *c, cloak_conn_drained_cb cb, void *userdata) {
    if (c == NULL) {
        return;
    }
    c->on_drained = cb;
    c->on_drained_userdata = userdata;
}

size_t cloak_conn_send_queued(const cloak_conn_t *c) {
    if (c == NULL) {
        return 0;
    }
    return cloak_bytequeue_len(&c->send_q);
}

size_t cloak_conn_send_capacity(const cloak_conn_t *c) {
    if (c == NULL) {
        return 0;
    }
    return cloak_bytequeue_len(&c->send_q) + cloak_bytequeue_free_space(&c->send_q);
}

size_t cloak_conn_send_free(const cloak_conn_t *c) {
    if (c == NULL) {
        return 0;
    }
    return cloak_bytequeue_free_space(&c->send_q);
}
