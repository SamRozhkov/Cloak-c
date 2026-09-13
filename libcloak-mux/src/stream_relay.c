#define _POSIX_C_SOURCE 200809L
#include "cloak/stream_relay.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cloak/conn.h" /* CLOAK_CONN_LEN_PREFIX_LEN: a fixed wire-format
                          * constant, needed below to compute the true
                          * worst-case on-wire cost of one frame -- not a
                          * reach into any per-instance connection state. */

#define STREAM_RELAY_CHUNK 16384

static void stream_relay_teardown(cloak_stream_relay_t *sr, int fire_done);

/* The worst-case on-wire bytes a single full frame can ever cost
 * (matching cloak_frame_obfuscate's own worst case: CLOAK_FRAME_HEADER_LEN
 * + payload + up to CLOAK_FRAME_MAX_EXTRA_LEN of padding/AEAD tag, plus
 * the connection layer's own CLOAK_CONN_LEN_PREFIX_LEN length prefix).
 * Shared by stream_relay_fd_read_budget and cloak_stream_relay_start's own
 * start-time rejection check so the two can never disagree about what
 * "one frame's worth of room" means. */
static size_t stream_relay_frame_cost_for(const cloak_stream_t *stream) {
    return (size_t)CLOAK_CONN_LEN_PREFIX_LEN + stream->max_payload_per_frame +
           (size_t)CLOAK_FRAME_HEADER_LEN + (size_t)CLOAK_FRAME_MAX_EXTRA_LEN;
}

static size_t stream_relay_frame_cost(const cloak_stream_relay_t *sr) {
    return stream_relay_frame_cost_for(sr->stream);
}

/* The number of raw bytes it is currently safe to pull from the fd and
 * hand to cloak_stream_write without asking any connection cloak_switch-
 * board_send might pick to hold more than it can actually take right
 * now. 0 means fully backed up -- the caller must pause rather than read
 * with that length (reading 0 bytes on purpose is indistinguishable from
 * the fd itself reaching EOF, which read() also reports as 0).
 *
 * This is sized in whole FRAMES, not raw bytes, and that distinction is
 * the whole point: cloak_stream_write's actual on-wire cost for n raw
 * bytes is NOT n. It is n plus a fixed per-frame overhead (see
 * stream_relay_frame_cost) for EVERY frame the chunk is split into --
 * ceil(n / stream->max_payload_per_frame) of them, chunked exactly that
 * way by cloak_stream_write itself. An earlier version of this function
 * sized the read in raw bytes alone (min(STREAM_RELAY_CHUNK, capacity -
 * queued)), which looked exact but wasn't: a single already-permitted
 * read of up to STREAM_RELAY_CHUNK bytes could still chunk into enough
 * frames that their summed overhead alone pushed the bound past capacity
 * in one step -- the same class of overrun this function exists to
 * prevent, just moved from "advisory sizing constraint" to
 * "off-by-a-forgotten-unit", and it took a real (100%-reproducible, not
 * flaky) run of this file's own large-transfer test to catch it.
 * min_free / frame_cost (rounded down) is therefore the number of frames
 * guaranteed to fit no matter how much padding cloak_frame_obfuscate
 * actually adds, and budgeting exactly that many frames' worth of raw
 * payload keeps the bound exact -- provably unable to overrun capacity --
 * rather than an approximation relying on a hand-picked safety margin.
 *
 * This budgets off cloak_session_send_min_conn_free -- the MINIMUM free
 * space over every connection in the pool -- not the aggregate
 * cloak_session_send_capacity/_queued this function used to use. The
 * aggregate is the wrong quantity for anything downstream of
 * cloak_switchboard_send: that function hands each whole frame to ONE
 * connection chosen uniformly at random, not spread across the pool, so
 * the realistic failure is one congested connection among many idle
 * ones -- the aggregate stays large (dominated by the N-1 idle
 * connections) right up until the random pick lands on the congested one
 * again and cloak_conn_send's own per-connection cap fires
 * conn_mark_broken, which is fatal to the whole pool and the whole
 * session. No conn_send_queue_cap fixes that against the aggregate bound,
 * because the aggregate scales with N * cap while the limit that
 * actually binds is one connection's own cap. Budgeting off the minimum
 * instead guarantees the number of frames this call permits will fit
 * REGARDLESS of which connection cloak_switchboard_send's next random
 * pick lands on -- the guarantee this object actually needs to make. */
static size_t stream_relay_fd_read_budget(const cloak_stream_relay_t *sr) {
    size_t min_free = cloak_session_send_min_conn_free(sr->sesh);
    size_t frame_cost = stream_relay_frame_cost(sr);
    size_t frames = min_free / frame_cost;
    if (frames == 0) {
        return 0;
    }
    size_t budget = frames * sr->stream->max_payload_per_frame;
    return budget < STREAM_RELAY_CHUNK ? budget : STREAM_RELAY_CHUNK;
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
    /* Also gated on !stream_ended: once the stream has ended, the session
     * has already retired it (a Cloak closing frame closes the stream in
     * both directions -- see pump_stream_to_fd's own comment below), so
     * anything pump_fd_to_stream reads from fd from this point on can only
     * turn into frames the peer will drop as tombstoned. Without this,
     * the relay keeps reading fd and emitting dead frames for however
     * long it takes to_fd to drain and the relay to actually tear down. */
    if (!sr->fd_read_paused && !sr->stream_ended) {
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

/* Fills to_fd from the stream, bounded by whatever free space to_fd
 * currently has. Returns the number of bytes moved (0 if none), and sets
 * sr->stream_ended if the stream reported end-of-stream while filling.
 * "Nothing ready right now" and "stream ended" are both ordinary
 * terminal conditions for a single call, not errors. */
static size_t try_fill_from_stream(cloak_stream_relay_t *sr) {
    uint8_t buf[STREAM_RELAY_CHUNK];
    size_t total = 0;
    if (sr->stream_ended) {
        return 0;
    }
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
        total += (size_t)n;
    }
    return total;
}

/* Drains to_fd to the fd. On success (*out_sent is the number of bytes
 * actually sent, 0 if none were queued or none could be sent right now)
 * returns 0; returns -1 if the fd itself is broken. */
static int try_drain_to_fd(cloak_stream_relay_t *sr, size_t *out_sent) {
    uint8_t buf[STREAM_RELAY_CHUNK];
    size_t total = 0;
    for (;;) {
        size_t have = cloak_bytequeue_peek(&sr->to_fd, buf, sizeof(buf));
        if (have == 0) {
            break;
        }
        ssize_t n = send(sr->fd, buf, have, MSG_NOSIGNAL);
        if (n > 0) {
            cloak_bytequeue_read(&sr->to_fd, buf, (size_t)n);
            total += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }
        *out_sent = total;
        return -1;
    }
    *out_sent = total;
    return 0;
}

/* Moves bytes from the stream to the fd, retrying both directions
 * together until neither makes further progress in a single call.
 *
 * This is NOT the same as calling "fill once, then drain once": room
 * try_drain_to_fd frees in to_fd must be revisited by try_fill_from_stream
 * within THIS SAME call, or bytes the stream already holds -- but that
 * didn't fit in to_fd on an earlier, separate call -- can be stranded
 * forever. Concretely: to_fd fills to capacity while the fd is stalled,
 * leaving excess unread in the stream's own reassembly buffer; later,
 * once the fd becomes writable again, a naive "fill once, drain once"
 * structure would check room before this call's own drain has freed any,
 * see none, skip filling, then drain the queue to empty and (via
 * sync_interest) drop WRITABLE interest entirely -- with the stream's
 * leftover bytes never revisited, since a fd-writable event carries no
 * information about the stream and cloak_stream_relay_notify_stream_data
 * only fires for a NEW frame, which may never come again (e.g. the far
 * end already sent everything and is now waiting for a reply). The
 * do/while below closes that gap by re-checking room every time either
 * side just moved bytes.
 *
 * Terminates because each iteration that repeats has moved a strictly
 * positive, bounded number of bytes: try_fill_from_stream is bounded by
 * whatever the stream currently holds, and try_drain_to_fd by whatever
 * to_fd currently holds -- both finite quantities that only shrink
 * (nothing refills the stream's own reassembly buffer from within this
 * function). The loop is not reachable with both returning 0 while
 * either side still has real progress available, and stops the instant
 * both genuinely have none.
 *
 * Returns 0 to continue, -1 if the relay should tear down. */
static int pump_stream_to_fd(cloak_stream_relay_t *sr) {
    size_t filled;
    size_t sent;
    do {
        filled = try_fill_from_stream(sr);
        if (try_drain_to_fd(sr, &sent) != 0) {
            return -1;
        }
    } while (filled > 0 || sent > 0);

    if (sr->stream_ended && cloak_bytequeue_len(&sr->to_fd) == 0) {
        /* This is a one-way teardown trigger, not a half-close: there is
         * deliberately no symmetric "fd reached EOF -> drain the stream
         * one last time" step on the other side (see pump_fd_to_stream's
         * own EOF handling below). A socket half-close still lets the
         * other direction keep flowing, but a Cloak closing frame closes
         * the stream in BOTH directions at once -- by the time
         * stream_ended is observable here, cloak_stream_write on this
         * same stream would already be writing into a retired stream.
         * "Restoring symmetry" would mean adding exactly that, not fixing
         * an oversight. */
        return -1; /* everything the stream ever sent has reached the fd */
    }
    return 0;
}

/* Reads the fd into the stream while the session has room, never asking
 * for more than stream_relay_fd_read_budget currently allows. Returns 0
 * to continue, -1 if the relay should tear down. */
static int pump_fd_to_stream(cloak_stream_relay_t *sr) {
    uint8_t buf[STREAM_RELAY_CHUNK];
    for (;;) {
        size_t budget = stream_relay_fd_read_budget(sr);
        if (budget == 0) {
            /* Stop reading; cloak_stream_relay_notify_writable re-arms. */
            sr->fd_read_paused = 1;
            return 0;
        }
        ssize_t n = read(sr->fd, buf, budget);
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

    /* Reject outright rather than start a relay that could never move a
     * single byte fd->stream. If not even the least-congested connection
     * in the session's pool could ever hold one worst-case frame,
     * stream_relay_fd_read_budget will compute 0 on this relay's very
     * first read forever -- nothing would ever be queued on that
     * connection, so it can never drain-to-zero, so on_drained/on_writable
     * can never fire, so notify_writable is never called to re-arm read
     * interest. The relay would hang forever holding an open fd, with no
     * error anywhere (this exact shape: conn_send_queue_cap == 8192,
     * max_on_wire_size == 16401 -- both individually accepted by
     * cloak_conn_init/cloak_session_init -- silently stalls the very
     * first read). Checked against the SAME per-connection quantity the
     * running budget uses, so the two can never drift apart. */
    /* -2, NOT -1: this is the one TRANSIENT rejection this function has.
     * See this function's own doc comment for why the caller must be able
     * to tell it apart from every permanent failure. */
    if (cloak_session_send_min_conn_free(sesh) < stream_relay_frame_cost_for(stream)) {
        return -2;
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
             * the reactor's own timer heap fails.
             *
             * Unwind WITHOUT taking the descriptor: this function's
             * contract is that a FAILED start always leaves fd with the
             * caller, and this is the one path that could otherwise have
             * consumed it. Deregister it (the add_fd above succeeded),
             * then clear sr->fd so the shared teardown below skips its
             * whole fd block rather than closing a descriptor the caller
             * still owns. Everything else teardown does is still wanted,
             * which is why this defers to it instead of inlining a second
             * unwind -- there is deliberately one teardown path in this
             * file. An earlier version closed fd here, which made this
             * the single exception to the ownership rule; the exception
             * was documented but could not be reached from any test (it
             * needs the reactor's timer-heap allocation to fail), and a
             * caller that got it wrong would double-close a descriptor,
             * which no sanitizer detects. Removing the exception is
             * strictly better than documenting it. */
            cloak_reactor_remove_fd(r, fd);
            sr->fd = -1;
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
    if (stream_relay_fd_read_budget(sr) == 0) {
        return; /* drained some, but still nothing safe to read yet */
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
