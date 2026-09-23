#include <stdio.h>
#include "cloak/conn.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cloak/ws_frame.h"

/* How many payload bytes the client send path masks at a time on its way
 * into send_q. The payload arrives as a const buffer the caller still
 * owns, so it cannot be masked in place; it is copied through this stack
 * chunk instead, which keeps the send path allocation-free.
 *
 * DELIBERATELY NOT A MULTIPLE OF FOUR. cloak/ws_frame.h singles out the
 * running mask position as "the one thing implementations of this
 * reliably get wrong": a loop that restarts the position at 0 for each
 * chunk produces a frame whose first chunk decodes and whose every later
 * chunk is garbage. If this constant were a multiple of 4 -- 1024, say --
 * every chunk boundary would land on a key-cycle boundary, the bug would
 * produce identical bytes, and NO TEST COULD EVER SEE IT. At 1022 the
 * second chunk starts at key offset 2, so
 * test_client_mask_position_runs_across_chunk_boundaries (which masks a
 * 9001-byte payload and unmasks it by the RFC's absolute key[i & 3])
 * fails immediately if the position stops running. */
#define CONN_WS_MASK_CHUNK 1022u

/* The interest mask this connection wants right now.
 *
 * READABLE is dropped for exactly one reason: the user's rx token bucket
 * is empty and the connection has been told to stop pulling bytes off
 * the wire until it refills (see conn_pause_read_for_rate). There is no
 * other recv-side backpressure here and there never was -- recv_acc is
 * sized so it cannot fill (cloak_conn_init). */
static uint32_t conn_desired_interest(const cloak_conn_t *c) {
    uint32_t events = 0;
    if (!c->read_paused && !c->rx_backpressure) {
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

/* THE DIRECT PATH. Unchanged by the CDN work, and deliberately so: this
 * function is what the 46-line comment at the top of cloak/conn.h is
 * about, and libcloak-mux/tests/test_conn_record.c pins every byte of it.
 * The WebSocket receive path below is a SEPARATE function reached through
 * conn_extract_and_dispatch's switch, not a generalisation of this one --
 * merging them would put the two disguises' logic in one place where a
 * change to either could silently reach the other. */
static void conn_tls_extract_and_dispatch(cloak_conn_t *c) {
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
        /* THE PART THAT MAKES THE PAUSE MEAN ANYTHING.
         *
         * The callback above may have filled a stream to its watermark
         * and switched this connection's backpressure on. Reading the
         * interest mask is not enough to act on that: this loop is
         * already inside one readable event, with a whole socket buffer
         * worth of envelopes decoded and waiting in recv_acc, and it
         * would deliver every one of them before the reactor ever
         * consulted the mask again. Measured: one call delivered 56 more
         * frames after the pause, which is exactly what overflowed the
         * receive heap and dropped the frame that killed the stream.
         *
         * Stopping here leaves the rest of recv_acc untouched -- nothing
         * is decrypted until it is dispatched -- so cloak_conn_set_rx_-
         * backpressure(c, 0) resumes precisely where this left off. */
        if (c->rx_backpressure) {
            return;
        }
    }
}

/* ------------------------------------------------------------------ */
/* The CDN path: RFC 6455 WebSocket framing                            */
/* ------------------------------------------------------------------ */

/* Enqueues one complete WebSocket frame: header written by the codec,
 * payload copied (and masked, in the client direction) into send_q behind
 * it. Shared by the data path (cloak_conn_send) and the control path
 * (pong, close echo), because the masking rule is a property of which END
 * we are, not of which opcode we are sending -- a control path that
 * bypassed it would be rejected by gorilla exactly as a data frame would.
 *
 * Returns 0 if the whole frame was enqueued, -1 if it was refused. A
 * refusal here always means the connection cannot carry what it was asked
 * to carry, so every -1 path marks it broken; a partially-enqueued frame
 * would be a corrupt stream, so the capacity check happens before the
 * first byte is written and this function never enqueues part of one. */
static int conn_ws_enqueue_frame(cloak_conn_t *c, cloak_ws_opcode_t op,
                                 const uint8_t *payload, size_t payload_len) {
    uint8_t key[4];
    const uint8_t *keyp = NULL;
    if (c->framing == CLOAK_CONN_FRAMING_WS_CLIENT) {
        /* Fresh PER FRAME, from cloak_random_bytes. Not hoisted to a
         * per-connection key: RFC 6455 section 5.3 requires a new one for
         * every frame, and a reused key is invisible to any round-trip
         * test because our own unmasking works just as well against a
         * constant. */
        cloak_ws_frame_mask_key(key);
        keyp = key;
    }
    uint8_t header[CLOAK_WS_FRAME_MAX_HEADER_LEN];
    ssize_t hn = cloak_ws_frame_write_header(header, sizeof(header), op, 1, keyp, payload_len);
    if (hn < 0) {
        conn_mark_broken(c);
        return -1;
    }
    size_t total = (size_t)hn + payload_len;
    if (cloak_bytequeue_free_space(&c->send_q) < total) {
        conn_mark_broken(c); /* send queue's hard cap exceeded -- a connection failure */
        return -1;
    }
    cloak_bytequeue_write(&c->send_q, header, (size_t)hn);
    if (keyp == NULL) {
        cloak_bytequeue_write(&c->send_q, payload, payload_len);
    } else {
        /* Masked BEFORE enqueueing, so send_q only ever holds finished
         * bytes and a partial kernel write can never resume in the middle
         * of a key cycle -- the shape cloak/ws_frame.h recommends. pos is
         * threaded across chunks: it is the offset within the WHOLE
         * payload, not within this chunk. See CONN_WS_MASK_CHUNK. */
        uint8_t chunk[CONN_WS_MASK_CHUNK];
        size_t pos = 0;
        for (size_t off = 0; off < payload_len;) {
            size_t n = payload_len - off;
            if (n > sizeof(chunk)) {
                n = sizeof(chunk);
            }
            memcpy(chunk, payload + off, n);
            pos = cloak_ws_frame_mask(chunk, n, key, pos);
            cloak_bytequeue_write(&c->send_q, chunk, n);
            off += n;
        }
    }
    return 0;
}

/* Reads one whole frame's worth of bytes out of recv_acc into dst, having
 * already established that they are all present, and unmasks them if the
 * peer masked. The mask position starts at 0 because dst holds the whole
 * payload of THIS frame (a fragment's payload is masked from its own
 * offset 0 -- masking is per frame, reassembly is per message). */
static void conn_ws_take_payload(cloak_conn_t *c, const cloak_ws_frame_header_t *h,
                                 uint8_t *dst, size_t payload_len) {
    uint8_t skip[CLOAK_WS_FRAME_MAX_HEADER_LEN];
    cloak_bytequeue_read(&c->recv_acc, skip, h->header_len);
    if (payload_len > 0) {
        cloak_bytequeue_read(&c->recv_acc, dst, payload_len);
        if (h->masked) {
            cloak_ws_frame_mask(dst, payload_len, h->mask_key, 0);
        }
    }
}

static void conn_ws_extract_and_dispatch(cloak_conn_t *c) {
    /* Which way round the mask must be, from RFC 6455 section 5.1 and
     * from gorilla's advanceFrame ("if c.isServer != mask": the same
     * check, in the same place). A conn whose own end is the SERVER
     * requires its peer -- a client -- to have masked. */
    const int peer_must_mask = (c->framing == CLOAK_CONN_FRAMING_WS_SERVER);

    for (;;) {
        uint8_t hdrbuf[CLOAK_WS_FRAME_MAX_HEADER_LEN];
        size_t peeked = cloak_bytequeue_peek(&c->recv_acc, hdrbuf, sizeof(hdrbuf));
        cloak_ws_frame_header_t h;
        ssize_t hn = cloak_ws_frame_parse_header(hdrbuf, peeked, &h);
        if (hn == 0) {
            return; /* header not complete yet -- wait for more bytes */
        }
        if (hn < 0) {
            /* Malformed, NOT "incomplete". The codec reports an error as
             * soon as the bytes that prove it are in hand precisely so
             * that this branch exists: treating -1 as "wait for more"
             * would let a peer pin the connection open forever with two
             * bytes it has already invalidated. */
            conn_mark_broken(c);
            return;
        }
        if (h.masked != peer_must_mask) {
            conn_mark_broken(c); /* RFC 6455 s5.1 -- gorilla's "bad MASK" */
            return;
        }

        /* THE PAYLOAD LENGTH BOUND cloak/ws_frame.h says is owed by the
         * caller, paid here, because this is the first layer on this path
         * that owns a buffer.
         *
         * The codec reports payload_len EXACTLY AS THE PEER DECLARED IT
         * and compares it to nothing: a header declaring
         * 0x7FFFFFFFFFFFFFFF parses perfectly there, and its own tests
         * pin that on purpose. The three pre-existing enforcers of
         * CLOAK_CONN_MAX_FRAME_LEN -- cloak_conn_init,
         * cloak_session_init, cloak_switchboard_init -- are all on the
         * direct path and never see a byte that arrived through a
         * WebSocket frame.
         *
         * Checked HERE, against the declaration alone, before a single
         * payload byte is buffered on its behalf, and treated as a
         * protocol violation rather than clamped -- exactly as the TLS
         * path treats an over-long record length. It is a MIMICRY bound
         * as much as a memory one (see CLOAK_CONN_MAX_FRAME_LEN's own
         * comment): one oversized frame is a single-probe distinguisher.
         *
         * The comparison is in uint64_t, not size_t: payload_len is
         * attacker-controlled and 64 bits wide even where size_t is 32,
         * so narrowing first would truncate a hostile declaration into an
         * acceptable one. */
        if (h.payload_len > (uint64_t)c->max_frame_len) {
            conn_mark_broken(c);
            return;
        }
        size_t payload_len = (size_t)h.payload_len;
        size_t total = h.header_len + payload_len;
        if (cloak_bytequeue_len(&c->recv_acc) < total) {
            return; /* the whole frame hasn't arrived yet */
        }

        if (h.opcode == CLOAK_WS_OP_PING || h.opcode == CLOAK_WS_OP_PONG ||
            h.opcode == CLOAK_WS_OP_CLOSE) {
            /* A control frame may be interleaved into a fragmented
             * message (RFC 6455 s5.4), so its payload goes to a buffer of
             * its own and the reassembly state above is left untouched.
             * The codec has already refused any control frame longer than
             * 125 bytes or lacking FIN, so this buffer cannot overflow. */
            uint8_t ctl[CLOAK_WS_FRAME_MAX_CONTROL_PAYLOAD];
            conn_ws_take_payload(c, &h, ctl, payload_len);
            if (h.opcode == CLOAK_WS_OP_PING) {
                /* A CDN pings idle WebSocket connections and hangs up
                 * when no pong comes back, so this is load-bearing in
                 * production and invisible in a lab. RFC 6455 s5.5.3: the
                 * pong carries the ping's application data verbatim. */
                if (conn_ws_enqueue_frame(c, CLOAK_WS_OP_PONG, ctl, payload_len) != 0) {
                    return; /* already marked broken */
                }
                conn_try_drain_send(c);
                if (c->broken) {
                    return;
                }
                continue;
            }
            if (h.opcode == CLOAK_WS_OP_PONG) {
                continue; /* unsolicited pongs are legal and carry nothing we want */
            }
            /* CLOSE. RFC 6455 s5.5.1 asks the receiving endpoint to send
             * a Close in response; the status code is echoed back, which
             * is what gorilla's default close handler does too. Enqueued
             * and flushed BEFORE the connection is marked broken, since
             * conn_mark_broken deregisters the fd and nothing would drain
             * it afterwards. Best effort: a peer that has already gone
             * away simply makes the write fail, which is the same outcome
             * as the close itself. The frame is never delivered as
             * session data -- a two-byte status code handed to the
             * deobfuscator is a decryption failure reported as a corrupt
             * peer rather than as a clean hang-up. */
            (void)conn_ws_enqueue_frame(c, CLOAK_WS_OP_CLOSE, ctl, payload_len);
            if (!c->broken) {
                conn_try_drain_send(c);
            }
            conn_mark_broken(c);
            return;
        }

        /* A data frame: BINARY, TEXT or CONTINUATION.
         *
         * TEXT is accepted as data rather than refused. Cloak only ever
         * SENDS binary (cloak/ws_frame.h: the first header byte of every
         * Cloak message is 0x82), but Go's WSOverTLS.Read takes whatever
         * NextReader hands it and never inspects the message type, so
         * refusing TEXT here would make this port fussier than the
         * reference implementation -- itself a behavioural
         * distinguisher, the same argument cloak/conn.h makes for not
         * validating the TLS record's type byte. */
        if (h.opcode == CLOAK_WS_OP_CONTINUATION) {
            if (!c->ws_msg_active) {
                conn_mark_broken(c); /* gorilla: "continuation after final frame" */
                return;
            }
        } else if (c->ws_msg_active) {
            conn_mark_broken(c); /* a new data message interleaved into an unfinished one */
            return;
        }

        /* The bound again, on the REASSEMBLED total. The per-frame check
         * above is not sufficient: three fragments of 200 bytes each
         * individually satisfy a max_frame_len of 300 and together
         * declare 600, which is the classic shape of a reassembly
         * overflow. recv_scratch holds max_recv_envelope_len bytes, which
         * is comfortably more than max_frame_len, but the bound enforced
         * here is max_frame_len because that is the mimicry limit -- and
         * because one WebSocket message is exactly one mux frame, so a
         * longer message is not a frame this session could carry anyway. */
        if (payload_len > c->max_frame_len - c->ws_msg_len) {
            conn_mark_broken(c);
            return;
        }

        conn_ws_take_payload(c, &h, c->recv_scratch + c->ws_msg_len, payload_len);
        c->ws_msg_len += payload_len;
        if (!h.fin) {
            c->ws_msg_active = 1;
            continue;
        }

        size_t msg_len = c->ws_msg_len;
        c->ws_msg_len = 0;
        c->ws_msg_active = 0;
        if (c->on_envelope) {
            c->on_envelope(c, c->recv_scratch, msg_len, c->on_envelope_userdata);
        }
        if (c->broken) {
            return; /* the callback may have torn c down re-entrantly */
        }
    }
}

static void conn_extract_and_dispatch(cloak_conn_t *c) {
    if (c->framing == CLOAK_CONN_FRAMING_TLS_RECORD) {
        conn_tls_extract_and_dispatch(c);
    } else {
        conn_ws_extract_and_dispatch(c);
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
    if (c->rx_backpressure) {
        return;
    }
    /* Envelopes left in recv_acc by a previous pause come out before any
     * new byte is read, or a resume would read the socket while already
     * holding undelivered frames and grow recv_acc without bound. */
    conn_extract_and_dispatch(c);
    if (c->broken || c->rx_backpressure) {
        return;
    }
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
        if (c->broken || c->rx_backpressure) {
            return;
        }
    }
}

void cloak_conn_set_rx_backpressure(cloak_conn_t *c, int on) {
    if (c == NULL || c->broken) {
        return;
    }
    on = on ? 1 : 0;
    if (c->rx_backpressure == on) {
        return;
    }
    c->rx_backpressure = on;
    conn_sync_interest(c);
    if (!on && !c->read_paused) {
        /* THE SAME REDUNDANT PAIR conn_rx_resume_cb DOCUMENTS, and for
         * the same reason: conn_sync_interest's 0 -> READABLE transition
         * re-arms an edge-triggered fd and re-reports what is already in
         * the socket, and this call pulls it directly. Either alone would
         * usually do; together they mean a resume cannot depend on an
         * epoll_ctl(EPOLL_CTL_MOD) detail being what we think it is. */
        conn_handle_readable(c);
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

/* The number of framing bytes one frame of payload_len costs, in the
 * given direction. RFC 6455 section 5.2: two fixed bytes, plus the
 * extended length (none for 0..125, two for 126..65535 -- an 8-byte form
 * exists but max_frame_len can never reach it, since
 * CLOAK_CONN_MAX_FRAME_LEN is 16640), plus four for the mask key when the
 * frame is masked.
 *
 * One function for both directions and both purposes -- the send
 * envelope, the receive envelope -- so that the two cannot drift. An
 * earlier draft of this file sized the receive buffer off the SEND
 * envelope, which is short by exactly the four mask bytes on a WS_SERVER
 * conn: that is not an overflow but a deadlock, since a
 * maximum-size incoming frame never completes, so nothing is consumed, so
 * room never appears. */
static size_t conn_ws_envelope_len(size_t payload_len, int masked) {
    size_t n = 2;
    if (payload_len > CLOAK_WS_FRAME_MAX_CONTROL_PAYLOAD) {
        n += 2;
    }
    if (masked) {
        n += 4;
    }
    return n + payload_len;
}

int cloak_conn_init(cloak_conn_t *c, int fd, cloak_reactor_t *reactor,
                     size_t max_frame_len, size_t send_queue_cap,
                     cloak_conn_envelope_cb on_envelope, void *on_envelope_userdata,
                     cloak_conn_closed_cb on_closed, void *on_closed_userdata) {
    /* The direct path's constructor, kept at its original signature so
     * that every existing call site is untouched by the CDN work and
     * cannot be forgotten INTO the wrong mode -- only into a construction
     * failure, which is what the config form below is for. */
    cloak_conn_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.fd = fd;
    cfg.reactor = reactor;
    cfg.max_frame_len = max_frame_len;
    cfg.send_queue_cap = send_queue_cap;
    cfg.framing = CLOAK_CONN_FRAMING_TLS_RECORD;
    cfg.on_envelope = on_envelope;
    cfg.on_envelope_userdata = on_envelope_userdata;
    cfg.on_closed = on_closed;
    cfg.on_closed_userdata = on_closed_userdata;
    return cloak_conn_init_cfg(c, &cfg);
}

int cloak_conn_init_cfg(cloak_conn_t *c, const cloak_conn_config_t *cfg) {
    memset(c, 0, sizeof(*c));
    /* FIRST, before any other validation. A zeroed config is invalid in
     * several ways at once (max_frame_len 0, send_queue_cap 0), and the
     * diagnosis a caller gets should name the field they actually forgot
     * rather than whichever one happened to be checked first. Ordering
     * pinned by test_zeroed_config_fails_with_the_named_error case (a). */
    if (cfg->framing != CLOAK_CONN_FRAMING_TLS_RECORD &&
        cfg->framing != CLOAK_CONN_FRAMING_WS_CLIENT &&
        cfg->framing != CLOAK_CONN_FRAMING_WS_SERVER) {
        return CLOAK_CONN_ERR_INVALID_FRAMING;
    }
    int fd = cfg->fd;
    cloak_reactor_t *reactor = cfg->reactor;
    size_t max_frame_len = cfg->max_frame_len;
    size_t send_queue_cap = cfg->send_queue_cap;
    if (max_frame_len == 0 || max_frame_len > CLOAK_CONN_MAX_FRAME_LEN || send_queue_cap == 0) {
        return -1;
    }
    c->fd = fd;
    c->reactor = reactor;
    c->framing = cfg->framing;
    c->max_frame_len = max_frame_len;
    if (cfg->framing == CLOAK_CONN_FRAMING_TLS_RECORD) {
        c->max_envelope_len = (size_t)CLOAK_CONN_RECORD_HEADER_LEN + max_frame_len;
        c->max_recv_envelope_len = c->max_envelope_len;
    } else {
        /* We mask iff we are the client; our peer masks iff we are the
         * server. The two envelopes therefore differ by the four mask
         * bytes, in opposite directions -- which is why a WS_CLIENT
         * conn's SEND envelope (16648 at CLOAK_CONN_MAX_FRAME_LEN) is
         * larger than the TLS one (16645) while a WS_SERVER conn's
         * (16644) is smaller. */
        int we_mask = (cfg->framing == CLOAK_CONN_FRAMING_WS_CLIENT);
        c->max_envelope_len = conn_ws_envelope_len(max_frame_len, we_mask);
        c->max_recv_envelope_len = conn_ws_envelope_len(max_frame_len, !we_mask);
    }
    c->on_envelope = cfg->on_envelope;
    c->on_envelope_userdata = cfg->on_envelope_userdata;
    c->on_closed = cfg->on_closed;
    c->on_closed_userdata = cfg->on_closed_userdata;

    if (cloak_bytequeue_init(&c->recv_acc, 2 * c->max_recv_envelope_len) != 0) {
        return -1;
    }
    if (cloak_bytequeue_init(&c->send_q, send_queue_cap) != 0) {
        cloak_bytequeue_destroy(&c->recv_acc);
        return -1;
    }
    /* Sized off the RECEIVE envelope, which on a WS conn is the larger of
     * the two and is also what an incoming frame's payload is bounded by.
     * On the WS path this buffer holds the reassembled MESSAGE (at most
     * max_frame_len bytes, enforced in conn_ws_extract_and_dispatch)
     * rather than one envelope, and max_recv_envelope_len exceeds
     * max_frame_len by the framing bytes in every mode. */
    c->recv_scratch = (uint8_t *)malloc(c->max_recv_envelope_len);
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
    if (c->framing != CLOAK_CONN_FRAMING_TLS_RECORD) {
        /* The CDN path. NO TLS RECORD HEADER: the real TLS session is
         * outside this WebSocket, between us and the CDN, and supplies
         * its own records. Emitting 0x17 0x03 0x03 <len> inside a
         * WebSocket binary frame would be wire-incompatible with Go's
         * WSOverTLS and, to anyone who can see inside the CDN's TLS, a
         * perfect Cloak signature. See cloak_conn_framing_t.
         *
         * NO SECOND CEILING ON THE ENVELOPE HERE, and the omission is
         * deliberate rather than forgotten -- a reader comparing this
         * branch with the TLS one below will notice the asymmetry. A
         * first draft did check conn_ws_envelope_len(frame_len, ...)
         * against max_envelope_len, and that check could not fire:
         * frame_len <= max_frame_len is established immediately above,
         * conn_ws_envelope_len is monotonic in payload_len, and
         * max_envelope_len IS conn_ws_envelope_len(max_frame_len, ...)
         * for this same mode and the same we-mask expression. Deleting it
         * left all 65 tests passing, which is the definition of a check
         * nothing can pin -- and an unpinnable bound is exactly what
         * cloak/conn.h warns rots into a false guarantee, the same
         * reasoning that removed the redundant cancel in
         * conn_mark_broken. The send queue's hard cap is still enforced,
         * inside conn_ws_enqueue_frame, where the real header length is
         * already known. (The TLS branch's equivalent ceiling is now
         * equally unreachable, for the same reason: it predates the
         * frame_len check above, which is what made it dead. It stays put
         * because that path is byte-for-byte pinned by
         * test_conn_record.c and is not this task's to disturb.) */
        if (conn_ws_enqueue_frame(c, CLOAK_WS_OP_BINARY, frame_bytes, frame_len) != 0) {
            return -1; /* already marked broken */
        }
        conn_try_drain_send(c);
        /* Same reasoning as the TLS path below: a hard write failure
         * discovered during THIS call means the bytes just enqueued will
         * never be delivered, and reporting success would silently drop
         * them. */
        return c->broken ? -1 : 0;
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

size_t cloak_conn_envelope_len(const cloak_conn_t *c, size_t frame_len) {
    if (c == NULL) {
        return 0;
    }
    if (c->framing == CLOAK_CONN_FRAMING_TLS_RECORD) {
        return (size_t)CLOAK_CONN_RECORD_HEADER_LEN + frame_len;
    }
    /* The same conn_ws_envelope_len cloak_conn_send uses to decide
     * whether the frame fits, asked in the same direction (we mask iff
     * we are the client). Sharing the function is the point: a meter
     * that recomputed the envelope would be free to drift from the
     * bytes actually emitted, which is precisely the failure this
     * function exists to end. */
    return conn_ws_envelope_len(frame_len, c->framing == CLOAK_CONN_FRAMING_WS_CLIENT);
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
