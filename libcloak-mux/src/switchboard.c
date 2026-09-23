#include "cloak/switchboard.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cloak/common.h"
#include "cloak/conn.h"

/* THE CONNECTION PICK'S RANDOMNESS. See switchboard.h's header comment
 * for WHY this has to be cryptographic; this is the how.
 *
 * A refill of CSPRNG bytes held in the pool, drawn four at a time --
 * structurally the same thing Go does (rand.Rand over rand.NewChaCha8
 * refills 32 words of ChaCha8 keystream at a time and hands them out one
 * per call), and for the same reason: the per-draw cost of going to the
 * operating system's generator does not belong on a per-frame path.
 *
 * MEASURED, 2,000,000 draws each, in this project's dev image:
 *   the xorshift32 this replaces      2.0 ns/draw
 *   cloak_random_below(4) directly  644-658 ns/draw   (~320x)
 *   this buffer                      10.9-11.0 ns/draw (~5.4x)
 * The direct call is a real cost on a small-datagram flood -- one
 * RAND_bytes syscall-ish trip per datagram, against a per-datagram cost
 * of a couple of microseconds -- and 9 ns is not. Both are unbiased; this
 * one is also cheap, so the choice cost nothing.
 *
 * THE BUFFER IS NOT A WEAKENING. Every byte in it is RAND_bytes output
 * that has not been handed out yet; what a censor sees is the picks, and
 * those are as unpredictable as the generator that produced them either
 * way. What it does change is forward secrecy over a 256-byte window --
 * an attacker with the pool's memory learns up to 64 future picks. The
 * picks are published on the wire the moment they are used, so that
 * window buys an attacker who already has our address space nothing. */
#define SWITCHBOARD_RNG_BUF_LEN 256

static uint32_t switchboard_random_u32(cloak_switchboard_t *sb) {
    if (sb->rng_pos + 4 > SWITCHBOARD_RNG_BUF_LEN) {
        sb->rng_pos = SWITCHBOARD_RNG_BUF_LEN;
    }
    if (sb->rng_pos == SWITCHBOARD_RNG_BUF_LEN) {
        cloak_random_bytes(sb->rng_buf, SWITCHBOARD_RNG_BUF_LEN);
        sb->rng_pos = 0;
    }
    uint32_t v = ((uint32_t)sb->rng_buf[sb->rng_pos] << 24) |
                 ((uint32_t)sb->rng_buf[sb->rng_pos + 1] << 16) |
                 ((uint32_t)sb->rng_buf[sb->rng_pos + 2] << 8) |
                 (uint32_t)sb->rng_buf[sb->rng_pos + 3];
    sb->rng_pos += 4;
    return v;
}

/* [0, n), REJECTION-SAMPLED -- the same strategy, and the same arithmetic,
 * as cloak_random_below (libcloak-common/src/random.c), which is itself
 * the port of Go's common.RandInt. `% n` on the raw draw is what this
 * deliberately is not: module 8's fix wave removed exactly that shape
 * from a one-byte draw in frame.c after it put a 2.009x size bias on the
 * wire, and this is its 32-bit cousin. The discarded tail here is at most
 * n-1 values out of 2^32, so for the pool sizes Cloak uses (NumConn is a
 * handful) the loop's second iteration has probability below 2^-29 and
 * the cost above is the cost. */
static uint32_t switchboard_random_below(cloak_switchboard_t *sb, uint32_t n) {
    if (n <= 1) {
        return 0;
    }
    uint64_t limit = 0x100000000ULL - (0x100000000ULL % (uint64_t)n);
    for (;;) {
        uint32_t v = switchboard_random_u32(sb);
        if ((uint64_t)v < limit) {
            return v % n;
        }
    }
}

static void switchboard_conn_envelope_adapter(cloak_conn_t *conn, const uint8_t *bytes, size_t len, void *userdata) {
    (void)conn;
    cloak_switchboard_t *sb = (cloak_switchboard_t *)userdata;
    if (sb->on_envelope) {
        sb->on_envelope(sb, bytes, len, sb->on_envelope_userdata);
    }
}

static void switchboard_conn_drained_adapter(cloak_conn_t *c, void *userdata) {
    (void)c;
    cloak_switchboard_t *sb = (cloak_switchboard_t *)userdata;
    if (sb->on_drained != NULL) {
        sb->on_drained(sb, sb->on_drained_userdata);
    }
}

static void switchboard_conn_closed_adapter(cloak_conn_t *conn, void *userdata) {
    (void)conn;
    cloak_switchboard_t *sb = (cloak_switchboard_t *)userdata;
    if (sb->broken) {
        return; /* idempotent -- another conn in this same dispatch batch may have already reported */
    }
    sb->broken = 1;
    if (sb->on_broken) {
        sb->on_broken(sb, sb->on_broken_userdata);
    }
}

int cloak_switchboard_init(cloak_switchboard_t *sb, cloak_reactor_t *reactor,
                            size_t max_frame_len, size_t conn_send_queue_cap,
                            cloak_switchboard_envelope_cb on_envelope, void *on_envelope_userdata,
                            cloak_switchboard_broken_cb on_broken, void *on_broken_userdata) {
    memset(sb, 0, sizeof(*sb));
    /* CLOAK_CONN_MAX_FRAME_LEN, not a 65535 of its own: switchboard.h
     * promises "same validation as cloak_conn_init", and max_frame_len is
     * forwarded to cloak_conn_init unchanged by add_conn. Restating the
     * bound as a literal here let the two drift once already -- a caller
     * passing 20000 got a successful init and then -1 from every single
     * add_conn, which is a far harder failure to read than a rejection at
     * construction. */
    if (max_frame_len == 0 || max_frame_len > CLOAK_CONN_MAX_FRAME_LEN || conn_send_queue_cap == 0) {
        return -1;
    }
    sb->reactor = reactor;
    sb->max_frame_len = max_frame_len;
    sb->conn_send_queue_cap = conn_send_queue_cap;
    sb->on_envelope = on_envelope;
    sb->on_envelope_userdata = on_envelope_userdata;
    sb->on_broken = on_broken;
    sb->on_broken_userdata = on_broken_userdata;

    /* "Empty", so the first pick refills from RAND_bytes. The memset
     * above already did this; it is restated because an rng_pos of 0 with
     * a zeroed buffer would be the one catastrophic state (64 picks of
     * connection 0), and a reader should be able to see that it cannot
     * arise without re-deriving the memset's effect on a field declared
     * thirty lines away in another file. */
    sb->rng_pos = SWITCHBOARD_RNG_BUF_LEN;
    return 0;
}

void cloak_switchboard_destroy(cloak_switchboard_t *sb) {
    cloak_switchboard_close_all(sb);
    free(sb->conns);
    memset(sb, 0, sizeof(*sb));
}

int cloak_switchboard_add_conn(cloak_switchboard_t *sb, int fd) {
    return cloak_switchboard_add_conn_framed(sb, fd, CLOAK_CONN_FRAMING_TLS_RECORD);
}

int cloak_switchboard_add_conn_framed(cloak_switchboard_t *sb, int fd,
                                       cloak_conn_framing_t framing) {
    /* Rejected BEFORE the pool array is grown and before a conn is
     * allocated, so an invalid framing mode leaves the pool exactly as it
     * was and leaves fd with its caller -- the failure a zeroed config is
     * meant to produce is a clean refusal, not a half-built pool. */
    if (framing == CLOAK_CONN_FRAMING_INVALID) {
        return CLOAK_CONN_ERR_INVALID_FRAMING;
    }
    if (sb->broken) {
        return -1;
    }
    if (sb->conns_len == sb->conns_cap) {
        size_t new_cap = sb->conns_cap == 0 ? 4 : sb->conns_cap * 2;
        cloak_conn_t **new_conns = (cloak_conn_t **)realloc(sb->conns, new_cap * sizeof(cloak_conn_t *));
        if (new_conns == NULL) {
            return -1;
        }
        sb->conns = new_conns;
        sb->conns_cap = new_cap;
    }
    cloak_conn_t *c = (cloak_conn_t *)malloc(sizeof(cloak_conn_t));
    if (c == NULL) {
        return -1;
    }
    cloak_conn_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.fd = fd;
    cfg.reactor = sb->reactor;
    cfg.max_frame_len = sb->max_frame_len;
    cfg.send_queue_cap = sb->conn_send_queue_cap;
    cfg.framing = framing;
    cfg.on_envelope = switchboard_conn_envelope_adapter;
    cfg.on_envelope_userdata = sb;
    cfg.on_closed = switchboard_conn_closed_adapter;
    cfg.on_closed_userdata = sb;
    int rc = cloak_conn_init_cfg(c, &cfg);
    if (rc != 0) {
        free(c);
        /* Propagated verbatim rather than flattened to -1: a framing
         * value outside the enum entirely (a truncated read, an
         * uninitialised byte pattern) is caught here rather than by the
         * INVALID test above, and the caller should still get the
         * diagnosis that names the field. */
        return rc;
    }
    cloak_conn_set_drained_cb(c, switchboard_conn_drained_adapter, sb);
    cloak_conn_set_valve(c, sb->valve); /* NULL if this pool is unmetered */
    sb->conns[sb->conns_len++] = c;
    /* A connection that joins while the session is backed up must start
     * paused, or the pause has a hole exactly the size of a reconnect. */
    if (sb->rx_backpressure) {
        cloak_conn_set_rx_backpressure(sb->conns[sb->conns_len - 1], 1);
    }
    return 0;
}

int cloak_switchboard_send(cloak_switchboard_t *sb, const uint8_t *frame_bytes, size_t frame_len) {
    if (sb->broken || sb->conns_len == 0) {
        return -1;
    }
    size_t idx = (size_t)switchboard_random_below(sb, (uint32_t)sb->conns_len);
    int rc = cloak_conn_send(sb->conns[idx], frame_bytes, frame_len);
    if (rc == 0) {
        /* TX counting point. Go's switchboard.go:106 -- sb.valve.AddTx(int64(n))
         * as the last statement of switchboard.send, reached only on the
         * success path (Go returns from the error branches BEFORE it, so
         * a write that failed is never billed; the same is true here,
         * hence the rc == 0 guard rather than counting unconditionally).
         *
         * Here rather than inside cloak_conn_send's own drain loop: Go
         * counts what a successful conn.Write accepted, and this port's
         * equivalent of "the write was accepted" is cloak_conn_send
         * returning 0. Counting bytes as the kernel actually swallows
         * them would move the count into conn_try_drain_send, which runs
         * again later from reactor dispatch and would bill the same
         * frame's tail at an arbitrarily later moment -- a needless
         * divergence from Go, and one that loses the bytes of a frame
         * still queued when a connection dies.
         *
         * THE FRAMING BYTES ARE INCLUDED because cloak_conn_send really
         * does put them on the socket: the count is the whole on-wire
         * envelope, which is also exactly what the peer's RX side counts
         * for the same frame.
         *
         * AND THE ENVELOPE IS ASKED OF THE CONNECTION, NOT ASSUMED. This
         * line used to read CLOAK_CONN_RECORD_HEADER_LEN + frame_len --
         * a flat +5, the TLS record header's size, billed for every frame
         * on every connection. That was correct while the TLS path was
         * the only path; it stopped being correct the moment a CDN
         * connection could exist, because a WebSocket envelope is two
         * bytes below a 126-byte payload and four at or above it (six and
         * eight from the client, whose mask key is another four). The
         * error was not academic: on the ~30-byte interactive frames this
         * comment's own example uses, +5 against a true +2 OVER-CHARGED a
         * metered user by about 8.6% -- 3 bytes in 35 charged, 88 MiB per
         * charged GiB -- and on a 16401-byte bulk frame in the CLIENT
         * direction it under-charged by about 0.018% (3 bytes of mask key
         * in 16409: 196 kB per GiB).
         * Over-charging is the half that matters, because this counter is
         * what spends a user's credit. cloak_conn_envelope_len is the
         * same arithmetic cloak_conn_send performs before it enqueues, so
         * the billed figure and the emitted bytes cannot drift.
         *
         * THIS DELIBERATELY DIVERGES FROM GO, AND BY A DIFFERENT AMOUNT
         * PER TRANSPORT NOW. Go bills neither transport's framing:
         * common.TLSConn.Write ends `return n - recordLayerLength` and
         * common.WebSocketConn.Write returns len(data), so Go bills
         * exactly frame_len in each direction on both. This port bills
         * the true envelope here and raw wire bytes on the RX side
         * (conn.c's own counting point explains why an envelope-level RX
         * counter would meter a peer that streams megabytes which never
         * assemble into a valid frame as zero -- unmetered traffic is not
         * a cosmetic difference when the counter charges a user's credit,
         * and cloak/valve.h states the WIRE-BYTES rule as this project's
         * ruling). The counters are NOT to be aligned with Go's. What an
         * operator comparing a Cloak-C bill against a Cloak-Go one should
         * expect is now a gap of five bytes per frame on the direct path
         * and two or four on the CDN path, rather than five everywhere;
         * cloak/valve.h is where that is promised, and
         * libcloak-server/tests/test_dispatcher_ws.c is where both are
         * bracketed against literals.
         *
         * rx/tx here are the SERVER's directions, NOT the user manager's
         * up/down -- see cloak/valve.h before touching this line. */
        cloak_valve_add_tx(sb->valve,
                           (int64_t)cloak_conn_envelope_len(sb->conns[idx], frame_len));
    }
    return rc;
}

void cloak_switchboard_close_all(cloak_switchboard_t *sb) {
    for (size_t i = 0; i < sb->conns_len; i++) {
        int fd = sb->conns[i]->fd;
        cloak_conn_destroy(sb->conns[i]);
        close(fd);
        free(sb->conns[i]);
    }
    sb->conns_len = 0;
}

size_t cloak_switchboard_conn_count(const cloak_switchboard_t *sb) {
    return sb->conns_len;
}

void cloak_switchboard_set_drained_cb(cloak_switchboard_t *sb, cloak_switchboard_drained_cb cb,
                                       void *userdata) {
    if (sb == NULL) {
        return;
    }
    sb->on_drained = cb;
    sb->on_drained_userdata = userdata;
}

void cloak_switchboard_set_rx_backpressure(cloak_switchboard_t *sb, int on) {
    if (sb == NULL) {
        return;
    }
    /* EVERY connection, because a session's streams are multiplexed
     * across all of them and a frame for the saturated stream can arrive
     * on any one. Pausing only the connection the last frame came in on
     * would leave the other NumConn-1 free to deliver the frame that
     * overflows. The cost of being conservative here is throughput on
     * OTHER streams sharing the session while one of them is backed up;
     * the cost of being precise would be per-stream credit, which is a
     * wire change Go does not have either. */
    sb->rx_backpressure = on ? 1 : 0;
    for (size_t i = 0; i < sb->conns_len; i++) {
        cloak_conn_set_rx_backpressure(sb->conns[i], sb->rx_backpressure);
    }
}

void cloak_switchboard_set_valve(cloak_switchboard_t *sb, cloak_valve_t *v) {
    if (sb == NULL) {
        return;
    }
    sb->valve = v;
    /* Connections added before this call would otherwise keep metering
     * into whatever they were given at add time (usually nothing), which
     * would silently under-count a user whose valve is installed after
     * their first connection. */
    for (size_t i = 0; i < sb->conns_len; i++) {
        cloak_conn_set_valve(sb->conns[i], v);
    }
}

size_t cloak_switchboard_send_queued(const cloak_switchboard_t *sb) {
    if (sb == NULL) {
        return 0;
    }
    size_t total = 0;
    for (size_t i = 0; i < sb->conns_len; i++) {
        total += cloak_conn_send_queued(sb->conns[i]);
    }
    return total;
}

size_t cloak_switchboard_send_capacity(const cloak_switchboard_t *sb) {
    if (sb == NULL) {
        return 0;
    }
    size_t total = 0;
    for (size_t i = 0; i < sb->conns_len; i++) {
        total += cloak_conn_send_capacity(sb->conns[i]);
    }
    return total;
}

size_t cloak_switchboard_send_min_conn_free(const cloak_switchboard_t *sb) {
    if (sb == NULL || sb->conns_len == 0) {
        return 0;
    }
    size_t min_free = cloak_conn_send_free(sb->conns[0]);
    for (size_t i = 1; i < sb->conns_len; i++) {
        size_t free_space = cloak_conn_send_free(sb->conns[i]);
        if (free_space < min_free) {
            min_free = free_space;
        }
    }
    return min_free;
}
