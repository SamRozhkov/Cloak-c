#define _POSIX_C_SOURCE 200809L

/* Pins the CDN-PATH FRAMING MODE: which bytes a cloak_conn_t puts around
 * a mux frame, and that the choice between them is made once, at
 * construction, by a field whose zero value is invalid.
 *
 * WHY THIS FILE EXISTS, AND WHY ITS CENTREPIECE IS ONE BYTE
 *
 * This port once shipped five modules in which the data path carried a
 * bare two-byte length prefix where Go writes a five-byte TLS
 * application-data record header -- the disguise held for exactly one
 * round trip and then stopped, which is a LOUDER fingerprint than no
 * disguise at all (cloak/conn.h, the 46-line comment above
 * CLOAK_CONN_RECORD_HEADER_LEN). One assertion would have caught it: read
 * the raw bytes off the socket and look at byte 0.
 *
 * This task is the EXACT INVERSE of that defect, and it is a trap in both
 * directions. On the CDN path the TLS record header must NOT be there:
 * Go's WSOverTLS embeds only a WebSocket connection, and the real TLS
 * session outside it supplies its own records. A conn left in TLS-record
 * mode on a WebSocket connection emits 0x17 0x03 0x03 <len> INSIDE a
 * WebSocket binary frame -- wire-incompatible with Go, and, to anyone who
 * can see inside the CDN's TLS, a perfect Cloak signature. A WebSocket
 * framing mode leaking onto the direct path undoes the five-byte fix.
 *
 * AND THE WRONG CHOICE IS INVISIBLE TO EVERY ROUND-TRIP TEST, BECAUSE
 * BOTH ENDS AGREE. A C-to-C test in which one conn sends and another
 * receives passes identically whichever framing both of them use. So
 * every on-wire expectation in this file is a LITERAL BYTE checked at a
 * LITERAL OFFSET, taken from RFC 6455 and from cloak/conn.h -- never
 * computed from a constant the code under test owns, and never obtained
 * by asking our own other end what it thinks it sent.
 *
 * THE OTHER THING THIS FILE PINS: THE PAYLOAD LENGTH BOUND.
 *
 * cloak/ws_frame.h reports payload_len exactly as the peer DECLARED it
 * and bounds it nowhere -- a header declaring 0x7FFFFFFFFFFFFFFF parses
 * perfectly. Its own header says, in as many words, that the bound is
 * owed by the caller, and this module is the caller: it is the first
 * layer on this path that owns a buffer. test_declared_length_* below are
 * the tests that prove the bound was actually written, with a measured
 * bracket on each side of it rather than a claimed margin. */

#include "cloak/conn.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "cloak/common.h"
#include "cloak/reactor.h"
#include "cloak/session.h"
#include "cloak/switchboard.h"
#include "test_framework.h"

#define MAX_FRAME_LEN 300u
#define SEND_QUEUE_CAP 131072u

/* Every wait in this file is bounded by the CLOCK, not by an iteration
 * count: an iteration bound that is generous on a fast machine is a
 * flake on a loaded one, and one that is generous everywhere is slow
 * everywhere. Two seconds is far beyond any legitimate socketpair
 * round trip; the ctest TIMEOUT of 120 is the outer backstop. */
#define PUMP_BUDGET_MS 2000u

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

#define PUMP_UNTIL(r, cond)                                       \
    do {                                                          \
        uint64_t _deadline = now_ms() + PUMP_BUDGET_MS;           \
        while (!(cond) && now_ms() < _deadline) {                 \
            cloak_reactor_run_once((r), 10);                      \
        }                                                         \
    } while (0)

static void pump(cloak_reactor_t *r) { cloak_reactor_run_once(r, 10); }

static int make_nonblocking_socketpair(int fds[2]) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return -1;
    if (fcntl(fds[0], F_SETFL, O_NONBLOCK) != 0) return -1;
    if (fcntl(fds[1], F_SETFL, O_NONBLOCK) != 0) return -1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Harness                                                             */
/* ------------------------------------------------------------------ */

#define HARNESS_MAX_MSGS 8
#define HARNESS_MSG_CAP 2048

typedef struct {
    uint8_t received[HARNESS_MAX_MSGS][HARNESS_MSG_CAP];
    size_t received_len[HARNESS_MAX_MSGS];
    int received_count;
    int closed_count;
} ws_harness_t;

static void on_envelope(cloak_conn_t *c, const uint8_t *bytes, size_t len, void *userdata) {
    (void)c;
    ws_harness_t *h = (ws_harness_t *)userdata;
    ASSERT_TRUE(h->received_count < HARNESS_MAX_MSGS);
    ASSERT_TRUE(len <= HARNESS_MSG_CAP);
    if (h->received_count >= HARNESS_MAX_MSGS || len > HARNESS_MSG_CAP) {
        return;
    }
    memcpy(h->received[h->received_count], bytes, len);
    h->received_len[h->received_count] = len;
    h->received_count++;
}

static void on_closed(cloak_conn_t *c, void *userdata) {
    (void)c;
    ws_harness_t *h = (ws_harness_t *)userdata;
    h->closed_count++;
}

static int init_conn(cloak_conn_t *c, int fd, cloak_reactor_t *r, ws_harness_t *h,
                     cloak_conn_framing_t framing, size_t max_frame_len) {
    cloak_conn_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.fd = fd;
    cfg.reactor = r;
    cfg.max_frame_len = max_frame_len;
    cfg.send_queue_cap = SEND_QUEUE_CAP;
    cfg.framing = framing;
    cfg.on_envelope = on_envelope;
    cfg.on_envelope_userdata = h;
    cfg.on_closed = on_closed;
    cfg.on_closed_userdata = h;
    return cloak_conn_init_cfg(c, &cfg);
}

/* Reads up to want bytes off the peer end of the socketpair, pumping the
 * reactor between attempts so a write the kernel only partly accepted
 * gets its chance to drain. Returns how many were actually collected;
 * callers assert on that number, so a short read is a visible failure
 * rather than a hang. */
static size_t drain_peer(cloak_reactor_t *r, int peer_fd, uint8_t *out, size_t want) {
    size_t got = 0;
    uint64_t deadline = now_ms() + PUMP_BUDGET_MS;
    while (got < want && now_ms() < deadline) {
        pump(r);
        ssize_t n = read(peer_fd, out + got, want - got);
        if (n > 0) {
            got += (size_t)n;
        }
    }
    return got;
}

/* Builds a WebSocket frame BY HAND, from RFC 6455 section 5.2 and
 * nothing else. Deliberately NOT cloak_ws_frame_write_header: a test that
 * encodes with the same code the implementation decodes with cannot
 * detect the two agreeing on something wrong, and agreement between our
 * own two ends is precisely the blind spot this file exists to cover. */
static size_t build_ws_frame(uint8_t *buf, uint8_t opcode, int fin, const uint8_t *key,
                             const uint8_t *payload, size_t n) {
    size_t i = 0;
    buf[i++] = (uint8_t)((fin ? 0x80 : 0x00) | opcode);
    uint8_t maskbit = (key != NULL) ? 0x80 : 0x00;
    if (n <= 125) {
        buf[i++] = (uint8_t)(maskbit | (uint8_t)n);
    } else if (n <= 0xffffu) {
        buf[i++] = (uint8_t)(maskbit | 126u);
        buf[i++] = (uint8_t)((n >> 8) & 0xff);
        buf[i++] = (uint8_t)(n & 0xff);
    } else {
        buf[i++] = (uint8_t)(maskbit | 127u);
        for (int k = 7; k >= 0; k--) {
            buf[i++] = (uint8_t)((uint64_t)n >> (k * 8)) & 0xff;
        }
    }
    if (key != NULL) {
        memcpy(buf + i, key, 4);
        i += 4;
    }
    for (size_t j = 0; j < n; j++) {
        buf[i + j] = (key != NULL) ? (uint8_t)(payload[j] ^ key[j & 3]) : payload[j];
    }
    return i + n;
}

/* A header declaring `declared` payload bytes, with NO payload following
 * it. Used by the declared-length bracket: the point is that the
 * declaration alone must be enough to break the connection, before a
 * single payload byte has been buffered on its behalf. */
static size_t build_ws_header_only(uint8_t *buf, uint8_t opcode, int fin, const uint8_t *key,
                                   uint64_t declared) {
    size_t i = 0;
    buf[i++] = (uint8_t)((fin ? 0x80 : 0x00) | opcode);
    uint8_t maskbit = (key != NULL) ? 0x80 : 0x00;
    if (declared <= 125) {
        buf[i++] = (uint8_t)(maskbit | (uint8_t)declared);
    } else if (declared <= 0xffffu) {
        buf[i++] = (uint8_t)(maskbit | 126u);
        buf[i++] = (uint8_t)((declared >> 8) & 0xff);
        buf[i++] = (uint8_t)(declared & 0xff);
    } else {
        buf[i++] = (uint8_t)(maskbit | 127u);
        for (int k = 7; k >= 0; k--) {
            buf[i++] = (uint8_t)(((declared >> (k * 8)) & 0xff));
        }
    }
    if (key != NULL) {
        memcpy(buf + i, key, 4);
        i += 4;
    }
    return i;
}

static const uint8_t k_client_key[4] = {0xA1, 0xB2, 0xC3, 0xD4};

/* ================================================================== */
/* 1. THE ASSERTION THAT WOULD HAVE CAUGHT THE ORIGINAL DEFECT         */
/* ================================================================== */

/* The first byte of the data path, read raw off the socket exactly as a
 * passive observer on the path would capture it.
 *
 *   TLS_RECORD -> 0x17, ContentType application_data (RFC 8446 s5.1)
 *   WS_SERVER  -> 0x82, FIN | opcode 0x2 binary      (RFC 6455 s5.2)
 *   WS_CLIENT  -> 0x82, likewise
 *
 * Nothing else in this test is derived from the implementation. A conn
 * that emitted a TLS record header inside a WebSocket frame would fail
 * on line one of its own case, and so would a conn that emitted a
 * WebSocket header on the direct path.
 *
 * The payload is 290 bytes on purpose: 290 == 0x0122 straddles the byte
 * boundary, so the two length bytes pin their ORDER as well as their
 * values in every mode at once (a 10-byte payload would pass against a
 * little-endian writer). 290 is also above 125, which selects the 126 +
 * u16 extended form on the WebSocket side -- the form every real Cloak
 * frame uses, since max_on_wire_size is 16401. */
static void test_first_wire_byte_is_0x17_on_the_direct_path(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) return;

    ws_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_TLS_RECORD, MAX_FRAME_LEN), 0);

    uint8_t payload[290];
    for (int i = 0; i < 290; i++) payload[i] = (uint8_t)(i & 0xff);
    ASSERT_EQ_INT(cloak_conn_send(&c, payload, sizeof(payload)), 0);

    uint8_t wire[512];
    size_t got = drain_peer(r, fds[1], wire, 295);
    ASSERT_EQ_INT((long long)got, 295); /* 5-byte record header + 290 body */
    if (got == 295) {
        ASSERT_EQ_INT(wire[0], 0x17); /* application_data -- NOT 0x82 */
        ASSERT_EQ_INT(wire[1], 0x03);
        ASSERT_EQ_INT(wire[2], 0x03);
        ASSERT_EQ_INT(wire[3], 0x01);
        ASSERT_EQ_INT(wire[4], 0x22);
        ASSERT_MEM_EQ(wire + 5, payload, 290);
    }

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

static void test_first_wire_byte_is_0x82_for_a_ws_server(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) return;

    ws_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_SERVER, MAX_FRAME_LEN), 0);

    uint8_t payload[290];
    for (int i = 0; i < 290; i++) payload[i] = (uint8_t)(i & 0xff);
    ASSERT_EQ_INT(cloak_conn_send(&c, payload, sizeof(payload)), 0);

    /* 2 fixed bytes + 2 extended-length bytes + 290 payload. NO mask key:
     * RFC 6455 s5.1 -- "A server MUST NOT mask any frames" -- and gorilla
     * rejects a masked server frame outright ("bad MASK"). */
    uint8_t wire[512];
    size_t got = drain_peer(r, fds[1], wire, 294);
    ASSERT_EQ_INT((long long)got, 294);
    if (got == 294) {
        ASSERT_EQ_INT(wire[0], 0x82); /* FIN | binary -- NOT 0x17 */
        ASSERT_EQ_INT(wire[1], 0x7E); /* MASK clear | 126 extended-length form */
        ASSERT_EQ_INT(wire[2], 0x01); /* 290 >> 8 */
        ASSERT_EQ_INT(wire[3], 0x22); /* 290 & 0xff */
        ASSERT_MEM_EQ(wire + 4, payload, 290); /* unmasked: plaintext on the wire */
    }

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

static void test_first_wire_byte_is_0x82_for_a_ws_client(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) return;

    ws_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_CLIENT, MAX_FRAME_LEN), 0);

    uint8_t payload[290];
    for (int i = 0; i < 290; i++) payload[i] = (uint8_t)(i & 0xff);
    ASSERT_EQ_INT(cloak_conn_send(&c, payload, sizeof(payload)), 0);

    /* 2 + 2 + 4 mask-key bytes + 290 payload. */
    uint8_t wire[512];
    size_t got = drain_peer(r, fds[1], wire, 298);
    ASSERT_EQ_INT((long long)got, 298);
    if (got == 298) {
        ASSERT_EQ_INT(wire[0], 0x82); /* FIN | binary */
        ASSERT_EQ_INT(wire[1], 0xFE); /* MASK set | 126 extended-length form */
        ASSERT_EQ_INT(wire[2], 0x01);
        ASSERT_EQ_INT(wire[3], 0x22);
        /* wire[4..7] is the mask key. The payload must be MASKED, i.e.
         * not equal to the plaintext -- a client that set the MASK bit
         * and then forgot to apply the key produces a frame gorilla
         * decodes into garbage, and the round-trip test against our own
         * other end would still pass because it would also skip the
         * unmasking. */
        ASSERT_MEM_NE(wire + 8, payload, 290);
        uint8_t unmasked[290];
        memcpy(unmasked, wire + 8, 290);
        for (size_t i = 0; i < 290; i++) unmasked[i] ^= wire[4 + (i & 3)];
        ASSERT_MEM_EQ(unmasked, payload, 290);
    }

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

/* The 0..125 inline-length form, which is the branch the "(0 or 2)" in
 * the envelope table turns on. Checked on the wire so that an
 * implementation that always emitted the 126 form -- legal per RFC 6455,
 * rejected by nothing, and four bytes wrong in the envelope arithmetic --
 * is visible here rather than only at max_frame_len under load. */
static void test_short_payload_uses_the_inline_length_form(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) return;

    ws_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_SERVER, MAX_FRAME_LEN), 0);

    uint8_t payload[100];
    for (int i = 0; i < 100; i++) payload[i] = (uint8_t)(0x30 + (i & 0x0f));
    ASSERT_EQ_INT(cloak_conn_send(&c, payload, sizeof(payload)), 0);

    uint8_t wire[256];
    size_t got = drain_peer(r, fds[1], wire, 102);
    ASSERT_EQ_INT((long long)got, 102); /* 2 header bytes only, no extended length */
    if (got == 102) {
        ASSERT_EQ_INT(wire[0], 0x82);
        ASSERT_EQ_INT(wire[1], 0x64); /* 100 inline, MASK clear */
        ASSERT_MEM_EQ(wire + 2, payload, 100);
    }

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

/* ================================================================== */
/* 2. THE ZERO VALUE IS INVALID                                        */
/* ================================================================== */

/* The one mechanical defence in this task that does not depend on
 * anybody remembering anything. A mode passed only as a parameter has no
 * zero value unless a caller types one; a mode that is a FIELD of the
 * construction config has one on every memset, which is how C structs
 * are initialised everywhere in this tree.
 *
 * The named error is asserted, not merely a non-zero return: a config
 * that is invalid for some OTHER reason also fails construction, and a
 * test that accepted any failure would pass against an implementation
 * that never looked at framing at all. */
static void test_zeroed_config_fails_with_the_named_error(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) return;

    ws_harness_t h;
    memset(&h, 0, sizeof(h));

    /* (a) An entirely zeroed config. Every other field is invalid too --
     * max_frame_len 0, send_queue_cap 0 -- so this also pins the ORDER of
     * the checks: framing is validated FIRST, so the diagnosis a caller
     * gets names the field they actually forgot. */
    cloak_conn_t c;
    cloak_conn_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT_EQ_INT(cloak_conn_init_cfg(&c, &cfg), CLOAK_CONN_ERR_INVALID_FRAMING);

    /* (b) A config that is otherwise perfectly valid and whose ONLY
     * defect is the un-set framing field. This is the realistic shape of
     * the accident: somebody copies a working config and adds a field. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.fd = fds[0];
    cfg.reactor = r;
    cfg.max_frame_len = MAX_FRAME_LEN;
    cfg.send_queue_cap = SEND_QUEUE_CAP;
    cfg.on_envelope = on_envelope;
    cfg.on_envelope_userdata = &h;
    cfg.on_closed = on_closed;
    cfg.on_closed_userdata = &h;
    ASSERT_EQ_INT(cloak_conn_init_cfg(&c, &cfg), CLOAK_CONN_ERR_INVALID_FRAMING);

    /* (c) A value outside the enum entirely -- an uninitialised byte
     * pattern, a truncated read, a future mode that never landed. */
    cfg.framing = (cloak_conn_framing_t)99;
    ASSERT_EQ_INT(cloak_conn_init_cfg(&c, &cfg), CLOAK_CONN_ERR_INVALID_FRAMING);

    /* (d) And the same config with a real mode succeeds -- otherwise (b)
     * would pass against an init that rejects everything. */
    cfg.framing = CLOAK_CONN_FRAMING_WS_CLIENT;
    ASSERT_EQ_INT(cloak_conn_init_cfg(&c, &cfg), 0);
    cloak_conn_destroy(&c);

    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

/* The same guard at the public entry point, plus the promise that
 * cloak_session_add_conn -- whose signature and call sites are
 * deliberately untouched -- still means TLS_RECORD and nothing else. The
 * stored mode is read straight out of the pool, because "it still
 * compiles" is not evidence about which bytes go on the wire. */
static void test_session_add_conn_framing(void) {
    int fds_a[2], fds_b[2], fds_c[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds_a), 0);
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds_b), 0);
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds_c), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) return;

    cloak_session_config_t scfg;
    memset(&scfg, 0, sizeof(scfg));
    scfg.obfuscator.method = CLOAK_AEAD_AES_256_GCM;
    cloak_random_bytes(scfg.obfuscator.session_key, sizeof(scfg.obfuscator.session_key));
    scfg.ordering = CLOAK_SESSION_ORDERING_ORDERED;
    scfg.max_on_wire_size = 2048;
    scfg.stream_recv_capacity = 65536;
    scfg.stream_max_pending_frames = 64;
    scfg.conn_send_queue_cap = 65536;
    scfg.inactivity_timeout_ms = 60000;

    cloak_session_t sesh;
    ASSERT_EQ_INT(cloak_session_init(&sesh, 1, r, &scfg), 0);

    /* The zero value, arriving through the public API. */
    ASSERT_EQ_INT(cloak_session_add_conn_framed(&sesh, fds_a[0], CLOAK_CONN_FRAMING_INVALID),
                  CLOAK_CONN_ERR_INVALID_FRAMING);
    ASSERT_EQ_INT((long long)cloak_switchboard_conn_count(&sesh.sb), 0);

    /* The untouched direct-path entry point still means TLS_RECORD. */
    ASSERT_EQ_INT(cloak_session_add_conn(&sesh, fds_b[0]), 0);
    ASSERT_EQ_INT((long long)cloak_switchboard_conn_count(&sesh.sb), 1);
    ASSERT_EQ_INT(sesh.sb.conns[0]->framing, CLOAK_CONN_FRAMING_TLS_RECORD);

    ASSERT_EQ_INT(cloak_session_add_conn_framed(&sesh, fds_c[0], CLOAK_CONN_FRAMING_WS_CLIENT), 0);
    ASSERT_EQ_INT((long long)cloak_switchboard_conn_count(&sesh.sb), 2);
    ASSERT_EQ_INT(sesh.sb.conns[1]->framing, CLOAK_CONN_FRAMING_WS_CLIENT);

    cloak_session_destroy(&sesh); /* closes fds_b[0] and fds_c[0] */
    cloak_reactor_destroy(r);
    close(fds_a[0]); /* the rejected add never took ownership */
    close(fds_a[1]);
    close(fds_b[1]);
    close(fds_c[1]);
}

/* ================================================================== */
/* 3. THE MASK BIT, IN BOTH DIRECTIONS                                 */
/* ================================================================== */

/* RFC 6455 s5.1: a client MUST mask every frame it sends and a server
 * MUST NOT mask any. Each side rejects the other's mistake -- gorilla
 * with "bad MASK", every browser likewise -- so getting this backwards
 * means the CDN path never carries a byte, and getting it half right
 * (bit set, key not applied) means it carries garbage.
 *
 * Checked across several payload lengths so that neither answer can come
 * from a single hard-coded header. */
static void test_ws_server_never_sets_the_mask_bit(void) {
    const size_t sizes[] = {1, 125, 126, 290};
    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        int fds[2];
        ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
        cloak_reactor_t *r = cloak_reactor_create();
        ASSERT_TRUE(r != NULL);
        if (r == NULL) return;

        ws_harness_t h;
        memset(&h, 0, sizeof(h));
        cloak_conn_t c;
        ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_SERVER, MAX_FRAME_LEN), 0);

        uint8_t payload[300];
        memset(payload, 0x5a, sizeof(payload));
        ASSERT_EQ_INT(cloak_conn_send(&c, payload, sizes[s]), 0);

        uint8_t wire[8];
        size_t got = drain_peer(r, fds[1], wire, 2);
        ASSERT_EQ_INT((long long)got, 2);
        if (got == 2) {
            ASSERT_EQ_INT(wire[0], 0x82);
            ASSERT_EQ_INT(wire[1] & 0x80, 0x00); /* MASK clear, always */
        }

        cloak_conn_destroy(&c);
        cloak_reactor_destroy(r);
        close(fds[0]);
        close(fds[1]);
    }
}

/* The client half, plus the property an author is most tempted to skip:
 * the mask key must be FRESH PER FRAME. A hard-coded key pair passed an
 * entire suite one branch ago in this project, and a round-trip test
 * cannot see it -- our own unmasking works just as well against a
 * constant. Two consecutive frames with identical keys fail here.
 *
 * (Two 32-bit draws from a CSPRNG collide with probability 2^-32; this
 * is not a flake worth engineering around.) */
static void test_ws_client_always_masks_with_a_fresh_key(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) return;

    ws_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_CLIENT, MAX_FRAME_LEN), 0);

    uint8_t payload[64];
    for (int i = 0; i < 64; i++) payload[i] = (uint8_t)i;
    ASSERT_EQ_INT(cloak_conn_send(&c, payload, sizeof(payload)), 0);
    ASSERT_EQ_INT(cloak_conn_send(&c, payload, sizeof(payload)), 0);

    uint8_t wire[2 * (2 + 4 + 64)];
    size_t got = drain_peer(r, fds[1], wire, sizeof(wire));
    ASSERT_EQ_INT((long long)got, (long long)sizeof(wire));
    if (got == sizeof(wire)) {
        const uint8_t *f1 = wire;
        const uint8_t *f2 = wire + 70;
        ASSERT_EQ_INT(f1[0], 0x82);
        ASSERT_EQ_INT(f1[1], 0xC0); /* MASK set | 64 inline */
        ASSERT_EQ_INT(f2[0], 0x82);
        ASSERT_EQ_INT(f2[1], 0xC0);
        ASSERT_MEM_NE(f1 + 2, f2 + 2, 4); /* a fresh key per frame */
        uint8_t u1[64], u2[64];
        for (size_t i = 0; i < 64; i++) {
            u1[i] = (uint8_t)(f1[6 + i] ^ f1[2 + (i & 3)]);
            u2[i] = (uint8_t)(f2[6 + i] ^ f2[2 + (i & 3)]);
        }
        ASSERT_MEM_EQ(u1, payload, 64);
        ASSERT_MEM_EQ(u2, payload, 64);
    }

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

/* The running mask position, which cloak/ws_frame.h singles out as "the
 * one thing implementations of this reliably get wrong": a send path that
 * hands its payload to the masker in chunks and restarts the position at
 * 0 for each chunk produces a frame whose first chunk decodes and whose
 * every later chunk is garbage. A whole-buffer test cannot see it.
 *
 * So this frame is deliberately LARGER than the send path's internal
 * masking chunk, and it is unmasked here by the RFC's own formula
 * key[i & 3] over the whole payload -- an absolute position, not a
 * per-chunk one. */
static void test_client_mask_position_runs_across_chunk_boundaries(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) return;

    ws_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_CLIENT, 16640), 0);

    static uint8_t payload[9001];
    for (size_t i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)((i * 31u + 7u) & 0xff);
    ASSERT_EQ_INT(cloak_conn_send(&c, payload, sizeof(payload)), 0);

    static uint8_t wire[8 + 9001];
    size_t got = drain_peer(r, fds[1], wire, sizeof(wire));
    ASSERT_EQ_INT((long long)got, (long long)sizeof(wire));
    if (got == sizeof(wire)) {
        ASSERT_EQ_INT(wire[0], 0x82);
        ASSERT_EQ_INT(wire[1], 0xFE);
        ASSERT_EQ_INT(wire[2], (9001 >> 8) & 0xff);
        ASSERT_EQ_INT(wire[3], 9001 & 0xff);
        static uint8_t unmasked[9001];
        for (size_t i = 0; i < sizeof(payload); i++) {
            unmasked[i] = (uint8_t)(wire[8 + i] ^ wire[4 + (i & 3)]);
        }
        ASSERT_MEM_EQ(unmasked, payload, sizeof(payload));
    }

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

/* ================================================================== */
/* 4. max_envelope_len, AS LITERALS, AND A MEASURED BRACKET            */
/* ================================================================== */

/* Get this wrong by four bytes and it fails only at the maximum frame
 * size -- under load, in production, never in a unit test. So the three
 * values are written as literals computed by hand from RFC 6455 s5.2 and
 * from cloak/conn.h, not from the expressions the implementation uses.
 *
 *   max_frame_len 16640 (CLOAK_CONN_MAX_FRAME_LEN, > 125 so the 126+u16
 *   extended-length form applies):
 *     TLS_RECORD  5                 + 16640 = 16645
 *     WS_SERVER   2 + 2             + 16640 = 16644
 *     WS_CLIENT   2 + 2 + 4         + 16640 = 16648   <- largest of the three
 *
 *   max_frame_len 100 (<= 125, so NO extended-length bytes -- the
 *   "(0 or 2)" branch of the table):
 *     TLS_RECORD  5                 + 100   = 105
 *     WS_SERVER   2                 + 100   = 102
 *     WS_CLIENT   2 + 4             + 100   = 106
 *
 * The client envelope being LARGER than the TLS one is the specific
 * arithmetic an implementation that reused the TLS sizing would get
 * wrong, and it is checked explicitly below.
 *
 * AND THE RECEIVE ENVELOPE, WHICH IS NOT THE SAME NUMBER. We mask iff we
 * are the client; our peer masks iff we are the server, so the four mask
 * bytes land on the OPPOSITE side inbound and the two WS modes simply
 * trade values:
 *
 *   max_frame_len 16640            send      receive
 *     TLS_RECORD   5 + n           16645     16645   (symmetric)
 *     WS_SERVER    2+2 [+4] + n    16644     16648   <- receive is LARGER
 *     WS_CLIENT    2+2 [+4] + n    16648     16644   <- receive is SMALLER
 *
 * That asymmetry is stated here as a fact rather than left to be inferred
 * from a stall. It is the whole reason max_recv_envelope_len exists: an
 * earlier draft sized the receive buffer off max_envelope_len, which
 * leaves a WS_SERVER conn four bytes short inbound -- not an overflow but
 * a DEADLOCK, since a maximum-size frame never completes, so nothing is
 * consumed, so room never appears.
 *
 * THE BRACKET ON max_recv_envelope_len IS TWO-SIDED, and only one side of
 * it can be behavioural. Too SMALL is caught by the stall:
 * test_recv_accumulator_holds_a_whole_inbound_frame at max_frame_len == 1
 * is the case where recv_acc (two envelopes wide) stops hiding a -4, and
 * it is the ONLY frame size that could find it -- the reachability
 * condition is 2*(send envelope) < (receive envelope), i.e. n + e < 2.
 * Too LARGE is pure over-allocation: it has no behavioural consequence at
 * any frame size, so no test can bracket it from above and the literals
 * below are the only thing that can. Hence the second assertion per case. */
static void test_max_envelope_len_per_mode(void) {
    struct {
        cloak_conn_framing_t framing;
        size_t max_frame_len;
        size_t expect_send;
        size_t expect_recv;
    } cases[] = {
        {CLOAK_CONN_FRAMING_TLS_RECORD, 16640, 16645, 16645},
        {CLOAK_CONN_FRAMING_WS_SERVER, 16640, 16644, 16648},
        {CLOAK_CONN_FRAMING_WS_CLIENT, 16640, 16648, 16644},
        {CLOAK_CONN_FRAMING_TLS_RECORD, 100, 105, 105},
        {CLOAK_CONN_FRAMING_WS_SERVER, 100, 102, 106},
        {CLOAK_CONN_FRAMING_WS_CLIENT, 100, 106, 102},
        /* 125/126 is the exact boundary of the inline length form. */
        {CLOAK_CONN_FRAMING_WS_SERVER, 125, 127, 131},
        {CLOAK_CONN_FRAMING_WS_SERVER, 126, 130, 134},
        {CLOAK_CONN_FRAMING_WS_CLIENT, 125, 131, 127},
        {CLOAK_CONN_FRAMING_WS_CLIENT, 126, 134, 130},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int fds[2];
        ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
        cloak_reactor_t *r = cloak_reactor_create();
        ASSERT_TRUE(r != NULL);
        if (r == NULL) return;
        ws_harness_t h;
        memset(&h, 0, sizeof(h));
        cloak_conn_t c;
        ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, cases[i].framing, cases[i].max_frame_len), 0);
        ASSERT_EQ_INT((long long)c.max_envelope_len, (long long)cases[i].expect_send);
        ASSERT_EQ_INT((long long)c.max_recv_envelope_len, (long long)cases[i].expect_recv);
        cloak_conn_destroy(&c);
        cloak_reactor_destroy(r);
        close(fds[0]);
        close(fds[1]);
    }
    /* Stated as its own assertion because it is the surprising one. */
    ASSERT_TRUE(16648 > 16645);
    /* And the surprising one about the receive side: a WS_SERVER conn's
     * inbound envelope is bigger than its outbound one, which is the
     * direction the deadlock came from. */
    ASSERT_TRUE(16648 > 16644);
}

/* THE MEASURED BRACKET, on the send side, at the real maximum: a frame of
 * exactly max_frame_len is accepted and one of max_frame_len + 1 is
 * refused -- in every mode -- and the accepted one puts EXACTLY
 * max_envelope_len bytes on the wire. That last count is what turns the
 * table above from an assertion about a struct field into an assertion
 * about the network: an off-by-four in the envelope arithmetic that the
 * struct field happened to agree with still fails here. */
static void test_send_bracket_at_max_frame_len(void) {
    struct {
        cloak_conn_framing_t framing;
        size_t on_wire;
    } cases[] = {
        {CLOAK_CONN_FRAMING_TLS_RECORD, 16645},
        {CLOAK_CONN_FRAMING_WS_SERVER, 16644},
        {CLOAK_CONN_FRAMING_WS_CLIENT, 16648},
    };
    static uint8_t payload[16641];
    for (size_t i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)(i & 0xff);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        /* --- this size succeeds --- */
        int fds[2];
        ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
        cloak_reactor_t *r = cloak_reactor_create();
        ASSERT_TRUE(r != NULL);
        if (r == NULL) return;
        ws_harness_t h;
        memset(&h, 0, sizeof(h));
        cloak_conn_t c;
        ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, cases[i].framing, 16640), 0);
        ASSERT_EQ_INT(cloak_conn_send(&c, payload, 16640), 0);
        ASSERT_EQ_INT(h.closed_count, 0);

        static uint8_t wire[16648];
        size_t got = drain_peer(r, fds[1], wire, cases[i].on_wire);
        ASSERT_EQ_INT((long long)got, (long long)cases[i].on_wire);
        /* And not one byte more: the envelope is exactly this long. */
        uint8_t extra[8];
        ssize_t n = read(fds[1], extra, sizeof(extra));
        ASSERT_TRUE(n < 0);

        cloak_conn_destroy(&c);
        cloak_reactor_destroy(r);
        close(fds[0]);
        close(fds[1]);

        /* --- and this size is refused --- */
        ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
        r = cloak_reactor_create();
        ASSERT_TRUE(r != NULL);
        if (r == NULL) return;
        memset(&h, 0, sizeof(h));
        ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, cases[i].framing, 16640), 0);
        ASSERT_EQ_INT(cloak_conn_send(&c, payload, 16641), -1);
        ASSERT_EQ_INT(h.closed_count, 1); /* refusal is fatal to the conn, as on the direct path */
        cloak_conn_destroy(&c);
        cloak_reactor_destroy(r);
        close(fds[0]);
        close(fds[1]);
    }
}

/* ================================================================== */
/* 5. THE DECLARED-LENGTH BOUND -- THE TRAP ws_frame.h HANDS US        */
/* ================================================================== */

/* cloak_ws_frame_parse_header reports payload_len exactly as declared and
 * bounds it NOWHERE: a header declaring 0x7FFFFFFFFFFFFFFF parses
 * perfectly, and libcloak-mux/tests/test_ws_frame.c pins that on purpose.
 * The three places that enforce CLOAK_CONN_MAX_FRAME_LEN before this task
 * -- cloak_conn_init, cloak_session_init, cloak_switchboard_init -- are
 * all on the direct TLS-record path and never see a byte that arrived
 * through a WebSocket frame.
 *
 * This module is the first layer on the CDN path that owns a buffer, so
 * the bound is its debt. These tests are the proof it was paid, and the
 * bracket is measured on both sides rather than claimed. */
static void test_declared_length_bracket_is_max_frame_len(void) {
    /* Accepted: a frame declaring EXACTLY max_frame_len, with the payload
     * actually present. */
    {
        int fds[2];
        ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
        cloak_reactor_t *r = cloak_reactor_create();
        ASSERT_TRUE(r != NULL);
        if (r == NULL) return;
        ws_harness_t h;
        memset(&h, 0, sizeof(h));
        cloak_conn_t c;
        ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_SERVER, 300), 0);

        uint8_t payload[300];
        for (int i = 0; i < 300; i++) payload[i] = (uint8_t)(i & 0xff);
        static uint8_t frame[8 + 300];
        size_t flen = build_ws_frame(frame, 0x2, 1, k_client_key, payload, 300);
        ASSERT_EQ_INT((long long)flen, 308);
        ASSERT_EQ_INT((long long)write(fds[1], frame, flen), (long long)flen);
        PUMP_UNTIL(r, h.received_count > 0 || h.closed_count > 0);
        ASSERT_EQ_INT(h.received_count, 1);
        ASSERT_EQ_INT(h.closed_count, 0);
        if (h.received_count == 1) {
            ASSERT_EQ_INT((long long)h.received_len[0], 300);
            ASSERT_MEM_EQ(h.received[0], payload, 300);
        }
        cloak_conn_destroy(&c);
        cloak_reactor_destroy(r);
        close(fds[0]);
        close(fds[1]);
    }

    /* Refused: max_frame_len + 1, DECLARED ONLY. No payload follows, so
     * nothing but the declaration itself can have caused the rejection --
     * an implementation that waited for the bytes to arrive before
     * checking would hang here instead of closing, and would in the
     * meantime be sizing buffers off a hostile number. */
    {
        int fds[2];
        ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
        cloak_reactor_t *r = cloak_reactor_create();
        ASSERT_TRUE(r != NULL);
        if (r == NULL) return;
        ws_harness_t h;
        memset(&h, 0, sizeof(h));
        cloak_conn_t c;
        ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_SERVER, 300), 0);

        uint8_t hdr[16];
        size_t hlen = build_ws_header_only(hdr, 0x2, 1, k_client_key, 301);
        ASSERT_EQ_INT((long long)write(fds[1], hdr, hlen), (long long)hlen);
        PUMP_UNTIL(r, h.closed_count > 0);
        ASSERT_EQ_INT(h.closed_count, 1);
        ASSERT_EQ_INT(h.received_count, 0);
        cloak_conn_destroy(&c);
        cloak_reactor_destroy(r);
        close(fds[0]);
        close(fds[1]);
    }
}

/* The declaration ws_frame.h names by value: 0x7FFFFFFFFFFFFFFF. It has
 * its high bit clear, so RFC 6455 s5.2 admits it and the codec parses it
 * without complaint. Fourteen bytes of header, no payload, and the
 * connection must be gone. */
static void test_absurd_declared_length_is_refused(void) {
    const uint64_t declarations[] = {
        301u,                      /* just over */
        65535u,                    /* the 126-form ceiling */
        4294967296ull,             /* 4 GiB -- the 127 form */
        0x7FFFFFFFFFFFFFFFull      /* the value ws_frame.h names */
    };
    for (size_t i = 0; i < sizeof(declarations) / sizeof(declarations[0]); i++) {
        int fds[2];
        ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
        cloak_reactor_t *r = cloak_reactor_create();
        ASSERT_TRUE(r != NULL);
        if (r == NULL) return;
        ws_harness_t h;
        memset(&h, 0, sizeof(h));
        cloak_conn_t c;
        ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_SERVER, 300), 0);

        uint8_t hdr[16];
        size_t hlen = build_ws_header_only(hdr, 0x2, 1, k_client_key, declarations[i]);
        ASSERT_EQ_INT((long long)write(fds[1], hdr, hlen), (long long)hlen);
        PUMP_UNTIL(r, h.closed_count > 0);
        ASSERT_EQ_INT(h.closed_count, 1);
        ASSERT_EQ_INT(h.received_count, 0);

        cloak_conn_destroy(&c);
        cloak_reactor_destroy(r);
        close(fds[0]);
        close(fds[1]);
    }
}

/* A per-frame bound alone is not enough. Three fragments of 200 bytes
 * each individually satisfy max_frame_len == 300 and together declare
 * 600, so an implementation that checks only the frame in hand
 * overflows its reassembly buffer -- the classic shape of this bug. The
 * bracket: 300 total across fragments is delivered, 301 is refused. */
static void test_reassembled_length_is_bounded_too(void) {
    struct { size_t a; size_t b; int expect_ok; } cases[] = {
        {150, 150, 1}, /* 300 total: exactly the bound */
        {150, 151, 0}, /* 301 total: one over */
        {200, 200, 0}, /* each fragment legal alone, 400 together */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int fds[2];
        ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
        cloak_reactor_t *r = cloak_reactor_create();
        ASSERT_TRUE(r != NULL);
        if (r == NULL) return;
        ws_harness_t h;
        memset(&h, 0, sizeof(h));
        cloak_conn_t c;
        ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_SERVER, 300), 0);

        uint8_t payload[400];
        for (int k = 0; k < 400; k++) payload[k] = (uint8_t)(0x11 + (k & 0x3f));
        static uint8_t wire[1024];
        size_t n = build_ws_frame(wire, 0x2, 0, k_client_key, payload, cases[i].a);
        n += build_ws_frame(wire + n, 0x0, 1, k_client_key, payload + cases[i].a, cases[i].b);
        ASSERT_EQ_INT((long long)write(fds[1], wire, n), (long long)n);
        PUMP_UNTIL(r, h.received_count > 0 || h.closed_count > 0);

        if (cases[i].expect_ok) {
            ASSERT_EQ_INT(h.received_count, 1);
            ASSERT_EQ_INT(h.closed_count, 0);
            if (h.received_count == 1) {
                ASSERT_EQ_INT((long long)h.received_len[0], (long long)(cases[i].a + cases[i].b));
                ASSERT_MEM_EQ(h.received[0], payload, cases[i].a + cases[i].b);
            }
        } else {
            ASSERT_EQ_INT(h.received_count, 0);
            ASSERT_EQ_INT(h.closed_count, 1);
        }

        cloak_conn_destroy(&c);
        cloak_reactor_destroy(r);
        close(fds[0]);
        close(fds[1]);
    }
}

/* ================================================================== */
/* 6. RECEIVE-SIDE CONTINUATION REASSEMBLY                             */
/* ================================================================== */

/* Go never SENDS a fragmented message -- gorilla's WriteMessage emits one
 * frame per message -- so neither end of a C-to-C test would ever produce
 * this sequence, and it has to be synthesised by hand. It is nonetheless
 * load-bearing: a CDN is entitled to re-fragment a message it forwards,
 * and gorilla always accepts fragments, so a Cloak conn that did not
 * reassemble would work perfectly in a lab and fail behind Cloudflare.
 *
 * One logical message, three frames: BINARY/FIN=0, CONTINUATION/FIN=0,
 * CONTINUATION/FIN=1. It must arrive as exactly ONE mux frame -- three
 * envelopes would be three ruined deobfuscations, since one WebSocket
 * message is exactly one Cloak frame. */
static void test_continuation_frames_reassemble_into_one_message(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) return;
    ws_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_SERVER, MAX_FRAME_LEN), 0);

    const uint8_t msg[] = "the-quick-brown-fox-jumps-over-the-lazy-dog";
    const size_t msg_len = sizeof(msg) - 1;
    const size_t a = 10, b = 13, cz = msg_len - 10 - 13;

    static uint8_t wire[512];
    size_t n = build_ws_frame(wire, 0x2, 0, k_client_key, msg, a);
    n += build_ws_frame(wire + n, 0x0, 0, k_client_key, msg + a, b);
    n += build_ws_frame(wire + n, 0x0, 1, k_client_key, msg + a + b, cz);
    ASSERT_EQ_INT((long long)write(fds[1], wire, n), (long long)n);

    PUMP_UNTIL(r, h.received_count > 0 || h.closed_count > 0);
    ASSERT_EQ_INT(h.received_count, 1);
    ASSERT_EQ_INT(h.closed_count, 0);
    if (h.received_count == 1) {
        ASSERT_EQ_INT((long long)h.received_len[0], (long long)msg_len);
        ASSERT_MEM_EQ(h.received[0], msg, msg_len);
    }

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

/* The same three frames delivered ONE BYTE PER REACTOR TURN. Nothing may
 * block the reactor, and a partial read can land mid-header, mid
 * extended length, mid mask key or mid payload; every one of those split
 * points is forced here. Nothing may be dispatched before the very last
 * byte -- a reassembler that flushed on any earlier boundary fires early
 * and is caught inside the loop, not after it. */
static void test_continuation_reassembly_survives_byte_at_a_time_delivery(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) return;
    ws_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_SERVER, MAX_FRAME_LEN), 0);

    uint8_t msg[200];
    for (int i = 0; i < 200; i++) msg[i] = (uint8_t)(0x80 ^ (i & 0xff));
    static uint8_t wire[512];
    size_t n = build_ws_frame(wire, 0x2, 0, k_client_key, msg, 130);
    n += build_ws_frame(wire + n, 0x0, 0, k_client_key, msg + 130, 1);
    n += build_ws_frame(wire + n, 0x0, 1, k_client_key, msg + 131, 69);

    for (size_t off = 0; off < n; off++) {
        ASSERT_EQ_INT((long long)write(fds[1], wire + off, 1), 1);
        pump(r);
        if (off + 1 < n) {
            ASSERT_EQ_INT(h.received_count, 0);
        }
    }
    PUMP_UNTIL(r, h.received_count > 0 || h.closed_count > 0);
    ASSERT_EQ_INT(h.received_count, 1);
    ASSERT_EQ_INT(h.closed_count, 0);
    if (h.received_count == 1) {
        ASSERT_EQ_INT((long long)h.received_len[0], 200);
        ASSERT_MEM_EQ(h.received[0], msg, 200);
    }

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

/* A CONTINUATION arriving with no message in progress is a protocol
 * violation (gorilla: "continuation after final frame"). Without this,
 * "reassembly" could be implemented as "append everything, flush on
 * FIN", which happens to pass the two tests above. */
static void test_orphan_continuation_is_rejected(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) return;
    ws_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_SERVER, MAX_FRAME_LEN), 0);

    const uint8_t body[] = "orphan";
    uint8_t wire[64];
    size_t n = build_ws_frame(wire, 0x0, 1, k_client_key, body, sizeof(body) - 1);
    ASSERT_EQ_INT((long long)write(fds[1], wire, n), (long long)n);
    PUMP_UNTIL(r, h.closed_count > 0);
    ASSERT_EQ_INT(h.closed_count, 1);
    ASSERT_EQ_INT(h.received_count, 0);

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

/* The MIRROR IMAGE of the orphan CONTINUATION, and the more dangerous of
 * the pair: a NEW DATA FRAME arriving while a fragmented message is still
 * in progress (RFC 6455 s5.4 -- "the fragments of one message MUST NOT be
 * interleaved between the fragments of another message"). gorilla refuses
 * it too.
 *
 * What makes this worth its own test rather than a symmetry argument is
 * the FAILURE MODE IF THE GUARD IS MISSING, which is not a rejected
 * connection. Without it, the second frame's payload is appended to the
 * first message's buffer and, because it carries FIN, the whole
 * concatenation is handed to the deobfuscator AS ONE MUX FRAME: a corrupt
 * frame delivered silently, reported downstream as a decryption failure
 * or a corrupt peer, with nothing anywhere naming the real cause.
 *
 * And it is not a hostile-only shape. A CDN that re-fragments what it
 * relays -- listed in the scouting report as EXPECTED behaviour on this
 * path, not an attack -- is exactly the peer that rewrites frame
 * boundaries, so this guard runs against ordinary traffic.
 *
 * Both non-CONTINUATION data opcodes are driven, since the guard is
 * written as "anything that is not a CONTINUATION" and a version that
 * only special-cased BINARY would pass a BINARY-only test. */
static void test_new_data_frame_mid_fragmentation_is_rejected(void) {
    const uint8_t interrupting_opcodes[] = {0x2 /* BINARY */, 0x1 /* TEXT */};
    for (size_t i = 0; i < sizeof(interrupting_opcodes); i++) {
        int fds[2];
        ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
        cloak_reactor_t *r = cloak_reactor_create();
        ASSERT_TRUE(r != NULL);
        if (r == NULL) return;
        ws_harness_t h;
        memset(&h, 0, sizeof(h));
        cloak_conn_t c;
        ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_SERVER, MAX_FRAME_LEN), 0);

        /* An unfinished message (FIN=0), then a brand-new data frame that
         * does carry FIN. If the guard is gone the conn stays open and
         * delivers 11 bytes -- "first" and "second" run together. */
        const uint8_t first[] = "first";
        const uint8_t second[] = "second";
        uint8_t wire[128];
        size_t n = build_ws_frame(wire, 0x2, 0, k_client_key, first, sizeof(first) - 1);
        n += build_ws_frame(wire + n, interrupting_opcodes[i], 1, k_client_key,
                            second, sizeof(second) - 1);
        ASSERT_EQ_INT((long long)write(fds[1], wire, n), (long long)n);
        PUMP_UNTIL(r, h.closed_count > 0 || h.received_count > 0);
        ASSERT_EQ_INT(h.closed_count, 1);
        ASSERT_EQ_INT(h.received_count, 0);

        cloak_conn_destroy(&c);
        cloak_reactor_destroy(r);
        close(fds[0]);
        close(fds[1]);
    }
}

/* ================================================================== */
/* 7. PING -> PONG                                                     */
/* ================================================================== */

/* A CDN pings idle WebSocket connections and hangs up when no pong comes
 * back, so this is load-bearing in production and invisible in a lab.
 *
 * The ping is injected BETWEEN two data frames in a SINGLE write, which
 * pins two things at once: the pong is produced in the same pass that
 * handles the surrounding data (not deferred to some later turn), and
 * the ping does not appear as session data -- a control frame handed to
 * the deobfuscator is a session teardown. The pong's payload must be
 * byte-identical to the ping's (RFC 6455 s5.5.3). */
static void test_ping_is_answered_with_a_pong_and_is_not_session_data(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) return;
    ws_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_SERVER, MAX_FRAME_LEN), 0);

    const uint8_t d1[] = "first";
    const uint8_t d2[] = "second";
    const uint8_t ping_body[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x7F};
    static uint8_t wire[256];
    size_t n = build_ws_frame(wire, 0x2, 1, k_client_key, d1, sizeof(d1) - 1);
    n += build_ws_frame(wire + n, 0x9, 1, k_client_key, ping_body, sizeof(ping_body));
    n += build_ws_frame(wire + n, 0x2, 1, k_client_key, d2, sizeof(d2) - 1);
    ASSERT_EQ_INT((long long)write(fds[1], wire, n), (long long)n);

    PUMP_UNTIL(r, h.received_count >= 2 || h.closed_count > 0);
    ASSERT_EQ_INT(h.received_count, 2); /* the ping is NOT one of them */
    ASSERT_EQ_INT(h.closed_count, 0);
    if (h.received_count == 2) {
        ASSERT_EQ_INT((long long)h.received_len[0], 5);
        ASSERT_MEM_EQ(h.received[0], d1, 5);
        ASSERT_EQ_INT((long long)h.received_len[1], 6);
        ASSERT_MEM_EQ(h.received[1], d2, 6);
    }

    /* And the pong, on the wire, as a server sends it: 0x8A (FIN | pong),
     * MASK clear, 6 inline, then the ping's payload verbatim. */
    uint8_t pong[2 + 6];
    size_t got = drain_peer(r, fds[1], pong, sizeof(pong));
    ASSERT_EQ_INT((long long)got, (long long)sizeof(pong));
    if (got == sizeof(pong)) {
        ASSERT_EQ_INT(pong[0], 0x8A);
        ASSERT_EQ_INT(pong[1], 0x06); /* MASK clear | 6 */
        ASSERT_MEM_EQ(pong + 2, ping_body, sizeof(ping_body));
    }

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

/* The client half: a pong a CLIENT sends must be masked, like every other
 * client frame. A control-frame path that bypassed the direction rule
 * would pass the server test above and be rejected by gorilla here. */
static void test_client_pong_is_masked(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) return;
    ws_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_CLIENT, MAX_FRAME_LEN), 0);

    /* A server-sent ping: unmasked, which is what a WS_CLIENT conn must
     * require of its peer. */
    const uint8_t ping_body[] = {0x01, 0x02, 0x03};
    uint8_t wire[64];
    size_t n = build_ws_frame(wire, 0x9, 1, NULL, ping_body, sizeof(ping_body));
    ASSERT_EQ_INT((long long)write(fds[1], wire, n), (long long)n);

    uint8_t pong[2 + 4 + 3];
    size_t got = drain_peer(r, fds[1], pong, sizeof(pong));
    ASSERT_EQ_INT((long long)got, (long long)sizeof(pong));
    ASSERT_EQ_INT(h.closed_count, 0);
    ASSERT_EQ_INT(h.received_count, 0);
    if (got == sizeof(pong)) {
        ASSERT_EQ_INT(pong[0], 0x8A);
        ASSERT_EQ_INT(pong[1], 0x83); /* MASK set | 3 */
        uint8_t unmasked[3];
        for (int i = 0; i < 3; i++) unmasked[i] = (uint8_t)(pong[6 + i] ^ pong[2 + (i & 3)]);
        ASSERT_MEM_EQ(unmasked, ping_body, 3);
    }

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

/* A pong arriving unsolicited is neither data nor an error -- a CDN or a
 * peer keepalive may send one at any time. Pinned so that "ignore" stays
 * a decision rather than a gap. */
static void test_received_pong_is_ignored(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) return;
    ws_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_SERVER, MAX_FRAME_LEN), 0);

    const uint8_t body[] = {0x11, 0x22};
    const uint8_t data[] = "after";
    uint8_t wire[128];
    size_t n = build_ws_frame(wire, 0xA, 1, k_client_key, body, sizeof(body));
    n += build_ws_frame(wire + n, 0x2, 1, k_client_key, data, sizeof(data) - 1);
    ASSERT_EQ_INT((long long)write(fds[1], wire, n), (long long)n);
    PUMP_UNTIL(r, h.received_count > 0 || h.closed_count > 0);
    ASSERT_EQ_INT(h.received_count, 1);
    ASSERT_EQ_INT(h.closed_count, 0);
    if (h.received_count == 1) {
        ASSERT_MEM_EQ(h.received[0], data, 5);
    }
    /* Nothing was written back for a pong. */
    uint8_t back[8];
    ssize_t rn = read(fds[1], back, sizeof(back));
    ASSERT_TRUE(rn < 0);

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

/* A control frame is allowed to be interleaved INTO a fragmented message
 * (RFC 6455 s5.4), and answering it must not disturb the message being
 * reassembled. An implementation that reused the reassembly buffer for
 * the ping's payload corrupts the message and still passes every other
 * test in this file. */
static void test_ping_interleaved_into_a_fragmented_message(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) return;
    ws_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_SERVER, MAX_FRAME_LEN), 0);

    uint8_t msg[120];
    for (int i = 0; i < 120; i++) msg[i] = (uint8_t)(0xC0 + (i & 0x1f));
    const uint8_t ping_body[] = "cdn-keepalive";
    static uint8_t wire[512];
    size_t n = build_ws_frame(wire, 0x2, 0, k_client_key, msg, 40);
    n += build_ws_frame(wire + n, 0x9, 1, k_client_key, ping_body, sizeof(ping_body) - 1);
    n += build_ws_frame(wire + n, 0x0, 1, k_client_key, msg + 40, 80);
    ASSERT_EQ_INT((long long)write(fds[1], wire, n), (long long)n);

    PUMP_UNTIL(r, h.received_count > 0 || h.closed_count > 0);
    ASSERT_EQ_INT(h.received_count, 1);
    ASSERT_EQ_INT(h.closed_count, 0);
    if (h.received_count == 1) {
        ASSERT_EQ_INT((long long)h.received_len[0], 120);
        ASSERT_MEM_EQ(h.received[0], msg, 120);
    }
    uint8_t pong[2 + 13];
    size_t got = drain_peer(r, fds[1], pong, sizeof(pong));
    ASSERT_EQ_INT((long long)got, (long long)sizeof(pong));
    if (got == sizeof(pong)) {
        ASSERT_EQ_INT(pong[0], 0x8A);
        ASSERT_EQ_INT(pong[1], 0x0D);
        ASSERT_MEM_EQ(pong + 2, ping_body, 13);
    }

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

/* ================================================================== */
/* 8. CLOSE                                                            */
/* ================================================================== */

/* A close ends the connection and is NOT forwarded as data: a two-byte
 * status code handed to cloak_frame_deobfuscate is a decryption failure
 * that would be reported as a corrupt peer rather than as a clean
 * hang-up. The echoed close is checked too (RFC 6455 s5.5.1 -- the
 * endpoint that receives a close "MUST send a Close frame in response"),
 * because a CDN that never sees one may hold the socket open. */
static void test_close_frame_ends_the_conn_and_is_not_data(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) return;
    ws_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_SERVER, MAX_FRAME_LEN), 0);

    const uint8_t data[] = "before";
    const uint8_t close_body[] = {0x03, 0xE8}; /* status 1000, normal closure */
    static uint8_t wire[128];
    size_t n = build_ws_frame(wire, 0x2, 1, k_client_key, data, sizeof(data) - 1);
    n += build_ws_frame(wire + n, 0x8, 1, k_client_key, close_body, sizeof(close_body));
    ASSERT_EQ_INT((long long)write(fds[1], wire, n), (long long)n);

    PUMP_UNTIL(r, h.closed_count > 0);
    ASSERT_EQ_INT(h.closed_count, 1);
    ASSERT_EQ_INT(h.received_count, 1); /* the data frame before it, and only that */
    if (h.received_count >= 1) {
        ASSERT_MEM_EQ(h.received[0], data, 6);
    }

    uint8_t echo[2 + 2];
    size_t got = drain_peer(r, fds[1], echo, sizeof(echo));
    ASSERT_EQ_INT((long long)got, (long long)sizeof(echo));
    if (got == sizeof(echo)) {
        ASSERT_EQ_INT(echo[0], 0x88); /* FIN | close */
        ASSERT_EQ_INT(echo[1], 0x02); /* MASK clear | 2 */
        ASSERT_MEM_EQ(echo + 2, close_body, 2);
    }

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

/* ================================================================== */
/* 9. THE DIRECTION RULE ON RECEIPT                                    */
/* ================================================================== */

/* RFC 6455 s5.1: a client MUST mask. So an UNMASKED frame arriving at a
 * server is a protocol violation, and gorilla reports exactly that
 * ("bad MASK"). A conn that accepted both would interoperate with a
 * broken peer nobody else interoperates with -- a behavioural
 * distinguisher, which is the class of leak this whole product exists to
 * avoid. */
static void test_ws_server_requires_the_peer_to_mask(void) {
    /* Accepted: masked. */
    {
        int fds[2];
        ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
        cloak_reactor_t *r = cloak_reactor_create();
        ASSERT_TRUE(r != NULL);
        if (r == NULL) return;
        ws_harness_t h;
        memset(&h, 0, sizeof(h));
        cloak_conn_t c;
        ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_SERVER, MAX_FRAME_LEN), 0);
        const uint8_t body[] = "masked-ok";
        uint8_t wire[64];
        size_t n = build_ws_frame(wire, 0x2, 1, k_client_key, body, sizeof(body) - 1);
        ASSERT_EQ_INT((long long)write(fds[1], wire, n), (long long)n);
        PUMP_UNTIL(r, h.received_count > 0 || h.closed_count > 0);
        ASSERT_EQ_INT(h.received_count, 1);
        ASSERT_EQ_INT(h.closed_count, 0);
        if (h.received_count == 1) ASSERT_MEM_EQ(h.received[0], body, 9);
        cloak_conn_destroy(&c);
        cloak_reactor_destroy(r);
        close(fds[0]);
        close(fds[1]);
    }
    /* Rejected: the identical frame with the MASK bit clear and the key
     * absent. Same opcode, same payload, same everything else. */
    {
        int fds[2];
        ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
        cloak_reactor_t *r = cloak_reactor_create();
        ASSERT_TRUE(r != NULL);
        if (r == NULL) return;
        ws_harness_t h;
        memset(&h, 0, sizeof(h));
        cloak_conn_t c;
        ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_SERVER, MAX_FRAME_LEN), 0);
        const uint8_t body[] = "masked-ok";
        uint8_t wire[64];
        size_t n = build_ws_frame(wire, 0x2, 1, NULL, body, sizeof(body) - 1);
        ASSERT_EQ_INT((long long)write(fds[1], wire, n), (long long)n);
        PUMP_UNTIL(r, h.closed_count > 0);
        ASSERT_EQ_INT(h.closed_count, 1);
        ASSERT_EQ_INT(h.received_count, 0);
        cloak_conn_destroy(&c);
        cloak_reactor_destroy(r);
        close(fds[0]);
        close(fds[1]);
    }
}

/* And the converse, which gorilla also enforces: a server MUST NOT mask,
 * so a masked frame arriving at a CLIENT is a violation. Without this
 * case the direction rule could be implemented as "always require a
 * mask", which passes every server-side test above. */
static void test_ws_client_rejects_a_masked_frame(void) {
    /* Accepted: unmasked, as a server sends. */
    {
        int fds[2];
        ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
        cloak_reactor_t *r = cloak_reactor_create();
        ASSERT_TRUE(r != NULL);
        if (r == NULL) return;
        ws_harness_t h;
        memset(&h, 0, sizeof(h));
        cloak_conn_t c;
        ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_CLIENT, MAX_FRAME_LEN), 0);
        const uint8_t body[] = "from-server";
        uint8_t wire[64];
        size_t n = build_ws_frame(wire, 0x2, 1, NULL, body, sizeof(body) - 1);
        ASSERT_EQ_INT((long long)write(fds[1], wire, n), (long long)n);
        PUMP_UNTIL(r, h.received_count > 0 || h.closed_count > 0);
        ASSERT_EQ_INT(h.received_count, 1);
        ASSERT_EQ_INT(h.closed_count, 0);
        if (h.received_count == 1) ASSERT_MEM_EQ(h.received[0], body, 11);
        cloak_conn_destroy(&c);
        cloak_reactor_destroy(r);
        close(fds[0]);
        close(fds[1]);
    }
    /* Rejected: masked. */
    {
        int fds[2];
        ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
        cloak_reactor_t *r = cloak_reactor_create();
        ASSERT_TRUE(r != NULL);
        if (r == NULL) return;
        ws_harness_t h;
        memset(&h, 0, sizeof(h));
        cloak_conn_t c;
        ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_CLIENT, MAX_FRAME_LEN), 0);
        const uint8_t body[] = "from-server";
        uint8_t wire[64];
        size_t n = build_ws_frame(wire, 0x2, 1, k_client_key, body, sizeof(body) - 1);
        ASSERT_EQ_INT((long long)write(fds[1], wire, n), (long long)n);
        PUMP_UNTIL(r, h.closed_count > 0);
        ASSERT_EQ_INT(h.closed_count, 1);
        ASSERT_EQ_INT(h.received_count, 0);
        cloak_conn_destroy(&c);
        cloak_reactor_destroy(r);
        close(fds[0]);
        close(fds[1]);
    }
}

/* ================================================================== */
/* 10. A MALFORMED HEADER BREAKS THE CONN RATHER THAN BEING SKIPPED    */
/* ================================================================== */

/* cloak_ws_frame_parse_header distinguishes "need more bytes" (0) from
 * "malformed" (-1), and the difference matters here: a caller that
 * treated -1 as "wait for more" would let a peer pin the connection open
 * forever with two bytes. RSV1 set is the cheapest malformed header the
 * codec recognises. */
static void test_malformed_header_breaks_the_conn(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) return;
    ws_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_SERVER, MAX_FRAME_LEN), 0);

    const uint8_t bad[] = {0xC2, 0x80, 0x00, 0x00, 0x00, 0x00}; /* RSV1 set */
    ASSERT_EQ_INT((long long)write(fds[1], bad, sizeof(bad)), (long long)sizeof(bad));
    PUMP_UNTIL(r, h.closed_count > 0);
    ASSERT_EQ_INT(h.closed_count, 1);
    ASSERT_EQ_INT(h.received_count, 0);

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

/* Two whole messages arriving in one read must both be dispatched -- the
 * receive loop has to keep going after a dispatch rather than return to
 * the reactor, which on an edge-triggered fd would mean the second
 * message sits unread until the peer happens to send more. */
static void test_two_messages_in_one_read(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) return;
    ws_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_SERVER, MAX_FRAME_LEN), 0);

    const uint8_t a[] = "foo";
    const uint8_t b[] = "quux";
    uint8_t wire[128];
    size_t n = build_ws_frame(wire, 0x2, 1, k_client_key, a, 3);
    n += build_ws_frame(wire + n, 0x2, 1, k_client_key, b, 4);
    ASSERT_EQ_INT((long long)write(fds[1], wire, n), (long long)n);
    PUMP_UNTIL(r, h.received_count >= 2 || h.closed_count > 0);
    ASSERT_EQ_INT(h.received_count, 2);
    ASSERT_EQ_INT(h.closed_count, 0);
    if (h.received_count == 2) {
        ASSERT_EQ_INT((long long)h.received_len[0], 3);
        ASSERT_MEM_EQ(h.received[0], a, 3);
        ASSERT_EQ_INT((long long)h.received_len[1], 4);
        ASSERT_MEM_EQ(h.received[1], b, 4);
    }

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

/* The receive accumulator must be able to hold ONE WHOLE INCOMING FRAME,
 * and an incoming frame is not the same size as an outgoing one: a
 * WS_SERVER conn sends unmasked and receives masked, so its inbound
 * envelope is four bytes larger than its outbound one. Sizing the
 * accumulator off the SEND envelope is not an overflow -- it is a
 * DEADLOCK: the frame never completes, so nothing is ever consumed, so
 * room never appears, and the connection sits there looking healthy
 * forever.
 *
 * The accumulator is two envelopes wide, and that slack hides the mistake
 * at every ordinary size. max_frame_len == 1 is where it stops hiding:
 * two send envelopes is 2*(2+1) == 6 bytes, and one masked inbound frame
 * is 2+4+1 == 7. So this test is written at the one configuration that
 * can see the difference, and it is written here rather than reasoned
 * about in a comment because reasoning is what let the earlier draft
 * size this buffer wrongly in the first place. */
static void test_recv_accumulator_holds_a_whole_inbound_frame(void) {
    const size_t sizes[] = {1, 2, 125, 126};
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        int fds[2];
        ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
        cloak_reactor_t *r = cloak_reactor_create();
        ASSERT_TRUE(r != NULL);
        if (r == NULL) return;
        ws_harness_t h;
        memset(&h, 0, sizeof(h));
        cloak_conn_t c;
        ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_SERVER, sizes[i]), 0);

        uint8_t payload[126];
        for (size_t k = 0; k < sizeof(payload); k++) payload[k] = (uint8_t)(0xA0 + (k & 0x0f));
        uint8_t wire[160];
        size_t n = build_ws_frame(wire, 0x2, 1, k_client_key, payload, sizes[i]);
        ASSERT_EQ_INT((long long)write(fds[1], wire, n), (long long)n);
        PUMP_UNTIL(r, h.received_count > 0 || h.closed_count > 0);
        ASSERT_EQ_INT(h.received_count, 1);
        ASSERT_EQ_INT(h.closed_count, 0);
        if (h.received_count == 1) {
            ASSERT_EQ_INT((long long)h.received_len[0], (long long)sizes[i]);
            ASSERT_MEM_EQ(h.received[0], payload, sizes[i]);
        }

        cloak_conn_destroy(&c);
        cloak_reactor_destroy(r);
        close(fds[0]);
        close(fds[1]);
    }
}

/* A control frame's payload must NOT be written into the reassembly
 * buffer, and the case that proves it is a maximum-length ping arriving
 * when the buffer is already full of an unfinished message.
 *
 * The fragment here is exactly max_frame_len bytes with FIN clear, so
 * ws_msg_len is at the bound; the ping that follows carries the 125 bytes
 * RFC 6455 s5.5 allows a control frame at most. An implementation that
 * unmasked the ping into recv_scratch + ws_msg_len would write 125 bytes
 * past a buffer with 8 to spare -- a heap overflow driven entirely by
 * attacker-chosen lengths. It is invisible without a sanitizer (the
 * message's own 300 bytes survive, since ws_msg_len was never advanced),
 * which is why this test is only meaningful in the ASan build and why it
 * is written to run there. */
static void test_ping_after_a_full_length_fragment_does_not_touch_reassembly(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) return;
    ws_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(init_conn(&c, fds[0], r, &h, CLOAK_CONN_FRAMING_WS_SERVER, 300), 0);

    uint8_t msg[300];
    for (int i = 0; i < 300; i++) msg[i] = (uint8_t)(i & 0xff);
    uint8_t ping_body[125];
    for (int i = 0; i < 125; i++) ping_body[i] = (uint8_t)(0xF0 - i);

    static uint8_t wire[1024];
    size_t n = build_ws_frame(wire, 0x2, 0, k_client_key, msg, 300);
    n += build_ws_frame(wire + n, 0x9, 1, k_client_key, ping_body, 125);
    n += build_ws_frame(wire + n, 0x0, 1, k_client_key, msg, 0);
    ASSERT_EQ_INT((long long)write(fds[1], wire, n), (long long)n);

    PUMP_UNTIL(r, h.received_count > 0 || h.closed_count > 0);
    ASSERT_EQ_INT(h.received_count, 1);
    ASSERT_EQ_INT(h.closed_count, 0);
    if (h.received_count == 1) {
        ASSERT_EQ_INT((long long)h.received_len[0], 300);
        ASSERT_MEM_EQ(h.received[0], msg, 300);
    }
    uint8_t pong[2 + 125];
    size_t got = drain_peer(r, fds[1], pong, sizeof(pong));
    ASSERT_EQ_INT((long long)got, (long long)sizeof(pong));
    if (got == sizeof(pong)) {
        ASSERT_EQ_INT(pong[0], 0x8A);
        ASSERT_EQ_INT(pong[1], 0x7D); /* MASK clear | 125 */
        ASSERT_MEM_EQ(pong + 2, ping_body, 125);
    }

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

/* The switchboard is where the framing guard actually lives -- the
 * session delegates to it rather than repeating the check -- so it is
 * tested directly. Without this, a mutation that made the pool silently
 * substitute TLS_RECORD for an invalid mode (and adopt the caller's fd
 * while doing it) left the whole suite green. */
static void switchboard_on_envelope(cloak_switchboard_t *sb, const uint8_t *b, size_t n, void *ud) {
    (void)sb; (void)b; (void)n; (void)ud;
}
static void switchboard_on_broken(cloak_switchboard_t *sb, void *ud) {
    (void)sb; (void)ud;
}

static void test_switchboard_rejects_invalid_framing(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) return;

    cloak_switchboard_t sb;
    ASSERT_EQ_INT(cloak_switchboard_init(&sb, r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                          switchboard_on_envelope, NULL,
                                          switchboard_on_broken, NULL), 0);

    ASSERT_EQ_INT(cloak_switchboard_add_conn_framed(&sb, fds[0], CLOAK_CONN_FRAMING_INVALID),
                  CLOAK_CONN_ERR_INVALID_FRAMING);
    ASSERT_EQ_INT((long long)cloak_switchboard_conn_count(&sb), 0);
    ASSERT_EQ_INT(cloak_switchboard_add_conn_framed(&sb, fds[0], (cloak_conn_framing_t)77),
                  CLOAK_CONN_ERR_INVALID_FRAMING);
    ASSERT_EQ_INT((long long)cloak_switchboard_conn_count(&sb), 0);

    /* fds[0] was never adopted by either rejected call, so adding it for
     * real still works -- and now the pool owns it. */
    ASSERT_EQ_INT(cloak_switchboard_add_conn_framed(&sb, fds[0], CLOAK_CONN_FRAMING_WS_SERVER), 0);
    ASSERT_EQ_INT((long long)cloak_switchboard_conn_count(&sb), 1);
    ASSERT_EQ_INT(sb.conns[0]->framing, CLOAK_CONN_FRAMING_WS_SERVER);

    cloak_switchboard_destroy(&sb); /* close()s fds[0] */
    cloak_reactor_destroy(r);
    close(fds[1]);
}

TEST_MAIN_BEGIN()
    test_first_wire_byte_is_0x17_on_the_direct_path();
    test_first_wire_byte_is_0x82_for_a_ws_server();
    test_first_wire_byte_is_0x82_for_a_ws_client();
    test_short_payload_uses_the_inline_length_form();
    test_zeroed_config_fails_with_the_named_error();
    test_session_add_conn_framing();
    test_ws_server_never_sets_the_mask_bit();
    test_ws_client_always_masks_with_a_fresh_key();
    test_client_mask_position_runs_across_chunk_boundaries();
    test_max_envelope_len_per_mode();
    test_send_bracket_at_max_frame_len();
    test_declared_length_bracket_is_max_frame_len();
    test_absurd_declared_length_is_refused();
    test_reassembled_length_is_bounded_too();
    test_continuation_frames_reassemble_into_one_message();
    test_continuation_reassembly_survives_byte_at_a_time_delivery();
    test_orphan_continuation_is_rejected();
    test_new_data_frame_mid_fragmentation_is_rejected();
    test_ping_is_answered_with_a_pong_and_is_not_session_data();
    test_client_pong_is_masked();
    test_received_pong_is_ignored();
    test_ping_interleaved_into_a_fragmented_message();
    test_close_frame_ends_the_conn_and_is_not_data();
    test_ws_server_requires_the_peer_to_mask();
    test_ws_client_rejects_a_masked_frame();
    test_malformed_header_breaks_the_conn();
    test_two_messages_in_one_read();
    test_recv_accumulator_holds_a_whole_inbound_frame();
    test_ping_after_a_full_length_fragment_does_not_touch_reassembly();
    test_switchboard_rejects_invalid_framing();
TEST_MAIN_END()
