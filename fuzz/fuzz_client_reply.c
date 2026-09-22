#define _POSIX_C_SOURCE 200809L

/* TARGET #7: the CLIENT's handshake-reply reader --
 * cloak_client_handshake_t's READ_RECORD_HEADER / READ_RECORD_BODY
 * states (libcloak-client/src/client_transport.c), driven over a real
 * socket by bytes nobody has authenticated and nobody can authenticate,
 * since this object runs before the session key is recovered.
 *
 * WHY THIS TARGET EXISTS AT ALL. Every fuzz list this project has
 * written -- the spec's, module 8's, module 9's, and the first six
 * entries of module 10's scouting report -- names SERVER-side parsers.
 * This is the only client-side pre-auth parser in the tree, and the
 * asymmetry that hid it is worth stating plainly: reaching the server's
 * parsers requires nothing but a TCP connection, and reaching this one
 * requires nothing but ANSWERING a TCP connection. Any on-path censor,
 * any DNS or BGP hijack, any operator of the IP the client was pointed
 * at, feeds these bytes. You do not have to be the server. Everything
 * below record 0's AEAD tag runs on attacker-chosen input.
 *
 * WHAT IT DRIVES, AND WHY THROUGH A REAL fd. client_transport.c's `feed`
 * is static and its only caller is `do_read`, which recv()s exactly
 * bytes_wanted(h) bytes -- never a speculative fill. So this target
 * drives the object the way the reactor does: a socketpair, a real
 * registration, and the server's bytes written into the peer end in
 * chunks the input chooses. Two consequences follow and are stated
 * rather than glossed:
 *
 *   - The split boundary IS controllable, and it is the axis (see
 *     below): a write of n bytes followed by one reactor turn makes
 *     do_read's recv return at most n, so the input can park the machine
 *     anywhere inside a record header, anywhere inside the ServerHello
 *     prefix, or anywhere inside a record body.
 *   - `feed`'s own internal min_size() clamps are NOT an axis here, and
 *     cannot be: do_read already caps every recv at the remaining length
 *     of the piece in flight, so `len` never exceeds it and the clamps
 *     are dead under the object's only real caller. That is the opposite
 *     of fuzz_firstpacket.c, whose subject documents an over-feeding
 *     caller as legal and therefore fuzzes one. Fuzzing an over-feed
 *     here would be fuzzing a caller that does not exist.
 *
 * THE CRYPTOGRAPHIC GATE, AND WHY THE HARNESS BUILDS PART OF THE INPUT.
 * Record 0 is a ServerHello carrying a 32-byte session key sealed under
 * the ECDH shared secret with AES-256-GCM. Completing record 0 with
 * bytes the mutator chose therefore fails cloak_aead_open with
 * probability 1 - 2^-128, and records 1 and 2 -- half of the state
 * machine -- are unreachable behind it. No seed corpus can fix this
 * either, because the shared secret is derived from a FRESH ephemeral
 * X25519 key on every single execution: there is no fixed byte string
 * that authenticates twice. So flags bit 0 asks the harness to seal a
 * key under h->shared_secret itself and prepend the resulting valid
 * record 0 to the stream -- the runtime equivalent of task 1's seed
 * generator, forced to be runtime rather than a committed corpus by the
 * ephemeral key. Measured with the prepend disabled and an oracle that
 * aborts on success: see this target's entry in the task 4 report.
 *
 * INPUT FORMAT. Fixed offsets, deliberately, so that a mutation to a
 * chunk size does not shift the reply bytes and a mutation to the reply
 * does not shift the chunk sizes -- the two axes stay independent under
 * libFuzzer's insert/erase operators:
 *
 *   [0]        FLAGS. bit 0: prepend a harness-sealed, valid ServerHello
 *              record to the front of the stream (see above). Bits 1..7
 *              are unused and are not consumed, so they are free for a
 *              later axis without moving anything.
 *   [1..17)    SIXTEEN CHUNK CONTROL BYTES, cycled for as long as the
 *              stream lasts. bits 0..6 are the chunk size (0 means 128);
 *              bit 7, when set, SUPPRESSES the reactor turn after that
 *              write, so two or more chunks coalesce in the socket and
 *              do_read sees one larger recv. Size and coalescing
 *              together are what move the split boundary.
 *   [17..)     THE REPLY BYTES, appended after the prepended record if
 *              there is one. Records 1 and 2 (and any trailing bytes the
 *              reader must NOT consume) live here.
 *
 * An input shorter than 17 bytes is padded with zeroes, so a one-byte
 * input is meaningful and truncating an input never changes the meaning
 * of what is left.
 *
 * THE ORACLES. Every one is a line of client_transport.h's own contract;
 * none is invented here, and none of them is "it did not crash".
 *
 *   O1 CONSERVATION / NO OVER-READ. Every byte written to the peer is
 *      either counted in h->reply_bytes or still sitting unread in the
 *      client's socket: unread(fd) + h->reply_bytes == bytes written,
 *      where unread() drains the socket and counts, rather than asking
 *      FIONREAD -- see drain_unread below for the measurement that
 *      forced the change.
 *      This is the guarantee the header calls load-bearing -- "a byte of
 *      the session's first frame consumed here would be silently lost
 *      and the session would desynchronise immediately" -- and it is
 *      checked on EVERY input, including the ones that fail.
 *   O2 THE FRAMING IS RE-DERIVED, NOT TRUSTED. An independent scan of
 *      the same bytes (reference_scan below, written from the record
 *      layout rather than from client_transport.c) says how many bytes a
 *      correct reader consumes and where it stops. h->reply_bytes must
 *      equal that number exactly. A reader that mis-splices a record
 *      across a chunk boundary gets a different answer here without
 *      crashing.
 *   O3 THE OUTCOME IS RE-DERIVED TOO. The same scan says whether the
 *      reply is structurally complete, structurally illegal, or
 *      truncated, and the status/error must agree: DONE, PROTOCOL, EOF.
 *   O4 THE RECOVERED KEY. When the harness sealed record 0, a completed
 *      handshake must hand back the exact 32 bytes that were sealed --
 *      whatever chunking delivered them. This is the check that a
 *      subtly wrong answer, rather than a crash, cannot survive.
 *   O5 THE CAPTURED ServerHello PREFIX. Whenever 112 bytes of record
 *      0's body have been delivered, h->sh must be byte-for-byte the
 *      first 112 bytes of that body as they appear in the stream. This
 *      one needs NO valid crypto, so it is reachable on every input that
 *      gets that far, and it is the direct detector of an off-by-one in
 *      the resumable capture.
 *   O6 STRUCTURAL INVARIANTS: header_len <= 5, body_len <= body_total <=
 *      MAX_RECORD_BODY, sh_len <= SERVERHELLO_PREFIX, record_index <=
 *      REPLY_RECORDS, reply_bytes <= MAX_REPLY_BYTES.
 *   O7 LIVENESS. Once the peer has closed its write half and the
 *      reactor has been pumped, the handshake MUST be terminal. A
 *      machine that parks itself with nothing left to wait for holds a
 *      registered fd on a shared reactor until the 15-second deadline --
 *      the exact resource the header's deadline exists to bound, spent
 *      by a censor for the cost of one malformed record.
 *
 * WHAT THIS TARGET DOES NOT COVER: the write half (WRITE_HELLO short
 * writes, which test_partial_client_hello_write already forces on a
 * shrunken send buffer and which no server-supplied byte influences),
 * and the deadline (a timer, not a parser; nothing here runs long enough
 * to fire it).
 */

#include "cloak/client_transport.h"
#include "cloak/crypto.h"
#include "cloak/reactor.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Not <assert.h>: assert() is a no-op under NDEBUG, and a fuzz target
 * whose oracles silently vanish in a release-flavoured build is the
 * failure mode this whole module exists to avoid. abort() is what
 * libFuzzer reports as a crash. */
#define FUZZ_CHECK(cond, msg)                                                  \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "fuzz_client_reply: oracle failed: %s\n", (msg));   \
            abort();                                                           \
        }                                                                      \
    } while (0)

#define SIZE_BYTES 16
#define HEADER_BYTES (1 + SIZE_BYTES)
#define VALID_RECORD_LEN (5 + CLOAK_CLIENT_HANDSHAKE_SERVERHELLO_PREFIX)
#define MAX_PAYLOAD 65536
#define PREFIX CLOAK_CLIENT_HANDSHAKE_SERVERHELLO_PREFIX

/* The server identity the client is configured with. Generated once:
 * cloak_client_auth_build needs a real X25519 public key to derive
 * against, and re-generating one per execution would buy nothing but
 * keygens. The client's OWN ephemeral key is still fresh every
 * execution, which is what makes the gate above unclimbable. */
static uint8_t g_server_priv[CLOAK_X25519_KEY_LEN];
static uint8_t g_server_pub[CLOAK_X25519_KEY_LEN];
static cloak_reactor_t *g_reactor;

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    if (cloak_x25519_generate_keypair(g_server_priv, g_server_pub) != 0) {
        fprintf(stderr, "fuzz_client_reply: keypair generation failed\n");
        abort();
    }
    g_reactor = cloak_reactor_create();
    if (g_reactor == NULL) {
        fprintf(stderr, "fuzz_client_reply: reactor creation failed\n");
        abort();
    }
    return 0;
}

/* ---- the independent reference scan (O2, O3) ---------------------------- */

typedef enum {
    REF_DONE = 0,      /* three legal, complete records */
    REF_PROTOCOL = 1,  /* a record header the reader must reject */
    REF_TRUNCATED = 2, /* ran out of bytes mid-record */
} ref_verdict_t;

typedef struct {
    ref_verdict_t verdict;
    /* Bytes a correct reader consumes before it stops, ASSUMING record
     * 0 authenticates. */
    size_t consumed;
    /* Bytes consumed through the end of record 0, valid when
     * rec0_complete. A reader that rejects record 0's key stops exactly
     * here. */
    size_t consumed_rec0_end;
    int rec0_complete;
    /* Offset of record 0's body in the stream, valid once record 0's
     * header has been accepted. */
    size_t rec0_body_off;
    int rec0_header_ok;
} ref_t;

/* Written from the record layout in client_transport.h, not from
 * client_transport.c: three records, each a 5-byte header whose last two
 * bytes are a big-endian body length, record 0 additionally required to
 * be content type 0x16 and at least SERVERHELLO_PREFIX bytes long, every
 * body bounded by MAX_RECORD_BODY. The reply-byte ceiling is deliberately
 * NOT reproduced: client_transport.c documents it as a consistency guard
 * between two constants that no input can reach, and reproducing an
 * unreachable branch here would be copying the implementation rather than
 * re-deriving the format. */
static void reference_scan(const uint8_t *s, size_t len, ref_t *out) {
    memset(out, 0, sizeof(*out));
    size_t pos = 0;
    for (size_t rec = 0; rec < CLOAK_CLIENT_HANDSHAKE_REPLY_RECORDS; rec++) {
        if (len - pos < 5) {
            out->verdict = REF_TRUNCATED;
            out->consumed = len;
            return;
        }
        size_t body = ((size_t)s[pos + 3] << 8) | (size_t)s[pos + 4];
        if (body > CLOAK_CLIENT_HANDSHAKE_MAX_RECORD_BODY ||
            (rec == 0 && (s[pos] != 0x16 || body < PREFIX))) {
            out->verdict = REF_PROTOCOL;
            out->consumed = pos + 5;
            return;
        }
        pos += 5;
        if (rec == 0) {
            out->rec0_header_ok = 1;
            out->rec0_body_off = pos;
        }
        if (len - pos < body) {
            out->verdict = REF_TRUNCATED;
            out->consumed = len;
            return;
        }
        pos += body;
        if (rec == 0) {
            out->rec0_complete = 1;
            out->consumed_rec0_end = pos;
        }
    }
    out->verdict = REF_DONE;
    out->consumed = pos;
}

/* ---- harness plumbing --------------------------------------------------- */

typedef struct {
    int fired;
    cloak_client_handshake_status_t status;
} done_state_t;

static void on_done(cloak_client_handshake_t *h, cloak_client_handshake_status_t status,
                    void *userdata) {
    (void)h;
    done_state_t *d = userdata;
    d->fired++;
    d->status = status;
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* O1'S INSTRUMENT, AND WHY IT IS NOT FIONREAD.
 *
 * This used to ask FIONREAD how many bytes were still unread. FIONREAD is
 * not exact for an AF_UNIX stream socket across kernels, and the error is
 * not hypothetical: on the SAME corpus input (client_reply/02abce5c...),
 * with byte-identical reader state on both sides -- reply_bytes 122,
 * written 215, status FAILED, err 5, sh_len 112, header_len 5,
 * body_total 34438 -- FIONREAD reported
 *
 *     93 on Linux 6.12.76-linuxkit (aarch64)
 *     95 on Linux 6.17.0-1022-azure (x86_64)
 *
 * for the same 215 bytes written and 122 consumed. Two of those bytes
 * exist only in the kernel's answer. O1 then fired on every x86_64 run
 * (40/40) and on none locally (0/40), reporting "the reader consumed more
 * than it accounted for" about a reader that had consumed exactly the
 * right number -- the accounting was over, not under, which the old
 * message could not say.
 *
 * So the remainder is now MEASURED rather than asked for: read the socket
 * dry and count what comes out. Nothing after O1 reads this fd again --
 * every later oracle inspects `h`, `stream` and `ref` -- so draining here
 * costs nothing. */
static size_t drain_unread(int fd) {
    size_t total = 0;
    uint8_t buf[4096];
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n > 0) {
            total += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    return total;
}

/* Everything the structural invariants (O6) say about h, checked after
 * every reactor turn rather than only at the end: a violation that is
 * repaired before the handshake finishes is still a violation. */
static void check_invariants(const cloak_client_handshake_t *h) {
    FUZZ_CHECK(h->header_len <= 5, "header_len past the record header");
    /* Only while the machine is live. feed() assigns body_total from the
     * header and THEN rejects an over-long one, so an illegal value is
     * legitimately visible on a handshake that has already failed --
     * found by this oracle firing on the protocol_too_long seed, which
     * is what an oracle written from the header rather than the code
     * looks like when the header did not say which of the two came
     * first. */
    if (h->status == CLOAK_CLIENT_HANDSHAKE_PENDING) {
        FUZZ_CHECK(h->body_total <= CLOAK_CLIENT_HANDSHAKE_MAX_RECORD_BODY,
                   "body_total past the record-body ceiling");
    }
    FUZZ_CHECK(h->body_len <= h->body_total, "body_len past body_total");
    FUZZ_CHECK(h->sh_len <= PREFIX, "sh_len past the ServerHello prefix buffer");
    FUZZ_CHECK(h->record_index <= CLOAK_CLIENT_HANDSHAKE_REPLY_RECORDS,
               "record_index past the reply's record count");
    FUZZ_CHECK(h->reply_bytes <= CLOAK_CLIENT_HANDSHAKE_MAX_REPLY_BYTES,
               "reply_bytes past the reply ceiling");
    FUZZ_CHECK(h->state != CLOAK_CLIENT_HS_STATE_WRITE_HELLO || h->hello_sent < h->hello_len,
               "still in WRITE_HELLO with the whole hello sent");
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    uint8_t flags = data[0];
    uint8_t sizes[SIZE_BYTES];
    for (size_t i = 0; i < SIZE_BYTES; i++) {
        sizes[i] = (1 + i) < size ? data[1 + i] : 0;
    }
    const uint8_t *payload = size > HEADER_BYTES ? data + HEADER_BYTES : NULL;
    size_t payload_len = size > HEADER_BYTES ? size - HEADER_BYTES : 0;
    if (payload_len > MAX_PAYLOAD) {
        payload_len = MAX_PAYLOAD;
    }

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        return 0;
    }
    if (set_nonblocking(sv[0]) != 0 || set_nonblocking(sv[1]) != 0) {
        close(sv[0]);
        close(sv[1]);
        return 0;
    }

    done_state_t done;
    memset(&done, 0, sizeof(done));

    cloak_client_handshake_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.reactor = g_reactor;
    cfg.fd = sv[0];
    cfg.browser = CLOAK_CLIENT_BROWSER_CHROME;
    cfg.server_name = "example.com";
    memcpy(cfg.server_pub, g_server_pub, sizeof(cfg.server_pub));
    memset(cfg.uid, 0x5a, sizeof(cfg.uid));
    cfg.proxy_method = "shadowsocks";
    cfg.encryption_method = 0;
    cfg.session_id = 1;
    cfg.unordered = 0;
    cfg.now_unix = 1700000000;
    cfg.timeout_ms = 0;
    cfg.on_done = on_done;
    cfg.on_done_userdata = &done;

    cloak_client_handshake_t h;
    if (cloak_client_handshake_init(&h, &cfg) != 0) {
        close(sv[0]);
        close(sv[1]);
        return 0;
    }
    if (cloak_client_handshake_start(&h) != 0) {
        cloak_client_handshake_destroy(&h);
        close(sv[0]);
        close(sv[1]);
        return 0;
    }

    /* Let the ClientHello out. A socketpair's send buffer dwarfs the
     * ~1.8KB hello, so one writable turn is normally enough; the bound
     * is a safety net, not an expectation. */
    for (int i = 0; i < 8 && h.state == CLOAK_CLIENT_HS_STATE_WRITE_HELLO; i++) {
        cloak_reactor_run_once(g_reactor, 0);
    }

    /* Build the stream the "server" will send. */
    static uint8_t stream[VALID_RECORD_LEN + MAX_PAYLOAD];
    size_t stream_len = 0;
    uint8_t expect_key[CLOAK_AEAD_KEY_LEN];
    int have_expect_key = 0;

    if ((flags & 0x01u) != 0) {
        /* A ServerHello record laid out exactly as
         * cloak_server_auth_compose_reply lays one out: the 12-byte AEAD
         * nonce at body[6:18), ciphertext[0:20) at body[18:38) and
         * ciphertext[20:48) at body[84:112). Everything else in the
         * prefix is filler the reader must ignore. */
        for (size_t i = 0; i < CLOAK_AEAD_KEY_LEN; i++) {
            expect_key[i] = (uint8_t)(0x40u + i);
        }
        uint8_t nonce[CLOAK_AEAD_NONCE_LEN];
        for (size_t i = 0; i < sizeof(nonce); i++) {
            nonce[i] = (uint8_t)(0x90u + i);
        }
        uint8_t sealed[CLOAK_AEAD_KEY_LEN + CLOAK_AEAD_TAG_LEN];
        size_t sealed_len = 0;
        if (cloak_aead_seal(CLOAK_AEAD_AES_256_GCM, h.shared_secret, nonce, NULL, 0, expect_key,
                            sizeof(expect_key), sealed, &sealed_len) == 0 &&
            sealed_len == sizeof(sealed)) {
            uint8_t *rec = stream;
            memset(rec, 0x11, VALID_RECORD_LEN);
            rec[0] = 0x16;
            rec[1] = 0x03;
            rec[2] = 0x03;
            rec[3] = (uint8_t)(PREFIX >> 8);
            rec[4] = (uint8_t)(PREFIX & 0xffu);
            memcpy(rec + 5 + 6, nonce, sizeof(nonce));
            memcpy(rec + 5 + 18, sealed, 20);
            memcpy(rec + 5 + 84, sealed + 20, 28);
            stream_len = VALID_RECORD_LEN;
            have_expect_key = 1;
        }
    }
    if (payload_len > 0) {
        memcpy(stream + stream_len, payload, payload_len);
        stream_len += payload_len;
    }

    /* Deliver it in the chunks the input asked for. */
    size_t written = 0;
    size_t si = 0;
    while (written < stream_len) {
        uint8_t c = sizes[si % SIZE_BYTES];
        si++;
        size_t n = (size_t)(c & 0x7fu);
        if (n == 0) {
            n = 128;
        }
        if (n > stream_len - written) {
            n = stream_len - written;
        }
        ssize_t w = write(sv[1], stream + written, n);
        if (w <= 0) {
            break; /* the peer stopped reading and the buffer filled */
        }
        written += (size_t)w;
        if ((c & 0x80u) == 0) {
            cloak_reactor_run_once(g_reactor, 0);
            check_invariants(&h);
        }
    }
    cloak_reactor_run_once(g_reactor, 0);
    check_invariants(&h);

    /* O7: with the peer's write half closed there is nothing left to
     * wait for, so the handshake must reach a terminal state. */
    shutdown(sv[1], SHUT_WR);
    for (int i = 0; i < 16 && cloak_client_handshake_status(&h) == CLOAK_CLIENT_HANDSHAKE_PENDING;
         i++) {
        cloak_reactor_run_once(g_reactor, 0);
        check_invariants(&h);
    }
    FUZZ_CHECK(cloak_client_handshake_status(&h) != CLOAK_CLIENT_HANDSHAKE_PENDING,
               "still pending after the peer closed: the reader parked with nothing to wait for");
    FUZZ_CHECK(done.fired == 1, "on_done did not fire exactly once");
    FUZZ_CHECK(done.status == cloak_client_handshake_status(&h), "on_done status disagrees");

    cloak_client_handshake_status_t status = cloak_client_handshake_status(&h);
    cloak_client_handshake_error_t err = cloak_client_handshake_error(&h);

    /* O1: every byte written is either accounted for or still unread.
     * The message names both directions, because the one time this fired
     * it fired the other way: see drain_unread above. */
    FUZZ_CHECK(drain_unread(sv[0]) + h.reply_bytes == written,
               "conservation broken: unread + reply_bytes is not the number of bytes written");

    ref_t ref;
    reference_scan(stream, written, &ref);

    /* O5: the captured ServerHello prefix, whenever it was filled. This
     * needs no valid crypto and so is reachable on nearly every input. */
    if (h.sh_len == PREFIX) {
        FUZZ_CHECK(ref.rec0_header_ok, "prefix captured from a record 0 with no legal header");
        FUZZ_CHECK(ref.rec0_body_off + PREFIX <= written, "prefix captured from bytes never sent");
        FUZZ_CHECK(memcmp(h.sh, stream + ref.rec0_body_off, PREFIX) == 0,
                   "captured ServerHello prefix differs from the bytes on the wire");
    }

    if (status == CLOAK_CLIENT_HANDSHAKE_FAILED && err == CLOAK_CLIENT_HANDSHAKE_ERR_AUTH) {
        /* The sealed key did not open. Only reachable after record 0 has
         * been consumed in full, and the reader must have stopped there.
         * With a harness-sealed record 0 it must not be reachable at all. */
        FUZZ_CHECK(!have_expect_key, "a harness-sealed record 0 failed to authenticate");
        FUZZ_CHECK(ref.rec0_complete, "AUTH failure without a complete record 0");
        /* O2 */
        FUZZ_CHECK(h.reply_bytes == ref.consumed_rec0_end,
                   "AUTH failure did not stop at the end of record 0");
    } else if (ref.verdict == REF_DONE) {
        if (have_expect_key) {
            /* O3 + O4: the structure is complete and record 0 was sealed
             * under this very handshake's shared secret, so nothing is
             * left to fail. */
            FUZZ_CHECK(status == CLOAK_CLIENT_HANDSHAKE_DONE,
                       "a complete, correctly sealed reply did not complete the handshake");
            const uint8_t *key = cloak_client_handshake_session_key(&h);
            FUZZ_CHECK(key != NULL, "DONE with no session key");
            FUZZ_CHECK(memcmp(key, expect_key, CLOAK_AEAD_KEY_LEN) == 0,
                       "recovered session key differs from the one that was sealed");
            FUZZ_CHECK(h.reply_bytes == ref.consumed, "consumed byte count disagrees with the scan");
            FUZZ_CHECK(h.record_index == CLOAK_CLIENT_HANDSHAKE_REPLY_RECORDS,
                       "DONE without three completed records");
        }
        /* Without a harness-sealed record 0 the only other outcome is the
         * AUTH branch above, which has already been taken. Reaching here
         * with DONE would mean 2^-128 luck; nothing is asserted about it. */
    } else if (ref.verdict == REF_PROTOCOL) {
        /* O3 */
        FUZZ_CHECK(status == CLOAK_CLIENT_HANDSHAKE_FAILED, "an illegal record header was accepted");
        FUZZ_CHECK(err == CLOAK_CLIENT_HANDSHAKE_ERR_PROTOCOL,
                   "an illegal record header was not reported as a protocol error");
        /* O2 */
        FUZZ_CHECK(h.reply_bytes == ref.consumed,
                   "rejection did not stop on the offending header's last byte");
    } else {
        /* REF_TRUNCATED: the peer closed mid-reply, which is exactly what
         * a Cloak server does to a client it declines to authenticate. */
        FUZZ_CHECK(status == CLOAK_CLIENT_HANDSHAKE_FAILED, "a truncated reply completed");
        FUZZ_CHECK(err == CLOAK_CLIENT_HANDSHAKE_ERR_EOF,
                   "a truncated reply was not reported as a clean close");
        /* O2: everything sent was consumed, and nothing more. */
        FUZZ_CHECK(h.reply_bytes == ref.consumed, "truncated reply left bytes unread");
    }

    cloak_client_handshake_destroy(&h);
    close(sv[0]);
    close(sv[1]);
    return 0;
}
