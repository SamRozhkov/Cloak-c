#define _POSIX_C_SOURCE 200809L

#include "cloak/client_transport.h"

#include "cloak/common.h"

#include <errno.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>

/* ---- random hostname (Go's randomServerName) --------------------------- */

const char *const cloak_client_top_level_domains[CLOAK_CLIENT_TLD_COUNT] = {
    "com", "net", "org", "it", "fr", "me", "ru", "cn", "es", "tr", "top", "xyz", "info",
};

/* A uniform draw from [0, n). n is tiny here (10, 13, 26) and the draw is
 * 64 bits wide, so the modulo bias is bounded by n / 2^64 -- below 1e-18,
 * i.e. unobservable across every handshake this software will ever
 * perform. That is why this is loop-free: rejection sampling would be
 * exactly unbiased but would introduce an unbounded loop (and a retry
 * branch no test can reach) into a module whose entire design premise is
 * that everything is bounded. Drawing 8 bytes instead of 1 buys the same
 * property with straight-line code.
 *
 * KEPT AS A LOCAL FUNCTION rather than replaced by cloak_random_below,
 * which was added later and rejection-samples exactly as Go's RandInt
 * does. The two differ only in whether the last 1e-18 of bias is removed
 * or merely bounded, and this file's argument for straight-line code in
 * the handshake path is the one that decides it. NOTE THE ARGUMENT'S
 * SCOPE, because two other sites in this tree got it wrong: it works here
 * ONLY because the draw is 8 bytes. The same reasoning applied to a ONE
 * byte draw produced a 2x bias in an on-wire frame length -- see
 * cloak/common.h. If this ever shrinks to one byte, it must become
 * cloak_random_below. */
static unsigned random_below(unsigned n) {
    uint8_t b[8];
    cloak_random_bytes(b, sizeof(b));
    uint64_t v = 0;
    for (size_t i = 0; i < sizeof(b); i++) {
        v = (v << 8) | (uint64_t)b[i];
    }
    return (unsigned)(v % (uint64_t)n);
}

int cloak_client_random_server_name(char *out, size_t cap) {
    if (out == NULL || cap < CLOAK_CLIENT_RANDOM_SERVER_NAME_MAX) {
        return -1;
    }
    /* Go: size := 3 + common.RandInt(10), i.e. 3..12 inclusive. */
    unsigned size = 3u + random_below(10u);
    size_t i = 0;
    for (; i < (size_t)size; i++) {
        out[i] = (char)('a' + (int)random_below(26u));
    }
    out[i++] = '.';
    const char *tld = cloak_client_top_level_domains[random_below(CLOAK_CLIENT_TLD_COUNT)];
    size_t tld_len = strlen(tld);
    memcpy(out + i, tld, tld_len);
    out[i + tld_len] = '\0';
    return 0;
}

/* ---- small helpers ------------------------------------------------------ */

static void store_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xff);
}

static size_t min_size(size_t a, size_t b) {
    return a < b ? a : b;
}

static const cloak_clienthello_template_t *template_for(cloak_client_browser_t b) {
    switch (b) {
    case CLOAK_CLIENT_BROWSER_CHROME:
        return &cloak_clienthello_chrome;
    case CLOAK_CLIENT_BROWSER_FIREFOX:
        return &cloak_clienthello_firefox;
    case CLOAK_CLIENT_BROWSER_SAFARI:
        return &cloak_clienthello_safari;
    }
    return NULL;
}

/* Releases everything the reactor holds on behalf of h: the fd
 * registration (the fd itself is never closed -- see the header) and the
 * deadline timer. Idempotent, and the only place either is released, so a
 * handshake that ends for any reason ends in exactly this state. */
static void release_reactor(cloak_client_handshake_t *h) {
    if (h->fd_registered) {
        cloak_reactor_remove_fd(h->reactor, h->fd);
        h->fd_registered = 0;
        h->fd_interest = 0;
    }
    if (h->deadline_timer != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(h->reactor, h->deadline_timer);
        h->deadline_timer = CLOAK_TIMER_INVALID;
    }
}

/* Marks the handshake terminally failed. Deliberately does NOT fire
 * on_done: every entry point calls `finish` as its last statement
 * instead, so the callback is never invoked with this module's own call
 * frames still on the stack above it -- which is what makes it legal for
 * a caller to free h from inside on_done. */
static void fail(cloak_client_handshake_t *h, cloak_client_handshake_error_t err) {
    if (h->status != CLOAK_CLIENT_HANDSHAKE_PENDING) {
        return;
    }
    h->status = CLOAK_CLIENT_HANDSHAKE_FAILED;
    h->state = CLOAK_CLIENT_HS_STATE_FAILED;
    h->error = err;
    release_reactor(h);
}

static void complete(cloak_client_handshake_t *h) {
    if (h->status != CLOAK_CLIENT_HANDSHAKE_PENDING) {
        return;
    }
    h->status = CLOAK_CLIENT_HANDSHAKE_DONE;
    h->state = CLOAK_CLIENT_HS_STATE_DONE;
    h->error = CLOAK_CLIENT_HANDSHAKE_ERR_NONE;
    release_reactor(h);
}

/* MUST be the last statement of any function the reactor can call into
 * this module: h may be destroyed or freed by on_done. */
static void finish(cloak_client_handshake_t *h) {
    if (h->status == CLOAK_CLIENT_HANDSHAKE_PENDING || h->notified) {
        return;
    }
    h->notified = 1;
    if (h->on_done != NULL) {
        h->on_done(h, h->status, h->on_done_userdata);
    }
}

static void set_interest(cloak_client_handshake_t *h, uint32_t want) {
    if (!h->fd_registered || h->fd_interest == want) {
        return;
    }
    if (cloak_reactor_mod_fd(h->reactor, h->fd, want) != 0) {
        fail(h, CLOAK_CLIENT_HANDSHAKE_ERR_IO);
        return;
    }
    h->fd_interest = want;
}

/* ---- the read half: an incremental, never-over-reading record reader ---- */

/* Recovers the session key from the ServerHello prefix captured in h->sh.
 *
 * REIMPLEMENTED, NOT SHARED, and the reason is worth stating: the only
 * existing implementation of this split is
 * extract_session_key_from_reply in libcloak-server/tests/client_harness.h
 * -- a TEST header in the SERVER library's test directory, which a
 * shipped client library cannot link against. The offsets below are
 * therefore re-derived from cloak_server_auth_compose_reply itself (the
 * producing side) and are expressed in ServerHello-handshake-message
 * coordinates, whereas the harness expresses the same three offsets in
 * whole-reply coordinates, 5 bytes further along:
 *
 *   reply nonce        sh[6:18)    == reply[11:23)
 *   ciphertext[0:20)   sh[18:38)   == reply[23:43)   (rest of `random`)
 *   ciphertext[20:48)  sh[84:112)  == reply[89:117)  (key_share payload)
 *
 * Together the two pieces are the 48-byte AES-256-GCM ciphertext+tag of
 * the server's chosen 32-byte session key, sealed under the same ECDH
 * shared secret cloak_client_auth_build already derived. Go does the same
 * thing with buf[6:38] ++ buf[84:116] (internal/client/TLS.go) -- the
 * same offsets, since Go's TLSConn.Read hands it the record-stripped
 * handshake message too. */
static int recover_session_key(cloak_client_handshake_t *h) {
    if (h->sh_len < CLOAK_CLIENT_HANDSHAKE_SERVERHELLO_PREFIX) {
        return -1;
    }
    uint8_t ciphertext[48];
    memcpy(ciphertext, h->sh + 18, 20);
    memcpy(ciphertext + 20, h->sh + 84, 28);

    uint8_t key[CLOAK_AEAD_KEY_LEN];
    size_t key_len = 0;
    if (cloak_aead_open(CLOAK_AEAD_AES_256_GCM, h->shared_secret, h->sh + 6, NULL, 0, ciphertext,
                        sizeof(ciphertext), key, &key_len) != 0) {
        return -1;
    }
    if (key_len != CLOAK_AEAD_KEY_LEN) {
        return -1;
    }
    memcpy(h->session_key, key, CLOAK_AEAD_KEY_LEN);
    return 0;
}

/* One record has been fully consumed. Record 0 (the ServerHello) yields
 * the session key; records 1 and 2 (ChangeCipherSpec and the fake
 * Certificate) are discarded unparsed, exactly as Go discards them -- it
 * reads them only to leave the stream positioned at the start of the
 * session's first frame. */
static void record_complete(cloak_client_handshake_t *h) {
    h->record_index++;
    if (h->record_index == 1) {
        if (recover_session_key(h) != 0) {
            fail(h, CLOAK_CLIENT_HANDSHAKE_ERR_AUTH);
            return;
        }
    }
    if (h->record_index == CLOAK_CLIENT_HANDSHAKE_REPLY_RECORDS) {
        complete(h);
        return;
    }
    h->header_len = 0;
    h->body_len = 0;
    h->body_total = 0;
    h->state = CLOAK_CLIENT_HS_STATE_READ_RECORD_HEADER;
}

/* How many bytes of the piece currently in flight are still missing.
 * This -- never a larger, speculative amount -- is exactly what the read
 * loop asks the kernel for, which is what guarantees no byte belonging to
 * the session's first frame is consumed here. */
static size_t bytes_wanted(const cloak_client_handshake_t *h) {
    if (h->state == CLOAK_CLIENT_HS_STATE_READ_RECORD_HEADER) {
        return 5 - h->header_len;
    }
    if (h->state == CLOAK_CLIENT_HS_STATE_READ_RECORD_BODY) {
        return h->body_total - h->body_len;
    }
    return 0;
}

/* Advances the machine by len bytes. Makes progress on ANY split: len may
 * be 1, and may land in the middle of a record header, in the middle of
 * the ServerHello prefix, or anywhere else. */
static void feed(cloak_client_handshake_t *h, const uint8_t *data, size_t len) {
    size_t i = 0;
    while (i < len && h->status == CLOAK_CLIENT_HANDSHAKE_PENDING) {
        if (h->state == CLOAK_CLIENT_HS_STATE_READ_RECORD_HEADER) {
            size_t take = min_size(5 - h->header_len, len - i);
            memcpy(h->header + h->header_len, data + i, take);
            h->header_len += take;
            h->reply_bytes += take;
            i += take;
            if (h->header_len < 5) {
                continue;
            }
            h->body_total = ((size_t)h->header[3] << 8) | (size_t)h->header[4];
            if (h->body_total > CLOAK_CLIENT_HANDSHAKE_MAX_RECORD_BODY) {
                fail(h, CLOAK_CLIENT_HANDSHAKE_ERR_PROTOCOL);
                return;
            }
            if (h->record_index == 0) {
                /* The one record whose contents are load-bearing. A
                 * ServerHello too short to hold both halves of the sealed
                 * session key is rejected here rather than later, so the
                 * key recovery below never reads uninitialised bytes of
                 * h->sh. */
                if (h->header[0] != 0x16 ||
                    h->body_total < CLOAK_CLIENT_HANDSHAKE_SERVERHELLO_PREFIX) {
                    fail(h, CLOAK_CLIENT_HANDSHAKE_ERR_PROTOCOL);
                    return;
                }
            }
            /* A CONSISTENCY GUARD BETWEEN TWO CONSTANTS. NOT a bound on
             * the wire -- read that first, because it looks like one.
             *
             * No input can reach it. CLOAK_CLIENT_HANDSHAKE_MAX_REPLY_BYTES
             * is defined as exactly CLOAK_CLIENT_HANDSHAKE_REPLY_RECORDS *
             * (5 + CLOAK_CLIENT_HANDSHAKE_MAX_RECORD_BODY), the per-record
             * bound above already rejects any record whose body exceeds
             * CLOAK_CLIENT_HANDSHAKE_MAX_RECORD_BODY, and the reply is
             * always exactly that many records -- so the
             * sum is arithmetically incapable of exceeding the ceiling
             * while those two hold. This project's rule is to delete
             * unreachable defensive code rather than annotate it, and on
             * the wire-bound reading this would go.
             *
             * It is kept on the other reading: it is what makes an
             * inconsistent edit to those two constants FAIL LOUDLY here
             * instead of silently turning the header's documented ceiling
             * into a lie. That is a real job, and there is nowhere
             * cheaper to do it. If you change either constant, expect this
             * to be the thing that tells you. */
            if (h->reply_bytes + h->body_total > CLOAK_CLIENT_HANDSHAKE_MAX_REPLY_BYTES) {
                fail(h, CLOAK_CLIENT_HANDSHAKE_ERR_PROTOCOL);
                return;
            }
            h->body_len = 0;
            h->state = CLOAK_CLIENT_HS_STATE_READ_RECORD_BODY;
            if (h->body_total == 0) {
                record_complete(h);
            }
            continue;
        }
        if (h->state == CLOAK_CLIENT_HS_STATE_READ_RECORD_BODY) {
            size_t take = min_size(h->body_total - h->body_len, len - i);
            if (h->record_index == 0 && h->sh_len < CLOAK_CLIENT_HANDSHAKE_SERVERHELLO_PREFIX) {
                size_t copy = min_size(take, CLOAK_CLIENT_HANDSHAKE_SERVERHELLO_PREFIX - h->sh_len);
                memcpy(h->sh + h->sh_len, data + i, copy);
                h->sh_len += copy;
            }
            h->body_len += take;
            h->reply_bytes += take;
            i += take;
            if (h->body_len == h->body_total) {
                record_complete(h);
            }
            continue;
        }
        break;
    }
}

static void do_read(cloak_client_handshake_t *h) {
    /* Edge-triggered registration: drain until EAGAIN or the handshake
     * ends, or the next readiness edge never arrives. */
    while (h->status == CLOAK_CLIENT_HANDSHAKE_PENDING) {
        size_t want = bytes_wanted(h);
        if (want == 0) {
            return;
        }
        uint8_t scratch[1024];
        if (want > sizeof(scratch)) {
            want = sizeof(scratch);
        }
        ssize_t n = recv(h->fd, scratch, want, 0);
        if (n > 0) {
            feed(h, scratch, (size_t)n);
            continue;
        }
        if (n == 0) {
            /* A clean close before the reply was complete. */
            fail(h, CLOAK_CLIENT_HANDSHAKE_ERR_EOF);
            return;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }
        fail(h, CLOAK_CLIENT_HANDSHAKE_ERR_IO);
        return;
    }
}

/* ---- the write half ----------------------------------------------------- */

static void do_write(cloak_client_handshake_t *h) {
    while (h->hello_sent < h->hello_len) {
        size_t remaining = h->hello_len - h->hello_sent;
        /* send() with MSG_NOSIGNAL rather than write(): a server that has
         * already closed would otherwise raise SIGPIPE and kill the whole
         * process, since nothing in this tree installs a handler for it
         * (the same reasoning conn.c and relay.c state for their own
         * writes). */
        ssize_t n = send(h->fd, h->hello + h->hello_sent, remaining, MSG_NOSIGNAL);
        if (n > 0) {
            h->hello_sent += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            /* A partial write. The ClientHello can be ~2KB and a socket
             * send buffer can be smaller, so this is an ordinary event,
             * not an error: keep the position and wait for the next
             * writable edge. */
            return;
        }
        if (n == 0) {
            /* Not reachable for a nonzero-length send on a stream socket,
             * but returning rather than looping keeps a surprising kernel
             * from spinning the reactor at 100% CPU. */
            return;
        }
        fail(h, CLOAK_CLIENT_HANDSHAKE_ERR_IO);
        return;
    }
    h->state = CLOAK_CLIENT_HS_STATE_READ_RECORD_HEADER;
    set_interest(h, CLOAK_REACTOR_READABLE);
}

/* ---- reactor entry points ----------------------------------------------- */

static void on_event(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    /* events is deliberately ignored: this reactor folds EPOLLHUP/EPOLLERR
     * into CLOAK_REACTOR_READABLE regardless of the registered mask (see
     * cloak/reactor.h), so the only reliable way to tell a hangup from
     * real readiness is to attempt the I/O the current state calls for
     * and read errno. */
    (void)events;
    cloak_client_handshake_t *h = userdata;
    if (h->status != CLOAK_CLIENT_HANDSHAKE_PENDING) {
        return;
    }
    if (h->state == CLOAK_CLIENT_HS_STATE_WRITE_HELLO) {
        do_write(h);
    }
    if (h->status == CLOAK_CLIENT_HANDSHAKE_PENDING &&
        (h->state == CLOAK_CLIENT_HS_STATE_READ_RECORD_HEADER ||
         h->state == CLOAK_CLIENT_HS_STATE_READ_RECORD_BODY)) {
        do_read(h);
    }
    finish(h); /* last statement: h may be freed by on_done */
}

static void on_deadline(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_client_handshake_t *h = userdata;
    /* The timer has fired, so it must not be cancelled again. */
    h->deadline_timer = CLOAK_TIMER_INVALID;
    fail(h, CLOAK_CLIENT_HANDSHAKE_ERR_TIMEOUT);
    finish(h); /* last statement: h may be freed by on_done */
}

/* ---- construction ------------------------------------------------------- */

int cloak_client_handshake_init(cloak_client_handshake_t *h,
                                 const cloak_client_handshake_config_t *cfg) {
    if (h == NULL) {
        return -1;
    }
    /* Fully initialized BEFORE anything is validated, so every rejected
     * call still leaves h safe for cloak_client_handshake_destroy. */
    memset(h, 0, sizeof(*h));
    h->fd = -1;
    h->deadline_timer = CLOAK_TIMER_INVALID;
    h->state = CLOAK_CLIENT_HS_STATE_FAILED;
    h->status = CLOAK_CLIENT_HANDSHAKE_FAILED;
    h->error = CLOAK_CLIENT_HANDSHAKE_ERR_CONFIG;
    h->notified = 1; /* a never-started handshake must never fire on_done */

    if (cfg == NULL || cfg->reactor == NULL || cfg->fd < 0 || cfg->server_name == NULL ||
        cfg->proxy_method == NULL || cfg->on_done == NULL) {
        return -1;
    }
    const cloak_clienthello_template_t *tmpl = template_for(cfg->browser);
    if (tmpl == NULL) {
        return -1;
    }
    if (strlen(cfg->proxy_method) > CLOAK_PROXY_METHOD_LEN) {
        return -1;
    }

    /* Go: strings.EqualFold(fields.serverName, "random") -> generate. */
    if (strcasecmp(cfg->server_name, "random") == 0) {
        if (cloak_client_random_server_name(h->server_name, sizeof(h->server_name)) != 0) {
            return -1;
        }
    } else {
        size_t n = strlen(cfg->server_name);
        if (n == 0 || n > CLOAK_CLIENT_SERVER_NAME_MAX) {
            return -1;
        }
        memcpy(h->server_name, cfg->server_name, n + 1);
    }

    cloak_client_auth_payload_t payload;
    if (cloak_client_auth_build(cfg->uid, cfg->proxy_method, cfg->encryption_method,
                                 cfg->session_id, cfg->unordered, cfg->now_unix, cfg->server_pub,
                                 &payload, h->shared_secret) != 0) {
        h->error = CLOAK_CLIENT_HANDSHAKE_ERR_BUILD;
        return -1;
    }

    /* random = the ephemeral public key; session_id = ciphertext[0:32);
     * x25519_key_share = ciphertext[32:64) -- the split
     * cloak_server_auth_decrypt reads back on the other end. */
    long hs_len = cloak_clienthello_build(tmpl, payload.random, payload.ciphertext,
                                           payload.ciphertext + 32, h->server_name, h->hello + 5,
                                           sizeof(h->hello) - 5);
    if (hs_len <= 0) {
        h->error = CLOAK_CLIENT_HANDSHAKE_ERR_BUILD;
        return -1;
    }

    /* Go: common.AddRecordLayer(ch, common.Handshake, common.VersionTLS11)
     * -- content type 0x16, legacy_record_version 0x0301, which is
     * exactly what cloak_clienthello_parse requires on the other end. */
    h->hello[0] = 0x16;
    h->hello[1] = 0x03;
    h->hello[2] = 0x01;
    store_be16(h->hello + 3, (uint16_t)hs_len);
    h->hello_len = 5 + (size_t)hs_len;

    h->reactor = cfg->reactor;
    h->fd = cfg->fd;
    h->timeout_ms = cfg->timeout_ms != 0 ? cfg->timeout_ms
                                          : (uint64_t)CLOAK_CLIENT_HANDSHAKE_DEFAULT_TIMEOUT_MS;
    h->on_done = cfg->on_done;
    h->on_done_userdata = cfg->on_done_userdata;

    h->state = CLOAK_CLIENT_HS_STATE_WRITE_HELLO;
    h->status = CLOAK_CLIENT_HANDSHAKE_PENDING;
    h->error = CLOAK_CLIENT_HANDSHAKE_ERR_NONE;
    h->notified = 0;
    return 0;
}

int cloak_client_handshake_start(cloak_client_handshake_t *h) {
    if (h == NULL || h->status != CLOAK_CLIENT_HANDSHAKE_PENDING ||
        h->state != CLOAK_CLIENT_HS_STATE_WRITE_HELLO || h->fd_registered) {
        return -1;
    }
    if (cloak_reactor_add_fd(h->reactor, h->fd, CLOAK_REACTOR_WRITABLE, on_event, h) != 0) {
        h->status = CLOAK_CLIENT_HANDSHAKE_FAILED;
        h->state = CLOAK_CLIENT_HS_STATE_FAILED;
        h->error = CLOAK_CLIENT_HANDSHAKE_ERR_IO;
        h->notified = 1;
        return -1;
    }
    h->fd_registered = 1;
    h->fd_interest = CLOAK_REACTOR_WRITABLE;

    /* Armed here, before a single byte moves, so it bounds the WHOLE
     * handshake -- the write of the ClientHello included -- not merely
     * the wait for a reply. */
    h->deadline_timer = cloak_reactor_add_timer(h->reactor, h->timeout_ms, on_deadline, h);
    if (h->deadline_timer == CLOAK_TIMER_INVALID) {
        cloak_reactor_remove_fd(h->reactor, h->fd);
        h->fd_registered = 0;
        h->fd_interest = 0;
        h->status = CLOAK_CLIENT_HANDSHAKE_FAILED;
        h->state = CLOAK_CLIENT_HS_STATE_FAILED;
        h->error = CLOAK_CLIENT_HANDSHAKE_ERR_IO;
        h->notified = 1;
        return -1;
    }
    return 0;
}

void cloak_client_handshake_destroy(cloak_client_handshake_t *h) {
    if (h == NULL || h->reactor == NULL) {
        /* A zeroed or failed-init h holds nothing: no registration (the
         * reactor pointer is only set once init has succeeded) and no
         * timer. Nothing to release. */
        return;
    }
    release_reactor(h);
    h->notified = 1;
    if (h->status == CLOAK_CLIENT_HANDSHAKE_PENDING) {
        h->status = CLOAK_CLIENT_HANDSHAKE_FAILED;
        h->state = CLOAK_CLIENT_HS_STATE_FAILED;
    }
}

/* ---- accessors ---------------------------------------------------------- */

cloak_client_handshake_status_t cloak_client_handshake_status(const cloak_client_handshake_t *h) {
    return h == NULL ? CLOAK_CLIENT_HANDSHAKE_FAILED : h->status;
}

cloak_client_handshake_error_t cloak_client_handshake_error(const cloak_client_handshake_t *h) {
    return h == NULL ? CLOAK_CLIENT_HANDSHAKE_ERR_CONFIG : h->error;
}

const uint8_t *cloak_client_handshake_session_key(const cloak_client_handshake_t *h) {
    if (h == NULL || h->status != CLOAK_CLIENT_HANDSHAKE_DONE) {
        return NULL;
    }
    return h->session_key;
}

const char *cloak_client_handshake_server_name(const cloak_client_handshake_t *h) {
    if (h == NULL || h->server_name[0] == '\0') {
        return NULL;
    }
    return h->server_name;
}
