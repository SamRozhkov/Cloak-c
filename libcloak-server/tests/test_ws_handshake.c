/* Tests for the CDN/WebSocket upgrade parser (cloak/ws_handshake.h).
 *
 * THE ORACLE, AND WHY THIS FILE HAS ONE AT ALL. Every literal below that
 * says "gorilla measured this" was produced by running Go 1.25.6 and
 * gorilla/websocket v1.5.3 inside this project's dev image: a live
 * `http.Serve` with `Upgrader{}` defaults over a net.Pipe, fed the exact
 * bytes in the test, with its status line and response captured. The
 * golden request is not hand-written either -- it is what
 * `websocket.NewClient(conn, u, header, 16480, 16480)`, the call Cloak
 * makes at internal/client/websocket.go:52, actually put on the wire.
 *
 * That matters because this project's standing lesson is that a
 * round-trip test cannot see a self-consistent error: both ends are our
 * own code, so an agreed-upon mistake passes. Here the accept vector
 * comes from RFC 6455 section 1.3 itself, and the accept/refuse decision
 * for every crafted request comes from an independently written Go
 * implementation that has never seen this code.
 *
 * THE THREAT MODEL, which decides how the inputs are built. These bytes
 * arrive from an unauthenticated peer -- the first thing a censor's
 * prober reaches. So EVERY input is copied into a heap allocation of
 * exactly its own length before it is parsed (parse_exact below), which
 * puts an ASan redzone immediately after the last byte: a parser that
 * reads one byte past `len` crashes here rather than passing. Nothing in
 * this file calls cloak_ws_handshake_parse on a stack buffer or a string
 * literal, because one such call silently disables that whole defence for
 * the input it uses.
 */

#define _POSIX_C_SOURCE 200809L

#include "cloak/ws_handshake.h"
#include "test_framework.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Interposition on EVP_Digest                                         */
/* ------------------------------------------------------------------ */

/* This binary supplies its OWN EVP_Digest, for one reason:
 * CLOAK_WS_HS_ERR_INTERNAL is unreachable from any input. SHA-1 over 60
 * bytes fails only if OpenSSL cannot allocate a digest context, and no
 * crafted request can make that happen -- so without an interposed
 * definition that return would be a line no test can ever execute, which
 * is the "dead code that merely looks like safety" this tree's http.h
 * already argues against.
 *
 * How it resolves: the executable's own definition preempts libcrypto's
 * for every call in this binary, including the calls made from
 * cloak-server's static archive. When digest_fail is 0 this forwards to
 * the real thing through the EVP_MD_CTX API (not through EVP_Digest,
 * which would recurse), so the accept values the tests check are still
 * OpenSSL's SHA-1 rather than a fixture.
 *
 * AND IT IS PROVEN TO INTERCEPT rather than merely to exist: digest_calls
 * is asserted non-zero after a successful parse, and the golden accepts
 * -- constants from gorilla and from RFC 6455 -- still match with the
 * interposition in place. A stub that was never called could not move
 * that counter; a stub that was called but computed the wrong thing could
 * not reproduce the RFC's own vector. */
static int digest_fail;
static int digest_calls;

int EVP_Digest(const void *data, size_t count, unsigned char *md,
               unsigned int *size, const EVP_MD *type, ENGINE *impl) {
    (void)impl;
    digest_calls++;
    if (digest_fail) {
        return 0;
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return 0;
    }
    int ok = EVP_DigestInit_ex(ctx, type, NULL) == 1 &&
             EVP_DigestUpdate(ctx, data, count) == 1 &&
             EVP_DigestFinal_ex(ctx, md, size) == 1;
    EVP_MD_CTX_free(ctx);
    return ok ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* Golden bytes, captured from live Go + gorilla                       */
/* ------------------------------------------------------------------ */

/* The 96-byte Hidden plaintext used throughout: p[i] = (i*7+3) & 0xff.
 * On the wire it is randPubKey[0:32] || ciphertextWithTag[0:64]; this
 * layer does not interpret it, so an arbitrary but checkable pattern is
 * exactly as good as a real one and lets every test assert all 96 bytes
 * rather than a length. */
#define HIDDEN_B64                                                             \
    "AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dzj6vH4/wYNFBsiKTA3PkVMU1phaG92" \
    "fYSLkpmgp661vMPK0djf5u30+wIJEBceJSwzOkFIT1ZdZGtyeYCHjpWc"

/* HIDDEN_B64 split after 60 characters, for the obs-fold test: the two
 * halves concatenate to exactly HIDDEN_B64, which is what lets that test
 * tell a parser that refuses a fold from one that joins it. The split
 * point is 60 rather than a round 64 so that the fold-inserted space
 * lands where Go's own decoder reports it -- "illegal base64 data at
 * input byte 60" -- and the partial decode before it is exactly 45
 * bytes, both measured. test_the_fold_halves_are_the_whole_payload
 * asserts the concatenation, so a future edit to either half that broke
 * the property would fail loudly instead of quietly turning the fold test
 * back into the weaker one it used to be. */
#define HIDDEN_B64_HEAD60 "AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dzj6vH4/wYNFBsiKTA3"
#define HIDDEN_B64_TAIL68 "PkVMU1phaG92fYSLkpmgp661vMPK0djf5u30+wIJEBceJSwzOkFIT1ZdZGtyeYCHjpWc"

/* The same 96 bytes with 95 and 97 in their place, and a 128-character
 * value that decodes to 94. All three exist to bracket "exactly 96" from
 * both sides -- and the last two prove the check is on the DECODED
 * length: the 95-byte encoding is also 128 characters long (it ends in
 * one '='), so a parser that checked the string length would accept it. */
#define HIDDEN_B64_95                                                          \
    "AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dzj6vH4/wYNFBsiKTA3PkVMU1phaG92" \
    "fYSLkpmgp661vMPK0djf5u30+wIJEBceJSwzOkFIT1ZdZGtyeYCHjpU="
#define HIDDEN_B64_97                                                          \
    "AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dzj6vH4/wYNFBsiKTA3PkVMU1phaG92" \
    "fYSLkpmgp661vMPK0djf5u30+wIJEBceJSwzOkFIT1ZdZGtyeYCHjpWcow=="
#define HIDDEN_B64_94_IN_128_CHARS                                             \
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="

/* The same 96 bytes in the URL-safe alphabet ('-' and '_' for '+' and
 * '/'). Go's StdEncoding refuses it, and so must this: base64.h ships
 * both decoders one character apart in the call, and picking the wrong
 * one is a mistake a C-to-C round trip cannot see. */
#define HIDDEN_B64_URLSAFE                                                     \
    "AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dzj6vH4_wYNFBsiKTA3PkVMU1phaG92" \
    "fYSLkpmgp661vMPK0djf5u30-wIJEBceJSwzOkFIT1ZdZGtyeYCHjpWc"

/* Four key/accept pairs. Every accept is what live gorilla wrote back to
 * a request carrying that key, and the second one is RFC 6455 section
 * 1.3's own published sample -- an outside constant that no amount of
 * self-consistency can produce. */
#define KEY_GO "Q6fJUvdRNbjAgU3LVM25sg=="
#define ACCEPT_GO "fmxopr2FgzOlKg8nTOunDaBh4TU="
#define KEY_RFC "dGhlIHNhbXBsZSBub25jZQ=="
#define ACCEPT_RFC "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
#define KEY_ZEROS "AAAAAAAAAAAAAAAAAAAAAA=="
#define ACCEPT_ZEROS "ICX+Yqv66kxgM0FcWaLWlFLwTAI="
#define KEY_COUNT "AAECAwQFBgcICQoLDA0ODw==" /* base64 of 0x00..0x0f */
#define ACCEPT_COUNT "Bz3qJYTGdOe8gUSpLosEdiLKDrk="

/* Exactly what websocket.NewClient wrote, 335 bytes, and exactly what a
 * gorilla Upgrader{} wrote back to it, 129 bytes. Nothing in either
 * literal was typed from documentation. */
static const char GOLDEN_REQUEST[] =
    "GET /ws/path HTTP/1.1\r\n"
    "Host: cdn.example.com:443\r\n"
    "User-Agent: Go-http-client/1.1\r\n"
    "Connection: Upgrade\r\n"
    "Hidden: " HIDDEN_B64 "\r\n"
    "Sec-WebSocket-Key: " KEY_GO "\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Upgrade: websocket\r\n"
    "\r\n";

static const char GOLDEN_RESPONSE[] =
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Accept: " ACCEPT_GO "\r\n"
    "\r\n";

/* ------------------------------------------------------------------ */
/* Harness                                                             */
/* ------------------------------------------------------------------ */

/* Parses a copy of `req` held in an allocation of exactly `len` bytes.
 * See the file header: this is the only way any test in this file reaches
 * the parser. */
static cloak_ws_hs_result_t parse_exact(const char *req, size_t len,
                                        cloak_ws_hs_t *out) {
    uint8_t *heap = NULL;
    if (len > 0) {
        heap = malloc(len);
        if (heap == NULL) {
            ASSERT_TRUE(0);
            return CLOAK_WS_HS_ERR_INTERNAL;
        }
        memcpy(heap, req, len);
    }
    cloak_ws_hs_result_t r = cloak_ws_handshake_parse(heap, len, out);
    free(heap);
    return r;
}

static cloak_ws_hs_result_t parse_str(const char *req, cloak_ws_hs_t *out) {
    return parse_exact(req, strlen(req), out);
}

/* THE HOST TRAP, and the one mechanical defence against it.
 *
 * Every false "measured" claim this file has carried -- four of them,
 * found across three review rounds -- was a claim about a request literal
 * with NO Host header. Go answers `400 Bad Request: missing required Host
 * header` to ANY HTTP/1.1 request that omits it (RFC 9112 3.2), before
 * the handler runs and for a reason that has nothing to do with the
 * property under test. So a Go measurement taken against such a literal
 * measures the Host check and nothing else, and it will agree with
 * whatever the comment above it claims, because 400 is also what a
 * genuinely malformed request gets. That is this project's most
 * expensive recurring shape -- a test green by a path other than the one
 * it names -- appearing here four times in one file, which makes it a
 * defect in how the literals are built rather than four typos.
 *
 * parse_measured is parse_exact plus one guard: the bytes must carry a
 * Host header line. USE IT FOR EVERY HAND-WRITTEN LITERAL WHOSE COMMENT
 * CLAIMS WHAT GO ANSWERS. A future literal that forgets Host then fails
 * here, loudly, instead of quietly becoming the fifth instance.
 *
 * Two deliberate exemptions, both of which would be wrong to guard:
 * requests that are TRUNCATED (the prefix sweep, and the "header block
 * never ends" cases) cannot be required to contain a Host line, since
 * the truncation is the point and Go answers nothing at all to them; and
 * the Host tests themselves, which omit Host on purpose and document the
 * divergence rather than claiming a measurement. Requests built through
 * build() need no guard: it emits Host by default, and the only way to
 * drop it is to write OMIT. */
static int has_host_header(const char *req, size_t len) {
    /* A Host line is a line whose name is "host", so look for a line
     * break followed by it. Case-insensitive, because the whole point of
     * this file is that a CDN rewrites the case of every name. */
    for (size_t i = 0; i + 6 <= len; i++) {
        if (req[i] != '\n') {
            continue;
        }
        const char *p = req + i + 1;
        size_t avail = len - i - 1;
        if (avail < 5) {
            return 0;
        }
        if ((p[0] == 'h' || p[0] == 'H') && (p[1] == 'o' || p[1] == 'O') &&
            (p[2] == 's' || p[2] == 'S') && (p[3] == 't' || p[3] == 'T') &&
            p[4] == ':') {
            return 1;
        }
    }
    return 0;
}

static cloak_ws_hs_result_t parse_measured(const char *req, size_t len,
                                           cloak_ws_hs_t *out) {
    if (!has_host_header(req, len)) {
        fprintf(stderr,
                "FAIL %s:%d: a literal used under a \"measured\" claim has no "
                "Host header; Go would 400 it for that reason alone\n",
                __FILE__, __LINE__);
        cloak_test_failures++;
    }
    return parse_exact(req, len, out);
}

/* The expected 96 bytes of Hidden plaintext. */
static void fill_expected_hidden(uint8_t *p) {
    for (size_t i = 0; i < CLOAK_WS_HS_HIDDEN_LEN; i++) {
        p[i] = (uint8_t)((i * 7 + 3) & 0xff);
    }
}

static void assert_hidden_ok(const cloak_ws_hs_t *hs) {
    uint8_t want[CLOAK_WS_HS_HIDDEN_LEN];
    fill_expected_hidden(want);
    ASSERT_MEM_EQ(want, hs->hidden, sizeof(want));
}

/* A sentinel meaning "leave this header out entirely". Compared by
 * pointer, so no legitimate value can collide with it. */
static const char OMIT_STORAGE[] = "<omit>";
#define OMIT (OMIT_STORAGE)

typedef struct {
    const char *request_line; /* default: Go's own */
    const char *host;
    const char *hidden_name; /* default "Hidden" */
    const char *hidden;      /* default HIDDEN_B64 */
    const char *conn;        /* default "Upgrade" */
    const char *key;         /* default KEY_GO */
    const char *version;     /* default "13" */
    const char *upgrade;     /* default "websocket" */
    const char *extra;       /* raw lines, each ending in CRLF */
} req_t;

static void app(char *buf, size_t cap, size_t *n, const char *s) {
    size_t l = strlen(s);
    if (*n + l >= cap) {
        ASSERT_TRUE(0);
        return;
    }
    memcpy(buf + *n, s, l);
    *n += l;
    buf[*n] = '\0';
}

static void app_hdr(char *buf, size_t cap, size_t *n, const char *name,
                    const char *val, const char *dflt) {
    if (val == OMIT) {
        return;
    }
    app(buf, cap, n, name);
    app(buf, cap, n, ": ");
    app(buf, cap, n, val != NULL ? val : dflt);
    app(buf, cap, n, "\r\n");
}

/* Assembles a request in Go's own header order -- Host, User-Agent, then
 * Connection, Hidden, Sec-WebSocket-Key, Sec-WebSocket-Version, Upgrade,
 * which is net/http's sorted-key order for everything Cloak sets. With
 * every field defaulted it reproduces GOLDEN_REQUEST byte for byte, and
 * test_the_builder_reproduces_the_golden_request asserts exactly that, so
 * no variant below can drift away from what Go really sends. */
static size_t build(char *buf, size_t cap, req_t r) {
    size_t n = 0;
    buf[0] = '\0';
    app(buf, cap, &n,
        r.request_line != NULL ? r.request_line : "GET /ws/path HTTP/1.1");
    app(buf, cap, &n, "\r\n");
    app_hdr(buf, cap, &n, "Host", r.host, "cdn.example.com:443");
    app(buf, cap, &n, "User-Agent: Go-http-client/1.1\r\n");
    app_hdr(buf, cap, &n, "Connection", r.conn, "Upgrade");
    app_hdr(buf, cap, &n, r.hidden_name != NULL ? r.hidden_name : "Hidden",
            r.hidden, HIDDEN_B64);
    app_hdr(buf, cap, &n, "Sec-WebSocket-Key", r.key, KEY_GO);
    app_hdr(buf, cap, &n, "Sec-WebSocket-Version", r.version, "13");
    app_hdr(buf, cap, &n, "Upgrade", r.upgrade, "websocket");
    if (r.extra != NULL) {
        app(buf, cap, &n, r.extra);
    }
    app(buf, cap, &n, "\r\n");
    return n;
}

/* Builds and parses in one step. */
static cloak_ws_hs_result_t parse_built(req_t r, cloak_ws_hs_t *out) {
    char buf[4096];
    size_t n = build(buf, sizeof(buf), r);
    return parse_exact(buf, n, out);
}

/* Composes into an allocation of exactly `cap` bytes, so a write past the
 * declared capacity is an ASan crash rather than a silent pass. */
static ssize_t compose_exact(size_t cap, const char *accept, uint8_t *copy_out) {
    uint8_t *heap = NULL;
    if (cap > 0) {
        heap = malloc(cap);
        if (heap == NULL) {
            ASSERT_TRUE(0);
            return -1;
        }
        memset(heap, 0x5a, cap);
    }
    ssize_t r = cloak_ws_handshake_compose_101(heap, cap, accept);
    if (copy_out != NULL && cap > 0) {
        memcpy(copy_out, heap, cap);
    }
    free(heap);
    return r;
}

/* ------------------------------------------------------------------ */
/* The golden pair                                                     */
/* ------------------------------------------------------------------ */

static void test_the_builder_reproduces_the_golden_request(void) {
    char buf[4096];
    req_t r = {0};
    size_t n = build(buf, sizeof(buf), r);
    ASSERT_EQ_INT(335, (int)n);
    ASSERT_EQ_INT((int)(sizeof(GOLDEN_REQUEST) - 1), (int)n);
    ASSERT_MEM_EQ(GOLDEN_REQUEST, buf, n);
}

static void test_the_host_guard_detects_a_missing_host(void) {
    /* parse_measured's guard is a tripwire for a literal nobody has
     * written yet, so nothing in today's suite makes it fire -- which is
     * exactly how a "defence" ends up being a function that returns the
     * wrong answer and is never noticed. Its LOGIC is therefore asserted
     * directly, both ways, including the two mistakes it would be easy to
     * make: matching "host:" anywhere in the bytes rather than at the
     * start of a line, and matching case-sensitively. */
    static const char with_host[] = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    static const char lower_host[] = "GET / HTTP/1.1\r\nhost: x\r\n\r\n";
    static const char upper_host[] = "GET / HTTP/1.1\r\nHOST: x\r\n\r\n";
    static const char lf_host[] = "GET / HTTP/1.1\nHost: x\n\n";
    static const char no_host[] = "GET / HTTP/1.1\r\nX-A: b\r\n\r\n";
    static const char host_in_target[] = "GET /host:/x HTTP/1.1\r\nX-A: b\r\n\r\n";
    static const char host_in_value[] = "GET / HTTP/1.1\r\nX-A: host: x\r\n\r\n";
    static const char host_space_colon[] = "GET / HTTP/1.1\r\nHost : x\r\n\r\n";

    ASSERT_EQ_INT(1, has_host_header(with_host, sizeof(with_host) - 1));
    ASSERT_EQ_INT(1, has_host_header(lower_host, sizeof(lower_host) - 1));
    ASSERT_EQ_INT(1, has_host_header(upper_host, sizeof(upper_host) - 1));
    ASSERT_EQ_INT(1, has_host_header(lf_host, sizeof(lf_host) - 1));
    ASSERT_EQ_INT(0, has_host_header(no_host, sizeof(no_host) - 1));
    ASSERT_EQ_INT(0, has_host_header(host_in_target, sizeof(host_in_target) - 1));
    ASSERT_EQ_INT(0, has_host_header(host_in_value, sizeof(host_in_value) - 1));
    ASSERT_EQ_INT(0, has_host_header(host_space_colon, sizeof(host_space_colon) - 1));
    /* And it never reads past the bytes it is given: a prefix that stops
     * inside the word "Host" must answer 0 rather than run on. */
    ASSERT_EQ_INT(0, has_host_header(with_host, 20));
    ASSERT_EQ_INT(0, has_host_header(with_host, 0));
}

static void test_the_fold_halves_are_the_whole_payload(void) {
    /* The obs-fold test below depends entirely on this: its two halves
     * must concatenate to the WHOLE valid payload, or a parser that joins
     * continuation lines without a space would produce a short value and
     * be refused for the wrong reason -- which is exactly the weakness
     * that version of the test had. Asserted here, next to the constants,
     * so an edit to either half fails loudly instead of quietly
     * re-weakening a test three directories away in a comment nobody
     * re-reads. */
    ASSERT_EQ_INT(60, (int)strlen(HIDDEN_B64_HEAD60));
    ASSERT_EQ_INT(68, (int)strlen(HIDDEN_B64_TAIL68));
    ASSERT_EQ_INT(CLOAK_WS_HS_HIDDEN_B64_LEN, (int)strlen(HIDDEN_B64));
    ASSERT_TRUE(strcmp(HIDDEN_B64_HEAD60 HIDDEN_B64_TAIL68, HIDDEN_B64) == 0);
}

static void test_golden_request_parses_with_gorillas_own_accept(void) {
    cloak_ws_hs_t hs;
    memset(&hs, 0, sizeof(hs));
    ASSERT_EQ_INT(CLOAK_WS_HS_OK,
                  parse_measured(GOLDEN_REQUEST, sizeof(GOLDEN_REQUEST) - 1, &hs));
    assert_hidden_ok(&hs);
    ASSERT_EQ_INT(CLOAK_WS_HS_ACCEPT_LEN, (int)strlen(hs.accept));
    ASSERT_TRUE(strcmp(ACCEPT_GO, hs.accept) == 0);

    /* The interposed EVP_Digest is genuinely on the path: it counted the
     * call that produced an accept matching gorilla's own output. */
    ASSERT_TRUE(digest_calls > 0);
}

static void test_composed_101_is_gorillas_response_byte_for_byte(void) {
    uint8_t buf[256];
    memset(buf, 0x5a, sizeof(buf));
    ssize_t n = cloak_ws_handshake_compose_101(buf, sizeof(buf), ACCEPT_GO);
    ASSERT_EQ_INT(CLOAK_WS_HS_101_LEN, (int)n);
    ASSERT_EQ_INT((int)(sizeof(GOLDEN_RESPONSE) - 1), (int)n);
    ASSERT_MEM_EQ(GOLDEN_RESPONSE, buf, (size_t)n);

    /* Nothing past the returned length was touched -- no NUL, and no
     * stray Date: or Server: that a longer buffer might have invited. */
    for (size_t i = (size_t)n; i < sizeof(buf); i++) {
        ASSERT_EQ_INT(0x5a, buf[i]);
    }
}

/* ------------------------------------------------------------------ */
/* The accept computation                                              */
/* ------------------------------------------------------------------ */

static void test_rfc6455_sample_accept_vector(void) {
    /* RFC 6455 section 1.3's own example, confirmed against live gorilla.
     * This is the one constant in the file that owes nothing to any
     * implementation at all. */
    cloak_ws_hs_t hs;
    memset(&hs, 0, sizeof(hs));
    req_t r = {0};
    r.key = KEY_RFC;
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(r, &hs));
    ASSERT_TRUE(strcmp(ACCEPT_RFC, hs.accept) == 0);
}

static void test_accept_is_computed_over_the_key_received(void) {
    /* Four different keys, four accepts measured from live gorilla. A
     * stored key, a hardcoded accept, or an accept derived from anything
     * other than this request's own key fails at least three of these. */
    static const char *const keys[] = {KEY_GO, KEY_RFC, KEY_ZEROS, KEY_COUNT};
    static const char *const accepts[] = {ACCEPT_GO, ACCEPT_RFC, ACCEPT_ZEROS,
                                          ACCEPT_COUNT};
    for (size_t i = 0; i < 4; i++) {
        cloak_ws_hs_t hs;
        memset(&hs, 0, sizeof(hs));
        req_t r = {0};
        r.key = keys[i];
        ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(r, &hs));
        ASSERT_TRUE(strcmp(accepts[i], hs.accept) == 0);
        for (size_t j = 0; j < 4; j++) {
            if (j != i) {
                ASSERT_TRUE(strcmp(accepts[j], hs.accept) != 0);
            }
        }
    }
}

static void test_key_surrounding_whitespace_is_trimmed_before_hashing(void) {
    /* Measured: gorilla answers "Sec-WebSocket-Key: <key> " (a trailing
     * space) with the SAME accept as the bare key, because net/http trims
     * OWS off every header value before gorilla ever sees it. A parser
     * that hashed the untrimmed bytes would produce a different accept
     * and every browser and CDN would reject the handshake. */
    static const char *const forms[] = {KEY_RFC, KEY_RFC " ", KEY_RFC "\t",
                                        KEY_RFC "  \t "};
    for (size_t i = 0; i < 4; i++) {
        cloak_ws_hs_t hs;
        memset(&hs, 0, sizeof(hs));
        req_t r = {0};
        r.key = forms[i];
        ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(r, &hs));
        ASSERT_TRUE(strcmp(ACCEPT_RFC, hs.accept) == 0);
    }
    /* And leading whitespace, which lands after the colon. */
    cloak_ws_hs_t hs;
    memset(&hs, 0, sizeof(hs));
    char buf[4096];
    req_t r = {0};
    r.key = OMIT;
    r.extra = "Sec-WebSocket-Key:   \t" KEY_RFC "\r\n";
    size_t n = build(buf, sizeof(buf), r);
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_exact(buf, n, &hs));
    ASSERT_TRUE(strcmp(ACCEPT_RFC, hs.accept) == 0);
}

static void test_digest_failure_is_reported_as_internal(void) {
    cloak_ws_hs_t hs;
    memset(&hs, 0xaa, sizeof(hs));
    cloak_ws_hs_t before = hs;

    digest_fail = 1;
    req_t r = {0};
    cloak_ws_hs_result_t res = parse_built(r, &hs);
    digest_fail = 0;

    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_INTERNAL, res);
    /* And nothing was committed: a caller cannot mistake a failed
     * handshake for an authenticated payload. */
    ASSERT_MEM_EQ(&before, &hs, sizeof(hs));

    /* The same request succeeds once the digest works again, which proves
     * the failure came from the interposition and not from the request. */
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(r, &hs));
    ASSERT_TRUE(strcmp(ACCEPT_GO, hs.accept) == 0);
}

/* ------------------------------------------------------------------ */
/* What a CDN does to the request                                      */
/* ------------------------------------------------------------------ */

static void test_hidden_header_name_is_case_insensitive(void) {
    /* The Cloudflare case, and the one defect in this file that a
     * self-consistent test suite would never see: a memcmp against
     * "Hidden" passes every test written against Go's own client and
     * fails every request that has been through an HTTP/2-fronted edge,
     * where field names are lowercase by definition. */
    static const char *const names[] = {"Hidden", "hidden", "HIDDEN", "HiDdEn",
                                        "hIdDeN"};
    for (size_t i = 0; i < 5; i++) {
        cloak_ws_hs_t hs;
        memset(&hs, 0, sizeof(hs));
        req_t r = {0};
        r.hidden_name = names[i];
        ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(r, &hs));
        assert_hidden_ok(&hs);
        ASSERT_TRUE(strcmp(ACCEPT_GO, hs.accept) == 0);
    }
}

static void test_every_header_name_lowercased(void) {
    /* Not just Hidden: an HTTP/2 edge lowercases the whole block, so the
     * same request written entirely in lowercase must parse identically.
     * Measured against gorilla: 101, same accept. */
    static const char lower[] =
        "GET /ws/path HTTP/1.1\r\n"
        "host: cdn.example.com:443\r\n"
        "user-agent: Go-http-client/1.1\r\n"
        "connection: upgrade\r\n"
        "hidden: " HIDDEN_B64 "\r\n"
        "sec-websocket-key: " KEY_GO "\r\n"
        "sec-websocket-version: 13\r\n"
        "upgrade: websocket\r\n"
        "\r\n";
    cloak_ws_hs_t hs;
    memset(&hs, 0, sizeof(hs));
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_measured(lower, sizeof(lower) - 1, &hs));
    assert_hidden_ok(&hs);
    ASSERT_TRUE(strcmp(ACCEPT_GO, hs.accept) == 0);

    /* And entirely uppercased, which no CDN does but which proves the
     * folding is not a one-directional "lowercase what we expected". */
    static const char upper[] =
        "GET /ws/path HTTP/1.1\r\n"
        "HOST: cdn.example.com:443\r\n"
        "CONNECTION: UPGRADE\r\n"
        "HIDDEN: " HIDDEN_B64 "\r\n"
        "SEC-WEBSOCKET-KEY: " KEY_GO "\r\n"
        "SEC-WEBSOCKET-VERSION: 13\r\n"
        "UPGRADE: WEBSOCKET\r\n"
        "\r\n";
    memset(&hs, 0, sizeof(hs));
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_measured(upper, sizeof(upper) - 1, &hs));
    assert_hidden_ok(&hs);
}

static void test_connection_is_matched_as_a_token_list(void) {
    /* Accepted, every one measured as 101 from live gorilla. */
    static const char *const ok[] = {
        "Upgrade",             /* what Go's own client sends */
        "Upgrade, keep-alive", /* the common CDN rewrite */
        "keep-alive, Upgrade", /* the other order */
        "keep-alive,Upgrade",  /* no space after the comma */
        "UPGRADE",             /* case-folded per RFC 4790 */
        "upgrade",
        "Upgrade,",             /* trailing comma */
        "TE, Upgrade, Trailer", /* three tokens, the hit in the middle */
    };
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
        cloak_ws_hs_t hs;
        memset(&hs, 0, sizeof(hs));
        req_t r = {0};
        r.conn = ok[i];
        ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(r, &hs));
    }

    /* Refused, every one measured as 400 from live gorilla. `Upgrades`
     * and `upgrade;q=1` are the cases that separate token matching from
     * substring matching, and `,Upgrade` and `"Upgrade"` are gorilla's
     * own quirk: an empty or non-token first element abandons the whole
     * header line (util.go:199-224), so the value that follows is never
     * examined. This port reproduces that rather than being more
     * generous than the peer it must be indistinguishable from. */
    static const char *const bad[] = {
        "keep-alive", "Upgrades", "upgrade;q=1", ",Upgrade",
        "\"Upgrade\"", "",        "close",       "upgrade websocket",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        cloak_ws_hs_t hs;
        memset(&hs, 0, sizeof(hs));
        req_t r = {0};
        r.conn = bad[i];
        ASSERT_EQ_INT(CLOAK_WS_HS_ERR_NOT_UPGRADE, parse_built(r, &hs));
    }

    /* Absent entirely. */
    cloak_ws_hs_t hs;
    memset(&hs, 0, sizeof(hs));
    req_t r = {0};
    r.conn = OMIT;
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_NOT_UPGRADE, parse_built(r, &hs));

    /* Two Connection lines, the token in each position in turn: gorilla
     * searches EVERY line with that name and stops at the first hit, so
     * both orders are 101 (both measured). One order alone is not
     * coverage -- a parser that keeps the LAST line's verdict passes the
     * "token second" case and fails the "token first" one, and a parser
     * that keeps the first passes the opposite. Only both together pin
     * the OR. */
    memset(&hs, 0, sizeof(hs));
    req_t token_second = {0};
    token_second.conn = "keep-alive";
    token_second.extra = "Connection: Upgrade\r\n";
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(token_second, &hs));

    memset(&hs, 0, sizeof(hs));
    req_t token_first = {0};
    token_first.conn = "Upgrade";
    token_first.extra = "Connection: keep-alive\r\n";
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(token_first, &hs));

    /* And neither line carrying it is still a refusal, so the two cases
     * above are not passing because repetition alone satisfies the
     * check. */
    memset(&hs, 0, sizeof(hs));
    req_t neither = {0};
    neither.conn = "keep-alive";
    neither.extra = "Connection: close\r\n";
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_NOT_UPGRADE, parse_built(neither, &hs));
}

static void test_upgrade_is_matched_as_a_token_list(void) {
    static const char *const ok[] = {"websocket", "WebSocket", "WEBSOCKET",
                                     "websocket, h2c", "h2c, websocket"};
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
        cloak_ws_hs_t hs;
        memset(&hs, 0, sizeof(hs));
        req_t r = {0};
        r.upgrade = ok[i];
        ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(r, &hs));
    }
    static const char *const bad[] = {"h2c", "websockets", "web socket", ""};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        cloak_ws_hs_t hs;
        memset(&hs, 0, sizeof(hs));
        req_t r = {0};
        r.upgrade = bad[i];
        ASSERT_EQ_INT(CLOAK_WS_HS_ERR_NOT_UPGRADE, parse_built(r, &hs));
    }
    cloak_ws_hs_t hs;
    memset(&hs, 0, sizeof(hs));
    req_t r = {0};
    r.upgrade = OMIT;
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_NOT_UPGRADE, parse_built(r, &hs));

    /* Both orders again, for the same reason as Connection: measured
     * 101 whether the websocket token is on the first or the second
     * Upgrade line. */
    memset(&hs, 0, sizeof(hs));
    req_t first = {0};
    first.upgrade = "websocket";
    first.extra = "Upgrade: h2c\r\n";
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(first, &hs));
    memset(&hs, 0, sizeof(hs));
    req_t second = {0};
    second.upgrade = "h2c";
    second.extra = "Upgrade: websocket\r\n";
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(second, &hs));
}

static void test_method_must_be_get(void) {
    /* gorilla refuses anything but GET (measured: 405, and its error
     * carries the same "not using the websocket protocol" prefix as the
     * Connection and Upgrade failures, which is why they share a code
     * here). The check is case-sensitive: "get" is refused too. Note that
     * cloak_firstpacket_t only reaches this parser for a first byte of
     * 'G', so GETX is the reachable case and POST is not -- both are
     * tested because this function is also a fuzz target with no
     * firstpacket in front of it. */
    static const char *const bad[] = {
        "POST /ws/path HTTP/1.1", "get /ws/path HTTP/1.1",
        "GETX /ws/path HTTP/1.1", "GE /ws/path HTTP/1.1",
        "HEAD /ws/path HTTP/1.1",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        cloak_ws_hs_t hs;
        memset(&hs, 0, sizeof(hs));
        req_t r = {0};
        r.request_line = bad[i];
        ASSERT_EQ_INT(CLOAK_WS_HS_ERR_NOT_UPGRADE, parse_built(r, &hs));
    }
}

static void test_cdn_injected_headers_are_skipped(void) {
    /* A Cloudflare-shaped request: twelve injected headers before,
     * between and after the ones that matter, the target rewritten, the
     * Host rewritten to the origin's internal name, every field name
     * lowercased and Connection rewritten. Measured as 101 against live
     * gorilla, 631 bytes on the wire against the bare client's 335 --
     * the same 631 this function asserts below and ws_handshake.h
     * quotes. (It said 630 until this round: the brief's number for a
     * differently-spelled example, carried one line further than the
     * first correction caught. A number that contradicts an assertion
     * 28 lines below it is exactly the kind of claim a reader stops
     * checking.) */
    static const char cf[] =
        "GET /ws/path?cf=1 HTTP/1.1\r\n"
        "host: origin.internal\r\n"
        "x-forwarded-for: 203.0.113.9\r\n"
        "x-forwarded-proto: https\r\n"
        "cf-connecting-ip: 203.0.113.9\r\n"
        "cf-ipcountry: DE\r\n"
        "connection: Upgrade, keep-alive\r\n"
        "cf-ray: 8f0a1b2c3d4e5f60-FRA\r\n"
        "cf-visitor: {\"scheme\":\"https\"}\r\n"
        "cdn-loop: cloudflare; loops=1\r\n"
        "hidden: " HIDDEN_B64 "\r\n"
        "accept-encoding: gzip, br\r\n"
        "x-real-ip: 203.0.113.9\r\n"
        "sec-websocket-key: " KEY_GO "\r\n"
        "via: 1.1 cloudflare\r\n"
        "x-request-id: abc123\r\n"
        "sec-websocket-version: 13\r\n"
        "upgrade: websocket\r\n"
        "x-amz-cf-id: deadbeef\r\n"
        "\r\n";
    cloak_ws_hs_t hs;
    memset(&hs, 0, sizeof(hs));
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_measured(cf, sizeof(cf) - 1, &hs));
    assert_hidden_ok(&hs);
    ASSERT_TRUE(strcmp(ACCEPT_GO, hs.accept) == 0);

    /* 631 bytes, against the bare client's 335 -- these exact bytes were
     * fed to live gorilla and answered with this exact accept. The
     * literal is asserted so a future edit that shrinks this case back
     * towards a bare request is visible rather than silent. */
    ASSERT_EQ_INT(631, (int)(sizeof(cf) - 1));
}

/* `Origin` IS NEVER READ, AND THE WHOLE POINT IS THAT gorilla WOULD HAVE
 * REFUSED THIS.
 *
 * gorilla's Upgrader{} has a nil CheckOrigin and therefore uses
 * checkSameOrigin, which compares the Origin's host to the request's Host
 * and refuses a mismatch. MEASURED against live gorilla v1.5.3 in this
 * project's dev image, the same harness every other constant in this file
 * came from:
 *
 *   origin absent                   -> accepted
 *   origin "http://example.com"     -> accepted (matches Host)
 *   origin "http://evil.example.com"
 *       -> 403, "request origin not allowed by Upgrader.CheckOrigin"
 *
 * So this is the ONE accept decision in this file that deliberately
 * differs from the oracle, and it is the third of the three triggers of
 * the Go wedge -- the 403 leaves websocket.go blocked on a channel
 * nothing will ever send on, after the UID has been authorised.
 * cloak/ws_handshake.h's `Origin` paragraph is the reasoning. This is the
 * tripwire: every arm below must parse OK and produce the SAME accept as
 * the bare golden request, so a future "restore gorilla parity" edit that
 * adds an Origin check fails here rather than in production behind a CDN
 * that injects one.
 *
 * Every plausible CDN shape is covered, because a check added later would
 * most likely key off just one of them: absent (what Cloak's own client
 * sends), same-site, cross-site, the canonical "null" a sandboxed origin
 * sends, lowercased as an HTTP/2-fronted edge would deliver it, a
 * syntactically broken value, and two Origin lines at once. The accept
 * being unchanged across all of them also proves `Origin` is not fed into
 * the SHA-1, which a naive "just hash the whole request" refactor would
 * do. */
static void test_cross_origin_is_accepted_unlike_gorilla(void) {
    static const char *const origin_lines[] = {
        NULL, /* absent: the Cloak client is not a browser and sends none */
        "Origin: https://cdn.example.com:443\r\n",   /* same-site: gorilla accepts too */
        "Origin: https://evil.example.com\r\n",      /* gorilla: 403 */
        "Origin: http://evil.example.com:8080\r\n",  /* gorilla: 403 */
        "Origin: null\r\n",                          /* gorilla: 403 */
        "origin: https://evil.example.com\r\n",      /* HTTP/2-fronted, lowercased */
        "Origin: not a url at all\r\n",              /* unparseable value */
        "Origin: https://a.example\r\nOrigin: https://b.example\r\n", /* two at once */
    };

    for (size_t i = 0; i < sizeof(origin_lines) / sizeof(origin_lines[0]); i++) {
        req_t r = {0};
        r.extra = origin_lines[i];
        cloak_ws_hs_t hs;
        memset(&hs, 0, sizeof(hs));
        ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(r, &hs));
        assert_hidden_ok(&hs);
        /* Byte-identical to the accept the SAME request without any
         * Origin produces -- gorilla's own, captured. */
        ASSERT_TRUE(strcmp(ACCEPT_GO, hs.accept) == 0);
    }

    /* And the parsed result carries no trace of the header: the struct
     * has no origin field to carry one, so the only observable is that
     * the cross-site request and the bare golden request are
     * indistinguishable in everything this parser returns. */
    cloak_ws_hs_t bare;
    cloak_ws_hs_t crossed;
    memset(&bare, 0, sizeof(bare));
    memset(&crossed, 0, sizeof(crossed));
    req_t r0 = {0};
    req_t r1 = {0};
    r1.extra = "Origin: https://evil.example.com\r\n";
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(r0, &bare));
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(r1, &crossed));
    ASSERT_MEM_EQ(&bare, &crossed, sizeof(bare));
}

static void test_high_bytes_in_a_header_value_are_accepted(void) {
    /* Go allows any byte from 0x80 up in a header value and refuses
     * everything below 0x20 except HTAB. Refusing high bytes would refuse
     * requests Go serves, so the value check has an upper bound as well
     * as a lower one and both sides of it are pinned (the refusals live
     * in test_malformed_requests).
     *
     * MEASURED ON THESE EXACT BYTES: 101, with the hidden payload
     * decoding to the same 96 bytes. An earlier version of this literal
     * had no Host header, and the 101 claimed here did not reproduce on
     * it -- Go answered `400 Bad Request: missing required Host header`,
     * for a reason with nothing to do with high bytes at all. The Host
     * line below is therefore load-bearing for the CLAIM even though this
     * parser never reads it, and parse_measured now refuses any literal
     * that forgets one. The counter-cases (0x7f, bare CR, NUL, 0x01 in
     * the same position) were re-measured WITH a Host present as well:
     * all four 400, so the principle survives removing the confound. */
    static const unsigned char raw[] = {
        'G',  'E',  'T',  ' ',  '/',  ' ',  'H',  'T',  'T',  'P',  '/',
        '1',  '.',  '1',  '\r', '\n', 'H',  'o',  's',  't',  ':',  ' ',
        'x',  '\r', '\n', 'X',  '-',  'A',  ':',  ' ',  0x80,
        0xfe, 0xff, '\r', '\n', 'H',  'i',  'd',  'd',  'e',  'n',  ':',
        ' '};
    char buf[4096];
    size_t n = sizeof(raw);
    memcpy(buf, raw, n);
    const char *tail = HIDDEN_B64
        "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        "Sec-WebSocket-Key: " KEY_GO "\r\nSec-WebSocket-Version: 13\r\n\r\n";
    memcpy(buf + n, tail, strlen(tail));
    n += strlen(tail);

    cloak_ws_hs_t hs;
    memset(&hs, 0, sizeof(hs));
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_measured(buf, n, &hs));
    assert_hidden_ok(&hs);
    ASSERT_TRUE(strcmp(ACCEPT_GO, hs.accept) == 0);
}

static void test_a_request_filling_the_firstpacket_buffer_still_parses(void) {
    /* CLOAK_FIRSTPACKET_MAX is 3000 and a CDN-fronted request is
     * typically 700-900, so the cap holds -- but it has stopped being
     * theoretical, and nothing in this parser may impose a tighter one of
     * its own. Pad to just under 3000 with injected headers and check it
     * still parses; the tail headers prove the scan did not stop early. */
    char pad[4096];
    size_t p = 0;
    pad[0] = '\0';
    for (int i = 0; i < 40; i++) {
        char line[80];
        snprintf(line, sizeof(line),
                 "X-Cdn-Trace-%02d: 0123456789abcdef0123456789abcdef012345\r\n",
                 i);
        app(pad, sizeof(pad), &p, line);
    }
    char buf[4096];
    req_t r = {0};
    r.extra = pad;
    size_t n = build(buf, sizeof(buf), r);
    ASSERT_TRUE(n > 2500);
    ASSERT_TRUE(n <= 3000);

    cloak_ws_hs_t hs;
    memset(&hs, 0, sizeof(hs));
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_exact(buf, n, &hs));
    assert_hidden_ok(&hs);
}

static void test_host_target_and_http_version_are_not_checked(void) {
    /* The Go server reads none of these, and being fussier than the
     * reference is itself a distinguisher -- the argument conn.h makes
     * about not validating record type bytes.
     *
     * EACH OF THE SIX REQUEST LINES BELOW, AND THE REWRITTEN Host, WAS
     * MEASURED AS 101 against live gorilla, `GET * HTTP/1.1` included.
     * THE ONE CASE THAT IS NOT is the last one, a request with no Host
     * header at all: see the note on it below. An earlier version of this
     * comment claimed the measurement covered that case too. It did not,
     * and a false "measured" is worse than no claim, because it stops the
     * next reader from checking. */
    cloak_ws_hs_t hs;
    static const char *const lines[] = {
        "GET / HTTP/1.1",
        "GET /completely/other/path HTTP/1.1",
        "GET /ws/path?stripped=by&the=cdn HTTP/1.1",
        "GET http://origin.internal/ws/path HTTP/1.1", /* absolute-form */
        "GET /ws/path HTTP/1.0",
        "GET * HTTP/1.1",
    };
    for (size_t i = 0; i < sizeof(lines) / sizeof(lines[0]); i++) {
        memset(&hs, 0, sizeof(hs));
        req_t r = {0};
        r.request_line = lines[i];
        ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(r, &hs));
    }
    /* Host rewritten to the origin's internal name, which is what a CDN
     * does. Measured: 101. */
    memset(&hs, 0, sizeof(hs));
    req_t rewritten = {0};
    rewritten.host = "10.0.0.7:8080";
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(rewritten, &hs));

    /* Host present but EMPTY. Measured: 101 -- Go requires the field to
     * be there and does not care what is in it. */
    memset(&hs, 0, sizeof(hs));
    req_t emptyhost = {0};
    emptyhost.host = "";
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(emptyhost, &hs));

    /* No Host header at all, on HTTP/1.0. Measured: 101. */
    memset(&hs, 0, sizeof(hs));
    req_t nohost_10 = {0};
    nohost_10.request_line = "GET /ws/path HTTP/1.0";
    nohost_10.host = OMIT;
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(nohost_10, &hs));

    /* No Host header at all, on HTTP/1.1. THIS PARSER ACCEPTS IT AND GO
     * DOES NOT: measured, `HTTP/1.1 400 Bad Request: missing required
     * Host header`, refused by net/http before the handler ever runs
     * (RFC 9112 3.2 requires the field on HTTP/1.1, and only there --
     * hence the 1.0 case above, which is 101).
     *
     * The permissive direction is kept deliberately, on the same grounds
     * as everything else in this function: the Cloak server reads Host
     * nowhere, requiring a field we never look at would refuse traffic
     * for a reason the reference implementation's own protocol layer
     * happens to impose rather than one Cloak has, and any CDN or client
     * that reaches this origin sends Host anyway. It is also unreachable
     * as a distinguisher -- a prober has no valid `Hidden`, so it sees
     * the cover site either way.
     *
     * What matters here is the LABEL, not the behaviour: this one case
     * is a deliberate divergence, not a measurement, and the comment now
     * says which it is. */
    memset(&hs, 0, sizeof(hs));
    req_t nohost = {0};
    nohost.host = OMIT;
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(nohost, &hs));
}

/* ------------------------------------------------------------------ */
/* Brackets: 96, 16 and 13, both sides of each                         */
/* ------------------------------------------------------------------ */

static void test_hidden_length_bracket(void) {
    cloak_ws_hs_t hs;

    /* 96 accepted. */
    memset(&hs, 0, sizeof(hs));
    req_t ok = {0};
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(ok, &hs));
    assert_hidden_ok(&hs);

    /* 95 and 97 refused -- one below and one above, never a margin. */
    memset(&hs, 0, sizeof(hs));
    req_t lo = {0};
    lo.hidden = HIDDEN_B64_95;
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_BAD_HIDDEN, parse_built(lo, &hs));
    memset(&hs, 0, sizeof(hs));
    req_t hi = {0};
    hi.hidden = HIDDEN_B64_97;
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_BAD_HIDDEN, parse_built(hi, &hs));

    /* The 95-byte encoding is ALSO 128 characters long, and so is a value
     * decoding to 94. Both refused -- the length that is checked is the
     * decoded one, exactly as Go's `len(hidden) < 96` then
     * `len(hidden[32:]) != 64` pair checks it. */
    ASSERT_EQ_INT(128, (int)strlen(HIDDEN_B64_95));
    ASSERT_EQ_INT(128, (int)strlen(HIDDEN_B64));
    ASSERT_EQ_INT(132, (int)strlen(HIDDEN_B64_97));
    memset(&hs, 0, sizeof(hs));
    req_t s94 = {0};
    s94.hidden = HIDDEN_B64_94_IN_128_CHARS;
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_BAD_HIDDEN, parse_built(s94, &hs));

    /* Absent and empty. */
    memset(&hs, 0, sizeof(hs));
    req_t none = {0};
    none.hidden = OMIT;
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_BAD_HIDDEN, parse_built(none, &hs));
    memset(&hs, 0, sizeof(hs));
    req_t empty = {0};
    empty.hidden = "";
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_BAD_HIDDEN, parse_built(empty, &hs));
}

static void test_hidden_must_be_standard_base64(void) {
    static const char *const bad[] = {
        HIDDEN_B64_URLSAFE,                     /* '-' and '_' */
        "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",     /* outside the alphabet */
        "AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5", /* well-formed but short */
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        cloak_ws_hs_t hs;
        memset(&hs, 0, sizeof(hs));
        req_t r = {0};
        r.hidden = bad[i];
        ASSERT_EQ_INT(CLOAK_WS_HS_ERR_BAD_HIDDEN, parse_built(r, &hs));
    }
    /* A value far longer than any base64 of 96 bytes: refused without
     * being copied anywhere. 512 characters is well inside
     * CLOAK_FIRSTPACKET_MAX, so this is a parser decision, not a framing
     * one. */
    char big[600];
    memset(big, 'A', 512);
    big[512] = '\0';
    cloak_ws_hs_t hs;
    memset(&hs, 0, sizeof(hs));
    req_t r = {0};
    r.hidden = big;
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_BAD_HIDDEN, parse_built(r, &hs));
}

static void test_version_bracket(void) {
    /* Accepted: 13, and 13 as one token of a list, with either kind of
     * surrounding whitespace. Every one measured as 101. */
    static const char *const ok[] = {"13", "13, 8", "8, 13", " 13 ", "\t13",
                                     "13,8"};
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
        cloak_ws_hs_t hs;
        memset(&hs, 0, sizeof(hs));
        req_t r = {0};
        r.version = ok[i];
        ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(r, &hs));
    }
    /* Refused: both sides of 13, and the two shapes that separate a token
     * comparison from a substring or numeric one. "013" and "130" were
     * both measured as 400. */
    static const char *const bad[] = {"12", "14", "013", "130", "1", "3", ""};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        cloak_ws_hs_t hs;
        memset(&hs, 0, sizeof(hs));
        req_t r = {0};
        r.version = bad[i];
        ASSERT_EQ_INT(CLOAK_WS_HS_ERR_BAD_VERSION, parse_built(r, &hs));
    }
    cloak_ws_hs_t hs;
    memset(&hs, 0, sizeof(hs));
    req_t none = {0};
    none.version = OMIT;
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_BAD_VERSION, parse_built(none, &hs));

    /* Two version lines, 13 in each position in turn: both measured as
     * 101, because gorilla checks the token list of every line. */
    memset(&hs, 0, sizeof(hs));
    req_t first = {0};
    first.version = "13";
    first.extra = "Sec-WebSocket-Version: 8\r\n";
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(first, &hs));
    memset(&hs, 0, sizeof(hs));
    req_t second = {0};
    second.version = "8";
    second.extra = "Sec-WebSocket-Version: 13\r\n";
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(second, &hs));
}

static void test_key_length_bracket(void) {
    cloak_ws_hs_t hs;

    /* 16 decoded bytes accepted. */
    memset(&hs, 0, sizeof(hs));
    req_t ok = {0};
    ok.key = KEY_COUNT;
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(ok, &hs));
    ASSERT_TRUE(strcmp(ACCEPT_COUNT, hs.accept) == 0);

    /* 15 and 17 refused. The 17-byte encoding is 24 characters long --
     * the same length as a valid key -- so a parser checking the string
     * length rather than the decoded length accepts it. Both measured as
     * 400 against live gorilla. */
    memset(&hs, 0, sizeof(hs));
    req_t k15 = {0};
    k15.key = "AAECAwQFBgcICQoLDA0O"; /* base64 of 15 bytes, 20 chars */
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_BAD_KEY, parse_built(k15, &hs));
    memset(&hs, 0, sizeof(hs));
    req_t k17 = {0};
    k17.key = "AAECAwQFBgcICQoLDA0ODxA="; /* base64 of 17 bytes, 24 chars */
    ASSERT_EQ_INT(24, (int)strlen(k17.key));
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_BAD_KEY, parse_built(k17, &hs));

    /* Absent, empty, unpadded, URL-safe, and a key with an interior
     * space: all measured as 400. The unpadded form is what a lenient
     * base64 decoder would accept and Go's StdEncoding will not. */
    static const char *const bad[] = {
        "",
        "AAECAwQFBgcICQoLDA0ODw",   /* 16 bytes, padding stripped */
        "-_-_-_-_-_-_-_-_-_-_-w==", /* URL-safe alphabet */
        "dGhlIHNhb XBsZSBub25jZQ==", /* interior space */
        "dGhlIHNhbXBsZSBub25jZQ",    /* truncated */
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        memset(&hs, 0, sizeof(hs));
        req_t r = {0};
        r.key = bad[i];
        ASSERT_EQ_INT(CLOAK_WS_HS_ERR_BAD_KEY, parse_built(r, &hs));
    }
    memset(&hs, 0, sizeof(hs));
    req_t none = {0};
    none.key = OMIT;
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_BAD_KEY, parse_built(none, &hs));
}

/* ------------------------------------------------------------------ */
/* Duplicates, malformed input, and the refusal order                  */
/* ------------------------------------------------------------------ */

static void test_duplicate_single_valued_headers_take_the_first(void) {
    /* Go's Header.Get returns the first value, and both Hidden and the
     * key are read through it. Measured: a request with a 95-byte Hidden
     * first and a 96-byte Hidden second is refused; the reverse order is
     * accepted; and a bad key before a good one is refused. */
    cloak_ws_hs_t hs;
    memset(&hs, 0, sizeof(hs));
    req_t bad_first = {0};
    bad_first.hidden = HIDDEN_B64_95;
    bad_first.extra = "Hidden: " HIDDEN_B64 "\r\n";
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_BAD_HIDDEN, parse_built(bad_first, &hs));

    memset(&hs, 0, sizeof(hs));
    req_t good_first = {0};
    good_first.extra = "Hidden: " HIDDEN_B64_95 "\r\n";
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(good_first, &hs));
    assert_hidden_ok(&hs);

    memset(&hs, 0, sizeof(hs));
    req_t bad_key_first = {0};
    bad_key_first.key = "AAECAwQFBgcICQoLDA0O";
    bad_key_first.extra = "Sec-WebSocket-Key: " KEY_GO "\r\n";
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_BAD_KEY, parse_built(bad_key_first, &hs));

    /* A second Hidden with a DIFFERENT valid payload must not overwrite
     * the first: the accepted bytes are the first line's. */
    memset(&hs, 0, sizeof(hs));
    req_t two_valid = {0};
    two_valid.extra =
        "Hidden: "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n";
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(two_valid, &hs));
    assert_hidden_ok(&hs);
}

static void test_malformed_requests(void) {
    cloak_ws_hs_t hs;
    static const char *const bad[] = {
        /* No blank line: the header block never ends inside the bytes
         * given. cloak_firstpacket_t cannot produce this, a fuzzer can. */
        "GET /ws/path HTTP/1.1\r\nHost: x\r\n",
        "GET /ws/path HTTP/1.1\r\n",
        "GET /ws/path HTTP/1.1",
        "GET",
        "\r\n",
        /* A leading blank line before the request line: measured 400. */
        "\r\nGET /ws/path HTTP/1.1\r\nHost: x\r\n\r\n",
        /* Request lines that are not METHOD SP TARGET SP HTTP/x.y.
         * "GET  /ws/path HTTP/1.1" (two spaces) was measured as 400 --
         * Go reads the target as empty and the version as
         * "/ws/path HTTP/1.1", which fails its version parse. */
        "GET /ws/path\r\nHost: x\r\n\r\n",
        "GET  /ws/path HTTP/1.1\r\nHost: x\r\n\r\n",
        /* An empty target with an otherwise valid version token, which
         * is the only shape that separates the empty-target check from
         * the version check. Go refuses it too (measured: 400 --
         * url.ParseRequestURI("") fails). */
        "GET  HTTP/1.1\r\nHost: x\r\n\r\n",
        "GET /ws/path HTTP/1.1 extra\r\nHost: x\r\n\r\n",
        "GET /ws/path FTP/1.1\r\nHost: x\r\n\r\n",
        " GET /ws/path HTTP/1.1\r\nHost: x\r\n\r\n",
        /* Header lines Go refuses: no colon, a space before the colon, a
         * name that is not an RFC 7230 token (both the '{' and the '"'
         * spellings), and an empty name. All five were re-measured as
         * 400 WITH the Host line they now carry, so the 400 is the
         * header-line refusal and not the missing-Host refusal that
         * masked it before.
         *
         * AND THEY ARE NOT ALL THE SAME 400, which the previous version
         * of this comment got wrong by attributing all of them to
         * textproto. Four are hard parse errors inside
         * textproto.ReadMIMEHeader ("malformed MIME header line"), and
         * Go reports them as a bare `400 Bad Request`. The space before
         * the colon is NOT one: textproto accepts it and stores the key
         * "Hidden " verbatim. It is refused later, by net/http's separate
         * header-name-validity check, and Go says so in the status line
         * -- `400 Bad Request: invalid header name`, which is how the
         * two were told apart. This parser reaches the same verdict in
         * one place, because it validates the name as a token and a
         * space is not a token octet. */
        "GET / HTTP/1.1\r\nHost: x\r\ngarbage-line\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: x\r\nHidden : x\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: x\r\nHid{den: x\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: x\r\nHid\"den: x\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: x\r\n: novalue\r\n\r\n",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        memset(&hs, 0, sizeof(hs));
        ASSERT_EQ_INT(CLOAK_WS_HS_ERR_MALFORMED, parse_str(bad[i], &hs));
    }

    /* Control bytes in a header value. Go rejects any byte below 0x20
     * that is not HTAB, and DEL; high bytes it allows (the acceptance
     * side is test_high_bytes_in_a_header_value_are_accepted). All four
     * below were measured as 400 with the Host line these literals now
     * carry -- NUL, 0x01, a bare CR and DEL -- so none of the four is
     * the missing-Host 400 in disguise. Built by hand rather than
     * through build() because a NUL cannot travel through a C string. */
    static const unsigned char ctl_bytes[] = {0x00, 0x01, 0x0d, 0x7f};
    for (size_t i = 0; i < sizeof(ctl_bytes); i++) {
        char raw[512];
        size_t n = 0;
        const char *head = "GET / HTTP/1.1\r\nHost: x\r\nX-Cdn: ab";
        memcpy(raw, head, strlen(head));
        n = strlen(head);
        raw[n++] = (char)ctl_bytes[i];
        memcpy(raw + n, "cd\r\n\r\n", 6);
        n += 6;
        memset(&hs, 0, sizeof(hs));
        ASSERT_EQ_INT(CLOAK_WS_HS_ERR_MALFORMED, parse_measured(raw, n, &hs));
    }
}

static void test_bare_lf_line_endings_are_refused(void) {
    /* A DELIBERATE, MEASURED DIVERGENCE. Go's net/http accepts bare LF as
     * a line terminator: the request below was measured as 101 against
     * live gorilla. This parser requires CRLF everywhere, for the reason
     * http.h states for the admin API -- accidental leniency about line
     * endings is the classic request-smuggling differential -- plus one
     * specific to this path: cloak_firstpacket_t frames the request on
     * CRLFCRLF, so a bare-LF request is one whose own line endings
     * disagree with its terminator, and no CDN emits one (a reverse proxy
     * re-serialises what it parsed, always with CRLF).
     *
     * It is not a distinguisher a prober can measure: reaching a 101
     * needs a valid Hidden, and without one both implementations answer
     * with the cover site. Recorded here so the difference is a decision
     * rather than an accident. */
    static const char lf[] =
        "GET /ws/path HTTP/1.1\n"
        "Host: x\n"
        "Connection: Upgrade\n"
        "Upgrade: websocket\n"
        "Hidden: " HIDDEN_B64 "\n"
        "Sec-WebSocket-Key: " KEY_GO "\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n";
    cloak_ws_hs_t hs;
    memset(&hs, 0, sizeof(hs));
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_MALFORMED, parse_measured(lf, sizeof(lf) - 1, &hs));

    /* An obs-fold continuation line is refused for the same reason. RFC
     * 7230 3.2.4 deprecates the syntax and lets a server reject it
     * outright; Go instead JOINS the continuation onto the previous value
     * with a single space.
     *
     * THE LITERAL BELOW IS BUILT SO THAT EVERY WAY OF HANDLING A FOLD
     * GIVES A DIFFERENT ANSWER. It is HIDDEN_B64 -- the whole, valid,
     * 128-character payload -- split after 60 characters, so:
     *
     *   - refusing the continuation line (what this parser does, because
     *     the line has no colon) is MALFORMED, which is what is asserted;
     *   - joining it WITHOUT a space reconstructs the valid payload
     *     exactly, and returns OK. That is the dangerous implementation,
     *     and it is the one the previous version of this test could not
     *     see: its two halves summed to 72 characters rather than 128, so
     *     a no-space join produced a short value that was refused anyway,
     *     for a reason that had nothing to do with folding;
     *   - joining it WITH a space, as Go does, gives 129 characters
     *     containing an illegal base64 byte;
     *   - skipping the continuation line silently leaves a 60-character
     *     value.
     *
     * The last two are both refusals here, but with a different CODE than
     * MALFORMED, so the assertion below discriminates all four. The two
     * counter-cases after it pin the first and second bullets.
     *
     * WHAT GO ACTUALLY DOES WITH THESE EXACT BYTES, measured rather than
     * transcribed from a neighbouring experiment (the previous version of
     * this comment quoted numbers belonging to a different literal, which
     * is the defect this round exists to fix): Header.Get("hidden")
     * returns 129 characters, and base64.StdEncoding.DecodeString fails
     * on it -- "illegal base64 data at input byte 60", the fold-inserted
     * space. It therefore fails Go's ALPHABET check first, not its length
     * check. The length check is still what refuses it in Cloak, because
     * Cloak discards that decode error (scouting report 6.6) and proceeds
     * with the 45 bytes DecodeString returned before the error, which its
     * `len < 96` then refuses. Both checks are involved, in that order;
     * this parser reaches neither, because it refuses the line itself. */
    static const char fold[] =
        "GET /ws/path HTTP/1.1\r\n"
        "Host: x\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Hidden: " HIDDEN_B64_HEAD60 "\r\n"
        " " HIDDEN_B64_TAIL68 "\r\n"
        "Sec-WebSocket-Key: " KEY_GO "\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n";
    memset(&hs, 0, sizeof(hs));
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_MALFORMED,
                  parse_measured(fold, sizeof(fold) - 1, &hs));

    /* Counter-case 1: the two halves really are the whole payload. Joined
     * with nothing between them, the same request parses and yields the
     * 96 bytes -- so OK is genuinely reachable from these bytes, and the
     * MALFORMED above is load-bearing rather than incidental. Measured:
     * 101, hidden decodes to 96. */
    static const char joined[] =
        "GET /ws/path HTTP/1.1\r\n"
        "Host: x\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Hidden: " HIDDEN_B64_HEAD60 HIDDEN_B64_TAIL68 "\r\n"
        "Sec-WebSocket-Key: " KEY_GO "\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n";
    memset(&hs, 0, sizeof(hs));
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_measured(joined, sizeof(joined) - 1, &hs));
    assert_hidden_ok(&hs);

    /* Counter-case 2: the same request with the continuation line simply
     * deleted. This is the LENGTH path, and it gets the length path's own
     * code -- BAD_HIDDEN, not MALFORMED -- which is what makes the
     * assertion above a statement about the fold line and not about the
     * short value it leaves behind. Measured: Go's Header.Get returns 60
     * characters, which decode cleanly (no alphabet error at all) to 45
     * bytes, and Cloak's `len < 96` refuses them. */
    static const char dropped[] =
        "GET /ws/path HTTP/1.1\r\n"
        "Host: x\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Hidden: " HIDDEN_B64_HEAD60 "\r\n"
        "Sec-WebSocket-Key: " KEY_GO "\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n";
    memset(&hs, 0, sizeof(hs));
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_BAD_HIDDEN,
                  parse_measured(dropped, sizeof(dropped) - 1, &hs));
}

static void test_refusal_order_matches_go(void) {
    /* Every refusal has the same consequence -- a redirect to the cover
     * site -- so the order is not a security property. It is pinned
     * because it is observable, and because the order is Go's: Cloak's
     * processFirstPacket reads Hidden before gorilla's Upgrade looks at
     * anything, and gorilla then checks Connection/Upgrade, the method,
     * the version and the key in that sequence. */
    cloak_ws_hs_t hs;

    /* Bad in four ways at once: Hidden wins. */
    memset(&hs, 0, sizeof(hs));
    req_t all_bad = {0};
    all_bad.hidden = HIDDEN_B64_95;
    all_bad.conn = "keep-alive";
    all_bad.version = "12";
    all_bad.key = "";
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_BAD_HIDDEN, parse_built(all_bad, &hs));

    /* Hidden good: the upgrade tokens win over version and key. */
    memset(&hs, 0, sizeof(hs));
    req_t no_upgrade = {0};
    no_upgrade.conn = "keep-alive";
    no_upgrade.version = "12";
    no_upgrade.key = "";
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_NOT_UPGRADE, parse_built(no_upgrade, &hs));

    /* Upgrade good: the version wins over the key. */
    memset(&hs, 0, sizeof(hs));
    req_t bad_ver = {0};
    bad_ver.version = "12";
    bad_ver.key = "";
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_BAD_VERSION, parse_built(bad_ver, &hs));

    /* And a malformed frame beats all of them: nothing is even looked
     * for in a request that is not a request. */
    memset(&hs, 0, sizeof(hs));
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_MALFORMED,
                  parse_str("POST /x HTTP/1.1\r\nHidden: zz\r\n", &hs));
}

static void test_out_is_untouched_unless_ok(void) {
    /* A half-filled `hidden` would be an unauthenticated payload sitting
     * in a struct the caller is about to read. Every failure path leaves
     * the caller's bytes exactly as they were. */
    static const req_t cases[5] = {
        {NULL, NULL, NULL, HIDDEN_B64_95, NULL, NULL, NULL, NULL, NULL},
        {NULL, NULL, NULL, NULL, "keep-alive", NULL, NULL, NULL, NULL},
        {NULL, NULL, NULL, NULL, NULL, NULL, "12", NULL, NULL},
        {NULL, NULL, NULL, NULL, NULL, "", NULL, NULL, NULL},
        {"POST / HTTP/1.1", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL},
    };
    for (size_t i = 0; i < 5; i++) {
        cloak_ws_hs_t hs;
        memset(&hs, 0x3c, sizeof(hs));
        cloak_ws_hs_t before = hs;
        ASSERT_TRUE(parse_built(cases[i], &hs) != CLOAK_WS_HS_OK);
        ASSERT_MEM_EQ(&before, &hs, sizeof(hs));
    }
    /* And the malformed path, which returns before any header is read. */
    cloak_ws_hs_t hs;
    memset(&hs, 0x3c, sizeof(hs));
    cloak_ws_hs_t before = hs;
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_MALFORMED, parse_str("GET / HTTP/1.1\r\n", &hs));
    ASSERT_MEM_EQ(&before, &hs, sizeof(hs));
}

static void test_null_and_empty_arguments(void) {
    cloak_ws_hs_t hs;
    memset(&hs, 0, sizeof(hs));
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_MALFORMED,
                  cloak_ws_handshake_parse(NULL, 0, &hs));
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_MALFORMED,
                  cloak_ws_handshake_parse(NULL, 100, &hs));
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_MALFORMED,
                  cloak_ws_handshake_parse((const uint8_t *)GOLDEN_REQUEST,
                                           sizeof(GOLDEN_REQUEST) - 1, NULL));
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_MALFORMED, parse_exact("", 0, &hs));
}

static void test_every_truncation_of_the_golden_request_is_refused(void) {
    /* 334 prefixes, each in an allocation of exactly its own length, so
     * ASan's redzone sits immediately after the last byte. Two properties
     * at once: a parser that scans past `len` looking for the CRLFCRLF it
     * expects crashes here, and a parser that accepts a request whose
     * header block never ended is caught by the assertion. */
    cloak_ws_hs_t hs;
    for (size_t n = 0; n < sizeof(GOLDEN_REQUEST) - 1; n++) {
        memset(&hs, 0, sizeof(hs));
        cloak_ws_hs_result_t r = parse_exact(GOLDEN_REQUEST, n, &hs);
        if (r == CLOAK_WS_HS_OK) {
            fprintf(stderr, "FAIL: prefix of %zu bytes parsed as OK\n", n);
            ASSERT_TRUE(0);
        }
    }
    /* And the whole thing still parses, so the loop above is not passing
     * because everything fails. */
    memset(&hs, 0, sizeof(hs));
    ASSERT_EQ_INT(CLOAK_WS_HS_OK,
                  parse_measured(GOLDEN_REQUEST, sizeof(GOLDEN_REQUEST) - 1, &hs));
}

static void test_bytes_after_the_blank_line_are_ignored(void) {
    /* cloak_firstpacket_t stops exactly at the CRLFCRLF and never
     * produces trailing bytes, but a fuzzer will, and those bytes belong
     * to the session's data path rather than to this parser. Appending a
     * WebSocket binary frame must change nothing. */
    char buf[4096];
    size_t n = 0;
    memcpy(buf, GOLDEN_REQUEST, sizeof(GOLDEN_REQUEST) - 1);
    n = sizeof(GOLDEN_REQUEST) - 1;
    static const unsigned char frame[] = {0x82, 0x84, 0x01, 0x02, 0x03, 0x04,
                                          'A',  'B',  'C',  'D'};
    memcpy(buf + n, frame, sizeof(frame));
    n += sizeof(frame);

    cloak_ws_hs_t hs;
    memset(&hs, 0, sizeof(hs));
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_exact(buf, n, &hs));
    assert_hidden_ok(&hs);
    ASSERT_TRUE(strcmp(ACCEPT_GO, hs.accept) == 0);

    /* Trailing bytes that LOOK like header lines must be ignored just as
     * firmly, and this is the case that matters: session data is
     * arbitrary bytes, so sooner or later it contains a CRLF. A parser
     * that kept scanning past the blank line would refuse a perfectly
     * good handshake because the first data frame happened to contain
     * something that is not a header... */
    char junk[4096];
    size_t jn = sizeof(GOLDEN_REQUEST) - 1;
    memcpy(junk, GOLDEN_REQUEST, jn);
    const char *tail = "not-a-header-line\r\nHid{den: x\r\n";
    memcpy(junk + jn, tail, strlen(tail));
    jn += strlen(tail);
    memset(&hs, 0, sizeof(hs));
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_measured(junk, jn, &hs));
    assert_hidden_ok(&hs);

    /* ...and, the other way round, a parser that kept scanning would let
     * bytes the peer sent AFTER the handshake supply a header the
     * handshake itself lacked. Here the real Connection header carries
     * no upgrade token and the trailing data does. */
    char smuggle[4096];
    req_t r = {0};
    r.conn = "keep-alive";
    size_t sn = build(smuggle, sizeof(smuggle), r);
    const char *after = "Connection: Upgrade\r\n\r\n";
    memcpy(smuggle + sn, after, strlen(after));
    sn += strlen(after);
    memset(&hs, 0, sizeof(hs));
    ASSERT_EQ_INT(CLOAK_WS_HS_ERR_NOT_UPGRADE, parse_exact(smuggle, sn, &hs));
}

/* ------------------------------------------------------------------ */
/* compose_101                                                         */
/* ------------------------------------------------------------------ */

static void test_compose_101_capacity_bracket(void) {
    uint8_t copy[CLOAK_WS_HS_101_LEN];

    /* Exactly enough is enough. */
    ASSERT_EQ_INT(CLOAK_WS_HS_101_LEN,
                  (int)compose_exact(CLOAK_WS_HS_101_LEN, ACCEPT_GO, copy));
    ASSERT_MEM_EQ(GOLDEN_RESPONSE, copy, CLOAK_WS_HS_101_LEN);

    /* One byte short is refused, and writes nothing: every byte of the
     * buffer still carries the 0x5a the harness filled it with. */
    uint8_t short_copy[CLOAK_WS_HS_101_LEN - 1];
    ASSERT_EQ_INT(-1,
                  (int)compose_exact(CLOAK_WS_HS_101_LEN - 1, ACCEPT_GO, short_copy));
    for (size_t i = 0; i < sizeof(short_copy); i++) {
        ASSERT_EQ_INT(0x5a, short_copy[i]);
    }

    ASSERT_EQ_INT(-1, (int)compose_exact(0, ACCEPT_GO, NULL));
    ASSERT_EQ_INT(-1, (int)compose_exact(1, ACCEPT_GO, NULL));
    ASSERT_EQ_INT(-1, (int)cloak_ws_handshake_compose_101(NULL, 1000, ACCEPT_GO));

    /* A larger buffer still produces exactly 129 bytes. */
    uint8_t big[1024];
    memset(big, 0x5a, sizeof(big));
    ASSERT_EQ_INT(CLOAK_WS_HS_101_LEN,
                  (int)cloak_ws_handshake_compose_101(big, sizeof(big), ACCEPT_GO));
    ASSERT_MEM_EQ(GOLDEN_RESPONSE, big, CLOAK_WS_HS_101_LEN);
    ASSERT_EQ_INT(0x5a, big[CLOAK_WS_HS_101_LEN]);
}

static void test_compose_101_refuses_a_malformed_accept(void) {
    /* The output is a response header. A value carrying CR or LF would
     * let its contents split the response into headers of someone else's
     * choosing, so the shape is checked rather than trusted. */
    static const char *const bad[] = {
        NULL,
        "",
        "s3pPLMBiTxaQ9kYGzzhZRbK+xO",    /* 26 */
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo",   /* 27 */
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo==", /* 29 */
        "s3pPLMBiTxaQ9kYGzzhZRbK+x\r\nX: y", /* response splitting */
        "s3pPLMBiTxaQ9kYGzzhZRbK+x\r\n",
        "s3pPLMBiTxaQ9kYGzzhZRbK+x\no=",
        "s3pPLMBiTxaQ9kYGzzhZRb +xOo=", /* space */
        "s3pPLMBiTxaQ9kYGzzhZRb-+xOo=", /* URL-safe character */
        "s3pPLMBiTxaQ9kYGzzhZRb:+xOo=",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        uint8_t buf[256];
        memset(buf, 0x5a, sizeof(buf));
        ASSERT_EQ_INT(
            -1, (int)cloak_ws_handshake_compose_101(buf, sizeof(buf), bad[i]));
        for (size_t j = 0; j < sizeof(buf); j++) {
            ASSERT_EQ_INT(0x5a, buf[j]);
        }
    }
    /* The three other measured accepts are all accepted, so the check
     * above is refusing shapes rather than refusing everything. */
    static const char *const good[] = {ACCEPT_RFC, ACCEPT_ZEROS, ACCEPT_COUNT};
    for (size_t i = 0; i < 3; i++) {
        uint8_t buf[256];
        ASSERT_EQ_INT(
            CLOAK_WS_HS_101_LEN,
            (int)cloak_ws_handshake_compose_101(buf, sizeof(buf), good[i]));
        ASSERT_MEM_EQ("Sec-WebSocket-Accept: ", buf + 75, 22);
        ASSERT_MEM_EQ(good[i], buf + 97, CLOAK_WS_HS_ACCEPT_LEN);
    }
}

static void test_the_101_carries_the_accept_this_request_produced(void) {
    /* The end-to-end shape Task 4 will use: parse the request, compose
     * the reply from what the parse produced, and get gorilla's bytes. */
    cloak_ws_hs_t hs;
    memset(&hs, 0, sizeof(hs));
    ASSERT_EQ_INT(CLOAK_WS_HS_OK,
                  parse_measured(GOLDEN_REQUEST, sizeof(GOLDEN_REQUEST) - 1, &hs));
    uint8_t buf[256];
    ssize_t n = cloak_ws_handshake_compose_101(buf, sizeof(buf), hs.accept);
    ASSERT_EQ_INT(CLOAK_WS_HS_101_LEN, (int)n);
    ASSERT_MEM_EQ(GOLDEN_RESPONSE, buf, (size_t)n);

    /* With the RFC sample key in the request, the same path produces the
     * RFC's own accept -- so the 101 is built from THIS request's key. */
    memset(&hs, 0, sizeof(hs));
    req_t r = {0};
    r.key = KEY_RFC;
    ASSERT_EQ_INT(CLOAK_WS_HS_OK, parse_built(r, &hs));
    n = cloak_ws_handshake_compose_101(buf, sizeof(buf), hs.accept);
    ASSERT_EQ_INT(CLOAK_WS_HS_101_LEN, (int)n);
    ASSERT_MEM_EQ("Sec-WebSocket-Accept: " ACCEPT_RFC "\r\n\r\n", buf + 75,
                  22 + CLOAK_WS_HS_ACCEPT_LEN + 4);
}

TEST_MAIN_BEGIN()
test_the_builder_reproduces_the_golden_request();
test_the_host_guard_detects_a_missing_host();
test_the_fold_halves_are_the_whole_payload();
test_golden_request_parses_with_gorillas_own_accept();
test_composed_101_is_gorillas_response_byte_for_byte();
test_rfc6455_sample_accept_vector();
test_accept_is_computed_over_the_key_received();
test_key_surrounding_whitespace_is_trimmed_before_hashing();
test_digest_failure_is_reported_as_internal();
test_hidden_header_name_is_case_insensitive();
test_every_header_name_lowercased();
test_connection_is_matched_as_a_token_list();
test_upgrade_is_matched_as_a_token_list();
test_method_must_be_get();
test_cdn_injected_headers_are_skipped();
test_cross_origin_is_accepted_unlike_gorilla();
test_high_bytes_in_a_header_value_are_accepted();
test_a_request_filling_the_firstpacket_buffer_still_parses();
test_host_target_and_http_version_are_not_checked();
test_hidden_length_bracket();
test_hidden_must_be_standard_base64();
test_version_bracket();
test_key_length_bracket();
test_duplicate_single_valued_headers_take_the_first();
test_malformed_requests();
test_bare_lf_line_endings_are_refused();
test_refusal_order_matches_go();
test_out_is_untouched_unless_ok();
test_null_and_empty_arguments();
test_every_truncation_of_the_golden_request_is_refused();
test_bytes_after_the_blank_line_are_ignored();
test_compose_101_capacity_bracket();
test_compose_101_refuses_a_malformed_accept();
test_the_101_carries_the_accept_this_request_produced();
TEST_MAIN_END()
