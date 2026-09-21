/* The server side of the CDN transport's WebSocket upgrade.
 *
 * The contract, the constants, every measurement behind them and the
 * reasoning for each refusal live in cloak/ws_handshake.h. What follows
 * is the shape of the scan and the three rules it is written to:
 *
 *   1. NO READ IS EVER UNBOUNDED. The buffer is attacker-controlled and
 *      unauthenticated, and it is NOT NUL-terminated -- it is whatever
 *      cloak_firstpacket_t accumulated. So no strlen, no strchr, no
 *      strstr, no strcmp anywhere in this file: every scan carries its
 *      own end pointer, and the only string functions used are memchr and
 *      memcpy with lengths already proven to be in range.
 *   2. NOTHING IS COPIED BEFORE ITS LENGTH IS CHECKED. The two values
 *      that leave the request buffer (`Hidden` and `Sec-WebSocket-Key`)
 *      go into fixed arrays sized from the protocol, and a value that
 *      does not fit is refused rather than truncated -- truncating would
 *      turn a value the peer sent into a different value we then act on.
 *   3. `out` IS WRITTEN ONLY ON SUCCESS, as the last act of the function.
 *
 * SHA-1 APPEARS HERE AND IS NOT A SECURITY PRIMITIVE. RFC 6455 section
 * 4.2.2 defines Sec-WebSocket-Accept as base64(SHA1(key || GUID)) and
 * every WebSocket implementation on earth computes exactly that. It
 * authenticates nothing and protects nothing: its entire job is to prove
 * to the client that the server understood the upgrade rather than
 * echoing a cached response. Replacing it with a stronger digest would
 * not improve anything and would make this server fail every handshake,
 * with the CDN in the middle being the first to reject it. Do not
 * "upgrade" it. Cloak's actual authentication is elsewhere entirely -- in
 * the `Hidden` payload this file only decodes and hands on.
 */

#define _POSIX_C_SOURCE 200809L

#include "cloak/ws_handshake.h"

#include "cloak/base64.h"

#include <openssl/evp.h>
#include <string.h>
#include <sys/types.h>

/* RFC 6455 section 1.3: 36 ASCII bytes, uppercase, no braces, no NUL,
 * appended to the key with no separator. */
static const char WS_GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
#define WS_GUID_LEN 36

/* A view into the request buffer. Never NUL-terminated, never copied
 * unless the destination's size has already been checked. */
typedef struct {
    const uint8_t *p;
    size_t len;
} span_t;

/* ------------------------------------------------------------------ */
/* Byte classes                                                        */
/* ------------------------------------------------------------------ */

/* ASCII-only case folding, deliberately not tolower(): tolower() is
 * locale-dependent, and a locale that folds bytes outside A-Z would make
 * two header names compare equal that Go would keep distinct. Go folds
 * per RFC 4790 (gorilla's equalASCIIFold, util.go:175-198) and net/http
 * canonicalises ASCII only. */
static unsigned char ascii_lower(unsigned char c) {
    return (c >= 'A' && c <= 'Z') ? (unsigned char)(c - 'A' + 'a') : c;
}

/* RFC 7230 token octets, which is also the set gorilla's nextToken walks
 * (util.go:33-118) and the set net/http validates header names against.
 * A name outside it makes the whole request malformed -- measured: Go
 * answers 400 and the handler never runs. */
static int is_token_octet(unsigned char c) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9')) {
        return 1;
    }
    switch (c) {
    case '!': case '#': case '$': case '%': case '&': case '\'':
    case '*': case '+': case '-': case '.': case '^': case '_':
    case '`': case '|': case '~':
        return 1;
    default:
        return 0;
    }
}

static int is_ows(unsigned char c) { return c == ' ' || c == '\t'; }

/* Go's rule for a header value byte (net/http's httpguts): anything below
 * a space other than HTAB is invalid, and so is DEL. High bytes are
 * allowed -- Go accepts them and so must this, since refusing them would
 * refuse requests Go serves. Measured: NUL and 0x01 in a value are both
 * 400. */
static int is_value_octet(unsigned char c) {
    if (c == '\t') {
        return 1;
    }
    return c >= 0x20 && c != 0x7f;
}

/* ------------------------------------------------------------------ */
/* Comparisons                                                         */
/* ------------------------------------------------------------------ */

/* Case-insensitive compare of a span against a NUL-terminated literal.
 * THIS IS THE FUNCTION THAT MAKES THE PARSER SURVIVE A CDN: every header
 * name goes through it, so `Hidden`, `hidden` and `HiDdEn` are one name,
 * as they are for Go (textproto.CanonicalMIMEHeaderKey canonicalises both
 * the wire name and the lookup) and as they must be for any request that
 * has passed through an HTTP/2-fronted edge. */
static int ci_eq(span_t s, const char *lit) {
    size_t i = 0;
    for (; i < s.len; i++) {
        unsigned char b = (unsigned char)lit[i];
        if (b == '\0') {
            return 0;
        }
        if (ascii_lower(s.p[i]) != ascii_lower(b)) {
            return 0;
        }
    }
    return lit[i] == '\0';
}

/* gorilla's tokenListContainsValue (util.go:199-224), reproduced exactly,
 * including its two surprising edges -- both measured against the live
 * implementation rather than read off the source:
 *
 *   - A token followed by anything that is not a comma ABANDONS THE WHOLE
 *     HEADER VALUE, so `Connection: upgrade;q=1` does not contain
 *     `upgrade` (measured: 400). So does an empty token, which is why
 *     `Connection: ,Upgrade` is refused (measured: 400) while
 *     `Connection: Upgrade,` is accepted (measured: 101).
 *   - Matching is whole-token and case-insensitive, so `Upgrades` is not
 *     `Upgrade` but `UPGRADE` is.
 *
 * Reproducing the quirks matters more than tidying them: a peer that is
 * more permissive than the reference implementation is distinguishable
 * from it by anyone willing to send `Connection: ,Upgrade` and see who
 * answers 101. */
static int token_list_contains(span_t v, const char *want) {
    size_t i = 0;
    for (;;) {
        while (i < v.len && is_ows(v.p[i])) {
            i++;
        }
        size_t start = i;
        while (i < v.len && is_token_octet(v.p[i])) {
            i++;
        }
        if (i == start) {
            return 0; /* empty token: the rest of this value is ignored */
        }
        span_t tok = {v.p + start, i - start};
        size_t after = i;
        while (after < v.len && is_ows(v.p[after])) {
            after++;
        }
        if (after < v.len && v.p[after] != ',') {
            return 0; /* not a 1#token value: abandon it, as gorilla does */
        }
        if (ci_eq(tok, want)) {
            return 1;
        }
        if (after >= v.len) {
            return 0;
        }
        i = after + 1; /* step past the comma */
    }
}

/* ------------------------------------------------------------------ */
/* The scan                                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    /* First occurrence only, matching Go's Header.Get, which returns the
     * first value of a repeated field (measured: a bad `Hidden` before a
     * good one is refused, and the reverse is accepted). */
    span_t hidden;
    span_t key;
    int have_hidden;
    int have_key;

    /* Token-list hits, ORed across every line carrying that name --
     * gorilla searches all of them (measured: `Connection: keep-alive`
     * followed by `Connection: Upgrade` is accepted). */
    int conn_upgrade;
    int upgrade_websocket;
    int version_13;
} scan_t;

/* Consumes one CRLF-terminated line starting at *off, returning the line
 * without its terminator. Returns 0 if no CRLF is found before `len`,
 * which is the only definition of "the header block ended" this parser
 * accepts -- see test_bare_lf_line_endings_are_refused for why a bare LF
 * is refused, and what Go does instead. */
static int next_line(const uint8_t *buf, size_t len, size_t *off, span_t *out) {
    if (*off >= len) {
        return 0;
    }
    const uint8_t *from = buf + *off;
    size_t avail = len - *off;
    const uint8_t *cr = memchr(from, '\r', avail);
    if (cr == NULL) {
        return 0;
    }
    size_t line_len = (size_t)(cr - from);
    if (line_len + 1 >= avail || cr[1] != '\n') {
        return 0; /* a bare CR: not a line ending here */
    }
    out->p = from;
    out->len = line_len;
    *off += line_len + 2;
    return 1;
}

/* METHOD SP TARGET SP HTTP/x.y, and nothing else is looked at.
 *
 * Returns REQLINE_MALFORMED, REQLINE_NOT_GET or REQLINE_GET, and the
 * middle one is not a nicety: Go separates the two failures too, and
 * observably so -- an unparseable request line is a 400 that the handler
 * never sees, while a well-formed POST reaches gorilla and comes back
 * 405. Collapsing them would report a request that merely used the wrong
 * method as unparseable, and would move the method's refusal ahead of
 * `Hidden`'s, changing the order ws_handshake.h pins.
 *
 * The target and the HTTP version are READ AND DISCARDED ON PURPOSE. The
 * Go server compares neither -- CDNWsUrlPath exists so an operator can
 * route a CDN to the right origin, never as a server-side check -- and a
 * CDN rewrites both. Adding a path check here would refuse traffic Go
 * accepts and would hand a prober a distinguisher for free. */
#define REQLINE_MALFORMED 0
#define REQLINE_NOT_GET 1
#define REQLINE_GET 2

static int parse_request_line(span_t line) {
    const uint8_t *sp1 = memchr(line.p, ' ', line.len);
    if (sp1 == NULL) {
        return REQLINE_MALFORMED;
    }
    size_t method_len = (size_t)(sp1 - line.p);
    const uint8_t *rest = sp1 + 1;
    size_t rest_len = line.len - method_len - 1;
    const uint8_t *sp2 = memchr(rest, ' ', rest_len);
    if (sp2 == NULL || sp2 == rest) {
        return REQLINE_MALFORMED; /* no version, or an empty target */
    }
    const uint8_t *vers = sp2 + 1;
    size_t vers_len = rest_len - (size_t)(sp2 - rest) - 1;
    /* "HTTP/" and at least one more byte, with no space inside: Go parses
     * this token and 400s if it cannot (measured: `GET  /x HTTP/1.1`,
     * whose doubled space makes the version "/x HTTP/1.1", is 400).
     * Nothing beyond the prefix is checked, because Go serves HTTP/1.0
     * here too (measured: 101) and this parser reads no more of the line
     * than Go's server does. */
    if (vers_len < 6 || memcmp(vers, "HTTP/", 5) != 0) {
        return REQLINE_MALFORMED;
    }
    if (memchr(vers, ' ', vers_len) != NULL) {
        return REQLINE_MALFORMED;
    }
    /* Case-sensitive and exact, as Go's `r.Method != http.MethodGet` is
     * (gorilla/websocket@v1.5.3 server.go:136-138): "get" and "GETX" are
     * both refused (measured: 405; re-measured in module 10b task 10
     * against go1.25.6 + gorilla v1.5.3). */
    if (method_len != 3 || memcmp(line.p, "GET", 3) != 0) {
        return REQLINE_NOT_GET;
    }
    return REQLINE_GET;
}

/* Splits one header line into a name and an OWS-trimmed value, and
 * records it if it is one of the five this parser reads. Returns 0 if the
 * line is malformed in a way Go also refuses. */
static int scan_header_line(span_t line, scan_t *s) {
    const uint8_t *colon = memchr(line.p, ':', line.len);
    if (colon == NULL) {
        /* No colon at all. This also covers an obs-fold continuation
         * line, which RFC 7230 3.2.4 deprecates and permits a server to
         * refuse; Go instead joins it with a space (measured), which
         * corrupts any structured value it is applied to. */
        return 0;
    }
    span_t name = {line.p, (size_t)(colon - line.p)};
    if (name.len == 0) {
        return 0;
    }
    for (size_t i = 0; i < name.len; i++) {
        if (!is_token_octet(name.p[i])) {
            /* Including the space in "Hidden : x", which Go reports as an
             * invalid header name (measured: 400). */
            return 0;
        }
    }

    span_t val = {colon + 1, line.len - name.len - 1};
    while (val.len > 0 && is_ows(val.p[0])) {
        val.p++;
        val.len--;
    }
    while (val.len > 0 && is_ows(val.p[val.len - 1])) {
        val.len--;
    }
    for (size_t i = 0; i < val.len; i++) {
        if (!is_value_octet(val.p[i])) {
            return 0;
        }
    }

    if (ci_eq(name, "hidden")) {
        if (!s->have_hidden) {
            s->hidden = val;
            s->have_hidden = 1;
        }
    } else if (ci_eq(name, "sec-websocket-key")) {
        if (!s->have_key) {
            s->key = val;
            s->have_key = 1;
        }
    } else if (ci_eq(name, "connection")) {
        s->conn_upgrade |= token_list_contains(val, "upgrade");
    } else if (ci_eq(name, "upgrade")) {
        s->upgrade_websocket |= token_list_contains(val, "websocket");
    } else if (ci_eq(name, "sec-websocket-version")) {
        s->version_13 |= token_list_contains(val, "13");
    }
    /* Everything else -- X-Forwarded-For, CF-RAY, CDN-Loop, Host,
     * User-Agent -- is validated for shape above and then dropped. */
    return 1;
}

/* base64-decodes a span into a fixed array, refusing anything that does
 * not fit rather than truncating it. `tmp` must hold cap+1 bytes: the
 * decoder takes a NUL-terminated string, which the request buffer is
 * not. */
static int decode_exact(span_t in, size_t b64_cap, uint8_t *out, size_t out_len) {
    char tmp[CLOAK_WS_HS_HIDDEN_B64_LEN + 1];
    if (b64_cap > sizeof(tmp) - 1) {
        return 0;
    }
    if (in.len == 0 || in.len > b64_cap) {
        return 0;
    }
    memcpy(tmp, in.p, in.len);
    tmp[in.len] = '\0';

    uint8_t decoded[CLOAK_WS_HS_HIDDEN_LEN];
    size_t got = 0;
    if (cloak_base64_decode(tmp, decoded, sizeof(decoded), &got) != 0) {
        return 0;
    }
    if (got != out_len) {
        return 0;
    }
    memcpy(out, decoded, out_len);
    return 1;
}

/* base64(SHA1(key || GUID)). See the file header on why this is SHA-1
 * and why that is not a security decision. */
static int compute_accept(span_t key, char *out /* ACCEPT_LEN + 1 */) {
    uint8_t buf[CLOAK_WS_HS_KEY_B64_MAX + WS_GUID_LEN];
    if (key.len > CLOAK_WS_HS_KEY_B64_MAX) {
        return 0;
    }
    memcpy(buf, key.p, key.len);
    memcpy(buf + key.len, WS_GUID, WS_GUID_LEN);

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (EVP_Digest(buf, key.len + WS_GUID_LEN, md, &md_len, EVP_sha1(), NULL) != 1) {
        return 0;
    }
    if (md_len != 20) {
        return 0;
    }
    /* Standard alphabet, never URL-safe: base64.h ships both one
     * character apart in the call, and the URL-safe one would produce an
     * accept every real client rejects while passing any C-to-C test. */
    if (cloak_base64_encode(md, md_len, out, CLOAK_WS_HS_ACCEPT_LEN + 1) != 0) {
        return 0;
    }
    return 1;
}

cloak_ws_hs_result_t cloak_ws_handshake_parse(const uint8_t *req, size_t len,
                                              cloak_ws_hs_t *out) {
    if (req == NULL || out == NULL || len == 0) {
        return CLOAK_WS_HS_ERR_MALFORMED;
    }

    size_t off = 0;
    span_t line = {NULL, 0};
    if (!next_line(req, len, &off, &line)) {
        return CLOAK_WS_HS_ERR_MALFORMED;
    }
    int reqline = parse_request_line(line);
    if (reqline == REQLINE_MALFORMED) {
        return CLOAK_WS_HS_ERR_MALFORMED;
    }

    scan_t s;
    memset(&s, 0, sizeof(s));

    int saw_blank = 0;
    while (next_line(req, len, &off, &line)) {
        if (line.len == 0) {
            saw_blank = 1;
            break;
        }
        if (!scan_header_line(line, &s)) {
            return CLOAK_WS_HS_ERR_MALFORMED;
        }
    }
    if (!saw_blank) {
        /* The header block never ended inside the bytes we were given.
         * cloak_firstpacket_t cannot produce this -- it frames on exactly
         * this blank line -- but a fuzzer can, and treating a truncated
         * request as complete is how a parser reads a value the peer had
         * not finished sending. */
        return CLOAK_WS_HS_ERR_MALFORMED;
    }

    /* The order below is Go's observable order; ws_handshake.h says why
     * it is pinned and why it is not a security property. */
    uint8_t hidden[CLOAK_WS_HS_HIDDEN_LEN];
    if (!s.have_hidden ||
        !decode_exact(s.hidden, CLOAK_WS_HS_HIDDEN_B64_LEN, hidden,
                      CLOAK_WS_HS_HIDDEN_LEN)) {
        return CLOAK_WS_HS_ERR_BAD_HIDDEN;
    }
    if (!s.conn_upgrade || !s.upgrade_websocket || reqline != REQLINE_GET) {
        return CLOAK_WS_HS_ERR_NOT_UPGRADE;
    }
    if (!s.version_13) {
        return CLOAK_WS_HS_ERR_BAD_VERSION;
    }
    uint8_t key_bytes[16];
    if (!s.have_key ||
        !decode_exact(s.key, CLOAK_WS_HS_KEY_B64_MAX, key_bytes,
                      sizeof(key_bytes))) {
        return CLOAK_WS_HS_ERR_BAD_KEY;
    }

    /* The accept is computed over the key AS RECEIVED, never over the
     * bytes it decoded to: gorilla hashes the header value itself
     * (util.go:19-24, h.Write([]byte(challengeKey))), and so does every
     * other implementation, so decoding and re-encoding would produce a
     * different accept and fail the RFC's own sample vector. key_bytes
     * above exists only to prove the value IS base64 of 16 bytes, which
     * is a separate check gorilla also makes (isValidChallengeKey). */
    char accept[CLOAK_WS_HS_ACCEPT_LEN + 1];
    if (!compute_accept(s.key, accept)) {
        return CLOAK_WS_HS_ERR_INTERNAL;
    }

    /* Commit, and only now. */
    memcpy(out->hidden, hidden, sizeof(hidden));
    memcpy(out->accept, accept, sizeof(accept));
    return CLOAK_WS_HS_OK;
}

/* The 101, exactly as gorilla's Upgrader writes it (server.go:219-224),
 * split only so the accept can be dropped in between. FOUR LINES AND
 * NOTHING ELSE -- see ws_handshake.h for why there is no Date and no
 * Server here, and why adding one would be a Cloak-only artefact on a leg
 * a CDN operator reads in plaintext. */
static const char RESP_HEAD[] =
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Accept: ";
static const char RESP_TAIL[] = "\r\n\r\n";
#define RESP_HEAD_LEN (sizeof(RESP_HEAD) - 1)
#define RESP_TAIL_LEN (sizeof(RESP_TAIL) - 1)

/* CLOAK_WS_HS_101_LEN is a promise made in a header, which callers size
 * buffers from; this makes the bytes and the promise fail the build
 * together rather than fail a connection apart. */
_Static_assert(RESP_HEAD_LEN + CLOAK_WS_HS_ACCEPT_LEN + RESP_TAIL_LEN ==
                   CLOAK_WS_HS_101_LEN,
               "the composed 101 is not CLOAK_WS_HS_101_LEN bytes");

ssize_t cloak_ws_handshake_compose_101(uint8_t *buf, size_t cap, const char *accept) {
    const size_t head_len = RESP_HEAD_LEN;
    const size_t tail_len = RESP_TAIL_LEN;

    if (buf == NULL || accept == NULL) {
        return -1;
    }
    /* The accept's shape is checked rather than trusted: this value goes
     * into a response header, and a CR or LF inside it would split the
     * response. See ws_handshake.h. */
    size_t i = 0;
    for (; i < CLOAK_WS_HS_ACCEPT_LEN; i++) {
        char c = accept[i];
        int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                 (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
        if (!ok) {
            return -1;
        }
    }
    if (accept[CLOAK_WS_HS_ACCEPT_LEN] != '\0') {
        return -1;
    }

    if (cap < head_len + CLOAK_WS_HS_ACCEPT_LEN + tail_len) {
        return -1;
    }
    memcpy(buf, RESP_HEAD, head_len);
    memcpy(buf + head_len, accept, CLOAK_WS_HS_ACCEPT_LEN);
    memcpy(buf + head_len + CLOAK_WS_HS_ACCEPT_LEN, RESP_TAIL, tail_len);
    return (ssize_t)(head_len + CLOAK_WS_HS_ACCEPT_LEN + tail_len);
}
