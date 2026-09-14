/* Tests for the incremental HTTP/1.1 request parser (cloak/http.h).
 *
 * The threat model this file is written against: every byte fed to this
 * parser is attacker-controlled AND authenticated as the operator, so a
 * bug here is remote code execution against the machine holding every
 * user's credentials rather than a mere fingerprint. Assertions are
 * therefore written to pin BOTH sides of every guard -- one byte under
 * and one byte over each cap -- because a test that only exercises "far
 * over" passes with the cap set anywhere.
 */
#include "cloak/http.h"
#include "test_framework.h"

#include <stdlib.h>
#include <string.h>

/* Sentinel for "this case does not pin a consumed count" (ERROR cases,
 * where consumed is deliberately unspecified past the offending byte). */
#define CONSUMED_ANY ((size_t)-1)

typedef struct {
    const char *name;
    uint8_t *req;
    size_t len;

    cloak_http_state_t state;
    int status;                 /* checked only when state == ERROR */
    cloak_http_method_t method; /* checked only when state == DONE */
    const char *path;           /* checked only when state == DONE */
    const char *body;           /* checked only when state == DONE */
    size_t body_len;
    size_t consumed;            /* CONSUMED_ANY to skip */
    int have_cl;
    size_t content_length;
} http_case_t;

#define MAX_CASES 64
static http_case_t g_cases[MAX_CASES];
static size_t g_case_count;

/* ---------------------------------------------------------------- */
/* Case-table construction                                          */
/* ---------------------------------------------------------------- */

static uint8_t *dup_bytes(const void *p, size_t n) {
    uint8_t *out = (uint8_t *)malloc(n == 0 ? 1 : n);
    if (out == NULL) {
        abort();
    }
    memcpy(out, p, n);
    return out;
}

/* Adds a case whose request is a NUL-free literal. */
static http_case_t *add_case(const char *name, const char *req) {
    size_t n = strlen(req);
    http_case_t *c;
    if (g_case_count >= MAX_CASES) {
        abort();
    }
    c = &g_cases[g_case_count++];
    memset(c, 0, sizeof(*c));
    c->name = name;
    c->req = dup_bytes(req, n);
    c->len = n;
    c->consumed = CONSUMED_ANY;
    return c;
}

/* Adds a case whose request carries arbitrary bytes (NULs included). */
static http_case_t *add_case_bytes(const char *name, const void *req, size_t n) {
    http_case_t *c;
    if (g_case_count >= MAX_CASES) {
        abort();
    }
    c = &g_cases[g_case_count++];
    memset(c, 0, sizeof(*c));
    c->name = name;
    c->req = dup_bytes(req, n);
    c->len = n;
    c->consumed = CONSUMED_ANY;
    return c;
}

static http_case_t *ok_case(const char *name, const char *req,
                            cloak_http_method_t m, const char *path) {
    http_case_t *c = add_case(name, req);
    c->state = CLOAK_HTTP_DONE;
    c->method = m;
    c->path = path;
    c->body = "";
    c->body_len = 0;
    c->consumed = c->len;
    return c;
}

static http_case_t *err_case(const char *name, const char *req, int status) {
    http_case_t *c = add_case(name, req);
    c->state = CLOAK_HTTP_ERROR;
    c->status = status;
    return c;
}

/* Appends "H<i>: <pad>" padded to exactly content_len bytes, plus CRLF. */
static size_t append_header_line(char *out, size_t off, int i, size_t content_len) {
    char head[32];
    int hn = snprintf(head, sizeof(head), "H%d: ", i);
    size_t k;
    if (hn < 0 || (size_t)hn > content_len) {
        abort();
    }
    memcpy(out + off, head, (size_t)hn);
    for (k = (size_t)hn; k < content_len; k++) {
        out[off + k] = 'a';
    }
    off += content_len;
    out[off++] = '\r';
    out[off++] = '\n';
    return off;
}

static void build_cases(void) {
    static char buf[8][262144];
    size_t off;
    size_t i;
    http_case_t *c;

    /* --- 1/2: the shapes the real admin client actually sends -------- */
    ok_case("minimal GET", "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
            CLOAK_HTTP_METHOD_GET, "/");
    ok_case("GET with HTTP/1.0", "GET /admin/users HTTP/1.0\r\n\r\n",
            CLOAK_HTTP_METHOD_GET, "/admin/users");
    ok_case("DELETE", "DELETE /admin/users/abc HTTP/1.1\r\n\r\n",
            CLOAK_HTTP_METHOD_DELETE, "/admin/users/abc");
    ok_case("OPTIONS", "OPTIONS /admin HTTP/1.1\r\n\r\n",
            CLOAK_HTTP_METHOD_OPTIONS, "/admin");

    c = ok_case("POST with a body",
                "POST /admin/users HTTP/1.1\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: 11\r\n"
                "\r\n"
                "hello world",
                CLOAK_HTTP_METHOD_POST, "/admin/users");
    c->body = "hello world";
    c->body_len = 11;
    c->have_cl = 1;
    c->content_length = 11;

    /* --- brief case 8: an unknown method reaches the router ---------- */
    ok_case("unknown method is OTHER, not an error",
            "PATCH /admin/users HTTP/1.1\r\n\r\n",
            CLOAK_HTTP_METHOD_OTHER, "/admin/users");
    /* Methods are case-sensitive per RFC 9110; "get" is a different
     * token, and answering it as GET would be a router differential. */
    ok_case("lowercase get is OTHER, not GET", "get / HTTP/1.1\r\n\r\n",
            CLOAK_HTTP_METHOD_OTHER, "/");

    /* --- brief case 9: a short body stays INCOMPLETE forever --------- */
    c = add_case("body shorter than Content-Length stays INCOMPLETE",
                 "POST /x HTTP/1.1\r\nContent-Length: 10\r\n\r\nshort");
    c->state = CLOAK_HTTP_INCOMPLETE;
    c->consumed = c->len;

    c = add_case("headers not terminated stays INCOMPLETE",
                 "GET / HTTP/1.1\r\nHost: x\r\n");
    c->state = CLOAK_HTTP_INCOMPLETE;
    c->consumed = c->len;

    c = add_case("request line not terminated stays INCOMPLETE",
                 "GET / HTTP/1.1");
    c->state = CLOAK_HTTP_INCOMPLETE;
    c->consumed = c->len;

    /* --- brief case 10: trailing bytes are not consumed --------------- */
    c = ok_case("body longer than Content-Length: extra bytes unconsumed",
                "POST /x HTTP/1.1\r\nContent-Length: 4\r\n\r\nbodyEXTRAEXTRA",
                CLOAK_HTTP_METHOD_POST, "/x");
    c->body = "body";
    c->body_len = 4;
    c->have_cl = 1;
    c->content_length = 4;
    c->consumed = c->len - strlen("EXTRAEXTRA");

    c = ok_case("bytes after a body-less request are not consumed",
                "GET / HTTP/1.1\r\n\r\nGET /again HTTP/1.1\r\n\r\n",
                CLOAK_HTTP_METHOD_GET, "/");
    c->consumed = strlen("GET / HTTP/1.1\r\n\r\n");

    /* --- line endings: strict CRLF (decision 1) ---------------------- */
    err_case("bare LF ending the request line", "GET / HTTP/1.1\nHost: x\r\n\r\n", 400);
    err_case("bare LF ending a header line", "GET / HTTP/1.1\r\nHost: x\n\r\n", 400);
    err_case("bare LF ending the header block", "GET / HTTP/1.1\r\nHost: x\r\n\n", 400);
    err_case("bare CR inside the request line", "GET /\ra HTTP/1.1\r\n\r\n", 400);
    err_case("bare CR inside a header value", "GET / HTTP/1.1\r\nHost: a\rb\r\n\r\n", 400);

    /* --- request line structure -------------------------------------- */
    err_case("HTTP/2.0 is refused", "GET / HTTP/2.0\r\n\r\n", 400);
    err_case("HTTP/1.2 is refused", "GET / HTTP/1.2\r\n\r\n", 400);
    err_case("lowercase http/1.1 is refused", "GET / http/1.1\r\n\r\n", 400);
    err_case("missing version", "GET /\r\n\r\n", 400);
    err_case("three fields plus one", "GET / x HTTP/1.1\r\n\r\n", 400);
    err_case("empty method", " / HTTP/1.1\r\n\r\n", 400);
    err_case("empty path", "GET  HTTP/1.1\r\n\r\n", 400);
    err_case("absolute-form URI is refused",
             "GET http://host/x HTTP/1.1\r\n\r\n", 400);
    err_case("asterisk-form is refused", "OPTIONS * HTTP/1.1\r\n\r\n", 400);
    err_case("empty request line", "\r\n\r\n", 400);

    /* A NUL inside the path would terminate the char[] early and hand
     * the router a shorter path than the one that was authenticated. */
    {
        static const char nul_req[] = "GET /a\0b HTTP/1.1\r\n\r\n";
        static const char nul_hdr[] = "GET / HTTP/1.1\r\nHost: a\0b\r\n\r\n";
        c = add_case_bytes("NUL byte in the path", nul_req, sizeof(nul_req) - 1);
        c->state = CLOAK_HTTP_ERROR;
        c->status = 400;
        c = add_case_bytes("NUL byte in a header value", nul_hdr, sizeof(nul_hdr) - 1);
        c->state = CLOAK_HTTP_ERROR;
        c->status = 400;
    }

    /* --- header structure -------------------------------------------- */
    err_case("header with no colon", "GET / HTTP/1.1\r\nHost x\r\n\r\n", 400);
    err_case("empty header name", "GET / HTTP/1.1\r\n: v\r\n\r\n", 400);
    err_case("space before the colon",
             "GET / HTTP/1.1\r\nContent-Length : 5\r\n\r\n12345", 400);
    err_case("obs-fold continuation line",
             "GET / HTTP/1.1\r\nHost: a\r\n  b\r\n\r\n", 400);
    ok_case("HT is legal OWS in a header value",
            "GET / HTTP/1.1\r\nHost:\tx\t\r\n\r\n", CLOAK_HTTP_METHOD_GET, "/");

    /* --- Content-Length (brief case 6) -------------------------------- */
    ok_case("no Content-Length on GET means no body",
            "GET /admin/users HTTP/1.1\r\n\r\n", CLOAK_HTTP_METHOD_GET,
            "/admin/users");
    err_case("Content-Length: abc", "POST /x HTTP/1.1\r\nContent-Length: abc\r\n\r\n", 400);
    err_case("Content-Length: -1", "POST /x HTTP/1.1\r\nContent-Length: -1\r\n\r\n", 400);
    err_case("Content-Length: +1", "POST /x HTTP/1.1\r\nContent-Length: +1\r\n\r\n", 400);
    err_case("Content-Length empty", "POST /x HTTP/1.1\r\nContent-Length:\r\n\r\n", 400);
    err_case("Content-Length list form",
             "POST /x HTTP/1.1\r\nContent-Length: 5, 5\r\n\r\n12345", 400);
    err_case("Content-Length: 5 5",
             "POST /x HTTP/1.1\r\nContent-Length: 5 5\r\n\r\n12345", 400);
    err_case("two conflicting Content-Length headers",
             "POST /x HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n123456", 400);

    /* Leading zeros are 1*DIGIT and therefore valid; the numeric value is
     * what we act on, so no differential follows from accepting them. */
    c = ok_case("Content-Length with leading zeros",
                "POST /x HTTP/1.1\r\nContent-Length: 007\r\n\r\nseven..",
                CLOAK_HTTP_METHOD_POST, "/x");
    c->body = "seven..";
    c->body_len = 7;
    c->have_cl = 1;
    c->content_length = 7;
    c->consumed = c->len;

    c = ok_case("Content-Length surrounded by OWS",
                "POST /x HTTP/1.1\r\nContent-Length:   4   \r\n\r\nbody",
                CLOAK_HTTP_METHOD_POST, "/x");
    c->body = "body";
    c->body_len = 4;
    c->have_cl = 1;
    c->content_length = 4;
    c->consumed = c->len;

    /* Two IDENTICAL Content-Length headers are accepted: RFC 9112 6.3
     * explicitly permits collapsing them, and no recipient differential
     * is possible when they agree. Disagreement is the vector, and is
     * refused above. */
    c = ok_case("two identical Content-Length headers are accepted",
                "POST /x HTTP/1.1\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\nbody",
                CLOAK_HTTP_METHOD_POST, "/x");
    c->body = "body";
    c->body_len = 4;
    c->have_cl = 1;
    c->content_length = 4;
    c->consumed = c->len;

    /* The field name is matched case-insensitively, so this IS a
     * Content-Length: a parser that matched it case-sensitively would
     * report have_content_length 0 here and then read no body at all
     * where a peer that matched it did -- a framing differential. */
    c = ok_case("case-insensitive header name",
                "POST /x HTTP/1.1\r\ncOnTeNt-LeNgTh: 3\r\n\r\nabc",
                CLOAK_HTTP_METHOD_POST, "/x");
    c->body = "abc";
    c->body_len = 3;
    c->have_cl = 1;
    c->content_length = 3;
    c->consumed = c->len;

    /* --- Transfer-Encoding (brief case 7): 501, never ignored -------- */
    err_case("Transfer-Encoding: chunked",
             "POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 501);
    err_case("Transfer-Encoding: identity",
             "POST /x HTTP/1.1\r\nTransfer-Encoding: identity\r\n\r\n", 501);
    err_case("Transfer-Encoding with an empty value",
             "POST /x HTTP/1.1\r\nTransfer-Encoding:\r\n\r\n", 501);
    err_case("Transfer-Encoding cased oddly",
             "POST /x HTTP/1.1\r\ntRaNsFeR-eNcOdInG: chunked\r\n\r\n", 501);
    /* The classic smuggle: a valid Content-Length alongside a TE. The TE
     * must still win as 501 rather than the CL quietly framing a body. */
    err_case("Transfer-Encoding beside a Content-Length",
             "POST /x HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\nbody",
             501);

    /* --- caps: one byte under, one byte over (brief case 5) ---------- */

    /* Path. */
    off = 0;
    off += (size_t)snprintf(buf[0], sizeof(buf[0]), "GET ");
    buf[0][off++] = '/';
    for (i = 1; i < CLOAK_HTTP_MAX_PATH - 1; i++) {
        buf[0][off++] = 'a';
    }
    memcpy(buf[0] + off, " HTTP/1.1\r\n\r\n", 13);
    off += 13;
    c = add_case_bytes("path at the cap", buf[0], off);
    c->state = CLOAK_HTTP_DONE;
    c->method = CLOAK_HTTP_METHOD_GET;
    c->body = "";
    c->consumed = off;
    {
        static char path_at_cap[CLOAK_HTTP_MAX_PATH];
        path_at_cap[0] = '/';
        for (i = 1; i < CLOAK_HTTP_MAX_PATH - 1; i++) {
            path_at_cap[i] = 'a';
        }
        path_at_cap[CLOAK_HTTP_MAX_PATH - 1] = '\0';
        c->path = path_at_cap;
    }

    off = 0;
    off += (size_t)snprintf(buf[1], sizeof(buf[1]), "GET ");
    buf[1][off++] = '/';
    for (i = 1; i < CLOAK_HTTP_MAX_PATH; i++) { /* one byte over */
        buf[1][off++] = 'a';
    }
    memcpy(buf[1] + off, " HTTP/1.1\r\n\r\n", 13);
    off += 13;
    c = add_case_bytes("path one byte over the cap", buf[1], off);
    c->state = CLOAK_HTTP_ERROR;
    c->status = 414;

    /* Request line: padded through the METHOD token so the PATH cap is
     * not what binds here -- otherwise this case would pass with the
     * request-line cap set anywhere. */
    off = 0;
    for (i = 0; i < CLOAK_HTTP_MAX_REQUEST_LINE - strlen(" / HTTP/1.1"); i++) {
        buf[2][off++] = 'M';
    }
    memcpy(buf[2] + off, " / HTTP/1.1\r\n\r\n", 15);
    off += 15;
    c = add_case_bytes("request line at the cap", buf[2], off);
    c->state = CLOAK_HTTP_DONE;
    c->method = CLOAK_HTTP_METHOD_OTHER;
    c->path = "/";
    c->body = "";
    c->consumed = off;

    off = 0;
    for (i = 0; i < CLOAK_HTTP_MAX_REQUEST_LINE + 1 - strlen(" / HTTP/1.1"); i++) {
        buf[3][off++] = 'M';
    }
    memcpy(buf[3] + off, " / HTTP/1.1\r\n\r\n", 15);
    off += 15;
    c = add_case_bytes("request line one byte over the cap", buf[3], off);
    c->state = CLOAK_HTTP_ERROR;
    c->status = 414;

    /* One header line. */
    off = (size_t)snprintf(buf[4], sizeof(buf[4]), "GET / HTTP/1.1\r\n");
    off = append_header_line(buf[4], off, 1, CLOAK_HTTP_MAX_HEADER_LINE);
    buf[4][off++] = '\r';
    buf[4][off++] = '\n';
    c = add_case_bytes("header line at the cap", buf[4], off);
    c->state = CLOAK_HTTP_DONE;
    c->method = CLOAK_HTTP_METHOD_GET;
    c->path = "/";
    c->body = "";
    c->consumed = off;

    off = (size_t)snprintf(buf[5], sizeof(buf[5]), "GET / HTTP/1.1\r\n");
    off = append_header_line(buf[5], off, 1, CLOAK_HTTP_MAX_HEADER_LINE + 1);
    buf[5][off++] = '\r';
    buf[5][off++] = '\n';
    c = add_case_bytes("header line one byte over the cap", buf[5], off);
    c->state = CLOAK_HTTP_ERROR;
    c->status = 431;

    /* Header block. Eight lines, sized so neither the per-line cap nor
     * the header-count cap binds: the block total is what is tested. */
    {
        size_t block_start;
        size_t line_content = CLOAK_HTTP_MAX_HEADER_LINE - 2; /* 2 for CRLF */
        size_t whole = line_content + 2;
        size_t nfull = (CLOAK_HTTP_MAX_HEADER_BLOCK - 2) / whole;
        size_t remainder = (CLOAK_HTTP_MAX_HEADER_BLOCK - 2) - nfull * whole;

        off = (size_t)snprintf(buf[6], sizeof(buf[6]), "GET / HTTP/1.1\r\n");
        block_start = off;
        for (i = 0; i < nfull; i++) {
            off = append_header_line(buf[6], off, (int)i, line_content);
        }
        if (remainder >= 2) {
            off = append_header_line(buf[6], off, 99, remainder - 2);
        }
        buf[6][off++] = '\r';
        buf[6][off++] = '\n';
        ASSERT_EQ_INT((int)CLOAK_HTTP_MAX_HEADER_BLOCK, (int)(off - block_start));
        c = add_case_bytes("header block at the cap", buf[6], off);
        c->state = CLOAK_HTTP_DONE;
        c->method = CLOAK_HTTP_METHOD_GET;
        c->path = "/";
        c->body = "";
        c->consumed = off;

        off = (size_t)snprintf(buf[7], sizeof(buf[7]), "GET / HTTP/1.1\r\n");
        block_start = off;
        for (i = 0; i < nfull; i++) {
            off = append_header_line(buf[7], off, (int)i, line_content);
        }
        off = append_header_line(buf[7], off, 99, remainder - 2 + 1); /* +1 byte */
        buf[7][off++] = '\r';
        buf[7][off++] = '\n';
        ASSERT_EQ_INT((int)CLOAK_HTTP_MAX_HEADER_BLOCK + 1, (int)(off - block_start));
        c = add_case_bytes("header block one byte over the cap", buf[7], off);
        c->state = CLOAK_HTTP_ERROR;
        c->status = 431;
    }
}

/* Header-count and body caps need their own buffers; they are built as
 * separate cases so the fixed case table above stays readable. */
static void build_count_and_body_cases(void) {
    static char cbuf[2][8192];
    static char bbuf[2][CLOAK_HTTP_MAX_BODY + 512];
    static char body_at_cap[CLOAK_HTTP_MAX_BODY];
    size_t off;
    unsigned i;
    http_case_t *c;

    off = (size_t)snprintf(cbuf[0], sizeof(cbuf[0]), "GET / HTTP/1.1\r\n");
    for (i = 0; i < CLOAK_HTTP_MAX_HEADERS; i++) {
        off += (size_t)snprintf(cbuf[0] + off, sizeof(cbuf[0]) - off, "H%u: v\r\n", i);
    }
    cbuf[0][off++] = '\r';
    cbuf[0][off++] = '\n';
    c = add_case_bytes("header count at the cap", cbuf[0], off);
    c->state = CLOAK_HTTP_DONE;
    c->method = CLOAK_HTTP_METHOD_GET;
    c->path = "/";
    c->body = "";
    c->consumed = off;

    off = (size_t)snprintf(cbuf[1], sizeof(cbuf[1]), "GET / HTTP/1.1\r\n");
    for (i = 0; i < CLOAK_HTTP_MAX_HEADERS + 1; i++) {
        off += (size_t)snprintf(cbuf[1] + off, sizeof(cbuf[1]) - off, "H%u: v\r\n", i);
    }
    cbuf[1][off++] = '\r';
    cbuf[1][off++] = '\n';
    c = add_case_bytes("header count one over the cap", cbuf[1], off);
    c->state = CLOAK_HTTP_ERROR;
    c->status = 431;

    /* Body exactly at the cap: accepted, and every byte delivered. */
    memset(body_at_cap, 'B', sizeof(body_at_cap));
    off = (size_t)snprintf(bbuf[0], sizeof(bbuf[0]),
                           "POST /x HTTP/1.1\r\nContent-Length: %u\r\n\r\n",
                           (unsigned)CLOAK_HTTP_MAX_BODY);
    memcpy(bbuf[0] + off, body_at_cap, sizeof(body_at_cap));
    off += sizeof(body_at_cap);
    c = add_case_bytes("body at the cap", bbuf[0], off);
    c->state = CLOAK_HTTP_DONE;
    c->method = CLOAK_HTTP_METHOD_POST;
    c->path = "/x";
    c->body = body_at_cap;
    c->body_len = sizeof(body_at_cap);
    c->have_cl = 1;
    c->content_length = sizeof(body_at_cap);
    c->consumed = off;

    /* One byte over: refused at the header, before a body is read or an
     * allocation is made. */
    off = (size_t)snprintf(bbuf[1], sizeof(bbuf[1]),
                           "POST /x HTTP/1.1\r\nContent-Length: %u\r\n\r\n",
                           (unsigned)CLOAK_HTTP_MAX_BODY + 1u);
    c = add_case_bytes("body one byte over the cap", bbuf[1], off);
    c->state = CLOAK_HTTP_ERROR;
    c->status = 413;

    /* A Content-Length no allocator on earth could satisfy. If the parser
     * ever allocated before checking its cap, this case would abort under
     * ASan instead of returning a clean 413. */
    c = err_case("absurd Content-Length is 413, not a failed malloc",
                 "POST /x HTTP/1.1\r\nContent-Length: 99999999999999999999\r\n\r\n",
                 413);
    (void)c;
}

/* ---------------------------------------------------------------- */
/* Drivers                                                          */
/* ---------------------------------------------------------------- */

static void check_case(const http_case_t *c, cloak_http_parser_t *p,
                       cloak_http_state_t st, size_t consumed,
                       const char *how) {
    const cloak_http_request_t *r = cloak_http_parser_request(p);

    if (st != c->state) {
        fprintf(stderr, "FAIL [%s/%s]: state %d, want %d (status %d)\n",
                c->name, how, (int)st, (int)c->state, r->status);
        cloak_test_failures++;
        return;
    }
    if (c->state == CLOAK_HTTP_ERROR) {
        if (r->status != c->status) {
            fprintf(stderr, "FAIL [%s/%s]: status %d, want %d\n",
                    c->name, how, r->status, c->status);
            cloak_test_failures++;
        }
        return;
    }
    if (c->state == CLOAK_HTTP_INCOMPLETE) {
        if (c->consumed != CONSUMED_ANY && consumed != c->consumed) {
            fprintf(stderr, "FAIL [%s/%s]: consumed %zu, want %zu\n",
                    c->name, how, consumed, c->consumed);
            cloak_test_failures++;
        }
        return;
    }

    if (r->method != c->method) {
        fprintf(stderr, "FAIL [%s/%s]: method %d, want %d\n",
                c->name, how, (int)r->method, (int)c->method);
        cloak_test_failures++;
    }
    if (strcmp(r->path, c->path) != 0) {
        fprintf(stderr, "FAIL [%s/%s]: path '%s', want '%s'\n",
                c->name, how, r->path, c->path);
        cloak_test_failures++;
    }
    if (r->body_len != c->body_len) {
        fprintf(stderr, "FAIL [%s/%s]: body_len %zu, want %zu\n",
                c->name, how, r->body_len, c->body_len);
        cloak_test_failures++;
    } else if (c->body_len > 0 && memcmp(r->body, c->body, c->body_len) != 0) {
        fprintf(stderr, "FAIL [%s/%s]: body bytes differ\n", c->name, how);
        cloak_test_failures++;
    }
    if (r->have_content_length != c->have_cl) {
        fprintf(stderr, "FAIL [%s/%s]: have_content_length %d, want %d\n",
                c->name, how, r->have_content_length, c->have_cl);
        cloak_test_failures++;
    }
    if (c->have_cl && r->content_length != c->content_length) {
        fprintf(stderr, "FAIL [%s/%s]: content_length %zu, want %zu\n",
                c->name, how, r->content_length, c->content_length);
        cloak_test_failures++;
    }
    if (c->consumed != CONSUMED_ANY && consumed != c->consumed) {
        fprintf(stderr, "FAIL [%s/%s]: consumed %zu, want %zu\n",
                c->name, how, consumed, c->consumed);
        cloak_test_failures++;
    }
}

/* Brief cases 1, 2, 5-10: every case fed in a single call. */
static void test_cases_whole(void) {
    size_t i;
    for (i = 0; i < g_case_count; i++) {
        cloak_http_parser_t p;
        size_t consumed = 0;
        cloak_http_state_t st;
        cloak_http_parser_init(&p);
        st = cloak_http_parser_feed(&p, g_cases[i].req, g_cases[i].len, &consumed);
        check_case(&g_cases[i], &p, st, consumed, "whole");
        cloak_http_parser_destroy(&p);
    }
}

/* Brief case 3: the same table, one byte per feed() call. Written as a
 * loop over the table rather than by hand so cases added later are
 * covered by it automatically. */
static void test_cases_byte_at_a_time(void) {
    size_t i;
    for (i = 0; i < g_case_count; i++) {
        cloak_http_parser_t p;
        size_t off = 0;
        size_t consumed_total = 0;
        cloak_http_state_t st = CLOAK_HTTP_INCOMPLETE;
        cloak_http_parser_init(&p);
        while (off < g_cases[i].len) {
            size_t consumed = 0;
            st = cloak_http_parser_feed(&p, g_cases[i].req + off, 1, &consumed);
            consumed_total += consumed;
            off++;
            if (st != CLOAK_HTTP_INCOMPLETE) {
                break;
            }
        }
        check_case(&g_cases[i], &p, st, consumed_total, "byte-at-a-time");
        cloak_http_parser_destroy(&p);
    }
}

/* Brief case 4: a split at EVERY offset, including inside a CRLF and
 * inside a header name, reaches the same result as no split at all. */
static void test_every_two_way_split(void) {
    static const char *reqs[] = {
        "POST /admin/users HTTP/1.1\r\nContent-Length: 5\r\nHost: h\r\n\r\nabcde",
        "GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
        "GET / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxy",
    };
    size_t r;
    for (r = 0; r < sizeof(reqs) / sizeof(reqs[0]); r++) {
        size_t len = strlen(reqs[r]);
        cloak_http_state_t want_st;
        int want_status;
        size_t split;
        {
            cloak_http_parser_t p;
            size_t consumed = 0;
            cloak_http_parser_init(&p);
            want_st = cloak_http_parser_feed(&p, (const uint8_t *)reqs[r], len,
                                             &consumed);
            want_status = cloak_http_parser_request(&p)->status;
            cloak_http_parser_destroy(&p);
        }
        for (split = 0; split <= len; split++) {
            cloak_http_parser_t p;
            size_t consumed = 0;
            cloak_http_state_t st;
            cloak_http_parser_init(&p);
            st = cloak_http_parser_feed(&p, (const uint8_t *)reqs[r], split,
                                        &consumed);
            if (st == CLOAK_HTTP_INCOMPLETE) {
                st = cloak_http_parser_feed(&p, (const uint8_t *)reqs[r] + split,
                                            len - split, &consumed);
            }
            ASSERT_EQ_INT((int)want_st, (int)st);
            ASSERT_EQ_INT(want_status, cloak_http_parser_request(&p)->status);
            cloak_http_parser_destroy(&p);
        }
    }
}

/* Brief case 9's other half: INCOMPLETE is permanent without more bytes.
 * The parser has no patience of its own to run out; only the caller's
 * deadline (Task 4's) ends this. */
static void test_short_body_never_completes(void) {
    const char *req = "POST /x HTTP/1.1\r\nContent-Length: 100\r\n\r\nnowhere near 100";
    cloak_http_parser_t p;
    size_t consumed = 0;
    int i;
    cloak_http_parser_init(&p);
    ASSERT_EQ_INT(CLOAK_HTTP_INCOMPLETE,
                  cloak_http_parser_feed(&p, (const uint8_t *)req, strlen(req),
                                         &consumed));
    for (i = 0; i < 1000; i++) {
        ASSERT_EQ_INT(CLOAK_HTTP_INCOMPLETE,
                      cloak_http_parser_feed(&p, (const uint8_t *)"", 0, &consumed));
        ASSERT_EQ_INT(CLOAK_HTTP_INCOMPLETE, (int)cloak_http_parser_state(&p));
    }
    ASSERT_EQ_INT(0, (int)cloak_http_parser_request(&p)->body_len);
    cloak_http_parser_destroy(&p);
}

/* Nothing oversized is allocated: a refused Content-Length leaves the
 * parser owning zero bytes of body storage, and an accepted one owns
 * exactly what was declared. */
static void test_refusal_precedes_allocation(void) {
    static const char *refused[] = {
        "POST /x HTTP/1.1\r\nContent-Length: 99999999999999999999\r\n\r\n",
        "POST /x HTTP/1.1\r\nContent-Length: 18446744073709551615\r\n\r\n",
        "POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
    };
    size_t i;
    char over[128];
    cloak_http_parser_t p;
    size_t consumed = 0;

    for (i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
        cloak_http_parser_init(&p);
        ASSERT_EQ_INT(CLOAK_HTTP_ERROR,
                      cloak_http_parser_feed(&p, (const uint8_t *)refused[i],
                                             strlen(refused[i]), &consumed));
        ASSERT_EQ_INT(0, (int)cloak_http_parser_body_allocated(&p));
        cloak_http_parser_destroy(&p);
    }

    snprintf(over, sizeof(over),
             "POST /x HTTP/1.1\r\nContent-Length: %u\r\n\r\n",
             (unsigned)CLOAK_HTTP_MAX_BODY + 1u);
    cloak_http_parser_init(&p);
    ASSERT_EQ_INT(CLOAK_HTTP_ERROR,
                  cloak_http_parser_feed(&p, (const uint8_t *)over, strlen(over),
                                         &consumed));
    ASSERT_EQ_INT(413, cloak_http_parser_request(&p)->status);
    ASSERT_EQ_INT(0, (int)cloak_http_parser_body_allocated(&p));
    cloak_http_parser_destroy(&p);

    /* The positive half of the same guard: an in-cap body does allocate,
     * so the assertion above is pinning a real mechanism rather than a
     * function that always returns 0. */
    cloak_http_parser_init(&p);
    ASSERT_EQ_INT(CLOAK_HTTP_DONE,
                  cloak_http_parser_feed(
                      &p, (const uint8_t *)"POST /x HTTP/1.1\r\nContent-Length: 9\r\n\r\nninebytes",
                      strlen("POST /x HTTP/1.1\r\nContent-Length: 9\r\n\r\nninebytes"),
                      &consumed));
    ASSERT_EQ_INT(9, (int)cloak_http_parser_body_allocated(&p));
    cloak_http_parser_destroy(&p);
}

/* Sticky terminal states, and destroy()'s contract. */
static void test_terminal_states_and_lifecycle(void) {
    const char *req = "GET / HTTP/1.1\r\n\r\n";
    const char *bad = "GET / HTTP/9.9\r\n\r\n";
    cloak_http_parser_t p;
    size_t consumed = 0;

    cloak_http_parser_init(&p);
    ASSERT_EQ_INT(CLOAK_HTTP_DONE,
                  cloak_http_parser_feed(&p, (const uint8_t *)req, strlen(req),
                                         &consumed));
    consumed = 12345;
    ASSERT_EQ_INT(CLOAK_HTTP_DONE,
                  cloak_http_parser_feed(&p, (const uint8_t *)req, strlen(req),
                                         &consumed));
    ASSERT_EQ_INT(0, (int)consumed); /* a finished parser consumes nothing */
    cloak_http_parser_destroy(&p);
    cloak_http_parser_destroy(&p); /* idempotent */

    cloak_http_parser_init(&p);
    ASSERT_EQ_INT(CLOAK_HTTP_ERROR,
                  cloak_http_parser_feed(&p, (const uint8_t *)bad, strlen(bad),
                                         &consumed));
    ASSERT_EQ_INT(400, cloak_http_parser_request(&p)->status);
    consumed = 12345;
    ASSERT_EQ_INT(CLOAK_HTTP_ERROR,
                  cloak_http_parser_feed(&p, (const uint8_t *)req, strlen(req),
                                         &consumed));
    ASSERT_EQ_INT(0, (int)consumed);
    ASSERT_EQ_INT(400, cloak_http_parser_request(&p)->status);
    cloak_http_parser_destroy(&p);

    /* Safe on a zeroed struct that was never initialized. */
    memset(&p, 0, sizeof(p));
    cloak_http_parser_destroy(&p);

    /* NULL tolerance, matching the rest of this codebase. */
    cloak_http_parser_init(NULL);
    cloak_http_parser_destroy(NULL);
    ASSERT_EQ_INT(CLOAK_HTTP_ERROR,
                  cloak_http_parser_feed(NULL, (const uint8_t *)req, 1, &consumed));
    ASSERT_TRUE(cloak_http_parser_request(NULL) == NULL);
    ASSERT_EQ_INT(0, (int)cloak_http_parser_body_allocated(NULL));
}

/* ---------------------------------------------------------------- */
/* Brief case 11: seeded fuzz smoke                                 */
/* ---------------------------------------------------------------- */

static uint64_t g_rng = 0x243F6A8885A308D3ull; /* fixed: failures reproduce */

static uint64_t rng_next(void) {
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 7;
    g_rng ^= g_rng << 17;
    return g_rng;
}

static void fuzz_check(cloak_http_parser_t *p, cloak_http_state_t st) {
    const cloak_http_request_t *r;
    ASSERT_TRUE(st == CLOAK_HTTP_INCOMPLETE || st == CLOAK_HTTP_DONE ||
                st == CLOAK_HTTP_ERROR);
    r = cloak_http_parser_request(p);
    if (st == CLOAK_HTTP_DONE) {
        ASSERT_TRUE(strlen(r->path) < CLOAK_HTTP_MAX_PATH);
        ASSERT_TRUE(r->body_len <= CLOAK_HTTP_MAX_BODY);
        ASSERT_TRUE(r->body_len == (r->have_content_length ? r->content_length : 0));
    } else if (st == CLOAK_HTTP_ERROR) {
        ASSERT_TRUE(r->status == 400 || r->status == 413 || r->status == 414 ||
                    r->status == 431 || r->status == 500 || r->status == 501);
    }
}

static void test_fuzz_smoke(void) {
    static const char alphabet[] =
        "GET POST DELETE OPTIONS / HTTP/1.1\r\n:; \t"
        "Content-Length Transfer-Encoding chunked 0123456789abcXYZ%-";
    static uint8_t buf[2048];
    int iter;

    /* Half pseudo-random noise, half HTTP-shaped noise -- the second half
     * is what actually reaches the header and body paths. */
    for (iter = 0; iter < 4000; iter++) {
        cloak_http_parser_t p;
        size_t len = (size_t)(rng_next() % sizeof(buf));
        size_t off = 0;
        int http_shaped = (iter & 1);
        cloak_http_state_t st = CLOAK_HTTP_INCOMPLETE;
        size_t i;

        for (i = 0; i < len; i++) {
            uint64_t v = rng_next();
            buf[i] = http_shaped ? (uint8_t)alphabet[v % (sizeof(alphabet) - 1)]
                                 : (uint8_t)(v & 0xff);
        }

        cloak_http_parser_init(&p);
        while (off < len) {
            size_t chunk = (size_t)(rng_next() % 64) + 1;
            size_t consumed = 0;
            if (chunk > len - off) {
                chunk = len - off;
            }
            st = cloak_http_parser_feed(&p, buf + off, chunk, &consumed);
            ASSERT_TRUE(consumed <= chunk);
            off += chunk;
            fuzz_check(&p, st);
            if (st != CLOAK_HTTP_INCOMPLETE) {
                break;
            }
        }
        fuzz_check(&p, st);
        cloak_http_parser_destroy(&p);
    }

    /* Mutations of a valid request: the shape most likely to walk the
     * parser one byte off a boundary rather than far away from it. */
    for (iter = 0; iter < 2000; iter++) {
        static const char valid[] =
            "POST /admin/users HTTP/1.1\r\nContent-Length: 5\r\nHost: h\r\n\r\nabcde";
        uint8_t mut[sizeof(valid)];
        cloak_http_parser_t p;
        size_t consumed = 0;
        int k;
        cloak_http_state_t st;

        memcpy(mut, valid, sizeof(valid) - 1);
        for (k = 0; k < 1 + (int)(rng_next() % 3); k++) {
            size_t pos = (size_t)(rng_next() % (sizeof(valid) - 1));
            mut[pos] = (uint8_t)(rng_next() & 0xff);
        }
        cloak_http_parser_init(&p);
        st = cloak_http_parser_feed(&p, mut, sizeof(valid) - 1, &consumed);
        fuzz_check(&p, st);
        cloak_http_parser_destroy(&p);
    }
}

static void free_cases(void) {
    size_t i;
    for (i = 0; i < g_case_count; i++) {
        free(g_cases[i].req);
    }
}

TEST_MAIN_BEGIN()
    build_cases();
    build_count_and_body_cases();
    test_cases_whole();
    test_cases_byte_at_a_time();
    test_every_two_way_split();
    test_short_body_never_completes();
    test_refusal_precedes_allocation();
    test_terminal_states_and_lifecycle();
    test_fuzz_smoke();
    free_cases();
TEST_MAIN_END()
