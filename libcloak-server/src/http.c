/* Incremental HTTP/1.1 request parser for the admin API.
 *
 * The contract, the caps and the reasoning behind every refusal live in
 * cloak/http.h. Read that first: this file is the mechanism, that file is
 * the argument. The one rule worth restating where the code is: every
 * byte here arrives from a client that has AUTHENTICATED AS THE OPERATOR,
 * which buys it exactly no trust -- bounds are checked before a byte is
 * stored, and a length is checked before a byte is allocated.
 *
 * No POSIX APIs are used (only <stdlib.h>, <string.h>), deliberately: this
 * parser is meant to be testable and auditable without a socket, a
 * session or a reactor anywhere near it.
 */
#include "cloak/http.h"

#include <stdlib.h>
#include <string.h>

/* Which part of the message is being read. Kept out of the header as
 * plain ints because it is nobody's business but this file's. */
#define PHASE_REQUEST_LINE 0
#define PHASE_HEADERS 1
#define PHASE_BODY 2

void cloak_http_parser_init(cloak_http_parser_t *p) {
    if (p == NULL) {
        return;
    }
    /* Fully initialized before anything else is looked at, so a parser is
     * destroyable from its first instruction. */
    memset(p, 0, sizeof(*p));
    p->state = CLOAK_HTTP_INCOMPLETE;
    p->phase = PHASE_REQUEST_LINE;
    p->req.method = CLOAK_HTTP_METHOD_OTHER;
    p->req.path[0] = '\0';
}

void cloak_http_parser_destroy(cloak_http_parser_t *p) {
    if (p == NULL) {
        return;
    }
    /* free(NULL) is defined, so this is safe on a zeroed struct that was
     * never initialized and on a second call. */
    free(p->body_buf);
    p->body_buf = NULL;
    cloak_http_parser_init(p);
}

const cloak_http_request_t *cloak_http_parser_request(const cloak_http_parser_t *p) {
    if (p == NULL) {
        return NULL;
    }
    return &p->req;
}

cloak_http_state_t cloak_http_parser_state(const cloak_http_parser_t *p) {
    if (p == NULL) {
        return CLOAK_HTTP_ERROR;
    }
    return p->state;
}

size_t cloak_http_parser_body_allocated(const cloak_http_parser_t *p) {
    if (p == NULL) {
        return 0;
    }
    return p->body_cap;
}

/* ---------------------------------------------------------------- */

static cloak_http_state_t fail(cloak_http_parser_t *p, int status) {
    p->state = CLOAK_HTTP_ERROR;
    p->req.status = status;
    return p->state;
}

static int ascii_lower(int c) {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A' + 'a';
    }
    return c;
}

/* Case-insensitive comparison of a non-NUL-terminated field name against
 * an already-lowercase literal. */
static int name_is(const char *name, size_t name_len, const char *lower) {
    size_t i;
    if (strlen(lower) != name_len) {
        return 0;
    }
    for (i = 0; i < name_len; i++) {
        if (ascii_lower((unsigned char)name[i]) != (unsigned char)lower[i]) {
            return 0;
        }
    }
    return 1;
}

/* RFC 9110 5.6.2 tchar. Field names outside this set are refused rather
 * than tolerated: a name containing a space is the "Content-Length : 5"
 * smuggling shape, and a name containing a control byte has no
 * interpretation two parsers are guaranteed to agree on. */
static int is_tchar(unsigned char c) {
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

static cloak_http_method_t method_of(const char *s, size_t len) {
    /* Case-SENSITIVE, per RFC 9110 9.1. An unknown method is not an error
     * here: the router answers 405, with the Allow header only it can
     * build. */
    if (len == 3 && memcmp(s, "GET", 3) == 0) {
        return CLOAK_HTTP_METHOD_GET;
    }
    if (len == 4 && memcmp(s, "POST", 4) == 0) {
        return CLOAK_HTTP_METHOD_POST;
    }
    if (len == 6 && memcmp(s, "DELETE", 6) == 0) {
        return CLOAK_HTTP_METHOD_DELETE;
    }
    if (len == 7 && memcmp(s, "OPTIONS", 7) == 0) {
        return CLOAK_HTTP_METHOD_OPTIONS;
    }
    return CLOAK_HTTP_METHOD_OTHER;
}

/* METHOD SP request-target SP HTTP-version. Exactly two spaces, no empty
 * field, origin-form target only. */
static cloak_http_state_t finish_request_line(cloak_http_parser_t *p) {
    const char *line = p->line;
    size_t len = p->line_len;
    const char *sp1;
    const char *sp2;
    size_t method_len;
    const char *path;
    size_t path_len;
    const char *version;
    size_t version_len;

    sp1 = (const char *)memchr(line, ' ', len);
    if (sp1 == NULL) {
        return fail(p, 400);
    }
    method_len = (size_t)(sp1 - line);
    if (method_len == 0) {
        return fail(p, 400);
    }

    path = sp1 + 1;
    sp2 = (const char *)memchr(path, ' ', len - method_len - 1);
    if (sp2 == NULL) {
        return fail(p, 400);
    }
    path_len = (size_t)(sp2 - path);
    if (path_len == 0) {
        return fail(p, 400);
    }

    version = sp2 + 1;
    version_len = len - (size_t)(version - line);
    /* A third space means a request target with a space in it, i.e. two
     * readings of where the target ends. Refuse rather than pick one. */
    if (memchr(version, ' ', version_len) != NULL) {
        return fail(p, 400);
    }
    if (version_len != 8 ||
        (memcmp(version, "HTTP/1.1", 8) != 0 &&
         memcmp(version, "HTTP/1.0", 8) != 0)) {
        return fail(p, 400);
    }

    /* Over a cap, not malformed -- 414, and refused before the copy. */
    if (path_len >= CLOAK_HTTP_MAX_PATH) {
        return fail(p, 414);
    }
    /* Origin-form only: no absolute-form ("http://host/x"), no
     * asterisk-form ("*"). Both would have to be normalised before
     * routing, and a target normalised in two places is a target two
     * parsers disagree about. */
    if (path[0] != '/') {
        return fail(p, 400);
    }

    p->req.method = method_of(line, method_len);
    memcpy(p->req.path, path, path_len);
    p->req.path[path_len] = '\0';

    p->phase = PHASE_HEADERS;
    p->line_len = 0;
    return CLOAK_HTTP_INCOMPLETE;
}

/* Content-Length: 1*DIGIT and nothing else. */
static cloak_http_state_t parse_content_length(cloak_http_parser_t *p,
                                               const char *v, size_t v_len) {
    size_t value = 0;
    size_t i;

    if (v_len == 0) {
        return fail(p, 400);
    }
    /* Shape first, magnitude second, so "999999999999abc" is reported as
     * malformed rather than as an over-cap length. A sign, a space, a
     * comma-separated list -- all land here. */
    for (i = 0; i < v_len; i++) {
        if (v[i] < '0' || v[i] > '9') {
            return fail(p, 400);
        }
    }
    for (i = 0; i < v_len; i++) {
        /* The cap is checked INSIDE the accumulation, so a twenty-digit
         * length is refused without ever overflowing a size_t and without
         * anything being allocated for it. Leading zeros are 1*DIGIT and
         * fold away here harmlessly. */
        value = value * 10 + (size_t)(v[i] - '0');
        if (value > CLOAK_HTTP_MAX_BODY) {
            return fail(p, 413);
        }
    }

    if (p->req.have_content_length) {
        /* Two that disagree frame two different requests: the classic
         * CL.CL smuggle. Two that agree are unambiguous and RFC 9112 6.3
         * permits collapsing them. */
        if (p->req.content_length != value) {
            return fail(p, 400);
        }
        return CLOAK_HTTP_INCOMPLETE;
    }
    p->req.have_content_length = 1;
    p->req.content_length = value;
    return CLOAK_HTTP_INCOMPLETE;
}

/* Called once the header block's terminating empty line has been seen. */
static cloak_http_state_t finish_headers(cloak_http_parser_t *p) {
    if (!p->req.have_content_length || p->req.content_length == 0) {
        /* No declared length means no body. This parser never reads a
         * body whose length it was not told. */
        p->req.body = NULL;
        p->req.body_len = 0;
        p->state = CLOAK_HTTP_DONE;
        return p->state;
    }

    /* The ONLY allocation in this file, and it happens strictly after
     * content_length has been proven <= CLOAK_HTTP_MAX_BODY by
     * parse_content_length. Reordering these two is the bug this module's
     * whole threat model is about; cloak_http_parser_body_allocated()
     * exists so a test can prove the order. */
    p->body_buf = (uint8_t *)malloc(p->req.content_length);
    if (p->body_buf == NULL) {
        /* An in-cap allocation failed: real OOM, not attacker leverage,
         * since 64 KiB is the most that can ever be asked for. */
        return fail(p, 500);
    }
    p->body_cap = p->req.content_length;
    p->body_have = 0;
    p->phase = PHASE_BODY;
    return CLOAK_HTTP_INCOMPLETE;
}

static cloak_http_state_t finish_header_line(cloak_http_parser_t *p) {
    const char *line = p->line;
    size_t len = p->line_len;
    const char *colon;
    const char *name;
    size_t name_len;
    const char *value;
    size_t value_len;
    size_t i;

    p->line_len = 0;

    if (len == 0) {
        return finish_headers(p);
    }

    /* obs-fold (a line beginning with SP or HT continuing the one before)
     * is deprecated by RFC 9112 5.2 and is a smuggling vector wherever it
     * is still honoured. Refused outright. */
    if (line[0] == ' ' || line[0] == '\t') {
        return fail(p, 400);
    }

    p->header_count++;
    if (p->header_count > CLOAK_HTTP_MAX_HEADERS) {
        return fail(p, 431);
    }

    colon = (const char *)memchr(line, ':', len);
    if (colon == NULL) {
        return fail(p, 400);
    }
    name = line;
    name_len = (size_t)(colon - line);
    if (name_len == 0) {
        return fail(p, 400);
    }
    for (i = 0; i < name_len; i++) {
        if (!is_tchar((unsigned char)name[i])) {
            return fail(p, 400);
        }
    }

    value = colon + 1;
    value_len = len - name_len - 1;
    while (value_len > 0 && (value[0] == ' ' || value[0] == '\t')) {
        value++;
        value_len--;
    }
    while (value_len > 0 &&
           (value[value_len - 1] == ' ' || value[value_len - 1] == '\t')) {
        value_len--;
    }

    /* Any Transfer-Encoding at all, including an empty value: 501. This
     * parser implements no transfer coding, and IGNORING the header is
     * precisely the CL.TE smuggle -- a peer that honours it and this
     * parser would disagree about where the request ends. */
    if (name_is(name, name_len, "transfer-encoding")) {
        return fail(p, 501);
    }
    if (name_is(name, name_len, "content-length")) {
        return parse_content_length(p, value, value_len);
    }
    /* Everything else is validated for shape and dropped: the router
     * routes on the method and the path alone, so storing the rest would
     * be attacker-controlled memory kept for no reason. */
    return CLOAK_HTTP_INCOMPLETE;
}

/* One byte of a line. Returns 0 to continue, or sets the terminal state
 * and returns -1. */
static int line_byte(cloak_http_parser_t *p, uint8_t b, cloak_http_state_t *out) {
    size_t cap;
    int over_status;

    if (p->phase == PHASE_REQUEST_LINE) {
        cap = CLOAK_HTTP_MAX_REQUEST_LINE;
        over_status = 414;
    } else {
        cap = CLOAK_HTTP_MAX_HEADER_LINE;
        over_status = 431;
    }

    if (p->pending_cr) {
        /* STRICT CRLF: a CR must be followed by an LF. See cloak/http.h
         * for why leniency here buys nothing and costs a differential. */
        if (b != '\n') {
            *out = fail(p, 400);
            return -1;
        }
        p->pending_cr = 0;
        *out = (p->phase == PHASE_REQUEST_LINE) ? finish_request_line(p)
                                                : finish_header_line(p);
        return (*out == CLOAK_HTTP_INCOMPLETE) ? 0 : -1;
    }
    if (b == '\r') {
        p->pending_cr = 1;
        return 0;
    }
    if (b == '\n') {
        /* A bare LF: refused, not accepted as a line ending. */
        *out = fail(p, 400);
        return -1;
    }
    /* NUL, and every other control byte, is refused before it can be
     * stored. A NUL in the target would terminate req.path early and hand
     * the router a shorter path than the one that was authenticated. HT
     * is legal OWS inside a header value, and only there. */
    if (b < 0x20 || b == 0x7f) {
        if (!(b == '\t' && p->phase == PHASE_HEADERS)) {
            *out = fail(p, 400);
            return -1;
        }
    }
    /* Bounds before the store, always. line[] is sized to the larger cap,
     * so this check -- not the array -- is what bounds the write. */
    if (p->line_len >= cap || p->line_len >= sizeof(p->line)) {
        *out = fail(p, over_status);
        return -1;
    }
    p->line[p->line_len++] = (char)b;
    return 0;
}

cloak_http_state_t cloak_http_parser_feed(cloak_http_parser_t *p,
                                          const uint8_t *data, size_t len,
                                          size_t *consumed_out) {
    size_t off = 0;

    if (consumed_out != NULL) {
        *consumed_out = 0;
    }
    if (p == NULL) {
        return CLOAK_HTTP_ERROR;
    }
    /* DONE and ERROR are sticky: a finished parser consumes nothing, so a
     * caller that keeps feeding cannot walk it into a second request. */
    if (p->state != CLOAK_HTTP_INCOMPLETE) {
        return p->state;
    }
    if (data == NULL && len > 0) {
        return fail(p, 400);
    }

    while (off < len) {
        if (p->phase == PHASE_BODY) {
            size_t need = p->req.content_length - p->body_have;
            size_t take = len - off;
            if (take > need) {
                take = need;
            }
            memcpy(p->body_buf + p->body_have, data + off, take);
            p->body_have += take;
            off += take;
            if (p->body_have == p->req.content_length) {
                p->req.body = p->body_buf;
                p->req.body_len = p->body_have;
                p->state = CLOAK_HTTP_DONE;
                /* Anything after the body is left UNCONSUMED on purpose:
                 * one stream carries one request here, and a parser that
                 * silently ate trailing bytes would hide the smuggling
                 * bug that makes them interesting. */
                break;
            }
            continue; /* ran out of input mid-body: still INCOMPLETE */
        }

        /* The header block is bounded by total bytes as well as by line
         * length and line count, and the count is charged BEFORE the byte
         * is acted on -- so a block that is one byte over its cap is
         * refused even when that byte is the last one of the terminating
         * CRLF. Over a cap is over a cap, whatever it completes. */
        if (p->phase == PHASE_HEADERS) {
            p->header_block_len++;
            if (p->header_block_len > CLOAK_HTTP_MAX_HEADER_BLOCK) {
                p->state = fail(p, 431);
                off++;
                break;
            }
        }

        {
            cloak_http_state_t st = CLOAK_HTTP_INCOMPLETE;
            int rc = line_byte(p, data[off], &st);
            off++;
            if (rc != 0) {
                p->state = st;
                break;
            }
            if (p->state != CLOAK_HTTP_INCOMPLETE) {
                break;
            }
        }
    }

    if (consumed_out != NULL) {
        *consumed_out = off;
    }
    return p->state;
}
