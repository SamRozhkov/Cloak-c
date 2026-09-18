/* TARGET #6: cloak_http_parser_* (libcloak-server/src/http.c), the admin
 * API's incremental HTTP/1.1 request parser.
 *
 * THIS ONE IS NOT REGRESSION INSURANCE, AND IT IS THE REASON THIS TASK
 * IS WORTH DOING. The other three targets in this task (#4, #5, #9) are
 * insurance against a future edit and say so in their own headers. This
 * one is different on every axis that matters:
 *
 *   - HIGHEST PER-BUG COST IN THE TREE, and the file says so itself.
 *     cloak/http.h:19-27: "Here the input is attacker-controlled AND
 *     AUTHENTICATED AS THE OPERATOR. ... A memory-safety bug in here is
 *     remote code execution, not a fingerprint." Everywhere else in
 *     libcloak-server the worst outcome of mishandling hostile bytes is a
 *     fingerprint; here it is the process holding every user's
 *     credentials.
 *   - LOWEST REACHABILITY: getting here costs an attacker the admin UID.
 *     That is what makes it a poor place to look for a fingerprint bug
 *     and an excellent place to look for a memory one.
 *   - AND, UNLIKE #4 AND #5, IT HAS STATE AND A HEAP. Those two are pure
 *     functions over one buffer. This is an incremental state machine
 *     that ALLOCATES A BODY FROM AN ATTACKER-DECLARED LENGTH and carries
 *     a partially-parsed request across feeds. "It did not crash" is a
 *     weak oracle for such a thing: the bugs that matter are a body
 *     allocated before its length was bounded, a body copied to the wrong
 *     offset, a consumed count that does not match where the body ended,
 *     and a state machine that answers differently depending on how the
 *     network happened to cut the stream.
 *
 * THE ORACLES, AND WHAT EACH WOULD ACTUALLY CATCH
 *
 *   O1  consumed <= len, always. The parser tells the caller how many
 *       bytes it took; a count past the buffer is a caller over-read.
 *   O2  status is 0 unless the state is ERROR, and is one of the six
 *       documented codes (400/413/414/431/500/501) when it is.
 *   O3  BOUNDS BEFORE ALLOCATION, MADE OBSERVABLE. At every step
 *       cloak_http_parser_body_allocated() must be <= CLOAK_HTTP_MAX_BODY,
 *       and must be 0 after a 413 or a 501 -- the two refusals the header
 *       says happen BEFORE any allocation. This is the oracle that
 *       notices an over-cap Content-Length being honoured, which ASan
 *       never would: a 1 MiB malloc is a perfectly valid malloc.
 *   O4  On DONE, body_len == content_length when one was declared, and
 *       body is NULL with body_len 0 when none was; and the allocation is
 *       exactly content_length, never more.
 *   O5  THE BODY IS WHERE IT SHOULD BE. On DONE the parser stops at the
 *       last body byte, so the body it returns must be byte-for-byte the
 *       last body_len bytes of the input it consumed. This catches a body
 *       copied from the wrong offset or by the wrong amount -- an answer
 *       that is wrong rather than a crash.
 *   O6  DONE and ERROR are sticky: a further feed consumes nothing and
 *       returns the same state, so no caller can walk a finished parser
 *       into a second request.
 *   O7  path is always NUL-terminated inside its array, and on DONE it is
 *       origin-form (begins with '/').
 *   O8  THE SPLIT DIFFERENTIAL, AND IT IS THE ONE THAT EARNS THE TARGET.
 *       The same bytes are parsed twice: once in a single feed, and once
 *       ONE BYTE AT A TIME. The two must agree on the final state, the
 *       status, the method, the path, the body length, the body bytes and
 *       the TOTAL number of bytes consumed. Every existing test feeds a
 *       chosen shape; this compares the two extremes of how a network can
 *       cut a stream, on every input, and any state carried wrongly
 *       across a feed boundary shows up as a disagreement rather than as
 *       a crash. It needs no harness input format to do it, so nothing
 *       sits between the mutator and the parser.
 *
 * A KNOWN ORACLE GAP, MEASURED RATHER THAN ARGUED. These oracles do NOT
 * re-derive the Content-Length from the request text, so they cannot
 * notice a value that is WRONG BUT IN RANGE. Measured: moving the cap
 * check out of the accumulation loop in parse_content_length and doing it
 * once at the end -- exactly the "simplification" a reviewer might make,
 * and the bug that makes a 20-digit Content-Length wrap a size_t and be
 * accepted as a small one -- SURVIVED 5,885,563 EXECUTIONS of this target
 * in 60 s from the committed corpus. The existing suite does catch it
 * (test_http_parse has explicit "2^64 exactly", "2^64+1" and
 * "2^64+65536" cases), which is why the gap is recorded here rather than
 * papered over: closing it needs a second, independent Content-Length
 * scanner in this harness, and an under-tested mirror that aborts on its
 * own bugs would be worse than the gap. If you delete those three test
 * cases, nothing else in the tree notices.
 *
 * INPUT FORMAT: none. The input is the request bytes. The byte-at-a-time
 * replay is derived from the same bytes rather than steered by a control
 * byte, deliberately: a format would cost the mutator half its bytes and
 * buy a chunking axis that the two extremes already bracket.
 *
 * GATE ANALYSIS: no gate of the shape module 10a task 1 measured (a
 * 2^64-wide equality with no coverage gradient). Reaching the body
 * allocation needs a request line, a `Content-Length: <digits>` header
 * and a blank line -- a structure, not an equality, and every byte of it
 * is behind its own comparison with its own coverage edge, so the mutator
 * is rewarded incrementally. The corpus is seeded with real request
 * shapes anyway; the measurement of what it is worth is in this module's
 * task 3 report.
 *
 * The input is copied into an exact-sized allocation so ASan's redzones
 * sit immediately either side of it.
 */

#include "cloak/http.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_CHECK(cond, msg)                                                  \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "fuzz_http: oracle failed: %s\n", (msg));           \
            abort();                                                           \
        }                                                                      \
    } while (0)

static int status_is_documented(int s) {
    return s == 400 || s == 413 || s == 414 || s == 431 || s == 500 || s == 501;
}

/* The invariants that hold at EVERY step, whatever the state. Called
 * after every single feed of both parsers, so a violation is reported at
 * the feed that produced it. */
static void check_step(const cloak_http_parser_t *p) {
    const cloak_http_request_t *req = cloak_http_parser_request(p);
    cloak_http_state_t st = cloak_http_parser_state(p);
    size_t alloc = cloak_http_parser_body_allocated(p);
    size_t i;

    FUZZ_CHECK(req != NULL, "request is NULL for a non-NULL parser");
    FUZZ_CHECK(st == CLOAK_HTTP_INCOMPLETE || st == CLOAK_HTTP_DONE ||
                   st == CLOAK_HTTP_ERROR,
               "state is not one of the three documented values");

    /* O2 */
    if (st == CLOAK_HTTP_ERROR) {
        FUZZ_CHECK(status_is_documented(req->status), "ERROR carries an undocumented status");
    } else {
        FUZZ_CHECK(req->status == 0, "a non-ERROR state carries a status");
    }

    /* O3: rule 2 of cloak/http.h, made observable. */
    FUZZ_CHECK(alloc <= CLOAK_HTTP_MAX_BODY,
               "the parser allocated more than CLOAK_HTTP_MAX_BODY");
    if (st == CLOAK_HTTP_ERROR && (req->status == 413 || req->status == 501)) {
        FUZZ_CHECK(alloc == 0, "a refusal that precedes allocation still allocated");
    }
    if (req->have_content_length) {
        FUZZ_CHECK(req->content_length <= CLOAK_HTTP_MAX_BODY,
                   "an over-cap Content-Length was accepted");
    }

    /* O7 */
    for (i = 0; i < CLOAK_HTTP_MAX_PATH; i++) {
        if (req->path[i] == '\0') {
            break;
        }
    }
    FUZZ_CHECK(i < CLOAK_HTTP_MAX_PATH, "path is not NUL-terminated inside its array");

    if (st == CLOAK_HTTP_DONE) {
        FUZZ_CHECK(req->path[0] == '/', "DONE with a path that is not origin-form");
        /* O4 */
        if (req->have_content_length) {
            FUZZ_CHECK(req->body_len == req->content_length,
                       "body length does not match the declared Content-Length");
            FUZZ_CHECK(alloc == req->content_length,
                       "allocation does not match the declared Content-Length");
            if (req->content_length > 0) {
                FUZZ_CHECK(req->body != NULL, "DONE with a declared body and a NULL pointer");
            }
        } else {
            FUZZ_CHECK(req->body == NULL && req->body_len == 0,
                       "a request with no Content-Length produced a body");
            FUZZ_CHECK(alloc == 0, "a request with no Content-Length allocated one");
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t *buf;
    cloak_http_parser_t one, split;
    cloak_http_state_t st_one, st_split;
    const cloak_http_request_t *r_one;
    const cloak_http_request_t *r_split;
    size_t consumed_one = 0;
    size_t consumed_split = 0;
    size_t off;

    buf = (uint8_t *)malloc(size == 0 ? 1 : size);
    if (buf == NULL) {
        return 0;
    }
    if (size > 0) {
        memcpy(buf, data, size);
    }

    /* Parser A: everything in one feed. */
    cloak_http_parser_init(&one);
    check_step(&one);
    st_one = cloak_http_parser_feed(&one, buf, size, &consumed_one);
    /* O1 */
    FUZZ_CHECK(consumed_one <= size, "one-shot feed consumed more than it was given");
    check_step(&one);

    /* Parser B: one byte at a time, the other extreme of how a network
     * can cut the same stream. */
    cloak_http_parser_init(&split);
    check_step(&split);
    st_split = CLOAK_HTTP_INCOMPLETE;
    for (off = 0; off < size; off++) {
        size_t took = (size_t)-1;
        st_split = cloak_http_parser_feed(&split, buf + off, 1, &took);
        FUZZ_CHECK(took <= 1, "a one-byte feed consumed more than one byte");
        consumed_split += took;
        check_step(&split);
        if (st_split != CLOAK_HTTP_INCOMPLETE) {
            break;
        }
    }

    r_one = cloak_http_parser_request(&one);
    r_split = cloak_http_parser_request(&split);

    /* O5: the body is the tail of what was consumed. */
    if (st_one == CLOAK_HTTP_DONE && r_one->body_len > 0) {
        FUZZ_CHECK(r_one->body_len <= consumed_one, "body is longer than the bytes consumed");
        FUZZ_CHECK(memcmp(r_one->body, buf + (consumed_one - r_one->body_len),
                          r_one->body_len) == 0,
                   "the body returned is not the bytes at the end of what was consumed");
    }

    /* O8: the split differential. */
    FUZZ_CHECK(st_one == st_split, "one-shot and byte-at-a-time disagree on the final state");
    FUZZ_CHECK(r_one->status == r_split->status,
               "one-shot and byte-at-a-time disagree on the status");
    FUZZ_CHECK(r_one->method == r_split->method,
               "one-shot and byte-at-a-time disagree on the method");
    FUZZ_CHECK(strcmp(r_one->path, r_split->path) == 0,
               "one-shot and byte-at-a-time disagree on the path");
    FUZZ_CHECK(r_one->have_content_length == r_split->have_content_length,
               "one-shot and byte-at-a-time disagree on whether a Content-Length was seen");
    FUZZ_CHECK(r_one->content_length == r_split->content_length,
               "one-shot and byte-at-a-time disagree on the Content-Length");
    FUZZ_CHECK(r_one->body_len == r_split->body_len,
               "one-shot and byte-at-a-time disagree on the body length");
    if (r_one->body_len > 0 && r_one->body != NULL && r_split->body != NULL) {
        FUZZ_CHECK(memcmp(r_one->body, r_split->body, r_one->body_len) == 0,
                   "one-shot and byte-at-a-time disagree on the body bytes");
    }
    FUZZ_CHECK(consumed_one == consumed_split,
               "one-shot and byte-at-a-time disagree on how many bytes were consumed");
    FUZZ_CHECK(cloak_http_parser_body_allocated(&one) ==
                   cloak_http_parser_body_allocated(&split),
               "one-shot and byte-at-a-time disagree on how much was allocated");

    /* O6: stickiness, on whichever parser reached a terminal state. */
    if (st_one != CLOAK_HTTP_INCOMPLETE) {
        static const uint8_t more[] = "GET / HTTP/1.1\r\n\r\n";
        size_t took = (size_t)-1;
        cloak_http_state_t again = cloak_http_parser_feed(&one, more, sizeof(more) - 1, &took);
        FUZZ_CHECK(again == st_one, "a terminal parser changed state on a further feed");
        FUZZ_CHECK(took == 0, "a terminal parser consumed bytes from a further feed");
        check_step(&one);
    }

    /* A NULL/0 feed is documented as a legal no-op -- it is how a caller
     * polls a parser that is waiting on a body. */
    {
        size_t took = (size_t)-1;
        cloak_http_state_t poll = cloak_http_parser_feed(&split, NULL, 0, &took);
        FUZZ_CHECK(took == 0, "a NULL/0 poll consumed bytes");
        FUZZ_CHECK(poll == st_split || st_split == CLOAK_HTTP_INCOMPLETE,
                   "a NULL/0 poll changed a terminal state");
    }

    cloak_http_parser_destroy(&one);
    cloak_http_parser_destroy(&split);
    /* Destroy is documented idempotent and safe twice; exercising it here
     * costs nothing and puts the double call under ASan. */
    cloak_http_parser_destroy(&one);
    free(buf);
    return 0;
}
