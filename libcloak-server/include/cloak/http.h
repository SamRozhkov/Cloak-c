#ifndef CLOAK_HTTP_H
#define CLOAK_HTTP_H

#include <stddef.h>
#include <stdint.h>

/* An incremental HTTP/1.1 request parser for the admin API, fed whatever
 * bytes have arrived, never blocking, never allocating a body it has not
 * first bounded.
 *
 * WHY THIS FILE EXISTS AT ALL. Go Cloak gets its request parsing free
 * from net/http (internal/server/adminhttp.go hands a net.Conn to
 * http.Server). This port has no such library, and the admin API is
 * served over the Cloak tunnel itself -- a client that authenticates with
 * the admin UID and session id 0 gets HTTP over its session's streams
 * instead of a proxy -- so the bytes have to be parsed here.
 *
 * WHY ITS THREAT MODEL IS DIFFERENT FROM EVERY OTHER PARSER IN THIS
 * PROJECT, and why that changes what a bug costs. Everywhere else in
 * libcloak-server (cloak_firstpacket_feed, cloak_clienthello_parse) the
 * input is attacker-controlled but UNAUTHENTICATED, and the worst outcome
 * of mishandling it is a fingerprint: the server stops looking like a web
 * server. Here the input is attacker-controlled AND AUTHENTICATED AS THE
 * OPERATOR. Reaching this parser costs an attacker only the admin UID, a
 * 16-byte shared secret sitting in a config file; on the far side of it
 * is the process holding every user's credentials. A memory-safety bug in
 * here is remote code execution, not a fingerprint. Two rules follow, and
 * they bind every line of the implementation:
 *
 *   1. NOTHING IS TRUSTED BECAUSE IT AUTHENTICATED. Every length, every
 *      header, every byte is treated as hostile. Authentication decides
 *      who may talk to this parser; it decides nothing about what they
 *      may say.
 *   2. BOUNDS BEFORE ALLOCATION, ALWAYS. A Content-Length arrives before
 *      its body does. An implausible one is refused at the header, before
 *      a single byte is allocated -- exceeding a cap is a clean HTTP
 *      status, never a failed malloc and never a silent truncation.
 *      cloak_http_parser_body_allocated() exists so that rule is
 *      observable rather than merely asserted in a comment.
 *
 * CALLER OBLIGATION this object cannot meet on its own: A DEADLINE. This
 * parser has no notion of time, of sockets, or of the stream it is being
 * fed from -- deliberately, so it is testable without a session, a
 * reactor or a socket. It therefore CANNOT time anything out. A request
 * whose body is one byte short of its Content-Length stays
 * CLOAK_HTTP_INCOMPLETE forever, which is the only correct answer a
 * parser can give (returning a short body would hand the router a message
 * the sender never finished sending). Ending that wait is the caller's
 * job: the admin-API handler MUST arm a deadline when it starts feeding a
 * parser and tear the stream down if the parser has not reached DONE or
 * ERROR by the time it fires. Without one, a client that sends
 * "Content-Length: 65536" and then nothing pins this parser, its body
 * allocation and the stream for as long as the session lives. This is the
 * same obligation cloak_firstpacket_t documents, for the same reason.
 *
 * LINE ENDINGS: STRICT CRLF, DELIBERATELY. A bare LF, and a bare CR not
 * immediately followed by LF, are both a hard 400 anywhere in the request
 * line or the header block. Being lenient here is defensible for a
 * general-purpose server that must accept the whole zoo of real clients;
 * this one has exactly one legitimate client, Cloak's own admin client,
 * and it emits CRLF. Leniency would buy nothing and cost the classic
 * request-smuggling differential, where one parser ends a header line at
 * a bare LF and another does not, so the same bytes frame two different
 * requests. What is NOT acceptable is being *accidentally* lenient, so
 * the strictness is stated here and pinned by a test.
 *
 * WHAT THIS PARSER DOES NOT DO: no chunked transfer decoding (any
 * Transfer-Encoding is 501, see below), no obs-fold continuation lines
 * (400), no absolute-form or asterisk-form request targets (400), no
 * header storage. Only two header fields mean anything here,
 * Content-Length and Transfer-Encoding; everything else is validated for
 * shape and then dropped, because the admin router routes on the method
 * and the path alone.
 */

/* ---------------- Caps ----------------
 *
 * Every cap below is justified against what the real admin client
 * actually sends, and every breach has its own status so a caller can
 * answer correctly rather than collapsing everything into 400. For scale:
 * the LARGEST genuine request the admin API ever receives is a POST of
 * one user's JSON -- a couple of hundred bytes. Every cap here is orders
 * of magnitude above that, which is the point: they exist to make
 * absurdity cheap to refuse, not to police legitimate traffic.
 */

/* Longest request target, INCLUDING the NUL terminator -- so the longest
 * path actually accepted is CLOAK_HTTP_MAX_PATH - 1 bytes. Real admin
 * paths are "/admin/users/<base64 UID>", about 40 bytes; 256 leaves room
 * for query strings and percent-encoding without ever approaching it.
 * Breach: 414 (URI Too Long). Deliberately NOT 400: an over-long target
 * is not malformed, it is over a cap, and telling the two apart matters
 * when debugging a client. */
#define CLOAK_HTTP_MAX_PATH 256

/* Longest request line, EXCLUDING its CRLF. Method (at most 7 bytes for
 * the four real ones) + SP + path + SP + "HTTP/1.1" is under 280 bytes
 * even at the path cap; 1024 is ~3.5x that. It is a separate cap from
 * the path cap because a long METHOD token is bounded by nothing else.
 * Breach: 414. */
#define CLOAK_HTTP_MAX_REQUEST_LINE 1024

/* Longest single header line, EXCLUDING its CRLF. The longest header the
 * real client sends is "Content-Type: application/json" (30 bytes); 512
 * is 17x that and still comfortably above any plausible Host,
 * User-Agent or Content-Length. Breach: 431 (Request Header Fields Too
 * Large) -- RFC 9110 6.5.11 covers a single oversized field as well as an
 * oversized block, so one status serves both. */
#define CLOAK_HTTP_MAX_HEADER_LINE 512

/* Total bytes of the header block: every header line plus its CRLF, plus
 * the empty line that ends the block. The real client sends three or four
 * headers, under 150 bytes; 4096 is a full memory page and ~27x the
 * largest real block. Breach: 431. This is the cap that actually bounds
 * how long a client can keep this parser alive without completing a
 * request, which is why it is the tighter of the two header caps in
 * practice. */
#define CLOAK_HTTP_MAX_HEADER_BLOCK 4096

/* Maximum number of header lines. Bounded separately from the block size
 * because a flood of tiny headers is cheap to send and, in a parser that
 * stored them, expensive to keep -- this one stores none, so the cap is
 * belt-and-braces, but it is the sort of belt whose absence is only ever
 * noticed once. The real client sends at most four. Breach: 431. */
#define CLOAK_HTTP_MAX_HEADERS 32

/* Maximum body, in bytes, and therefore the largest Content-Length that
 * will be accepted. One user's JSON is a couple of hundred bytes; 64 KiB
 * is over 300x that, and is chosen to stay small enough that allocating
 * one is never itself a denial of service (the admin session is a single
 * session, and Task 4 holds at most one parser per stream). Breach: 413
 * (Content Too Large), reported AT THE HEADER, before any allocation. */
#define CLOAK_HTTP_MAX_BODY 65536

typedef enum {
    CLOAK_HTTP_INCOMPLETE = 0, /* need more bytes; feed again */
    CLOAK_HTTP_DONE,           /* a complete request is available */
    CLOAK_HTTP_ERROR,          /* malformed or over a cap; see request.status */
} cloak_http_state_t;

typedef enum {
    CLOAK_HTTP_METHOD_OTHER = 0, /* anything else: the ROUTER answers 405 */
    CLOAK_HTTP_METHOD_GET,
    CLOAK_HTTP_METHOD_POST,
    CLOAK_HTTP_METHOD_DELETE,
    CLOAK_HTTP_METHOD_OPTIONS,
} cloak_http_method_t;

typedef struct {
    /* Methods are matched case-sensitively, per RFC 9110 9.1: "get" is a
     * different token from "GET", and quietly treating it as GET would be
     * a router differential. An unrecognised method is NOT a parser
     * error -- it is reported as CLOAK_HTTP_METHOD_OTHER so the router
     * can answer 405 with a proper Allow header, which is a decision the
     * parser has no business making. */
    cloak_http_method_t method;

    /* The request target exactly as received, NUL-terminated, never
     * decoded, unescaped or normalised here -- normalising a path is a
     * routing decision, and doing it in two places is how a path
     * traversal gets through one of them. Origin-form only. */
    char path[CLOAK_HTTP_MAX_PATH];

    /* content_length is meaningful only when have_content_length is 1. A
     * request with no Content-Length has no body, full stop: this parser
     * never reads a body it was not told the length of. */
    size_t content_length;
    int have_content_length;

    /* The body, once state is DONE. Points into storage OWNED BY THE
     * PARSER, allocated only after content_length was checked against
     * CLOAK_HTTP_MAX_BODY.
     *
     * LIFETIME, and it matters because Task 4 holds a
     * cloak_http_request_t across reactor turns: these bytes live until
     * cloak_http_parser_destroy() is called on the parser that produced
     * them, and not one instruction longer. The request struct is a VIEW
     * into the parser, not a value that can outlive it -- copy the bytes
     * out if you need them after the parser goes away.
     *
     * WHY PARSER-OWNED rather than a caller-provided buffer: a caller
     * buffer would have to be sized for the worst case (64 KiB) and
     * pinned per stream from the moment a request starts, whether or not
     * a body is ever declared, which is exactly the allocation this
     * parser exists to avoid making on an attacker's say-so. Parser-owned
     * storage is allocated once, at a size the parser has already proven
     * is in bounds, and only when a body was actually declared. NULL with
     * body_len 0 when there is no body. */
    const uint8_t *body;
    size_t body_len;

    /* The HTTP status to reply with. Meaningful ONLY when state is
     * CLOAK_HTTP_ERROR; 0 otherwise. One of:
     *   400 malformed -- request line, header syntax, bad or conflicting
     *       Content-Length, bare LF or bare CR, NUL or control byte
     *   413 Content-Length over CLOAK_HTTP_MAX_BODY
     *   414 request line or path over its cap
     *   431 one header line, the header block, or the header count over
     *       its cap
     *   500 the one allocation this parser makes -- of a body already
     *       proven to be at most CLOAK_HTTP_MAX_BODY -- failed. Genuine
     *       OOM, not attacker leverage: 64 KiB is the most that can ever
     *       be asked for, and an over-cap length never reaches malloc.
     *   501 a Transfer-Encoding header of ANY value (see below) */
    int status;
} cloak_http_request_t;

/* The parser. Fields are exposed so it can be embedded in a stream's
 * state without a second allocation, but they are INTERNAL: read the
 * request through cloak_http_parser_request() and nothing else. */
typedef struct {
    cloak_http_state_t state;
    int phase;       /* internal: which part of the message is being read */
    int pending_cr;  /* internal: a CR was seen and its LF is still owed */

    /* One line at a time. Sized to the larger of the two line caps; the
     * cap that applies is phase-dependent and is enforced BEFORE a byte
     * is written, so this array is never the thing that bounds anything. */
    char line[CLOAK_HTTP_MAX_REQUEST_LINE];
    size_t line_len;

    size_t header_block_len;
    unsigned header_count;

    uint8_t *body_buf;   /* internal: owned; see request.body */
    size_t body_cap;
    size_t body_have;

    cloak_http_request_t req;
} cloak_http_parser_t;

/* The invariant that makes the line-length checks in http.c sufficient:
 * line[] must be at least as large as the largest cap that governs it,
 * or a cap check would pass for a byte the array cannot hold.
 *
 * This is a COMPILE-TIME assertion on purpose. The runtime belt-and-
 * braces version of it -- a second "or the buffer is full" clause in the
 * store path -- is unreachable while this holds, which means no test can
 * ever exercise it and it would sit there forever as dead code that
 * merely looks like safety. Here it fails the build of whoever raises a
 * cap, which is the moment and the person that need to know, rather than
 * at runtime for a user. Raise CLOAK_HTTP_MAX_HEADER_LINE above
 * CLOAK_HTTP_MAX_REQUEST_LINE and this line stops the build. */
_Static_assert(CLOAK_HTTP_MAX_REQUEST_LINE <=
                   sizeof(((cloak_http_parser_t *)0)->line),
               "CLOAK_HTTP_MAX_REQUEST_LINE exceeds the line buffer");
_Static_assert(CLOAK_HTTP_MAX_HEADER_LINE <=
                   sizeof(((cloak_http_parser_t *)0)->line),
               "CLOAK_HTTP_MAX_HEADER_LINE exceeds the line buffer");

/* Resets p to its starting state. Must be called before any other
 * function; a cloak_http_parser_t is not usable zero-initialized (the
 * zero value is indistinguishable from a parser mid-request, which is
 * exactly the confusion that produces a use of uninitialised storage).
 *
 * The struct is FULLY initialized here before anything else is examined,
 * so a parser is always in a destroyable state from the first
 * instruction. p == NULL is a no-op. */
void cloak_http_parser_init(cloak_http_parser_t *p);

/* Releases the body storage p owns and returns p to its initialized
 * state. Idempotent, safe on a parser that was memset to zero and never
 * initialized, and safe on NULL. After this call any cloak_http_request_t
 * previously obtained from p has a dangling body pointer -- see the
 * lifetime note above. */
void cloak_http_parser_destroy(cloak_http_parser_t *p);

/* Feeds len bytes.
 *
 * Returns CLOAK_HTTP_INCOMPLETE (feed more), CLOAK_HTTP_DONE (a complete
 * request is available from cloak_http_parser_request) or
 * CLOAK_HTTP_ERROR (see request.status). Both DONE and ERROR are STICKY:
 * further feeds consume nothing and return the same state, so a caller
 * that keeps feeding cannot walk a finished parser into a second request.
 *
 * *consumed_out, when not NULL, receives how many of the len bytes were
 * taken. THIS IS NOT ALWAYS len, and the difference is load-bearing: once
 * a request's body is complete, the parser stops, and any bytes after it
 * are left for the caller. One stream carries one request here, so those
 * trailing bytes are a protocol violation rather than a pipelined second
 * request -- but a parser that silently ate them would hide exactly the
 * smuggling bug that makes them interesting. On ERROR, *consumed_out
 * counts the bytes read up to and including the offending one and should
 * not be relied on for anything else.
 *
 * A Transfer-Encoding header of ANY value, including an empty one, is
 * refused with 501 rather than ignored. Ignoring it is the well-known
 * CL.TE smuggling vector: an upstream that honours Transfer-Encoding and
 * a downstream that honours Content-Length disagree about where the
 * request ends, and the difference is a request the router never sees.
 * Since this parser implements no transfer coding at all, "not
 * implemented" is both the honest answer and the safe one.
 *
 * A Content-Length is accepted only as a plain non-negative decimal
 * integer (1*DIGIT): "abc", "-1", "+1", "5 5", "5, 5" and an empty value
 * are all 400. Leading zeros ARE accepted -- "007" is valid 1*DIGIT, the
 * numeric value is what gets acted on, and no recipient differential
 * follows. Two Content-Length headers that DISAGREE are 400, the second
 * classic smuggling vector. Two that AGREE are accepted and collapsed
 * into one, which RFC 9112 6.3 explicitly permits: with no disagreement
 * there is no differential for anyone to exploit, and refusing them would
 * reject a request that is unambiguous on its face.
 *
 * p == NULL returns CLOAK_HTTP_ERROR and touches nothing. data == NULL
 * with len == 0 is a legal no-op (it is how a caller polls a parser
 * waiting on a body); data == NULL with len > 0 is a caller bug and is
 * reported as ERROR/400 rather than dereferenced. */
cloak_http_state_t cloak_http_parser_feed(cloak_http_parser_t *p,
                                          const uint8_t *data, size_t len,
                                          size_t *consumed_out);

/* The parsed request. Never NULL for a non-NULL p; NULL for NULL p. Its
 * method, path and body are meaningful once the state is DONE; its status
 * is meaningful once the state is ERROR. */
const cloak_http_request_t *cloak_http_parser_request(const cloak_http_parser_t *p);

/* The current state, without feeding anything. */
cloak_http_state_t cloak_http_parser_state(const cloak_http_parser_t *p);

/* How many bytes of body storage this parser currently owns.
 *
 * This exists to make rule 2 above -- bounds before allocation --
 * OBSERVABLE. A refusal (413 on an over-cap Content-Length, 501 on a
 * Transfer-Encoding) must leave this at 0, because the refusal happened
 * before any allocation was attempted; an accepted body leaves it at
 * exactly content_length. A comment claiming that ordering cannot fail a
 * build; this accessor can. Returns 0 for NULL. */
size_t cloak_http_parser_body_allocated(const cloak_http_parser_t *p);

#endif
