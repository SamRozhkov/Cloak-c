#ifndef CLOAK_WS_HANDSHAKE_H
#define CLOAK_WS_HANDSHAKE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* The server side of the CDN transport's WebSocket upgrade: read the GET a
 * CDN forwarded to the origin, extract the auth payload hidden in one of
 * its headers, and compose the 101 that completes the handshake.
 *
 * WHERE THE BYTES COME FROM, AND WHY THAT MAKES THIS A PURE FUNCTION
 *
 * cloak_firstpacket_t has already done the framing. Its first byte 'G'
 * selects CLOAK_FIRSTPACKET_TRANSPORT_WEBSOCKET, it consumes to the
 * CRLFCRLF that ends the header block, and it reads NO byte past that --
 * which is what lets the session's data path start cleanly on the next
 * byte. So by the time anything here is called the request is complete,
 * bounded (CLOAK_FIRSTPACKET_MAX, 3000 bytes) and sitting in one
 * contiguous buffer.
 *
 * Nothing here therefore allocates, owns a file descriptor, touches the
 * reactor, or keeps state between calls, for the same two reasons
 * cloak/ws_frame.h gives: this is an ATTACKER-CONTROLLED, UNAUTHENTICATED
 * parser -- the first thing a censor's prober reaches -- and a pure
 * function over (buf, len) is directly fuzzable with no harness, which is
 * how module 10 will treat it. "Never reads past req + len" is then a
 * property that can be checked mechanically rather than argued.
 *
 * WHY NOT cloak/http.h's PARSER. It is the wrong tool twice: it is a
 * request parser with no response side, and it stores NO headers at all
 * (http.h:120-125 says so, and gives the reason). This needs `Hidden`,
 * `Sec-WebSocket-Key`, `Connection`, `Upgrade` and `Sec-WebSocket-Version`
 * BY VALUE. Teaching it header capture would mean editing the one file in
 * this tree whose header explains that a memory-safety bug in it is remote
 * code execution as the operator (http.h:17-30). This file reuses that
 * parser's DISCIPLINE -- bounds before storage, named caps, a stated
 * position on line endings -- and none of its code.
 *
 * WHAT GO DOES, since this is a port and not a design. Go splits the same
 * work across two packages:
 *   - internal/server/websocket.go:22-41, processFirstPacket, reads
 *     req.Header.Get("hidden") and nothing else, then decodes and
 *     authenticates it;
 *   - gorilla's Upgrader.Upgrade (server.go:125-175) checks `Connection`,
 *     `Upgrade`, the method, `Sec-WebSocket-Version` and
 *     `Sec-WebSocket-Key`, then writes the 101.
 * Go runs them in that order -- auth first, upgrade validation second --
 * and the module-8 scouting report measured what that costs: an upgrade
 * that fails validation leaks a goroutine and an fd FOREVER, after the UID
 * has already been authorised (scouting report section 6.5, reproduced
 * three ways). This port validates the whole upgrade here, in one pass,
 * BEFORE the dispatcher authorises anything -- so a bad upgrade is an
 * ordinary redirect to the cover site, exactly like an unrecognised
 * protocol. That is both the fix for Go's leak and the better mimicry: the
 * origin looks equally like a web server whether the GET carried a bad
 * `Hidden` or a bad `Connection`.
 *
 * EVERY CONSTANT AND EVERY ACCEPT/REFUSE DECISION BELOW WAS MEASURED
 * against Go 1.25.6 + gorilla/websocket v1.5.3 running in this project's
 * dev image, by feeding crafted requests to a live `http.Serve` +
 * `Upgrader{}` over a net.Pipe and recording the status line it wrote
 * back. Where this file deviates from that measurement, it says so and
 * says why. Nothing here is taken from prose about what HTTP "should" do.
 *
 * WHAT A CDN DOES TO THE REQUEST, which is the whole reason this parser is
 * not three memcmp calls. The client's bytes are NOT the origin's bytes:
 * an HTTP/1.1 reverse proxy re-serialises the request it parsed. Each of
 * the following is a production-only failure that a naive test suite
 * passes happily, and each has a test in test_ws_handshake.c:
 *
 *   - HEADER NAMES ARRIVE IN ANY CASE. `Hidden` becomes `hidden` behind
 *     Cloudflare and behind any HTTP/2-fronted edge, because HTTP/2 field
 *     names are lowercase by definition. Go never notices
 *     (textproto.CanonicalMIMEHeaderKey canonicalises both the incoming
 *     name and the lookup); a C parser that matches "Hidden" with memcmp
 *     fails ONLY in production. Every name comparison here is
 *     ASCII-case-insensitive.
 *   - UNKNOWN HEADERS ARE INJECTED. X-Forwarded-For, CF-Connecting-IP,
 *     CF-RAY, CDN-Loop, Accept-Encoding, Via, ... A bare Go client sends
 *     335 bytes; a Cloudflare-shaped request measured 630. 3000 still
 *     holds, but it has stopped being theoretical, and overflowing it
 *     silently redirects the connection to the cover site.
 *   - `Connection` IS REWRITTEN. `Upgrade, keep-alive` and
 *     `keep-alive, Upgrade` are both real and both must be accepted. This
 *     is token-list matching, not equality.
 *   - `Host` AND THE REQUEST TARGET ARE REWRITTEN. Neither is read here,
 *     and NO path check exists on purpose: the Go server has none
 *     (CDNWsUrlPath exists so the operator can route the CDN to the right
 *     origin, and is never compared server-side), and being fussier than
 *     the reference implementation is itself a behavioural distinguisher
 *     -- the argument libcloak-mux/include/cloak/conn.h already makes
 *     about not validating record type bytes.
 *   - `Sec-WebSocket-Key` MAY BE REGENERATED by the CDN on the origin leg.
 *     That is fine and it is why the accept is computed over the key
 *     RECEIVED, never over one stored anywhere: the CDN computes the
 *     client's accept from the client's key, and the origin's leg is its
 *     own handshake.
 */

/* Decoded length of the `Hidden` payload: randPubKey[0:32] ||
 * ciphertextWithTag[0:64].
 *
 * EXACTLY 96, not "at least". Go reads it as `if len(hidden) < 96` and
 * then `if len(hidden[32:]) != 64` (internal/server/websocket.go:76,96);
 * the pair admits exactly one length. 96 % 3 == 0, so the base64 is
 * CLOAK_WS_HS_HIDDEN_B64_LEN characters with no padding at all. */
#define CLOAK_WS_HS_HIDDEN_LEN 96
#define CLOAK_WS_HS_HIDDEN_B64_LEN 128

/* Longest `Sec-WebSocket-Key` accepted, in characters.
 *
 * gorilla's rule is "base64 that decodes to 16 bytes"
 * (util.go:285-298, isValidChallengeKey), and that rule fixes the length:
 * standard base64 of length L (a multiple of 4, which the strict decoder
 * requires) yields 3L/4 minus one or two padding bytes, so 16 decoded
 * bytes is reachable only from L == 24. Refusing a longer string before
 * decoding it is therefore the same answer the decode would give, arrived
 * at without copying an unbounded value. */
#define CLOAK_WS_HS_KEY_B64_MAX 24

/* base64 of a 20-byte SHA-1 digest: 28 characters including one '='. */
#define CLOAK_WS_HS_ACCEPT_LEN 28

/* Bytes cloak_ws_handshake_compose_101 writes. Four lines and nothing
 * else -- see that function's comment for why there is no Date and no
 * Server, and for where the 129 comes from. */
#define CLOAK_WS_HS_101_LEN 129

typedef enum {
    CLOAK_WS_HS_OK = 0,
    /* No `Upgrade: websocket`, or no `upgrade` token in `Connection`, or
     * a method other than GET. The three are one code because gorilla
     * itself groups them: all three return its `badHandshake` error, "the
     * client is not using the websocket protocol" (server.go:126-139).
     * The method check is case-sensitive and exact ("get" is refused,
     * measured: 405), matching Go's `r.Method != http.MethodGet`. */
    CLOAK_WS_HS_ERR_NOT_UPGRADE,
    /* No `13` token in `Sec-WebSocket-Version`. */
    CLOAK_WS_HS_ERR_BAD_VERSION,
    /* `Sec-WebSocket-Key` absent, empty, or not standard base64 of
     * exactly 16 bytes. */
    CLOAK_WS_HS_ERR_BAD_KEY,
    /* `Hidden` absent, empty, not standard base64, or not exactly
     * CLOAK_WS_HS_HIDDEN_LEN bytes once decoded. */
    CLOAK_WS_HS_ERR_BAD_HIDDEN,
    /* Not a request we can parse at all: no CRLFCRLF inside the supplied
     * bytes, a request line that is not exactly METHOD SP TARGET SP
     * HTTP/x.y, a header line with no colon, a header name that is not an
     * RFC 7230 token, or a header value carrying a control byte. Every
     * one of those is refused by Go's own net/http too (measured: 400,
     * with the request never reaching the handler). */
    CLOAK_WS_HS_ERR_MALFORMED,
    /* The SHA-1 digest failed. Not reachable from any input: EVP_Digest
     * over 60 bytes fails only if OpenSSL cannot allocate a context or
     * cannot supply SHA-1 at all. It exists because returning one of the
     * codes above for an internal failure would be a lie -- it would tell
     * the dispatcher the client sent something wrong -- and because a
     * caller that treats every non-OK the same way (which the dispatcher
     * does, by redirecting) loses nothing by its existence. It is NOT
     * reachable by the fuzzer either; test_ws_handshake.c reaches it by
     * interposing on EVP_Digest. */
    CLOAK_WS_HS_ERR_INTERNAL
} cloak_ws_hs_result_t;

typedef struct {
    /* The decoded `Hidden` payload: randPubKey[0:32] ||
     * ciphertextWithTag[0:64], ready to be handed to the same
     * authentication the TLS path uses. Not NUL-terminated; it is 96
     * bytes of ciphertext, not a string. */
    uint8_t hidden[CLOAK_WS_HS_HIDDEN_LEN];

    /* base64(SHA1(key || GUID)), NUL-terminated, where `key` is the
     * `Sec-WebSocket-Key` value exactly as it arrived. */
    char accept[CLOAK_WS_HS_ACCEPT_LEN + 1];
} cloak_ws_hs_t;

/* Parses one complete upgrade request.
 *
 * `req` is the whole first packet as cloak_firstpacket_data() returns it,
 * `len` its cloak_firstpacket_len(). The buffer is NOT required to be
 * NUL-terminated and is never assumed to be: every read is bounded by
 * `len`. Bytes after the CRLFCRLF that ends the header block are ignored
 * -- cloak_firstpacket_t never produces any, but a fuzzer will, and they
 * belong to the session's data path rather than to this parser.
 *
 * `out` IS WRITTEN ONLY ON CLOAK_WS_HS_OK, in full, as the last thing
 * this function does. On any failure it is left exactly as the caller
 * left it: there is no half-filled `hidden` for a caller to mistake for
 * an authenticated payload.
 *
 * ORDER OF REFUSALS, because tests pin it and a reader should know why:
 * `Hidden` is checked first, then Connection/Upgrade/method, then the
 * version, then the key -- which is the order the two Go layers apply
 * them in (processFirstPacket before Upgrader.Upgrade, and then gorilla's
 * own sequence). It is NOT a security property: every failure here has
 * the same consequence, a redirect to the cover site, and the dispatcher
 * must not branch on which one it was.
 *
 * NULL `req` or NULL `out`, or len == 0, return CLOAK_WS_HS_ERR_MALFORMED
 * without dereferencing anything. */
cloak_ws_hs_result_t cloak_ws_handshake_parse(const uint8_t *req, size_t len,
                                              cloak_ws_hs_t *out);

/* Writes the 101 response into buf and returns CLOAK_WS_HS_101_LEN, or -1
 * if cap is short, buf or accept is NULL, or `accept` is not exactly
 * CLOAK_WS_HS_ACCEPT_LEN characters drawn from the standard base64
 * alphabet.
 *
 * THE EXACT BYTES, captured from a live gorilla v1.5.3 `Upgrader{}`
 * answering a real Go client's request (129 bytes, byte for byte):
 *
 *     HTTP/1.1 101 Switching Protocols\r\n
 *     Upgrade: websocket\r\n
 *     Connection: Upgrade\r\n
 *     Sec-WebSocket-Accept: <28 characters>\r\n
 *     \r\n
 *
 * FOUR LINES AND NOTHING ELSE. No `Date`, no `Server` -- not an
 * omission: gorilla hijacks the connection and writes these bytes to the
 * socket itself (server.go:219-248), so net/http's ResponseWriter, which
 * is what would add those two headers, never runs. No
 * `Sec-WebSocket-Protocol` and no `Sec-WebSocket-Extensions` either,
 * because `Upgrader{}` negotiates no subprotocol and has
 * EnableCompression false. An extra header here would be a Cloak-only
 * artefact on a leg a CDN operator can read in plaintext.
 *
 * The accept's alphabet is validated rather than trusted because this
 * function's output is a response header: a value carrying CR or LF
 * would split the response into headers of an attacker's choosing. The
 * only caller passes cloak_ws_hs_t.accept, which cannot be anything
 * else -- but that is an argument about today's callers, and the check
 * costs 28 comparisons. gorilla makes the same call, replacing every
 * byte <= 31 in a response header value (server.go:241-243).
 *
 * No NUL is written, and nothing past the returned length is touched. */
ssize_t cloak_ws_handshake_compose_101(uint8_t *buf, size_t cap, const char *accept);

#endif
