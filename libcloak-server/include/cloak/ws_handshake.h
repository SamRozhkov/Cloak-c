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
 * Go runs them in that order -- auth first, upgrade validation second.
 * CITED, NOT MEASURED HERE: the module-8 scouting report (section 6.5,
 * where it was reproduced three ways with Cloak's own types) found what
 * that ordering costs -- an upgrade that fails validation leaks a
 * goroutine and an fd FOREVER, after the UID has already been
 * authorised. Nothing in this file pair can re-derive that, since it
 * needs a running Go server rather than a parser; treat it as a
 * reference to that report, and go and read it there rather than
 * believing it because it is repeated here.
 * This port validates the whole upgrade here, in one pass,
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
 *     CF-RAY, CDN-Loop, Accept-Encoding, Via, ... Go's own client sends
 *     335 bytes (measured: exactly what websocket.NewClient wrote, and
 *     the golden request in test_ws_handshake.c). The Cloudflare-shaped
 *     request in that same file -- nineteen header lines, the target and
 *     Host rewritten -- is 631 bytes, and live gorilla answered it 101.
 *     TREAT 631 AS A SCALE, NOT A CONSTANT: it is a property of the
 *     particular headers chosen, and an independent reviewer measuring
 *     its own plausible Cloudflare set got 627. The load-bearing fact is
 *     the one both numbers agree on -- a fronted request is roughly
 *     double a bare one, so CLOAK_FIRSTPACKET_MAX (3000) still holds
 *     while having stopped being theoretical. Overflowing it silently
 *     redirects the connection to the cover site.
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
 *   - `Origin` MAY BE INJECTED, AND THIS PARSER DOES NOT READ IT. This is
 *     a DELIBERATE DIVERGENCE FROM GORILLA, and it is the last of the
 *     three named triggers of the Go wedge described above. Details in
 *     the paragraph below, because it is the one accept decision here
 *     that gorilla would refuse.
 *
 * `Origin`: THE DIVERGENCE THAT IS AN ACCEPT RATHER THAN A REFUSAL.
 *
 * Go builds its upgrader as `websocket.Upgrader{}`
 * (internal/server/websocketAux.go:130). A zero-value Upgrader has a nil
 * CheckOrigin, and gorilla substitutes its own checkSameOrigin, which
 * refuses any request whose `Origin` host differs from `Host`. MEASURED
 * against live gorilla v1.5.3 in this project's dev image, same harness as
 * every other constant in this file:
 *
 *   origin absent                -> reaches the hijack (accepted)
 *   origin "http://example.com"  -> reaches the hijack (accepted, Host matched)
 *   origin "http://evil.example.com"
 *                                -> 403, "request origin not allowed by
 *                                   Upgrader.CheckOrigin"
 *
 * In Go that 403 is the WEDGE: internal/server/websocket.go:50-53 returns
 * from ServeHTTP without sending on `finished`, and the `<-handler.finished`
 * that follows blocks forever, with its goroutine, its socket and its
 * ActiveUser bookkeeping -- after the UID has already been authorised.
 *
 * THIS PORT ACCEPTS IT. Nothing in this file, in ws_handshake.c, or in the
 * dispatcher reads `Origin` at all. MEASURED at the built ck-server, 200
 * connections carrying a genuinely authorised `Hidden` and a cross-site
 * `Origin`: 200 x `HTTP/1.1 101 Switching Protocols`, 0 closed without an
 * answer, 0 hung. The two other triggers (no `Connection: Upgrade`, a
 * malformed `Sec-WebSocket-Key`) are refused here and redirect to the cover
 * site, 200 x `HTTP/1.1 200 OK`, also 0 hung.
 *
 * WHY ACCEPTING IS RIGHT, and not merely convenient. Same-origin policy is
 * a BROWSER defence against a page on one site opening a socket to another
 * on the user's credentials. The peer here is not a browser; it is a
 * pluggable transport that never sends `Origin` at all. Checking it buys
 * nothing and costs everything, because a CDN is entitled to add the
 * header on the origin leg -- and a CDN that does would wedge EVERY Go
 * connection through it while this port proceeds. That is not a
 * hypothetical: it is trigger 3 of the leak this file's ordering fix
 * exists to close, reachable by configuration rather than by an attacker.
 *
 * PINNED, so that "restoring gorilla parity" cannot quietly re-import it:
 * test_ws_handshake.c's test_cross_origin_is_accepted_unlike_gorilla and
 * test_dispatcher_ws.c's cross-origin case both fail if anyone adds an
 * `Origin` check here.
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
    /* Not a request we can parse at all. Two kinds, and they are not the
     * same kind of claim:
     *
     *   - A request line that is not exactly METHOD SP TARGET SP
     *     HTTP/x.y, a header line with no colon, a header name that is
     *     not an RFC 7230 token, or a header value carrying a control
     *     byte. Each of those is refused by Go's own net/http too
     *     (measured: 400, with the request never reaching the handler).
     *   - NO CRLFCRLF INSIDE THE SUPPLIED BYTES, which is THIS PARSER'S
     *     OWN DECISION and not Go's behaviour. Measured: Go answers a
     *     truncated request with NOTHING AT ALL -- it blocks waiting for
     *     the rest, which is exactly why cloak_firstpacket_t documents a
     *     15-second deadline as a caller obligation. There is no third
     *     answer available to a one-shot function over a complete
     *     buffer: "wait for more" is not in this function's vocabulary,
     *     and reporting a half-read request as anything other than
     *     unparseable would hand the caller a value the peer had not
     *     finished sending. The caller that owns the waiting is
     *     cloak_firstpacket_t, which only ever calls this once the
     *     blank line has arrived. */
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
 * them in (processFirstPacket, internal/server/websocket.go:22-39,
 * decodes and unmarshals `hidden` before it ever builds the responder
 * that calls Upgrader.Upgrade; gorilla's own sequence is then
 * Connection, Upgrade, method, version, origin, key --
 * gorilla/websocket@v1.5.3 server.go:128-158). It is NOT a security property: every failure here has
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
