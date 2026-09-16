#ifndef CLOAK_WS_FRAME_H
#define CLOAK_WS_FRAME_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* RFC 6455 WebSocket frame encode and decode: the framing layer a Cloak
 * session uses when it arrives CDN-fronted instead of over a direct TCP
 * connection.
 *
 * WHAT THIS REPLACES, AND WHY THAT MATTERS
 *
 * On the direct path, cloak/conn.h wraps every frame in a five-byte TLS
 * application-data record header. Read the 46-line comment above
 * CLOAK_CONN_RECORD_HEADER_LEN before you touch anything here: those five
 * bytes exist because this port once invented a two-byte length prefix of
 * its own, kept the framing purpose and dropped the DISGUISE purpose, and
 * thereby shipped five modules in which the TLS mimicry held for exactly
 * one round trip and then stopped. A censor's DPI box saw a valid TLS
 * handshake followed by bytes that are not TLS records -- a louder
 * fingerprint than no disguise at all.
 *
 * This codec is what stands in those five bytes' place on the CDN path,
 * and the same discipline applies for the same reason. Here the disguise
 * is "an ordinary WebSocket connection through an ordinary CDN", and the
 * observer who must be convinced is not only the censor: it is also the
 * CDN itself, and gorilla on the far end of an interop run, both of which
 * reject a frame that is off by one byte. Every constant below was taken
 * from RFC 6455 and from live measurement of Go + gorilla (the module-8
 * scouting report, section 1.6), not from prose.
 *
 * THE SHAPE: PURE FUNCTIONS OVER CALLER-OWNED BUFFERS
 *
 * Nothing here allocates, owns a file descriptor, touches the reactor, or
 * keeps state between calls. That is deliberate, twice over:
 *
 *   - cloak_ws_frame_parse_header is an ATTACKER-CONTROLLED PARSER. The
 *     bytes it reads come off a socket a censor may be sitting on. A pure
 *     function over (buf, len) is directly fuzzable with no harness, which
 *     is how module 10 will treat it, and "never reads past buf + len" is
 *     a property that can be checked mechanically rather than argued.
 *   - The layer above drives this from inside a state machine it already
 *     has. A codec that owned a buffer would force a second buffer layer
 *     between the socket and the mux; a codec that is three pure functions
 *     can be called straight out of the existing accumulator.
 *
 * WHAT THIS LAYER DOES NOT DO, deliberately:
 *
 *   - It does not reassemble continuation frames. Go never SENDS a
 *     fragmented message (WriteMessage emits one frame per message) but
 *     always ACCEPTS one, and a CDN is entitled to re-fragment, so
 *     reassembly is genuinely required -- one layer up, where there is
 *     somewhere to put the partial message. This layer's job is to
 *     CLASSIFY a continuation frame correctly so that layer can.
 *   - It does not enforce the direction rule. RFC 6455 requires a client
 *     to mask and a server not to, and each side rejects a frame masked
 *     the wrong way ("bad MASK" in gorilla, and every browser does the
 *     same). This header reports `masked` faithfully and leaves the
 *     judgement to the layer that knows which end of the connection it is.
 *   - It does not answer pings. A CDN pings idle WebSocket connections and
 *     closes them when no pong comes, so that is load-bearing in
 *     production -- and it belongs where the send path is.
 *   - It does not bound payload_len, AND NOTHING ELSE ON THIS PATH DOES
 *     EITHER YET. See the warning below; it is an obligation you inherit,
 *     not a check that has already happened somewhere else. */

/* THE PAYLOAD LENGTH BOUND IS OWED BY THE CALLER. READ THIS BEFORE USING
 * cloak_ws_frame_parse_header FOR ANYTHING.
 *
 * payload_len is reported exactly as the peer DECLARED it. This file never
 * compares it against CLOAK_CONN_MAX_FRAME_LEN (cloak/conn.h, 16640) or
 * against any other limit, and a hostile peer can legitimately get a
 * successful parse out of this function declaring 0x7FFFFFFFFFFFFFFF.
 *
 * That is the right division of labour -- this layer owns no buffer, so it
 * cannot know what the caller can hold, and a parser that silently
 * rejected a large declaration would hide a hostile peer rather than
 * report one -- but it means the check has to happen somewhere, and THAT
 * SOMEWHERE DOES NOT EXIST YET.
 *
 * Concretely, as of this file being written: the three places that enforce
 * CLOAK_CONN_MAX_FRAME_LEN today are cloak_conn_init, cloak_session_init
 * and cloak_switchboard_init, and ALL THREE are on the direct
 * TLS-record path. Not one of them sees a byte that arrived through a
 * WebSocket frame. An earlier revision of this comment said
 * CLOAK_CONN_MAX_FRAME_LEN "already bounds what this stack will accept",
 * which was false for exactly this path and is the sort of sentence that
 * gets a bound skipped: the next implementer reads it, believes the check
 * is handled downstream, and nobody ever writes it.
 *
 * So, for whoever builds the CDN-path receive loop on top of this: compare
 * payload_len against CLOAK_CONN_MAX_FRAME_LEN YOURSELF, before you size
 * or fill any buffer from it, and treat a larger declaration the way
 * cloak_conn does -- a protocol violation that breaks the connection, not
 * a value to clamp. It is a MIMICRY bound as much as a memory one (see
 * CLOAK_CONN_MAX_FRAME_LEN's own comment in cloak/conn.h: one oversized
 * record is a single-probe distinguisher), so it is not optional on this
 * path merely because this path is newer.
 *
 * libcloak-mux/tests/test_ws_frame.c pins the absence deliberately: 16640
 * and 16641 parse identically here, and so does 4 GiB. If you add the
 * check to THIS file those assertions will fail, and they are meant to --
 * the bound belongs where the buffer is. */

/* The longest header RFC 6455 admits: 2 fixed bytes + 8 extended-length
 * bytes + 4 mask bytes. Every header is 2, 4, 6, 8, 10 or 14 bytes. */
#define CLOAK_WS_FRAME_MAX_HEADER_LEN 14

/* RFC 6455 section 5.5: "All control frames MUST have a payload length of
 * 125 bytes or less and MUST NOT be fragmented." */
#define CLOAK_WS_FRAME_MAX_CONTROL_PAYLOAD 125

/* The six opcodes RFC 6455 section 5.2 defines. 0x3-0x7 and 0xB-0xF are
 * reserved and are a protocol error on receipt (gorilla: "unknown
 * opcode"), so this enum's value set is exactly the accepted set -- a
 * parsed header never carries an opcode outside it.
 *
 * Cloak itself uses only CLOAK_WS_OP_BINARY for data, in both directions,
 * always with FIN set: the first header byte of every Cloak message is
 * 0x82. One WebSocket binary message is exactly one Cloak mux frame --
 * message boundaries ARE Cloak's framing, because switchboard.deplex hands
 * whatever it read straight to a deobfuscator that requires one whole
 * frame. CLOSE/PING/PONG are here because a CDN sends them. */
typedef enum {
    CLOAK_WS_OP_CONTINUATION = 0x0,
    CLOAK_WS_OP_TEXT         = 0x1,
    CLOAK_WS_OP_BINARY       = 0x2,
    CLOAK_WS_OP_CLOSE        = 0x8,
    CLOAK_WS_OP_PING         = 0x9,
    CLOAK_WS_OP_PONG         = 0xA
} cloak_ws_opcode_t;

typedef struct {
    cloak_ws_opcode_t opcode;
    int      fin;            /* 1 if FIN set, 0 if this is a fragment with more to come */
    int      masked;         /* 1 if MASK set; the direction check is the caller's */
    uint8_t  mask_key[4];    /* zeroed when masked == 0, never left holding stale bytes */
    uint64_t payload_len;    /* as DECLARED by the peer; not yet bounded, see above */
    size_t   header_len;     /* 2, 4, 6, 8, 10 or 14 -- equals the return value */
} cloak_ws_frame_header_t;

/* Parses a frame header from buf[0, len).
 *
 * Returns the header's length in bytes (> 0) on success, 0 if the header
 * is not yet complete and more bytes are needed, and -1 if it is
 * malformed. NEVER reads past buf + len: at every length short of a
 * complete header this returns 0 having read only the bytes it was given,
 * which is what lets a caller feed it a socket accumulator directly and
 * call again after the next read.
 *
 * *out is written ONLY on success. A 0 or -1 return leaves it exactly as
 * the caller left it, so a header struct held across reactor wakeups is
 * never found half-overwritten by a short read.
 *
 * Malformed, in full -- these are the checks gorilla's advanceFrame makes,
 * no more and no fewer, because a peer FUSSIER than the reference
 * implementation is itself a behavioural distinguisher (the same argument
 * cloak/conn.h makes for NOT validating the TLS record's type byte):
 *
 *   - Any of RSV1/RSV2/RSV3 set. No extension is ever negotiated -- this
 *     port never offers Sec-WebSocket-Extensions and never accepts one --
 *     so all three are always zero on a legitimate wire.
 *   - A reserved opcode (0x3-0x7, 0xB-0xF).
 *   - A control frame (opcode >= 0x8) whose payload exceeds 125 bytes or
 *     whose FIN bit is clear.
 *   - A 127-form length whose 64-bit value has the high bit set; RFC 6455
 *     section 5.2 requires that bit to be zero.
 *
 * NOT malformed, equally deliberately: a non-minimal length encoding (a
 * 126-form frame declaring 5 bytes, say). RFC 6455 does require the
 * minimal form, but gorilla does not check it, and rejecting a frame the
 * reference implementation accepts is the distinguisher described above.
 *
 * An error is reported as soon as the bytes that prove it are in hand,
 * ahead of any remaining "need more bytes" -- a peer must not be able to
 * pin a connection open by declining to finish a header it has already
 * invalidated.
 *
 * buf and out must both be non-NULL; -1 is returned if either is NULL. */
ssize_t cloak_ws_frame_parse_header(const uint8_t *buf, size_t len,
                                    cloak_ws_frame_header_t *out);

/* Applies the WebSocket mask in place: payload[i] ^= key[(pos + i) & 3].
 * Returns the position to pass to the next call, always reduced to 0..3.
 * Masking is its own inverse, so this both masks and unmasks.
 *
 * pos is the offset OF payload[0] WITHIN THE WHOLE FRAME PAYLOAD, not
 * within this chunk, and that distinction is the one thing implementations
 * of this reliably get wrong. A partial-write loop that hands out a
 * payload in chunks and restarts pos at 0 for each of them produces a
 * frame whose first chunk decodes correctly and whose every later chunk is
 * garbage -- and any test that masks a whole buffer in one call still
 * passes. gorilla threads the same running position through
 * maskBytes(key, pos, b) for exactly this reason.
 *
 * The send path can sidestep the problem entirely by masking in place
 * BEFORE enqueueing, so that the queue only ever holds finished bytes;
 * that is the safer shape and the one to prefer. The resumable form exists
 * because the RECEIVE path has no such option: a masked payload arrives
 * split across however many TCP segments the network chose.
 *
 * len == 0 is a no-op and returns pos & 3; payload may be NULL in that
 * case, since an empty frame's payload pointer is legitimately
 * one-past-the-end of the header. */
size_t cloak_ws_frame_mask(uint8_t *payload, size_t len,
                           const uint8_t key[4], size_t pos);

/* Writes a complete frame header into buf[0, cap).
 *
 * Returns the number of bytes written (2, 4, 6, 8, 10 or 14), or -1
 * without writing ANYTHING at all. The capacity check happens before the
 * first byte is stored, so a short buffer is a refusal rather than an
 * overflow that happens to return -1.
 *
 * mask_key is 4 bytes for the client direction and NULL for the server
 * direction -- RFC 6455 section 5.1 requires a client to mask every frame
 * and a server to mask none, and each side rejects the other's mistake.
 * When mask_key is given, the MASK bit is set and the key is copied in
 * after the length; the PAYLOAD is not touched here (it is not passed),
 * so the caller still owes it a cloak_ws_frame_mask call with the same key
 * starting at pos 0.
 *
 * The minimal length form is always used: 0-125 inline, 126..65535 as
 * 126 + u16, above that as 127 + u64. Go never emits the 64-bit form,
 * since every Cloak message is at most 16401 bytes, but it is implemented
 * so that encode and decode are inverses over the whole format.
 *
 * -1 is also returned, for the same reason (never emit what our own parser
 * would reject, and never emit what a CDN would hang up on), if op is a
 * reserved opcode, if op is a control opcode and payload_len exceeds 125
 * or fin is 0, or if payload_len has its top bit set. */
ssize_t cloak_ws_frame_write_header(uint8_t *buf, size_t cap,
                                    cloak_ws_opcode_t op, int fin,
                                    const uint8_t mask_key[4], uint64_t payload_len);

/* Fills key with 4 fresh bytes from cloak_random_bytes -- OpenSSL
 * RAND_bytes, which aborts rather than returning weak output.
 *
 * This is the one function in this file that is not pure, and it is here
 * rather than left to each caller so that the decision is made once, in
 * the codec, instead of depending on a later module remembering it.
 *
 * IT IS A DELIBERATE DEVIATION FROM GO. gorilla's newMaskKey
 * (conn.go:184-187) draws from math/rand, not crypto/rand, against
 * RFC 6455 section 5.3's explicit requirement that the key "MUST be
 * derived from a strong source of entropy". The practical impact of
 * gorilla's choice is low -- Go's global source is randomly seeded and
 * ChaCha8-based since 1.22, and the masked payload is already AEAD-sealed
 * under the session key, so a recovered mask reveals ciphertext the
 * attacker could already read -- and it is NOT a distinguisher, because
 * mask keys look uniformly random either way. A CSPRNG is simply strictly
 * better here and costs nothing, so this port uses one. Recorded because
 * every intentional divergence in this port is recorded, not because it
 * needs defending.
 *
 * Draw once per frame (or batch); never once per byte. */
void cloak_ws_frame_mask_key(uint8_t key[4]);

#endif
