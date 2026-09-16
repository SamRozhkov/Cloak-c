#ifndef CLOAK_CLIENT_TRANSPORT_H
#define CLOAK_CLIENT_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/client_auth.h"
#include "cloak/clienthello.h"
#include "cloak/config.h"
#include "cloak/crypto.h"
#include "cloak/reactor.h"

/* The client half of Cloak's direct-TLS handshake: build a ClientHello
 * with the authentication payload hidden in it, write it, read the
 * server's three-record reply, and recover the session key the server
 * chose. Go's reference is internal/client/TLS.go's DirectTLS.Handshake.
 *
 * WHY THIS IS A RESUMABLE STATE MACHINE AND NOT A FUNCTION. Go's
 * Handshake is straight-line blocking code: rawConn.Write once,
 * tls.Read three times, each backed by io.ReadFull on a blocking socket
 * and a goroutine that is free to park. This port runs on a
 * single-threaded cloak_reactor_t shared with every other connection in
 * the process, so blocking anywhere is blocking everything. Every read
 * here can therefore return a partial TLS record -- including a split
 * that lands in the middle of a five-byte record header -- and every
 * write can be short. This object survives ANY split of the input,
 * including one byte per reactor turn, by keeping its position in
 * (state, bytes-of-current-piece-consumed) rather than on a call stack.
 *
 * IT NEVER READS PAST THE REPLY. The same property cloak_firstpacket_t
 * exists for on the server side, for the same reason and with the same
 * consequence if violated: on success the file descriptor is handed
 * onward to a cloak_session_t, which reads from wherever the kernel left
 * off. A byte of the session's first frame consumed here would be
 * silently lost and the session would desynchronise immediately. So the
 * read side never issues a read larger than what is left of the record
 * header, or of the record body, it is currently in -- never a
 * speculative "fill the buffer" read.
 *
 * IT BOUNDS WHAT IT WILL READ, IN BOTH DIMENSIONS:
 *   - structurally: it reads exactly CLOAK_CLIENT_HANDSHAKE_REPLY_RECORDS
 *     records and no more, each record's declared body length is checked
 *     against CLOAK_CLIENT_HANDSHAKE_MAX_RECORD_BODY (the same legal TLS
 *     record bound libcloak-mux enforces on the data path) as its header
 *     completes, and the running total is checked against
 *     CLOAK_CLIENT_HANDSHAKE_MAX_REPLY_BYTES at the same point. The last
 *     of those three cannot fire while the first two hold -- it guards
 *     the constants, not the wire -- but it is a real comparison rather
 *     than arithmetic left to the reader;
 *   - temporally, by a deadline armed at cloak_client_handshake_start
 *     and covering the WHOLE handshake, write half included. A server
 *     that sends a perfectly valid ServerHello and then dribbles (or
 *     stops) forever would otherwise pin this object and its file
 *     descriptor for as long as it cared to keep the socket open. This
 *     is the client-side counterpart of the 15-second deadline
 *     cloak/firstpacket.h requires the dispatcher to arm against a
 *     client that stops mid-packet -- and unlike that one it is enforced
 *     here rather than delegated to the caller, because unlike
 *     cloak_firstpacket_t this object does own the reactor and the fd.
 *
 * Go has no equivalent client-side deadline at all (DirectTLS.Handshake
 * sets none; only the dial itself is bounded). Adding one is a
 * deliberate divergence, not an oversight: a blocked goroutine in Go
 * costs a goroutine, while a blocked handshake here would cost a
 * registered fd on a shared reactor. */

/* Go Cloak's browser fingerprint selection (internal/client/TLS.go's
 * `browser` enum), one template each in cloak/clienthello.h. The
 * numeric values match Go's iota order. */
typedef enum {
    CLOAK_CLIENT_BROWSER_CHROME = 0,
    CLOAK_CLIENT_BROWSER_FIREFOX = 1,
    CLOAK_CLIENT_BROWSER_SAFARI = 2,
} cloak_client_browser_t;

/* The TLD list Go's randomServerName draws from, verbatim
 * (internal/client/TLS.go's topLevelDomains). It is a FINGERPRINT, not a
 * convenience: a client drawing from a different set than every other
 * Cloak client is distinguishable from them, so this list must track
 * Go's exactly rather than being "improved". */
#define CLOAK_CLIENT_TLD_COUNT 13
extern const char *const cloak_client_top_level_domains[CLOAK_CLIENT_TLD_COUNT];

/* Longest string cloak_client_random_server_name can produce, plus the
 * NUL: 12 letters + '.' + "info" + '\0'. */
#define CLOAK_CLIENT_RANDOM_SERVER_NAME_MAX 18

/* The DNS hostname length limit, which is also the longest server_name
 * cloak_clienthello_build accepts. A longer one is rejected by
 * cloak_client_handshake_init as CLOAK_CLIENT_HANDSHAKE_ERR_CONFIG
 * rather than truncated -- a truncated SNI would reach a different host
 * than the operator configured.
 *
 * DEFINED FROM cloak/config.h's CONSTANT, NOT AS A SECOND LITERAL. It was
 * a second literal, and cloak_client_config_t's parser had a different
 * one: 254- and 255-character ServerNames parsed cleanly and were then
 * refused here, which reached an operator as exit 4 ("runtime failure,
 * retrying may help") for a permanent configuration error naming no
 * field. cloak/client_stack.h makes exactly this argument for the
 * TEMPLATE arm -- "re-deriving the mux layer's bounds here would be a
 * second copy of them that could disagree with the first" -- and this is
 * that rule applied to the bound it was written about. */
#define CLOAK_CLIENT_SERVER_NAME_MAX CLOAK_MAX_DNS_NAME_LEN

/* Generates a plausible random hostname the way Go's randomServerName
 * does: 3 to 12 lowercase ASCII letters, a dot, and one of
 * cloak_client_top_level_domains. cap must be at least
 * CLOAK_CLIENT_RANDOM_SERVER_NAME_MAX.
 *
 * Both draws reduce a 64-bit random value modulo the range, rather than
 * a single byte as the `% n` idiom used elsewhere in this tree does.
 * That idiom is exact only when n divides 256, which holds where it is
 * used there (2 AEAD ids, 4 ECH payload lengths) but not for 26 letters
 * or 13 TLDs -- and an SNI is the single most visible field this client
 * emits, so a skewed letter or TLD distribution across many connections
 * is exactly the sort of aggregate distinguisher this hostname exists to
 * avoid. Widening the draw to 64 bits leaves a residual bias below 2^-60,
 * which is not exactly zero (rejection sampling would be) but is
 * unobservable, and it keeps the code loop-free -- see the
 * implementation's own comment for why that tradeoff was made in this
 * particular module.
 *
 * Returns 0 on success, -1 if out is NULL or cap is too small (out is
 * left untouched in that case). */
int cloak_client_random_server_name(char *out, size_t cap);

/* Every way this handshake can end other than success. Typed rather
 * than a bare -1 because a caller retrying against a server pool needs
 * to tell "this server refused/ignored us" (RESET, EOF, TIMEOUT) from
 * "our own configuration is wrong" (CONFIG, BUILD) -- only the first
 * class is worth retrying elsewhere. */
typedef enum {
    CLOAK_CLIENT_HANDSHAKE_ERR_NONE = 0,
    /* Bad arguments to init/start: a NULL reactor, fd < 0, a server name
     * too long for cloak_clienthello_build, an over-long proxy method. */
    CLOAK_CLIENT_HANDSHAKE_ERR_CONFIG = 1,
    /* cloak_client_auth_build or cloak_clienthello_build failed -- an
     * OpenSSL-level failure, since the argument-level causes are already
     * reported as CLOAK_CLIENT_HANDSHAKE_ERR_CONFIG. */
    CLOAK_CLIENT_HANDSHAKE_ERR_BUILD = 2,
    /* A socket-level error (not EAGAIN/EINTR) writing or reading. */
    CLOAK_CLIENT_HANDSHAKE_ERR_IO = 3,
    /* The server closed the connection before the reply was complete.
     * Distinct from ERR_IO because a clean close mid-reply is what a
     * Cloak server does to a client it declined to authenticate, and
     * what the redirect path does when the cover site closes -- i.e.
     * it is the EXPECTED failure for a rejected client, not a
     * malfunction. */
    CLOAK_CLIENT_HANDSHAKE_ERR_EOF = 4,
    /* The reply was not shaped like a reply: a record body larger than
     * CLOAK_CONN_MAX_FRAME_LEN, or a ServerHello record too short to
     * contain the two key-carrying fields. */
    CLOAK_CLIENT_HANDSHAKE_ERR_PROTOCOL = 5,
    /* The reply parsed, but the sealed session key did not open under
     * the shared secret -- i.e. whatever answered is not the server
     * whose public key we were configured with. */
    CLOAK_CLIENT_HANDSHAKE_ERR_AUTH = 6,
    /* The deadline fired before the handshake finished. */
    CLOAK_CLIENT_HANDSHAKE_ERR_TIMEOUT = 7,
} cloak_client_handshake_error_t;

typedef enum {
    CLOAK_CLIENT_HANDSHAKE_PENDING = 0,
    CLOAK_CLIENT_HANDSHAKE_DONE = 1,
    CLOAK_CLIENT_HANDSHAKE_FAILED = -1,
} cloak_client_handshake_status_t;

/* The state machine's position. Exposed (rather than hidden behind the
 * status above) because it is what a test asserts against to show the
 * machine genuinely resumes mid-piece rather than only mid-record, and
 * because it is the single most useful thing to look at in a debugger
 * when a handshake stalls.
 *
 * What advances each:
 *   WRITE_HELLO  -> bytes accepted by write(); completes when the whole
 *                   record-framed ClientHello has been handed to the
 *                   kernel. Then READ_RECORD_HEADER.
 *   READ_RECORD_HEADER -> bytes of the current record's 5-byte header;
 *                   completes at 5, having learned the body length.
 *                   Then READ_RECORD_BODY (or DONE, for an empty body).
 *   READ_RECORD_BODY -> bytes of the current record's body. On
 *                   completing record 0 the session key is recovered
 *                   from what was captured; records 1 and 2 are
 *                   discarded. After record 2, DONE.
 *   DONE / FAILED -> terminal; nothing advances them. */
typedef enum {
    CLOAK_CLIENT_HS_STATE_WRITE_HELLO = 0,
    CLOAK_CLIENT_HS_STATE_READ_RECORD_HEADER = 1,
    CLOAK_CLIENT_HS_STATE_READ_RECORD_BODY = 2,
    CLOAK_CLIENT_HS_STATE_DONE = 3,
    CLOAK_CLIENT_HS_STATE_FAILED = 4,
} cloak_client_handshake_state_t;

/* The reply is exactly three records -- ServerHello, ChangeCipherSpec,
 * and a fake Certificate whose length varies per connection by design
 * (cloak_server_auth_cert_lens). Only the first is parsed. */
#define CLOAK_CLIENT_HANDSHAKE_REPLY_RECORDS 3

/* The prefix of the ServerHello handshake message this client actually
 * reads: cloak_server_auth_compose_reply puts the reply nonce at [6:18),
 * ciphertext[0:20) at [18:38) (together the ServerHello's 32-byte
 * `random`) and ciphertext[20:48) at [84:112) (inside the key_share
 * extension's 32-byte key exchange field, whose last 4 bytes are
 * meaningless padding). 112 is therefore everything that matters; a
 * longer ServerHello is accepted and its tail discarded, matching Go,
 * which indexes those same fixed offsets without checking the length at
 * all. */
#define CLOAK_CLIENT_HANDSHAKE_SERVERHELLO_PREFIX 112

/* The largest record body this client will accept in a reply. 16640 is
 * RFC 8446 s5.2's ciphertext limit and is numerically the same bound
 * libcloak-mux's data path enforces as CLOAK_CONN_MAX_FRAME_LEN -- it
 * is restated rather than included because libcloak-client links only
 * cloak-common, never cloak-mux. If that constant ever moves (it will
 * not; it is fixed by the RFC and by Go's common.TLSConn.Write), this
 * one moves with it. */
#define CLOAK_CLIENT_HANDSHAKE_MAX_RECORD_BODY 16640

/* Largest reply this object will read before giving up: three records,
 * each a 5-byte header plus a maximal body. The real reply is ~165-206
 * bytes; this is a hostile-input ceiling, not an expectation. */
#define CLOAK_CLIENT_HANDSHAKE_MAX_REPLY_BYTES \
    (CLOAK_CLIENT_HANDSHAKE_REPLY_RECORDS * (5 + CLOAK_CLIENT_HANDSHAKE_MAX_RECORD_BODY))

/* The deadline used when cloak_client_handshake_config_t::timeout_ms is
 * 0. Matches the 15 seconds Go's server-side readFirstPacket allows a
 * client for the mirror-image obligation (see cloak/firstpacket.h);
 * Go's client sets no deadline of its own, so there is no Go constant to
 * match here and this is the closest principled one. */
#define CLOAK_CLIENT_HANDSHAKE_DEFAULT_TIMEOUT_MS 15000u

typedef struct cloak_client_handshake cloak_client_handshake_t;

/* Fired exactly once per successful cloak_client_handshake_start, and
 * never before that call returns (the first write is deferred to the
 * reactor's first writable dispatch, so there is no path on which this
 * runs re-entrantly from start).
 *
 * status is DONE or FAILED; on DONE the session key is available from
 * cloak_client_handshake_session_key, on FAILED the reason from
 * cloak_client_handshake_error.
 *
 * By the time this fires the fd has already been deregistered from the
 * reactor and the deadline cancelled, so the callback is free to hand
 * the fd straight to cloak_session_add_conn (on DONE) or close it (on
 * FAILED), and to free h itself -- nothing in this object touches h
 * after on_done returns. THE FD IS NEVER CLOSED BY THIS OBJECT on any
 * path -- the
 * caller owns it from before start to after this callback, which is the
 * opposite of cloak_dial_cb's hand-off and is deliberate: on success the
 * fd must survive into the session, and an object that closed it on some
 * paths but not others would be the harder contract to get right. */
typedef void (*cloak_client_handshake_cb)(cloak_client_handshake_t *h,
                                           cloak_client_handshake_status_t status,
                                           void *userdata);

typedef struct {
    cloak_reactor_t *reactor;

    /* An already-connected, non-blocking socket. Not owned (see
     * cloak_client_handshake_cb). */
    int fd;

    cloak_client_browser_t browser;

    /* The SNI to present. "random" (case-insensitive, matching Go's
     * strings.EqualFold) means "generate one per connection" via
     * cloak_client_random_server_name. NULL is rejected. */
    const char *server_name;

    /* Everything cloak_client_auth_build needs; see cloak/client_auth.h
     * for each field's contract. now_unix is taken as an argument
     * rather than read from the clock so a test can pin it. */
    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    uint8_t uid[CLOAK_UID_LEN];
    const char *proxy_method;
    uint8_t encryption_method;
    uint32_t session_id;
    int unordered;
    int64_t now_unix;

    /* Whole-handshake deadline. 0 selects
     * CLOAK_CLIENT_HANDSHAKE_DEFAULT_TIMEOUT_MS. */
    uint64_t timeout_ms;

    cloak_client_handshake_cb on_done;
    void *on_done_userdata;
} cloak_client_handshake_config_t;

/* h must stay live, at a fixed address, from a successful
 * cloak_client_handshake_start until on_done fires (or until
 * cloak_client_handshake_destroy, if torn down first): the reactor holds
 * a pointer to it for that whole span, so moving or freeing it while
 * still registered is a use-after-free -- the same rule
 * cloak_listener_t, cloak_dial_t and cloak_relay_t state for themselves.
 *
 * The struct is public (like cloak_firstpacket_t's) so that a test can
 * assert on `state` and on which record is in flight. Nothing outside
 * client_transport.c may WRITE to any field. */
struct cloak_client_handshake {
    cloak_reactor_t *reactor;
    int fd;
    int fd_registered;
    uint32_t fd_interest;

    cloak_client_handshake_state_t state;
    cloak_client_handshake_status_t status;
    cloak_client_handshake_error_t error;

    /* The record-framed ClientHello, and how much of it the kernel has
     * taken so far. Sized for the largest ClientHello any template and
     * any legal server name can produce, plus the 5-byte record header
     * this module adds (cloak_clienthello_build emits the handshake
     * message alone). */
    uint8_t hello[5 + CLOAK_CLIENTHELLO_MAX_BYTES];
    size_t hello_len;
    size_t hello_sent;

    /* The shared secret cloak_client_auth_build derived, kept because
     * the reply's session key is sealed under it. */
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];

    /* Read-side position. record_index counts completed records;
     * header_len is how much of the current 5-byte record header has
     * arrived; body_len/body_total how much of its body. */
    size_t record_index;
    uint8_t header[5];
    size_t header_len;
    size_t body_len;
    size_t body_total;
    size_t reply_bytes; /* total reply bytes read, against the ceiling */

    /* The ServerHello prefix accumulated from record 0. */
    uint8_t sh[CLOAK_CLIENT_HANDSHAKE_SERVERHELLO_PREFIX];
    size_t sh_len;

    uint8_t session_key[CLOAK_AEAD_KEY_LEN];

    /* The SNI actually sent -- the configured one, or the generated one
     * when the config said "random". Kept so a caller (or a test) can
     * see what went on the wire. */
    char server_name[CLOAK_CLIENT_SERVER_NAME_MAX + 1];

    uint64_t timeout_ms;
    cloak_timer_id_t deadline_timer;

    /* 1 once on_done has been fired, so it fires exactly once no matter
     * how many terminal conditions are reached in one dispatch. The
     * callback is always the LAST statement on the stack that touches h
     * (see client_transport.c's `finish`), which is what makes freeing h
     * from inside on_done legal. */
    int notified;

    cloak_client_handshake_cb on_done;
    void *on_done_userdata;
};

/* Prepares h: resolves the server name (generating one if the config
 * says "random"), builds the authentication payload and the ClientHello,
 * and frames it in a TLS handshake record -- everything that can be done
 * before the socket is touched. Nothing is written and no reactor
 * registration happens here.
 *
 * h is FULLY ZEROED as the first action, before any argument is
 * validated, so a rejected call still leaves h safe to pass to
 * cloak_client_handshake_destroy -- the same constructor discipline
 * cloak_client_auth_build and cloak_listener_open follow.
 *
 * Returns 0 on success, -1 on failure with the reason in
 * cloak_client_handshake_error(h) (CONFIG or BUILD). */
int cloak_client_handshake_init(cloak_client_handshake_t *h,
                                 const cloak_client_handshake_config_t *cfg);

/* Registers the fd with the reactor and arms the deadline. From here on
 * the handshake runs entirely from reactor callbacks and on_done fires
 * exactly once.
 *
 * Returns 0 if the handshake started, -1 if h was not successfully
 * initialized or the reactor registration failed -- in which case
 * on_done will NOT fire and the caller owns the failure (and, as
 * always, the fd). */
int cloak_client_handshake_start(cloak_client_handshake_t *h);

/* Tears the handshake down without firing on_done: deregisters the fd
 * (never closes it) and cancels the deadline. Idempotent, and safe on an
 * h left zeroed or left however a failed init/start left it -- the same
 * guarantee cloak_listener_close and cloak_relay_stop give. Must not be
 * called from within on_done itself (on_done already runs after this
 * object has released the reactor; calling it there is harmless but
 * pointless). */
void cloak_client_handshake_destroy(cloak_client_handshake_t *h);

/* PENDING until on_done fires, then DONE or FAILED. Returns FAILED for a
 * NULL h. */
cloak_client_handshake_status_t cloak_client_handshake_status(const cloak_client_handshake_t *h);

/* Why the handshake failed. Meaningless unless the status is FAILED.
 * Returns CLOAK_CLIENT_HANDSHAKE_ERR_CONFIG for a NULL h. */
cloak_client_handshake_error_t cloak_client_handshake_error(const cloak_client_handshake_t *h);

/* The CLOAK_AEAD_KEY_LEN-byte session key the server chose, valid only
 * once the status is DONE. Returns NULL otherwise. */
const uint8_t *cloak_client_handshake_session_key(const cloak_client_handshake_t *h);

/* The SNI this handshake actually put on the wire. Returns NULL for a
 * NULL or uninitialized h. */
const char *cloak_client_handshake_server_name(const cloak_client_handshake_t *h);

#endif
