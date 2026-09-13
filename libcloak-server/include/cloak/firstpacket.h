#ifndef CLOAK_FIRSTPACKET_H
#define CLOAK_FIRSTPACKET_H

#include <stddef.h>
#include <stdint.h>

/* Accumulates a connection's first packet across non-blocking reads,
 * identifying which transport it belongs to, without ever consuming a
 * byte past the end of that packet.
 *
 * That last property is the reason this object exists rather than a plain
 * buffer. After a successful handshake the file descriptor is handed to
 * cloak_session_add_conn, which wraps it in a cloak_conn_t that reads
 * from wherever the kernel left off -- so a byte read past the first
 * packet here would be silently lost and the session would desynchronise
 * on its very first frame. The caller therefore does not choose how much
 * to read: it asks cloak_firstpacket_want, reads exactly that many bytes,
 * and feeds them back. Go gets the same guarantee from blocking
 * io.ReadFull calls sized to exactly what it needs
 * (internal/server/dispatcher.go, readFirstPacket).
 *
 * This layer only FRAMES the packet -- it decides where the packet ends
 * and which transport it is, nothing more. Parsing a ClientHello is
 * cloak_clienthello_parse's job, and authenticating it is
 * cloak_server_auth_decrypt's. */

/* Go Cloak's firstPacketSize. Large enough for a modern Chrome
 * ClientHello, which passed 1500 bytes when uTLS updated its
 * fingerprints. */
#define CLOAK_FIRSTPACKET_MAX 3000

typedef enum {
    CLOAK_FIRSTPACKET_NEED_MORE = 0,
    CLOAK_FIRSTPACKET_DONE = 1,
    CLOAK_FIRSTPACKET_ERROR = -1,
} cloak_firstpacket_status_t;

typedef enum {
    CLOAK_FIRSTPACKET_TRANSPORT_UNKNOWN = 0,
    CLOAK_FIRSTPACKET_TRANSPORT_TLS = 1,      /* first byte 0x16: a TLS record */
    CLOAK_FIRSTPACKET_TRANSPORT_WEBSOCKET = 2, /* first byte 'G': an HTTP GET */
} cloak_firstpacket_transport_t;

typedef struct {
    uint8_t buf[CLOAK_FIRSTPACKET_MAX];
    size_t len;

    cloak_firstpacket_transport_t transport;
    cloak_firstpacket_status_t status;

    /* For the TLS path: the total packet length once the 5-byte record
     * header has been read, or 0 while it has not. */
    size_t record_total;

    /* For the WebSocket path: how many of the four bytes of the
     * terminating CRLFCRLF have been matched so far. */
    unsigned crlf_state;

    /* Go's redirOnErr: whether a failure here should still be forwarded
     * to RedirAddr rather than dropped. */
    int redirect_on_error;
} cloak_firstpacket_t;

/* Resets fp to its starting state. Must be called before any other
 * function; a cloak_firstpacket_t is not usable zero-initialized. */
void cloak_firstpacket_init(cloak_firstpacket_t *fp);

/* How many bytes the caller should read and feed next. Never returns more
 * than the packet has left, which is what makes over-reading impossible.
 * Returns 0 once the packet is complete or an error has been reported --
 * a caller that reads when want() is 0 is reading bytes that belong to
 * the next layer.
 *
 * On the WebSocket path this returns 1: HTTP headers have no length to
 * read ahead of, so the request is consumed one byte at a time, exactly
 * as Go's connReadLine does. That is a handshake-time cost of a few
 * hundred syscalls per connection, paid once, in exchange for the
 * no-over-read guarantee. */
size_t cloak_firstpacket_want(const cloak_firstpacket_t *fp);

/* Feeds len bytes. len must not exceed cloak_firstpacket_want(fp); bytes
 * beyond that are ignored rather than buffered, so a caller that ignores
 * want() loses data rather than corrupting the packet.
 *
 * Returns CLOAK_FIRSTPACKET_NEED_MORE (feed more), CLOAK_FIRSTPACKET_DONE
 * (the packet is complete and available via cloak_firstpacket_data), or
 * CLOAK_FIRSTPACKET_ERROR. Once DONE or ERROR is returned, further feeds
 * change nothing and return that same status.
 *
 * Every error this object can report is a REDIRECTABLE one -- an
 * unrecognised protocol, an oversized record, a request whose headers
 * never end. Those are all cases where Go forwards the connection to
 * RedirAddr rather than closing it, because closing would tell a prober
 * that something other than a web server is listening. Check
 * cloak_firstpacket_redirect_on_error rather than assuming. */
cloak_firstpacket_status_t cloak_firstpacket_feed(cloak_firstpacket_t *fp,
                                                   const uint8_t *data, size_t len);

/* The bytes accumulated so far. Valid until fp is re-initialized. After
 * an error this holds everything read before the error was detected,
 * which is exactly what the redirect path must forward -- a prober must
 * see its own bytes reach a real web server. */
const uint8_t *cloak_firstpacket_data(const cloak_firstpacket_t *fp);
size_t cloak_firstpacket_len(const cloak_firstpacket_t *fp);

/* 1 if a reported error should be handled by forwarding to RedirAddr.
 * Meaningless unless cloak_firstpacket_feed returned
 * CLOAK_FIRSTPACKET_ERROR. */
int cloak_firstpacket_redirect_on_error(const cloak_firstpacket_t *fp);

#endif
