#include "cloak/firstpacket.h"

#include <string.h>

#define TLS_RECORD_HEADER_LEN 5

void cloak_firstpacket_init(cloak_firstpacket_t *fp) {
    if (fp == NULL) {
        return;
    }
    memset(fp, 0, sizeof(*fp));
    fp->transport = CLOAK_FIRSTPACKET_TRANSPORT_UNKNOWN;
    fp->status = CLOAK_FIRSTPACKET_NEED_MORE;
}

size_t cloak_firstpacket_want(const cloak_firstpacket_t *fp) {
    if (fp == NULL || fp->status != CLOAK_FIRSTPACKET_NEED_MORE) {
        return 0;
    }
    switch (fp->transport) {
    case CLOAK_FIRSTPACKET_TRANSPORT_UNKNOWN:
        return 1; /* the first byte decides which protocol this is */
    case CLOAK_FIRSTPACKET_TRANSPORT_TLS:
        if (fp->len < TLS_RECORD_HEADER_LEN) {
            return TLS_RECORD_HEADER_LEN - fp->len;
        }
        return fp->record_total - fp->len;
    case CLOAK_FIRSTPACKET_TRANSPORT_WEBSOCKET:
        return 1; /* headers have no length to read ahead of */
    }
    return 0;
}

static cloak_firstpacket_status_t fail(cloak_firstpacket_t *fp, int redirect) {
    fp->status = CLOAK_FIRSTPACKET_ERROR;
    fp->redirect_on_error = redirect;
    return fp->status;
}

/* Appends one byte, or fails if the buffer is full. */
static int push_byte(cloak_firstpacket_t *fp, uint8_t b) {
    if (fp->len >= CLOAK_FIRSTPACKET_MAX) {
        return -1;
    }
    fp->buf[fp->len++] = b;
    return 0;
}

cloak_firstpacket_status_t cloak_firstpacket_feed(cloak_firstpacket_t *fp,
                                                   const uint8_t *data, size_t len) {
    if (fp == NULL) {
        return CLOAK_FIRSTPACKET_ERROR;
    }
    if (fp->status != CLOAK_FIRSTPACKET_NEED_MORE) {
        return fp->status;
    }
    if (data == NULL || len == 0) {
        return fp->status;
    }

    size_t want = cloak_firstpacket_want(fp);
    if (len > want) {
        len = want; /* a caller that ignores want() loses the excess */
    }

    for (size_t i = 0; i < len; i++) {
        uint8_t b = data[i];

        if (fp->transport == CLOAK_FIRSTPACKET_TRANSPORT_UNKNOWN) {
            /* Buffer the deciding byte first: the redirect path must
             * forward everything the client already sent, including the
             * byte that made us give up on it. */
            if (push_byte(fp, b) != 0) {
                return fail(fp, 1);
            }
            if (b == 0x16) {
                fp->transport = CLOAK_FIRSTPACKET_TRANSPORT_TLS;
            } else if (b == 'G') {
                fp->transport = CLOAK_FIRSTPACKET_TRANSPORT_WEBSOCKET;
            } else {
                /* Go's ErrUnrecognisedProtocol, with redirOnErr = true. */
                return fail(fp, 1);
            }
            continue;
        }

        if (push_byte(fp, b) != 0) {
            return fail(fp, 1);
        }

        if (fp->transport == CLOAK_FIRSTPACKET_TRANSPORT_TLS) {
            if (fp->len == TLS_RECORD_HEADER_LEN) {
                size_t body = ((size_t)fp->buf[3] << 8) | (size_t)fp->buf[4];
                if (body == 0) {
                    /* A record with no body is not a ClientHello and
                     * would leave want() at 0 with nothing parsed. */
                    return fail(fp, 1);
                }
                size_t total = TLS_RECORD_HEADER_LEN + body;
                if (total > CLOAK_FIRSTPACKET_MAX) {
                    /* Go's io.ErrShortBuffer path, redirOnErr = true. */
                    return fail(fp, 1);
                }
                fp->record_total = total;
            }
            if (fp->record_total != 0 && fp->len == fp->record_total) {
                fp->status = CLOAK_FIRSTPACKET_DONE;
                return fp->status;
            }
            continue;
        }

        /* WebSocket: consume until a blank line ends the headers. The
         * state machine matches CR, LF, CR, LF in order; any other byte
         * restarts it, except that a CR restarts it at 1 rather than 0
         * so "\r\r\n\r\n" is still recognised. */
        if (b == '\r') {
            fp->crlf_state = (fp->crlf_state == 2) ? 3 : 1;
        } else if (b == '\n') {
            if (fp->crlf_state == 1) {
                fp->crlf_state = 2;
            } else if (fp->crlf_state == 3) {
                fp->status = CLOAK_FIRSTPACKET_DONE;
                return fp->status;
            } else {
                fp->crlf_state = 0;
            }
        } else {
            fp->crlf_state = 0;
        }
    }

    return fp->status;
}

const uint8_t *cloak_firstpacket_data(const cloak_firstpacket_t *fp) {
    return fp == NULL ? NULL : fp->buf;
}

size_t cloak_firstpacket_len(const cloak_firstpacket_t *fp) {
    return fp == NULL ? 0 : fp->len;
}

int cloak_firstpacket_redirect_on_error(const cloak_firstpacket_t *fp) {
    return fp == NULL ? 0 : fp->redirect_on_error;
}
