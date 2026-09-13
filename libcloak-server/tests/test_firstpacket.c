#include "cloak/firstpacket.h"
#include "test_framework.h"

#include <string.h>

/* Feeds data one byte at a time, never offering more than want() asks
 * for, and returns the final status. This is the calling discipline the
 * dispatcher itself will use, so testing through it tests the real
 * contract rather than a convenient shortcut. */
static cloak_firstpacket_status_t feed_all(cloak_firstpacket_t *fp,
                                           const uint8_t *data, size_t len,
                                           size_t *consumed_out) {
    size_t off = 0;
    cloak_firstpacket_status_t st = CLOAK_FIRSTPACKET_NEED_MORE;
    while (off < len) {
        size_t want = cloak_firstpacket_want(fp);
        if (want == 0) {
            break;
        }
        size_t chunk = len - off;
        if (chunk > want) {
            chunk = want;
        }
        st = cloak_firstpacket_feed(fp, data + off, chunk);
        off += chunk;
        if (st != CLOAK_FIRSTPACKET_NEED_MORE) {
            break;
        }
    }
    if (consumed_out != NULL) {
        *consumed_out = off;
    }
    return st;
}

/* A minimal but structurally valid TLS record: 0x16, version, length,
 * then length bytes of body. The body's contents do not matter here --
 * this layer only frames the record, it does not parse the ClientHello. */
static size_t make_tls_record(uint8_t *out, size_t body_len) {
    out[0] = 0x16;
    out[1] = 0x03;
    out[2] = 0x01;
    out[3] = (uint8_t)((body_len >> 8) & 0xff);
    out[4] = (uint8_t)(body_len & 0xff);
    for (size_t i = 0; i < body_len; i++) {
        out[5 + i] = (uint8_t)(i & 0xff);
    }
    return 5 + body_len;
}

static void test_tls_record_assembled_from_single_bytes(void) {
    uint8_t record[1024];
    size_t record_len = make_tls_record(record, 512);

    cloak_firstpacket_t fp;
    cloak_firstpacket_init(&fp);

    size_t consumed = 0;
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_DONE, feed_all(&fp, record, record_len, &consumed));
    ASSERT_EQ_INT((int)record_len, (int)consumed);
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_TRANSPORT_TLS, (int)fp.transport);
    ASSERT_EQ_INT((int)record_len, (int)cloak_firstpacket_len(&fp));
    ASSERT_MEM_EQ(cloak_firstpacket_data(&fp), record, record_len);
}

static void test_never_asks_for_more_than_the_record(void) {
    /* The property the whole object exists for: after the record is
     * complete, want() is 0, so a caller driven by want() cannot consume
     * a byte that belongs to the session's first frame. */
    uint8_t record[1024];
    size_t record_len = make_tls_record(record, 100);

    cloak_firstpacket_t fp;
    cloak_firstpacket_init(&fp);

    /* Offer far more than the record contains, in one go. */
    uint8_t stream[2048];
    memcpy(stream, record, record_len);
    memset(stream + record_len, 0xEE, sizeof(stream) - record_len);

    size_t consumed = 0;
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_DONE, feed_all(&fp, stream, sizeof(stream), &consumed));
    ASSERT_EQ_INT((int)record_len, (int)consumed);
    ASSERT_EQ_INT(0, (int)cloak_firstpacket_want(&fp));
    ASSERT_EQ_INT((int)record_len, (int)cloak_firstpacket_len(&fp));
}

static void test_http_request_terminated_by_blank_line(void) {
    const char *req =
        "GET /ws HTTP/1.1\r\n"
        "Host: cdn.example\r\n"
        "Upgrade: websocket\r\n"
        "hidden: QUJD\r\n"
        "\r\n";
    size_t req_len = strlen(req);

    cloak_firstpacket_t fp;
    cloak_firstpacket_init(&fp);

    size_t consumed = 0;
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_DONE,
                  feed_all(&fp, (const uint8_t *)req, req_len, &consumed));
    ASSERT_EQ_INT((int)req_len, (int)consumed);
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_TRANSPORT_WEBSOCKET, (int)fp.transport);
    ASSERT_EQ_INT((int)req_len, (int)cloak_firstpacket_len(&fp));
    ASSERT_MEM_EQ(cloak_firstpacket_data(&fp), req, req_len);
}

static void test_http_stops_exactly_at_the_blank_line(void) {
    /* Same over-read property as the TLS case: a pipelined body after the
     * headers must not be consumed. */
    const char *req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    size_t req_len = strlen(req);
    uint8_t stream[256];
    memcpy(stream, req, req_len);
    memset(stream + req_len, 'Z', sizeof(stream) - req_len);

    cloak_firstpacket_t fp;
    cloak_firstpacket_init(&fp);

    size_t consumed = 0;
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_DONE, feed_all(&fp, stream, sizeof(stream), &consumed));
    ASSERT_EQ_INT((int)req_len, (int)consumed);
    ASSERT_EQ_INT(0, (int)cloak_firstpacket_want(&fp));
}

static void test_unrecognised_first_byte_is_a_redirectable_error(void) {
    /* Go's readFirstPacket returns redirOnErr = true here: an unknown
     * protocol is exactly the case the server must forward to RedirAddr
     * rather than drop. */
    const uint8_t junk[] = {0x41, 0x42, 0x43};

    cloak_firstpacket_t fp;
    cloak_firstpacket_init(&fp);

    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_ERROR, cloak_firstpacket_feed(&fp, junk, 1));
    ASSERT_EQ_INT(1, cloak_firstpacket_redirect_on_error(&fp));
    /* the byte that revealed the protocol is still buffered, because
     * goWeb must forward everything the client already sent */
    ASSERT_EQ_INT(1, (int)cloak_firstpacket_len(&fp));
    ASSERT_EQ_INT(0x41, cloak_firstpacket_data(&fp)[0]);
}

static void test_oversized_tls_record_is_a_redirectable_error(void) {
    /* A record whose declared length cannot fit in the buffer. Go treats
     * this as io.ErrShortBuffer with redirOnErr = true. */
    uint8_t header[5];
    header[0] = 0x16;
    header[1] = 0x03;
    header[2] = 0x01;
    header[3] = 0xff;
    header[4] = 0xff; /* 65535 bytes, far beyond CLOAK_FIRSTPACKET_MAX */

    cloak_firstpacket_t fp;
    cloak_firstpacket_init(&fp);

    cloak_firstpacket_status_t st = CLOAK_FIRSTPACKET_NEED_MORE;
    for (size_t i = 0; i < sizeof(header) && st == CLOAK_FIRSTPACKET_NEED_MORE; i++) {
        st = cloak_firstpacket_feed(&fp, header + i, 1);
    }
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_ERROR, st);
    ASSERT_EQ_INT(1, cloak_firstpacket_redirect_on_error(&fp));
}

static void test_oversized_http_headers_are_a_redirectable_error(void) {
    cloak_firstpacket_t fp;
    cloak_firstpacket_init(&fp);

    uint8_t byte = 'G';
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_NEED_MORE, cloak_firstpacket_feed(&fp, &byte, 1));

    /* Feed a header line that never ends. */
    cloak_firstpacket_status_t st = CLOAK_FIRSTPACKET_NEED_MORE;
    byte = 'x';
    for (size_t i = 0; i < CLOAK_FIRSTPACKET_MAX + 16; i++) {
        st = cloak_firstpacket_feed(&fp, &byte, 1);
        if (st != CLOAK_FIRSTPACKET_NEED_MORE) {
            break;
        }
    }
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_ERROR, st);
    ASSERT_EQ_INT(1, cloak_firstpacket_redirect_on_error(&fp));
    ASSERT_TRUE(cloak_firstpacket_len(&fp) <= CLOAK_FIRSTPACKET_MAX);
}

/* A header value containing a bare CR with no following LF -- the CRLF
 * automaton's trickiest expression (crlf_state's "any other byte restarts
 * it, except that a CR restarts it at 1 rather than 0" rule, per
 * firstpacket.c's own comment) was, before this test, backed only by a
 * hand-trace: a lone '\r' mid-value must move crlf_state to 1, and the
 * ordinary byte immediately after it ('b', neither CR nor LF) must then
 * reset it back to 0 -- rather than either being mistaken for progress
 * toward the terminating blank line or corrupting the count such that the
 * real blank line afterward is missed or matched early. */
static void test_header_value_with_bare_cr_no_lf(void) {
    const char *req =
        "GET / HTTP/1.1\r\n"
        "X-Weird: a\rb\r\n"
        "\r\n";
    size_t req_len = strlen(req);

    cloak_firstpacket_t fp;
    cloak_firstpacket_init(&fp);

    size_t consumed = 0;
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_DONE,
                  feed_all(&fp, (const uint8_t *)req, req_len, &consumed));
    ASSERT_EQ_INT((int)req_len, (int)consumed);
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_TRANSPORT_WEBSOCKET, (int)fp.transport);
    ASSERT_EQ_INT((int)req_len, (int)cloak_firstpacket_len(&fp));
    ASSERT_MEM_EQ(cloak_firstpacket_data(&fp), req, req_len);
}

static void test_feed_after_done_is_rejected(void) {
    uint8_t record[64];
    size_t record_len = make_tls_record(record, 8);

    cloak_firstpacket_t fp;
    cloak_firstpacket_init(&fp);
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_DONE, feed_all(&fp, record, record_len, NULL));

    uint8_t extra = 0x00;
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_DONE, cloak_firstpacket_feed(&fp, &extra, 1));
    /* and the buffered packet is unchanged */
    ASSERT_EQ_INT((int)record_len, (int)cloak_firstpacket_len(&fp));
}

static void test_zero_length_tls_record_is_an_error(void) {
    uint8_t header[5] = {0x16, 0x03, 0x01, 0x00, 0x00};

    cloak_firstpacket_t fp;
    cloak_firstpacket_init(&fp);

    cloak_firstpacket_status_t st = CLOAK_FIRSTPACKET_NEED_MORE;
    for (size_t i = 0; i < sizeof(header) && st == CLOAK_FIRSTPACKET_NEED_MORE; i++) {
        st = cloak_firstpacket_feed(&fp, header + i, 1);
    }
    ASSERT_EQ_INT(CLOAK_FIRSTPACKET_ERROR, st);
    ASSERT_EQ_INT(1, cloak_firstpacket_redirect_on_error(&fp));
}

TEST_MAIN_BEGIN()
    test_tls_record_assembled_from_single_bytes();
    test_never_asks_for_more_than_the_record();
    test_http_request_terminated_by_blank_line();
    test_http_stops_exactly_at_the_blank_line();
    test_unrecognised_first_byte_is_a_redirectable_error();
    test_oversized_tls_record_is_a_redirectable_error();
    test_oversized_http_headers_are_a_redirectable_error();
    test_header_value_with_bare_cr_no_lf();
    test_feed_after_done_is_rejected();
    test_zero_length_tls_record_is_an_error();
TEST_MAIN_END()
