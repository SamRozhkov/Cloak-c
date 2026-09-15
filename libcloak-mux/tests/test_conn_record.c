/* Pins the DATA-PATH DISGUISE: every post-handshake frame this port puts
 * on the wire must be wrapped in a TLS application-data record header,
 * exactly as Go's common.TLSConn.Write does
 * (/Users/sam/Cloak/internal/common/tls.go).
 *
 * This is a security property, not a framing detail. Cloak's whole reason
 * to exist is that a censor's DPI box parsing the connection sees an
 * ordinary TLS session. The handshake was already disguised on both
 * sides; the data path was not -- it carried a bare big-endian u16 length
 * prefix, whose first byte is 0x00 for every ordinary frame where TLS
 * demands 0x17. A valid TLS handshake followed by bytes that are not TLS
 * records is a stronger fingerprint than no disguise at all.
 *
 * Because that is the property, EVERY on-wire expectation in this file is
 * written as a LITERAL byte. Nothing here is computed from
 * CLOAK_CONN_RECORD_HEADER_LEN or from any other constant the code under
 * test owns: a test that derives its expectation from the implementation
 * cannot detect the implementation changing, which is precisely the
 * change this file exists to prevent. */

#include "cloak/conn.h"

#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cloak/reactor.h"
#include "test_framework.h"

#define MAX_FRAME_LEN 300u
#define SEND_QUEUE_CAP 4096u

typedef struct {
    uint8_t received[8][512];
    size_t received_len[8];
    int received_count;
    int closed_count;
} record_harness_t;

static void on_envelope(cloak_conn_t *c, const uint8_t *bytes, size_t len, void *userdata) {
    (void)c;
    record_harness_t *h = (record_harness_t *)userdata;
    ASSERT_TRUE(h->received_count < 8);
    ASSERT_TRUE(len <= 512);
    if (h->received_count >= 8 || len > 512) {
        return;
    }
    memcpy(h->received[h->received_count], bytes, len);
    h->received_len[h->received_count] = len;
    h->received_count++;
}

static void on_closed(cloak_conn_t *c, void *userdata) {
    (void)c;
    record_harness_t *h = (record_harness_t *)userdata;
    h->closed_count++;
}

static int make_nonblocking_socketpair(int fds[2]) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return -1;
    if (fcntl(fds[0], F_SETFL, O_NONBLOCK) != 0) return -1;
    if (fcntl(fds[1], F_SETFL, O_NONBLOCK) != 0) return -1;
    return 0;
}

/* One bounded dispatch turn. cloak_reactor_run_once returns as soon as
 * the currently-ready fds have been dispatched or the timeout expires, so
 * no test here can hang waiting for bytes that never come. */
static void pump(cloak_reactor_t *r) {
    cloak_reactor_run_once(r, 10);
}

/* ---- 1: what cloak_conn_send actually puts on the wire ------------------ */

/* THE assertion of this file. A censor sees these five bytes and nothing
 * else before the frame body, so they are checked one at a time against
 * literals: 0x17 (application_data), 0x03 0x03 (TLS 1.2 on the wire,
 * which is what TLS 1.3 records carry), then the body length big-endian.
 *
 * The payload is 290 bytes on purpose: a length that straddles the byte
 * boundary (0x0122) pins the ORDER of the two length bytes as well as
 * their values. A 10-byte payload would pass equally well against a
 * little-endian implementation. */
static void test_sent_frame_is_wrapped_in_an_application_data_record(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    record_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(cloak_conn_init(&c, fds[0], r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                   on_envelope, &h, on_closed, &h), 0);

    uint8_t payload[290];
    for (int i = 0; i < 290; i++) {
        payload[i] = (uint8_t)(i & 0xff);
    }
    ASSERT_EQ_INT(cloak_conn_send(&c, payload, sizeof(payload)), 0);

    /* Read the raw bytes straight off the peer socket -- this is exactly
     * what a passive observer on the path would capture. Pump between
     * reads because a 295-byte write may be split by the kernel. */
    uint8_t wire[512];
    size_t got = 0;
    for (int i = 0; i < 50 && got < 295; i++) {
        pump(r);
        ssize_t n = read(fds[1], wire + got, sizeof(wire) - got);
        if (n > 0) {
            got += (size_t)n;
        }
    }

    ASSERT_EQ_INT((long long)got, 295); /* 5-byte record header + 290 body */
    if (got >= 5) {
        ASSERT_EQ_INT(wire[0], 0x17); /* ContentType application_data */
        ASSERT_EQ_INT(wire[1], 0x03); /* legacy_record_version high byte */
        ASSERT_EQ_INT(wire[2], 0x03); /* legacy_record_version low byte  */
        ASSERT_EQ_INT(wire[3], 0x01); /* 290 >> 8                        */
        ASSERT_EQ_INT(wire[4], 0x22); /* 290 & 0xff                      */
    }
    if (got == 295) {
        ASSERT_MEM_EQ(wire + 5, payload, 290);
    }

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

/* ---- 2: a received record is accepted and its payload dispatched -------- */

static void test_received_record_is_accepted_and_payload_dispatched(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    record_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(cloak_conn_init(&c, fds[0], r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                   on_envelope, &h, on_closed, &h), 0);

    /* Hand-built with literals, as a real peer's TLSConn.Write would
     * emit it -- the length is in bytes 3-4, NOT 0-1. */
    const uint8_t wire[] = {0x17, 0x03, 0x03, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'};
    ASSERT_EQ_INT(write(fds[1], wire, sizeof(wire)), (ssize_t)sizeof(wire));
    for (int i = 0; i < 50 && h.received_count == 0; i++) {
        pump(r);
    }

    ASSERT_EQ_INT(h.received_count, 1);
    ASSERT_EQ_INT(h.closed_count, 0);
    if (h.received_count == 1) {
        ASSERT_EQ_INT((long long)h.received_len[0], 5);
        ASSERT_MEM_EQ(h.received[0], "hello", 5);
    }

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

/* ---- 3: byte-at-a-time delivery, including a split inside the header ---- */

/* A non-blocking read may return any prefix of a record, and a split
 * landing INSIDE the five-byte header is the case a two-byte-prefix
 * reader never had to survive: bytes 0-2 alone say nothing about how much
 * more to wait for. Delivering one byte per reactor turn forces every
 * possible split point, header-internal ones included. */
static void test_byte_at_a_time_delivery_reaches_the_same_result(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    record_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(cloak_conn_init(&c, fds[0], r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                   on_envelope, &h, on_closed, &h), 0);

    uint8_t wire[5 + 40];
    wire[0] = 0x17;
    wire[1] = 0x03;
    wire[2] = 0x03;
    wire[3] = 0x00;
    wire[4] = 0x28; /* 40 */
    for (int i = 0; i < 40; i++) {
        wire[5 + i] = (uint8_t)(0x40 + i);
    }

    for (size_t off = 0; off < sizeof(wire); off++) {
        ASSERT_EQ_INT(write(fds[1], wire + off, 1), 1);
        pump(r);
        /* Nothing may be dispatched before the LAST byte arrives: a
         * reader that guessed a length from the first two bytes would
         * have fired early here. */
        if (off + 1 < sizeof(wire)) {
            ASSERT_EQ_INT(h.received_count, 0);
        }
    }
    for (int i = 0; i < 50 && h.received_count == 0; i++) {
        pump(r);
    }

    ASSERT_EQ_INT(h.received_count, 1);
    ASSERT_EQ_INT(h.closed_count, 0);
    if (h.received_count == 1) {
        ASSERT_EQ_INT((long long)h.received_len[0], 40);
        ASSERT_MEM_EQ(h.received[0], wire + 5, 40);
    }

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

/* ---- 4: two records in one read ---------------------------------------- */

static void test_two_records_in_one_read_are_both_dispatched(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    record_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(cloak_conn_init(&c, fds[0], r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                   on_envelope, &h, on_closed, &h), 0);

    const uint8_t wire[] = {
        0x17, 0x03, 0x03, 0x00, 0x03, 'f', 'o', 'o',
        0x17, 0x03, 0x03, 0x00, 0x04, 'q', 'u', 'u', 'x',
    };
    ASSERT_EQ_INT(write(fds[1], wire, sizeof(wire)), (ssize_t)sizeof(wire));
    for (int i = 0; i < 50 && h.received_count < 2; i++) {
        pump(r);
    }

    ASSERT_EQ_INT(h.received_count, 2);
    ASSERT_EQ_INT(h.closed_count, 0);
    if (h.received_count == 2) {
        ASSERT_EQ_INT((long long)h.received_len[0], 3);
        ASSERT_MEM_EQ(h.received[0], "foo", 3);
        ASSERT_EQ_INT((long long)h.received_len[1], 4);
        ASSERT_MEM_EQ(h.received[1], "quux", 4);
    }

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

/* ---- 5: the leniency, pinned on purpose -------------------------------- */

/* DELIBERATE, NOT AN OVERSIGHT. Go's common.TLSConn.Read takes the length
 * from bytes 3-4 and never looks at the type or version bytes, and this
 * port matches it byte for byte. Rejecting a record a real Cloak peer
 * would have accepted would make this implementation distinguishable from
 * the reference one by behaviour -- the same class of leak the record
 * header itself exists to close -- and the frame's AEAD one layer up is
 * the only authenticator that could actually stop a forgery, so a check
 * here would buy nothing it does not already provide.
 *
 * This test exists so that a future "let's harden the parser" change has
 * to argue with a failing test rather than with a comment. If you are
 * here because this test is in your way: read cloak/conn.h first, and
 * change the reference implementation's behaviour deliberately or not at
 * all. */
static void test_nonconforming_type_and_version_bytes_are_still_accepted(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    record_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(cloak_conn_init(&c, fds[0], r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                   on_envelope, &h, on_closed, &h), 0);

    /* 0x16 is handshake, not application_data; 0x0301 is TLS 1.0, not
     * 0x0303. Both wrong, both ignored -- only bytes 3-4 are read. */
    const uint8_t wire[] = {0x16, 0x03, 0x01, 0x00, 0x03, 'o', 'd', 'd'};
    ASSERT_EQ_INT(write(fds[1], wire, sizeof(wire)), (ssize_t)sizeof(wire));
    for (int i = 0; i < 50 && h.received_count == 0; i++) {
        pump(r);
    }

    ASSERT_EQ_INT(h.received_count, 1);
    ASSERT_EQ_INT(h.closed_count, 0);
    if (h.received_count == 1) {
        ASSERT_EQ_INT((long long)h.received_len[0], 3);
        ASSERT_MEM_EQ(h.received[0], "odd", 3);
    }

    /* And the extreme: every byte outside the length field is garbage. */
    const uint8_t garbage[] = {0xff, 0x00, 0xab, 0x00, 0x02, 'h', 'i'};
    ASSERT_EQ_INT(write(fds[1], garbage, sizeof(garbage)), (ssize_t)sizeof(garbage));
    for (int i = 0; i < 50 && h.received_count < 2; i++) {
        pump(r);
    }

    ASSERT_EQ_INT(h.received_count, 2);
    ASSERT_EQ_INT(h.closed_count, 0);
    if (h.received_count == 2) {
        ASSERT_EQ_INT((long long)h.received_len[1], 2);
        ASSERT_MEM_EQ(h.received[1], "hi", 2);
    }

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

/* ---- 6: an over-long declared length still breaks the connection ------- */

/* Unchanged behaviour, re-pinned AT THE NEW OFFSET, and the connection's
 * max_frame_len is chosen so that this case can only pass for the right
 * reason. It is CLOAK_CONN_MAX_FRAME_LEN (16640) here, not MAX_FRAME_LEN:
 * bytes 0-1 of the record below read as 0x1703 == 5891, which is UNDER
 * 16640, while bytes 3-4 read as 0xffff == 65535, which is over it. A
 * reader still taking the length from bytes 0-1 therefore sits waiting
 * for 5891 bytes that never come and never breaks the connection, so this
 * test fails against it -- which it would not have done with a 300-byte
 * limit, where both readings are over the cap and the pass says nothing.
 *
 * This case only pins that the check reads the RIGHT OFFSET. It declares
 * 0xffff against 16640 -- wildly over -- so it cannot see the check's
 * bound loosened by a few bytes. Case 7 below is what pins that. */
static void test_declared_length_over_max_frame_len_breaks_the_connection(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    record_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(cloak_conn_init(&c, fds[0], r, CLOAK_CONN_MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                   on_envelope, &h, on_closed, &h), 0);

    /* A well-formed application-data header declaring 0xffff bytes, over
     * this connection's 16640-byte limit. No body follows: the violation
     * must be detected from the header alone, not by waiting for bytes
     * that were never going to arrive. */
    const uint8_t wire[] = {0x17, 0x03, 0x03, 0xff, 0xff};
    ASSERT_EQ_INT(write(fds[1], wire, sizeof(wire)), (ssize_t)sizeof(wire));
    for (int i = 0; i < 50 && h.closed_count == 0; i++) {
        pump(r);
    }

    ASSERT_EQ_INT(h.closed_count, 1);
    ASSERT_EQ_INT(h.received_count, 0);

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

/* ---- 7: the length check's BOUNDARY, both sides of it ------------------ */

/* WHY THIS EXISTS, AND WHY CASE 6 IS NOT ENOUGH. Case 6 declares 0xffff
 * against a 16640-byte limit: a length three times over the cap. Every
 * plausible wrong bound -- max_frame_len, max_envelope_len, max_frame_len
 * plus any small constant -- rejects it, so case 6 passing says only that
 * SOME check happens at the right offset, never that it is the right
 * check.
 *
 * That gap is not hypothetical. Loosening conn.c's test from
 * `frame_len > c->max_frame_len` to `> c->max_envelope_len` left this
 * whole suite green while opening a remotely triggerable heap overflow:
 * recv_scratch is malloc(max_envelope_len) == 5 + max_frame_len, but the
 * envelope a loosened check admits is 5 + frame_len, which can reach
 * 10 + max_frame_len -- five bytes past the end of the buffer
 * cloak_bytequeue_read writes into. A peer chooses that length, so a
 * censor or any on-path party could smash this process's heap with one
 * record header.
 *
 * So the boundary is pinned from BOTH sides, with a body actually
 * delivered on the accepting side -- a check that rejected max_frame_len
 * itself would pass a one-sided "it breaks when over" test just as
 * happily. MAX_FRAME_LEN is the connection's own configured limit, and
 * both lengths here are written relative to it rather than as magic
 * numbers, because it is the RELATIONSHIP (exactly at, exactly one past)
 * that is under test, not any particular value. */
static void test_declared_length_boundary_is_exact(void) {
    /* 7a: exactly max_frame_len is ACCEPTED, and its whole body arrives. */
    {
        int fds[2];
        ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
        cloak_reactor_t *r = cloak_reactor_create();
        ASSERT_TRUE(r != NULL);
        if (r == NULL) {
            return;
        }

        record_harness_t h;
        memset(&h, 0, sizeof(h));
        cloak_conn_t c;
        ASSERT_EQ_INT(cloak_conn_init(&c, fds[0], r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                       on_envelope, &h, on_closed, &h), 0);

        uint8_t wire[5 + MAX_FRAME_LEN];
        wire[0] = 0x17;
        wire[1] = 0x03;
        wire[2] = 0x03;
        wire[3] = (uint8_t)((MAX_FRAME_LEN >> 8) & 0xff);
        wire[4] = (uint8_t)(MAX_FRAME_LEN & 0xff);
        for (unsigned i = 0; i < MAX_FRAME_LEN; i++) {
            wire[5 + i] = (uint8_t)(i * 7u + 1u);
        }
        ASSERT_EQ_INT(write(fds[1], wire, sizeof(wire)), (ssize_t)sizeof(wire));
        for (int i = 0; i < 50 && h.received_count == 0; i++) {
            pump(r);
        }

        ASSERT_EQ_INT(h.received_count, 1);
        ASSERT_EQ_INT(h.closed_count, 0);
        if (h.received_count == 1) {
            /* The full body, not a truncated one: an off-by-one in the
             * other direction would show up here and nowhere else. */
            ASSERT_EQ_INT((long long)h.received_len[0], (long long)MAX_FRAME_LEN);
            ASSERT_MEM_EQ(h.received[0], wire + 5, MAX_FRAME_LEN);
        }

        cloak_conn_destroy(&c);
        cloak_reactor_destroy(r);
        close(fds[0]);
        close(fds[1]);
    }

    /* 7b: exactly max_frame_len + 1 BREAKS the connection -- one byte
     * over, which is the smallest loosening any wrong bound can produce
     * and the one case 6 cannot see. */
    {
        int fds[2];
        ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
        cloak_reactor_t *r = cloak_reactor_create();
        ASSERT_TRUE(r != NULL);
        if (r == NULL) {
            return;
        }

        record_harness_t h;
        memset(&h, 0, sizeof(h));
        cloak_conn_t c;
        ASSERT_EQ_INT(cloak_conn_init(&c, fds[0], r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                       on_envelope, &h, on_closed, &h), 0);

        /* Header only. The violation must be detected from the declared
         * length alone; a body is never sent, so an implementation that
         * waited for one would hang here rather than fail, and the
         * bounded pump below turns that hang into a failure too. */
        const unsigned too_long = MAX_FRAME_LEN + 1u;
        uint8_t wire[5];
        wire[0] = 0x17;
        wire[1] = 0x03;
        wire[2] = 0x03;
        wire[3] = (uint8_t)((too_long >> 8) & 0xff);
        wire[4] = (uint8_t)(too_long & 0xff);
        ASSERT_EQ_INT(write(fds[1], wire, sizeof(wire)), (ssize_t)sizeof(wire));
        for (int i = 0; i < 50 && h.closed_count == 0; i++) {
            pump(r);
        }

        ASSERT_EQ_INT(h.closed_count, 1);
        ASSERT_EQ_INT(h.received_count, 0);

        cloak_conn_destroy(&c);
        cloak_reactor_destroy(r);
        close(fds[0]);
        close(fds[1]);
    }
}

/* ---- 8: the configured max_frame_len bound, both sides of it ----------- */

/* CLOAK_CONN_MAX_FRAME_LEN is a MIMICRY bound, not a correctness one: a
 * bigger value would still encode in the record's 16-bit length field,
 * and would still round-trip perfectly between two copies of this port.
 * What it would not do is look like TLS -- 16640 is the ciphertext limit
 * RFC 8446 s5.2 sets and the exact point Go's own common.TLSConn.Write
 * refuses to write ("message is too long"). So no functional test can
 * ever notice this bound going missing, and it has to be pinned directly.
 *
 * It is reachable from configuration -- cloak_session_config_t's
 * operator-supplied max_on_wire_size becomes this argument unchanged --
 * which is why it is rejected at construction rather than left to a
 * comment. Both sides, because a bound that also rejected 16640 itself
 * would break every legitimate maximum-sized configuration. */
static void test_max_frame_len_is_capped_at_the_tls_record_limit(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    if (r == NULL) {
        return;
    }

    /* Exactly the limit is accepted. Literal 16640, not the macro: the
     * value is fixed by RFC 8446 and by the reference implementation, so
     * a test that read it back out of the header would agree with any
     * future edit to the header instead of catching it. */
    cloak_conn_t ok;
    ASSERT_EQ_INT(cloak_conn_init(&ok, fds[0], r, 16640u, SEND_QUEUE_CAP,
                                   on_envelope, NULL, on_closed, NULL), 0);
    cloak_conn_destroy(&ok);

    /* One over is rejected... */
    cloak_conn_t over;
    ASSERT_EQ_INT(cloak_conn_init(&over, fds[0], r, 16641u, SEND_QUEUE_CAP,
                                   on_envelope, NULL, on_closed, NULL), -1);
    cloak_conn_destroy(&over);

    /* ...and so is 65535, which the 16-bit length field would happily
     * encode. This is the value the bound used to be, so it is the one
     * that proves the bound actually moved. */
    cloak_conn_t way_over;
    ASSERT_EQ_INT(cloak_conn_init(&way_over, fds[0], r, 65535u, SEND_QUEUE_CAP,
                                   on_envelope, NULL, on_closed, NULL), -1);
    cloak_conn_destroy(&way_over);

    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

TEST_MAIN_BEGIN()
    test_sent_frame_is_wrapped_in_an_application_data_record();
    test_received_record_is_accepted_and_payload_dispatched();
    test_byte_at_a_time_delivery_reaches_the_same_result();
    test_two_records_in_one_read_are_both_dispatched();
    test_nonconforming_type_and_version_bytes_are_still_accepted();
    test_declared_length_over_max_frame_len_breaks_the_connection();
    test_declared_length_boundary_is_exact();
    test_max_frame_len_is_capped_at_the_tls_record_limit();
TEST_MAIN_END()
