#include "cloak/bytequeue.h"
#include "test_framework.h"

#include <string.h>
#include <stdlib.h>

static void test_basic_write_read(void) {
    cloak_bytequeue_t q;
    ASSERT_EQ_INT(cloak_bytequeue_init(&q, 16), 0);
    ASSERT_EQ_INT(cloak_bytequeue_write(&q, (const uint8_t *)"hello", 5), 5);
    ASSERT_EQ_INT(cloak_bytequeue_len(&q), 5);
    uint8_t out[16];
    ASSERT_EQ_INT(cloak_bytequeue_read(&q, out, 16), 5);
    ASSERT_MEM_EQ(out, "hello", 5);
    ASSERT_EQ_INT(cloak_bytequeue_len(&q), 0);
    cloak_bytequeue_destroy(&q);
}

static void test_capacity_rejects_oversized_write(void) {
    cloak_bytequeue_t q;
    cloak_bytequeue_init(&q, 4);
    ASSERT_EQ_INT(cloak_bytequeue_write(&q, (const uint8_t *)"abcd", 4), 4);
    ASSERT_EQ_INT(cloak_bytequeue_write(&q, (const uint8_t *)"e", 1), 0);
    ASSERT_EQ_INT(cloak_bytequeue_len(&q), 4);
    cloak_bytequeue_destroy(&q);
}

static void test_wraparound(void) {
    cloak_bytequeue_t q;
    cloak_bytequeue_init(&q, 4);
    uint8_t out[4];
    /* Fill, drain 3, write 3 more (wraps), read all 4. */
    ASSERT_EQ_INT(cloak_bytequeue_write(&q, (const uint8_t *)"ABCD", 4), 4);
    ASSERT_EQ_INT(cloak_bytequeue_read(&q, out, 3), 3);
    ASSERT_MEM_EQ(out, "ABC", 3);
    ASSERT_EQ_INT(cloak_bytequeue_write(&q, (const uint8_t *)"EFG", 3), 3);
    ASSERT_EQ_INT(cloak_bytequeue_read(&q, out, 4), 4);
    ASSERT_MEM_EQ(out, "DEFG", 4);
    cloak_bytequeue_destroy(&q);
}

static void test_close_semantics(void) {
    cloak_bytequeue_t q;
    cloak_bytequeue_init(&q, 8);
    ASSERT_EQ_INT(cloak_bytequeue_write(&q, (const uint8_t *)"ab", 2), 2);
    cloak_bytequeue_close(&q);
    ASSERT_EQ_INT(cloak_bytequeue_write(&q, (const uint8_t *)"c", 1), 0);
    ASSERT_TRUE(!cloak_bytequeue_is_eof(&q));
    uint8_t out[8];
    ASSERT_EQ_INT(cloak_bytequeue_read(&q, out, 8), 2);
    ASSERT_TRUE(cloak_bytequeue_is_eof(&q));
    cloak_bytequeue_close(&q); /* idempotent */
    cloak_bytequeue_destroy(&q);
}

static void test_read_partial(void) {
    cloak_bytequeue_t q;
    cloak_bytequeue_init(&q, 16);
    cloak_bytequeue_write(&q, (const uint8_t *)"0123456789", 10);
    uint8_t out[3];
    ASSERT_EQ_INT(cloak_bytequeue_read(&q, out, 3), 3);
    ASSERT_MEM_EQ(out, "012", 3);
    ASSERT_EQ_INT(cloak_bytequeue_read(&q, out, 3), 3);
    ASSERT_MEM_EQ(out, "345", 3);
    ASSERT_EQ_INT(cloak_bytequeue_len(&q), 4);
    cloak_bytequeue_destroy(&q);
}

static void test_empty_read_returns_zero(void) {
    cloak_bytequeue_t q;
    cloak_bytequeue_init(&q, 8);
    uint8_t out[8];
    ASSERT_EQ_INT(cloak_bytequeue_read(&q, out, 8), 0);
    ASSERT_TRUE(!cloak_bytequeue_is_eof(&q));
    cloak_bytequeue_destroy(&q);
}

/* Fuzz-style: many random write/read operations against a reference (a
 * simple growing shadow array), confirmed byte-identical FIFO order and
 * capacity-respecting behavior throughout. Run under ASan/UBSan. */
static void test_fuzz_against_reference(void) {
    cloak_bytequeue_t q;
    size_t cap = 37; /* deliberately awkward, non-power-of-2 capacity */
    cloak_bytequeue_init(&q, cap);

    uint8_t *shadow = (uint8_t *)malloc(1000000);
    size_t shadow_head = 0, shadow_len = 0;

    unsigned int seed = 12345;
    for (int iter = 0; iter < 200000; iter++) {
        seed = seed * 1103515245u + 12345u;
        int do_write = (seed >> 16) % 2;
        if (do_write) {
            size_t n = ((seed >> 8) % 20) + 1;
            uint8_t buf[20];
            for (size_t i = 0; i < n; i++) {
                buf[i] = (uint8_t)((seed + i) & 0xff);
            }
            size_t free_space = cloak_bytequeue_free_space(&q);
            size_t written = cloak_bytequeue_write(&q, buf, n);
            if (n <= free_space) {
                ASSERT_EQ_INT(written, n);
                memcpy(shadow + shadow_head + shadow_len, buf, n);
                shadow_len += n;
            } else {
                ASSERT_EQ_INT(written, 0);
            }
        } else {
            size_t n = ((seed >> 8) % 20) + 1;
            uint8_t buf[20];
            size_t read = cloak_bytequeue_read(&q, buf, n);
            ASSERT_TRUE(read <= shadow_len);
            if (read > 0) {
                ASSERT_MEM_EQ(buf, shadow + shadow_head, read);
                shadow_head += read;
                shadow_len -= read;
            }
        }
        ASSERT_EQ_INT(cloak_bytequeue_len(&q), shadow_len);
        ASSERT_TRUE(cloak_bytequeue_len(&q) <= cap);
    }
    free(shadow);
    cloak_bytequeue_destroy(&q);
}

TEST_MAIN_BEGIN()
    test_basic_write_read();
    test_capacity_rejects_oversized_write();
    test_wraparound();
    test_close_semantics();
    test_read_partial();
    test_empty_read_returns_zero();
    test_fuzz_against_reference();
TEST_MAIN_END()
