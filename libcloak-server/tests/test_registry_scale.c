#define _POSIX_C_SOURCE 200809L
#include "cloak/registry.h"

#include "cloak/base64.h"
#include "cloak/clienthello.h"
#include "cloak/common.h"
#include "cloak/crypto.h"
#include "cloak/dispatcher.h"
#include "cloak/log.h"
#include "cloak/net.h"
#include "cloak/reactor.h"
#include "cloak/server.h"
#include "cloak/server_auth.h"
#include "cloak/server_stack.h"
#include "cloak/usermanager.h"
#include "cloak/userpanel.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "test_framework.h"
#include "client_harness.h"

#include "../src/hash_internal.h"

/* THE SESSION CAP AT ITS OWN SCALE, and what a lookup costs there.
 *
 * WHY THIS FILE EXISTS. CLOAK_REGISTRY_MAX_SESSIONS was 256, defended by
 * a comment whose premise ("there is no user manager yet") had been false
 * since module 4, and it was the WHOLE SERVER'S session budget. Lifting
 * it to 1024 is half the change; the other half is that every lookup in
 * the registry and in the user panel used to be a linear scan of a fixed
 * table REGARDLESS OF OCCUPANCY, so raising the cap without replacing
 * those scans would have made the scan the new defect -- four times the
 * work per handshake, paid by every connection whether the server held
 * one session or a thousand.
 *
 * NOTHING IN THIS TREE HAD EVER OPENED SESSIONS TO THE CAP, and nothing
 * bounded the cost of finding one. Case 1 does the first and case 2 does
 * the second, and case 2 is the one that matters: a test asserting only
 * that a thousand sessions still work passes just as happily against an
 * O(n) lookup, and would have passed against the code this replaced.
 *
 * WHAT IS MEASURED HERE RATHER THAN ASSERTED. Case 3's timing numbers are
 * printed, not asserted, for the reason test_dispatcher_auth.c case 14
 * gives at length: this suite runs under ASan at -j4, where a duration
 * assertion is flaky, while the CAUSE of the one timing tell this project
 * has actually measured (a log line in a reactor callback) is binary and
 * is asserted directly. The numbers are in the commit's report. */

/* ------------------------------------------------------------------ */
/* Shared helpers                                                      */
/* ------------------------------------------------------------------ */

static void scale_make_obfuscator(cloak_obfuscator_t *o) {
    o->method = CLOAK_AEAD_AES_256_GCM;
    cloak_random_bytes(o->session_key, sizeof(o->session_key));
}

static void scale_base_config(cloak_session_config_t *cfg, const cloak_obfuscator_t *obfs) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->obfuscator = *obfs;
    cfg->ordering = CLOAK_SESSION_ORDERING_ORDERED;
    cfg->max_on_wire_size = 16401;
    cfg->stream_recv_capacity = 65536;
    cfg->stream_max_pending_frames = 64;
    cfg->conn_send_queue_cap = 262144;
    cfg->inactivity_timeout_ms = 60000;
}

static void scale_on_broken(cloak_server_registry_t *reg, cloak_session_t *sesh,
                            const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                            void *userdata) {
    (void)reg;
    (void)sesh;
    (void)uid;
    (void)session_id;
    (void)userdata;
}

/* A distinct UID per index, spread across the whole 16 bytes so that a
 * hash which only ever reads the first few of them is not accidentally
 * fed a well-distributed input. */
static void scale_uid(uint8_t uid[CLOAK_UID_LEN], unsigned n) {
    memset(uid, 0, CLOAK_UID_LEN);
    uid[0] = 0xD0;
    uid[5] = (uint8_t)(n & 0xff);
    uid[11] = (uint8_t)((n >> 8) & 0xff);
    uid[15] = (uint8_t)((n >> 16) & 0xff);
}

static uint64_t scale_mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int scale_cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : (x > y ? 1 : 0);
}

/* ------------------------------------------------------------------ */
/* 1. To the cap, and every one of them is the session we put there     */
/* ------------------------------------------------------------------ */

/* THE SCALE CASE. Nothing in this tree had ever done this: the closest
 * was two concurrent sessions (test_admin_e2e.c), and the two tests that
 * do reach CLOAK_REGISTRY_MAX_SESSIONS (test_registry.c case 6,
 * test_proxy_teardown.c case 8) fill the table only to prove the NEXT
 * request is refused -- neither looks at what is in it.
 *
 * WHAT THIS ASSERTS THAT A COUNT WOULD NOT. Every session pointer is
 * distinct, and every (uid, session_id) still resolves to the session
 * that key created. That is the shape of defect the last three tasks in
 * this module each found and the rest of the suite each missed: a SILENT
 * SUBSTITUTION, where the right number of the wrong things is returned.
 * A key hash that dropped the session_id term, a chain unlink that
 * relinked into the wrong bucket, or a get_or_create that handed back a
 * neighbour would all leave the count at exactly 1024 and fail here.
 *
 * It is also the answer to "does anything notice if the cap is raised but
 * the allocation still stops at 256?" -- the loop below establishes 1024
 * sessions or the test fails, and the count is read back from the
 * registry rather than from the loop counter. */
static void test_sessions_to_the_cap_all_establish(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    cloak_server_registry_t reg;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&reg, r, scale_on_broken, NULL));

    cloak_obfuscator_t obfs;
    scale_make_obfuscator(&obfs);
    cloak_session_config_t cfg;
    scale_base_config(&cfg, &obfs);

    static cloak_session_t *sesh[CLOAK_REGISTRY_MAX_SESSIONS];
    for (unsigned i = 0; i < CLOAK_REGISTRY_MAX_SESSIONS; i++) {
        uint8_t uid[CLOAK_UID_LEN];
        scale_uid(uid, i);
        int created = 0;
        sesh[i] = cloak_server_registry_get_or_create(&reg, uid, 7000u + i, &cfg, &created);
        ASSERT_TRUE(sesh[i] != NULL);
        ASSERT_EQ_INT(1, created);
    }
    ASSERT_EQ_INT(CLOAK_REGISTRY_MAX_SESSIONS, (int)cloak_server_registry_count(&reg));

    /* EVERY ONE OF THEM IS STILL ITSELF. Distinctness first (a table that
     * handed the same session back twice would still count 1024 only if
     * it also lost one, so this is checked against the count above, not
     * instead of it), then identity by key. */
    for (unsigned i = 0; i < CLOAK_REGISTRY_MAX_SESSIONS; i++) {
        for (unsigned j = i + 1; j < i + 8 && j < CLOAK_REGISTRY_MAX_SESSIONS; j++) {
            ASSERT_TRUE(sesh[i] != sesh[j]);
        }
        uint8_t uid[CLOAK_UID_LEN];
        scale_uid(uid, i);
        ASSERT_TRUE(cloak_server_registry_find(&reg, uid, 7000u + i) == sesh[i]);
        /* The session_id half of the key really is part of it: the same
         * uid with a session id nobody created must miss. */
        ASSERT_TRUE(cloak_server_registry_find(&reg, uid, 99000u + i) == NULL);
        ASSERT_EQ_INT(1, (int)cloak_server_registry_count_for_uid(&reg, uid));
    }

    /* One past the cap is a refusal, and it disturbs nothing. */
    uint8_t over[CLOAK_UID_LEN];
    scale_uid(over, 0xFFFFu);
    int created = -1;
    ASSERT_TRUE(cloak_server_registry_get_or_create(&reg, over, 1, &cfg, &created) == NULL);
    ASSERT_EQ_INT(CLOAK_REGISTRY_MAX_SESSIONS, (int)cloak_server_registry_count(&reg));

    uint8_t uid0[CLOAK_UID_LEN];
    scale_uid(uid0, 0);
    ASSERT_TRUE(cloak_server_registry_find(&reg, uid0, 7000u) == sesh[0]);

    /* An ADDITIONAL connection to a session that already exists is not a
     * new session and must still be admitted at the cap -- the same rule
     * test_dispatcher_users.c case 2 pins for the per-user cap. */
    created = -1;
    ASSERT_TRUE(cloak_server_registry_get_or_create(&reg, uid0, 7000u, &cfg, &created) == sesh[0]);
    ASSERT_EQ_INT(0, created);

    cloak_server_registry_destroy(&reg);
    cloak_reactor_destroy(r);
}

/* ------------------------------------------------------------------ */
/* 2. THE COST BRACKET                                                  */
/* ------------------------------------------------------------------ */

/* Fills a fresh registry with `n` sessions spread over `uid_count`
 * distinct uids (uid_count == 0 means one uid per session, the
 * 1024-users-with-one-session-each shape), performs `lookups` successful
 * lookups spread evenly over them, and returns the mean number of chain
 * steps per lookup in units of 1/1000 of a step. *out_ns, when non-NULL,
 * gets the mean wall-clock nanoseconds per lookup, which is reported but
 * never asserted on.
 *
 * WHY uid_count EXISTS, because it is the whole point of the second
 * bracket below. The key bucket is hashed from the PAIR (uid,
 * session_id). Under one uid per session the uid half alone already
 * separates every key, so with 1024 sessions over 2048 key buckets every
 * chain holds exactly one entry NO MATTER WHAT THE HASH DOES -- a hash
 * that ignored session_id entirely would measure identically. That was
 * measured, not reasoned: zeroing session_id out of registry.c's
 * registry_key_bucket input left the whole 85-binary suite passing. With
 * uid_count small the sessions of one uid all collide unless the
 * session_id half is really hashed, and the same mutation takes the mean
 * chain length from ~1.0 to ~65 at the cap. */
static unsigned long lookup_cost_milli_steps(unsigned n, unsigned uid_count, unsigned lookups,
                                             unsigned long *out_ns) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    cloak_server_registry_t reg;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&reg, r, scale_on_broken, NULL));

    cloak_obfuscator_t obfs;
    scale_make_obfuscator(&obfs);
    cloak_session_config_t cfg;
    scale_base_config(&cfg, &obfs);

    for (unsigned i = 0; i < n; i++) {
        uint8_t uid[CLOAK_UID_LEN];
        scale_uid(uid, uid_count == 0 ? i : (i % uid_count));
        int created = 0;
        ASSERT_TRUE(cloak_server_registry_get_or_create(&reg, uid, 7000u + i, &cfg, &created) !=
                    NULL);
    }
    ASSERT_EQ_INT((int)n, (int)cloak_server_registry_count(&reg));

    /* Zeroed AFTER the fill, so what is measured is the lookups and not
     * get_or_create's own existence checks. */
    reg.lookup_probe_steps = 0;
    reg.lookup_calls = 0;

    uint64_t t0 = scale_mono_ns();
    for (unsigned k = 0; k < lookups; k++) {
        unsigned i = k % n;
        uint8_t uid[CLOAK_UID_LEN];
        scale_uid(uid, uid_count == 0 ? i : (i % uid_count));
        cloak_session_t *s = cloak_server_registry_find(&reg, uid, 7000u + i);
        ASSERT_TRUE(s != NULL);
    }
    uint64_t t1 = scale_mono_ns();

    ASSERT_EQ_INT((int)lookups, (int)reg.lookup_calls);
    unsigned long milli = (unsigned long)((reg.lookup_probe_steps * 1000ull) / reg.lookup_calls);
    if (out_ns != NULL) {
        *out_ns = (unsigned long)((t1 - t0) / lookups);
    }

    cloak_server_registry_destroy(&reg);
    cloak_reactor_destroy(r);
    return milli;
}

/* Same, for cloak_server_registry_count_for_uid -- the OTHER lookup the
 * dispatcher performs on the handshake path (dispatcher.c calls it once
 * per new session to apply the per-user cap), and the one whose old doc
 * comment argued hardest for keeping the linear scan. */
static unsigned long count_for_uid_cost_milli_steps(unsigned n, unsigned lookups) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    cloak_server_registry_t reg;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&reg, r, scale_on_broken, NULL));

    cloak_obfuscator_t obfs;
    scale_make_obfuscator(&obfs);
    cloak_session_config_t cfg;
    scale_base_config(&cfg, &obfs);

    for (unsigned i = 0; i < n; i++) {
        uint8_t uid[CLOAK_UID_LEN];
        scale_uid(uid, i);
        int created = 0;
        ASSERT_TRUE(cloak_server_registry_get_or_create(&reg, uid, 7000u + i, &cfg, &created) !=
                    NULL);
    }
    reg.lookup_probe_steps = 0;
    reg.lookup_calls = 0;

    for (unsigned k = 0; k < lookups; k++) {
        uint8_t uid[CLOAK_UID_LEN];
        scale_uid(uid, k % n);
        ASSERT_EQ_INT(1, (int)cloak_server_registry_count_for_uid(&reg, uid));
    }
    unsigned long milli = (unsigned long)((reg.lookup_probe_steps * 1000ull) / reg.lookup_calls);

    cloak_server_registry_destroy(&reg);
    cloak_reactor_destroy(r);
    return milli;
}

/* THE POINT OF THIS COMMIT, STATED AS A MEASUREMENT.
 *
 * THE SHAPE BEING ASSERTED IS O(1): the mean cost of a lookup does not
 * grow with the number of sessions held. It is measured at four
 * occupancies, 1 / 64 / 256 / 1024, in CHAIN STEPS rather than in
 * seconds, because steps are deterministic and a duration is not -- this
 * suite runs under ASan at -j4.
 *
 * WHAT SEPARATES IT FROM O(n), and why the bracket is a ratio rather than
 * a constant somebody picked: the structure this replaced examined a
 * fixed CLOAK_REGISTRY_MAX_SESSIONS slots per lookup whatever the
 * occupancy, so on this measurement it would read 1024.000 steps at every
 * one of the four points; an array-with-early-exit implementation would
 * read about n/2, i.e. 0.5 / 32 / 128 / 512, a ratio of 1024 between the
 * ends. What a chained hash at load factor 0.5 predicts is 1 + (n-1)/2m
 * -- 1.000 at n=1 and about 1.250 at n=1024, a ratio of 1.25. The
 * assertion is that the ratio between the cheapest and the dearest of the
 * four points is under 3, which no O(n) or O(log n) structure reaches
 * across a 1024-fold range in n and which leaves ample room for the
 * variance of a randomly keyed hash.
 *
 * THE RATIO IS ALSO ASSERTED IN THE OTHER DIRECTION -- an absolute
 * ceiling of 4 steps per lookup at the cap -- because a ratio alone would
 * be satisfied by an implementation that was uniformly terrible.
 *
 * Wall-clock nanoseconds are printed alongside for the report and are
 * deliberately NOT asserted on.
 *
 * WHAT THIS CASE CANNOT SEE, stated here so the next reader does not
 * trust it further than it goes: it fills ONE UID PER SESSION, and under
 * that occupancy the uid half of the key already separates all 1024
 * entries, so every chain holds one entry whatever the hash does. A key
 * hash that dropped session_id entirely passes this case unchanged --
 * measured, by zeroing session_id out of registry.c's
 * registry_key_bucket input and watching all 85 test binaries still
 * pass. That is what
 * test_lookup_cost_is_bounded_when_one_user_holds_many_sessions below is
 * for; the two are a pair and neither is sufficient alone. */
static void test_lookup_cost_is_bounded_at_the_cap(void) {
    const unsigned points[4] = {1, 64, 256, CLOAK_REGISTRY_MAX_SESSIONS};
    unsigned long milli[4];
    unsigned long ns[4];

    for (int i = 0; i < 4; i++) {
        milli[i] = lookup_cost_milli_steps(points[i], 0u, 20000, &ns[i]);
        printf("case 2: find at n=%4u -> %lu.%03lu chain steps/lookup, %lu ns/lookup\n", points[i],
               milli[i] / 1000, milli[i] % 1000, ns[i]);
    }

    unsigned long lo = milli[0], hi = milli[0];
    for (int i = 1; i < 4; i++) {
        if (milli[i] < lo) {
            lo = milli[i];
        }
        if (milli[i] > hi) {
            hi = milli[i];
        }
    }
    ASSERT_TRUE(lo > 0); /* a lookup that examines nothing is not a lookup */
    printf("case 2: find cost ratio across a 1024-fold range in n = %lu.%03lu (linear would be "
           "~1024)\n",
           hi / lo, ((hi * 1000) / lo) % 1000);

    /* THE BRACKET. */
    ASSERT_TRUE(hi < 3 * lo);
    ASSERT_TRUE(milli[3] < 4000);

    /* The same, for the per-user cap lookup on the same path. */
    unsigned long c1 = count_for_uid_cost_milli_steps(1, 20000);
    unsigned long ccap = count_for_uid_cost_milli_steps(CLOAK_REGISTRY_MAX_SESSIONS, 20000);
    printf("case 2: count_for_uid at n=1 -> %lu.%03lu steps, at n=%d -> %lu.%03lu steps\n",
           c1 / 1000, c1 % 1000, CLOAK_REGISTRY_MAX_SESSIONS, ccap / 1000, ccap % 1000);
    ASSERT_TRUE(c1 > 0);
    ASSERT_TRUE(ccap < 3 * c1);
    /* This one does NOT stop at its first hit -- it counts, so it walks
     * its whole bucket -- and its predicted mean is therefore
     * 1 + (n-1)/m = 2.0 at the cap rather than find's 1.25. THE FIRST
     * VERSION OF THIS TEST MEASURED 4.988 HERE, against a uid array of
     * 256 buckets, and that measurement is what moved
     * CLOAK_REGISTRY_UID_BUCKETS to 1024: the bracket is what sized the
     * table, not the other way round. 1024 is what the scan it replaced
     * cost unconditionally. */
    ASSERT_TRUE(ccap < 3000);
}

/* THE SAME BRACKET, UNDER THE OCCUPANCY THE SERVER ACTUALLY HAS -- and
 * the reason the one above is not sufficient on its own.
 *
 * Cloak's uid IS A USER. cloak_server_registry_count_for_uid exists
 * precisely because one user legitimately holds many concurrent
 * sessions, and the per-user cap the dispatcher applies is a cap on that
 * number. So "1024 users holding one session each" is not the workload;
 * it is the ONE workload under which a (uid, session_id) key hash cannot
 * be told apart from a uid-only hash, because the uid half alone already
 * separates all 1024 keys.
 *
 * MEASURED, not argued. Zeroing session_id's four bytes out of
 * registry.c's registry_key_bucket input -- so the key bucket depends on
 * the uid alone -- leaves lookups CORRECT (the chain walk still compares
 * both halves of the key) and therefore leaves the whole 85-binary suite
 * passing 85/85, INCLUDING the bracket above. It is caught here, and
 * only here: at 8 uids the same mutation reads
 *
 *     n=   1 -> 1.000 chain steps    n=  64 ->  4.503
 *     n= 256 -> 16.522               n=1024 -> 65.316
 *
 * against the unmutated 1.000 / 1.062 / 1.046 / 1.239 this case asserts.
 * 65x, not a subtle margin. The control matters: the workload change
 * ALONE proves nothing, since the unmutated numbers are flat either way;
 * it is the mutation that shows the bracket can now fail.
 *
 * 8 is chosen so that at the cap one uid holds 128 sessions -- well above
 * any plausible per-user concurrency, which is the point: the bracket
 * should hold at a uid:session ratio far worse than deployment's. The
 * assertions are deliberately the SAME two as the case above, so the two
 * differ in workload and in nothing else. */
static void test_lookup_cost_is_bounded_when_one_user_holds_many_sessions(void) {
    const unsigned points[4] = {1, 64, 256, CLOAK_REGISTRY_MAX_SESSIONS};
    const unsigned uid_count = 8u;
    unsigned long milli[4];
    unsigned long ns[4];

    for (int i = 0; i < 4; i++) {
        milli[i] = lookup_cost_milli_steps(points[i], uid_count, 20000, &ns[i]);
        printf("case 2b: find at n=%4u over %u uids -> %lu.%03lu chain steps/lookup, %lu "
               "ns/lookup\n",
               points[i], uid_count, milli[i] / 1000, milli[i] % 1000, ns[i]);
    }

    unsigned long lo = milli[0], hi = milli[0];
    for (int i = 1; i < 4; i++) {
        if (milli[i] < lo) {
            lo = milli[i];
        }
        if (milli[i] > hi) {
            hi = milli[i];
        }
    }
    ASSERT_TRUE(lo > 0);
    printf("case 2b: find cost ratio across a 1024-fold range in n at %u uids = %lu.%03lu\n",
           uid_count, hi / lo, ((hi * 1000) / lo) % 1000);

    /* THE BRACKET, identical to case 2's. */
    ASSERT_TRUE(hi < 3 * lo);
    ASSERT_TRUE(milli[3] < 4000);
}

/* ------------------------------------------------------------------ */
/* 3. The refusal at the cap is still the cover-site redirect           */
/* ------------------------------------------------------------------ */

typedef struct {
    int calls;
    int last_created;
} scale_attached_t;

static void scale_attached_cb(cloak_dispatcher_t *d, cloak_session_t *sesh,
                              const cloak_server_clientinfo_t *info, int created, void *userdata) {
    (void)d;
    (void)sesh;
    (void)info;
    scale_attached_t *rec = userdata;
    rec->calls++;
    rec->last_created = created;
}

struct scale_fixture {
    cloak_reactor_t *reactor;
    cover_site_t cover;
    cloak_listener_t cover_listener;
    int have_cover_listener;
    cloak_server_config_t cfg;
    cloak_server_t srv;
    int srv_ready;
    cloak_server_registry_t registry;
    int registry_ready;
    scale_attached_t attached;
    cloak_dispatcher_t d;
    int d_ready;
    cloak_listener_t front;
    int have_front;

    uint8_t server_pub[CLOAK_X25519_KEY_LEN];
    uint8_t uid_ok[CLOAK_UID_LEN];  /* a BypassUID: authorised, no manager needed */
    uint8_t uid_bad[CLOAK_UID_LEN]; /* known to nobody */
};

static int scale_fixture_init(struct scale_fixture *fx) {
    memset(fx, 0, sizeof(*fx));
    char err[256] = {0};

    fx->reactor = cloak_reactor_create();
    ASSERT_TRUE(fx->reactor != NULL);
    if (fx->reactor == NULL) {
        return -1;
    }

    fx->cover.reactor = fx->reactor;
    fx->cover.fd = -1;
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->cover_listener, fx->reactor, "127.0.0.1:0",
                                         cover_on_accept, &fx->cover, err, sizeof(err)));
    fx->have_cover_listener = 1;
    int cover_port = cloak_listener_port(&fx->cover_listener);
    ASSERT_TRUE(cover_port > 0);

    uint8_t server_priv[CLOAK_X25519_KEY_LEN];
    ASSERT_EQ_INT(0, cloak_x25519_generate_keypair(server_priv, fx->server_pub));

    for (size_t i = 0; i < CLOAK_UID_LEN; i++) {
        fx->uid_ok[i] = (uint8_t)(0x10 + i);
        fx->uid_bad[i] = (uint8_t)(0x70 + i);
    }

    char priv_b64[64], uidok_b64[32];
    ASSERT_EQ_INT(0,
                  cloak_base64_encode(server_priv, CLOAK_X25519_KEY_LEN, priv_b64, sizeof(priv_b64)));
    ASSERT_EQ_INT(0, cloak_base64_encode(fx->uid_ok, CLOAK_UID_LEN, uidok_b64, sizeof(uidok_b64)));

    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"127.0.0.1:1\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"127.0.0.1:%d\","
             "\"PrivateKey\":\"%s\",\"BypassUID\":[\"%s\"]}",
             cover_port, priv_b64, uidok_b64);
    ASSERT_EQ_INT(0, cloak_server_config_parse_json(json, &fx->cfg, err, sizeof(err)));

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_server_init(&fx->srv, &fx->cfg, 16, err, sizeof(err)));
    fx->srv_ready = 1;

    ASSERT_EQ_INT(0,
                  cloak_server_registry_init(&fx->registry, fx->reactor, scale_on_broken, NULL));
    fx->registry_ready = 1;

    cloak_dispatcher_config_t dcfg;
    memset(&dcfg, 0, sizeof(dcfg));
    dcfg.reactor = fx->reactor;
    dcfg.srv = &fx->srv;
    dcfg.registry = &fx->registry;
    dcfg.session_config_template.max_on_wire_size = 16401;
    dcfg.session_config_template.stream_recv_capacity = 65536;
    dcfg.session_config_template.stream_max_pending_frames = 64;
    dcfg.session_config_template.conn_send_queue_cap = 262144;
    dcfg.session_config_template.inactivity_timeout_ms = 60000;
    dcfg.attached = scale_attached_cb;
    dcfg.attached_userdata = &fx->attached;

    ASSERT_EQ_INT(0, cloak_dispatcher_init(&fx->d, &dcfg));
    fx->d_ready = 1;

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_listener_open(&fx->front, fx->reactor, "127.0.0.1:0",
                                         cloak_dispatcher_accept, &fx->d, err, sizeof(err)));
    fx->have_front = 1;
    return 0;
}

static void scale_fixture_destroy(struct scale_fixture *fx) {
    if (fx->have_front) {
        cloak_listener_close(&fx->front);
    }
    if (fx->d_ready) {
        cloak_dispatcher_destroy(&fx->d);
    }
    if (fx->registry_ready) {
        cloak_server_registry_destroy(&fx->registry);
    }
    if (fx->srv_ready) {
        cloak_server_destroy(&fx->srv);
    }
    if (fx->have_cover_listener) {
        cloak_listener_close(&fx->cover_listener);
    }
    if (fx->cover.fd >= 0) {
        close(fx->cover.fd);
    }
    if (fx->reactor != NULL) {
        cloak_reactor_destroy(fx->reactor);
    }
}

/* One probe: writes `record` to the front door and waits, bounded by the
 * clock, for the cover site to have received all of it. Returns the
 * elapsed nanoseconds, or 0 if the redirect did not complete. */
static uint64_t scale_probe(struct scale_fixture *fx, const uint8_t *record, size_t len,
                            uint8_t *got, size_t got_cap) {
    fx->cover.len = 0;
    int client = client_connect(cloak_listener_port(&fx->front));
    ASSERT_TRUE(client >= 0);
    if (client < 0) {
        return 0;
    }
    uint64_t t0 = scale_mono_ns();
    ASSERT_TRUE(write(client, record, len) == (ssize_t)len);
    struct len_wait w = {&fx->cover, len};
    int ok = pump_until(fx->reactor, cover_has_len, &w, 300, 5);
    uint64_t t1 = scale_mono_ns();
    if (ok && got != NULL && fx->cover.len <= got_cap) {
        memcpy(got, fx->cover.buf, fx->cover.len);
    }
    close(client);
    return ok ? (t1 - t0) : 0;
}

/* THE REFUSAL AT THE CAP, HELD TO MODULE 9'S MEASURED PRECEDENT.
 *
 * Module 9 asserted that a refusal was indistinguishable from the
 * cover-site redirect and was WRONG: a reviewer measured bad-UID refusals
 * at p10 101.7-102.2 us against ordering-mismatch refusals at 114.3-119.6
 * us, a ~15 us tell created by one unthrottled fprintf(stderr) inside the
 * reactor callback. With the log line suppressed the two arms coincided
 * to within half a microsecond. The lesson recorded in
 * test_dispatcher_auth.c case 14 is that the CAUSE is what to assert --
 * it is binary, and a duration assertion in a suite that runs under ASan
 * at -j4 is flaky -- while the DURATION is what to measure.
 *
 * So both, in that order:
 *
 *  (a) ASSERTED: the two arms produce a byte-identical redirect, and the
 *      cap-refusal arm writes NOTHING to the log. The registry-full path
 *      in dispatcher.c (site A of the aborted-context callback) does more
 *      work than the bad-UID path -- it fires session_aborted and
 *      releases the user -- so "silent" is not free here, it is a
 *      property that can regress.
 *  (b) MEASURED and printed, never asserted: p10 and p50 over 120 probes
 *      per arm, interleaved so that any drift in the machine hits both
 *      arms equally.
 *
 * WHAT THE MEASUREMENT SAID, three runs in a Debug build at the commit
 * that added this, and it is NOT "they coincide":
 *
 *      bad-UID refusal   p10 108.4 / 108.5 / 109.2 us
 *      cap refusal       p10 109.0 / 109.2 / 109.7 us
 *      difference             0.5 /   0.8 /   0.5 us
 *      (p50 difference        1.0 /   1.5 /   1.0 us)
 *
 * The cap arm is consistently the slower of the two by about half a
 * microsecond at p10, in the same direction every time, and that is
 * REAL RATHER THAN NOISE: it is the extra work dispatcher.c does on that
 * path. A bad UID fails at step 5 and unwinds; a cap refusal has already
 * completed the X25519 and the AEAD open, and then fires
 * cloak_dispatch_session_aborted_cb and dispatcher_release_user on its
 * way out. Half a microsecond on a 109 us refusal is 0.5 %, against the
 * 13 % module 9 measured; separating the two arms across a network whose
 * jitter is measured in milliseconds needs on the order of a million
 * samples per arm. It is written down rather than rounded away because
 * "indistinguishable" is a claim this project has already made once and
 * been wrong about.
 *
 * The cap is reached by creating sessions directly in the registry rather
 * than by 1024 handshakes, which is both faster and unambiguous about
 * what is being tested -- the same choice test_proxy_teardown.c case 8
 * makes and for the same reason. */
static void test_refusal_at_the_cap_is_indistinguishable(void) {
    struct scale_fixture fx;
    ASSERT_EQ_INT(0, scale_fixture_init(&fx));

    cloak_obfuscator_t obfs;
    scale_make_obfuscator(&obfs);
    cloak_session_config_t scfg;
    scale_base_config(&scfg, &obfs);

    uint8_t filler[CLOAK_UID_LEN];
    scale_uid(filler, 0x4242);
    for (unsigned i = 0; i < CLOAK_REGISTRY_MAX_SESSIONS; i++) {
        int created = 0;
        ASSERT_TRUE(cloak_server_registry_get_or_create(&fx.registry, filler, 30000u + i, &scfg,
                                                        &created) != NULL);
    }
    ASSERT_EQ_INT(CLOAK_REGISTRY_MAX_SESSIONS, (int)cloak_server_registry_count(&fx.registry));

    int64_t now = (int64_t)time(NULL);
    uint8_t rec_bad[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t rec_full[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    uint8_t shared[CLOAK_AEAD_KEY_LEN];
    size_t len_bad = build_client_record(fx.server_pub, fx.uid_bad, "ss",
                                         (uint8_t)CLOAK_AEAD_AES_256_GCM, now, 4001, 0, rec_bad,
                                         sizeof(rec_bad), shared);
    ASSERT_TRUE(len_bad > 0);

    /* (a) THE BYTES, and the log. */
    uint8_t got_bad[8192], got_full[8192];
    ASSERT_TRUE(scale_probe(&fx, rec_bad, len_bad, got_bad, sizeof(got_bad)) > 0);
    ASSERT_EQ_INT((int)len_bad, (int)fx.cover.len);
    ASSERT_MEM_EQ(got_bad, rec_bad, len_bad);

    size_t len_full = build_client_record(fx.server_pub, fx.uid_ok, "ss",
                                          (uint8_t)CLOAK_AEAD_AES_256_GCM, now, 4002, 0, rec_full,
                                          sizeof(rec_full), shared);
    ASSERT_TRUE(len_full > 0);

    char *logbuf = NULL;
    size_t loglen = 0;
    FILE *logmem = open_memstream(&logbuf, &loglen);
    ASSERT_TRUE(logmem != NULL);
    cloak_log_set_stream(logmem);
    ASSERT_TRUE(scale_probe(&fx, rec_full, len_full, got_full, sizeof(got_full)) > 0);
    cloak_log_set_stream(NULL);
    fflush(logmem);
    fclose(logmem);
    ASSERT_EQ_INT(0, (int)loglen);
    free(logbuf);

    ASSERT_EQ_INT((int)len_full, (int)fx.cover.len);
    ASSERT_MEM_EQ(got_full, rec_full, len_full);

    /* Nothing was created and nothing attached: the refusal really was a
     * refusal, not a session that happened to be redirected as well. */
    ASSERT_EQ_INT(0, fx.attached.calls);
    ASSERT_EQ_INT(CLOAK_REGISTRY_MAX_SESSIONS, (int)cloak_server_registry_count(&fx.registry));

    /* (b) THE MEASUREMENT. */
#define SCALE_PROBES 120
    static uint64_t t_bad[SCALE_PROBES];
    static uint64_t t_full[SCALE_PROBES];
    int n_bad = 0, n_full = 0;
    for (int i = 0; i < SCALE_PROBES; i++) {
        /* BOTH RECORDS ARE REBUILT EVERY ITERATION. A Cloak ClientHello
         * is randomly padded, so two records built once and reused
         * differ in length by a few tens of bytes for every one of the
         * 120 probes -- a systematic difference between the arms, which
         * is exactly the thing a timing comparison must not have.
         * Rebuilding makes both arms sample the same length
         * distribution; it happens outside the timed region. */
        len_bad = build_client_record(fx.server_pub, fx.uid_bad, "ss",
                                      (uint8_t)CLOAK_AEAD_AES_256_GCM, now, 5000u + (uint32_t)i, 0,
                                      rec_bad, sizeof(rec_bad), shared);
        len_full = build_client_record(fx.server_pub, fx.uid_ok, "ss",
                                       (uint8_t)CLOAK_AEAD_AES_256_GCM, now, 6000u + (uint32_t)i, 0,
                                       rec_full, sizeof(rec_full), shared);
        ASSERT_TRUE(len_bad > 0 && len_full > 0);
        uint64_t a = scale_probe(&fx, rec_bad, len_bad, NULL, 0);
        if (a > 0) {
            t_bad[n_bad++] = a;
        }
        uint64_t b = scale_probe(&fx, rec_full, len_full, NULL, 0);
        if (b > 0) {
            t_full[n_full++] = b;
        }
    }
    ASSERT_TRUE(n_bad > SCALE_PROBES / 2);
    ASSERT_TRUE(n_full > SCALE_PROBES / 2);
    qsort(t_bad, (size_t)n_bad, sizeof(t_bad[0]), scale_cmp_u64);
    qsort(t_full, (size_t)n_full, sizeof(t_full[0]), scale_cmp_u64);
    printf("case 3: bad-UID refusal   p10 %.1f us, p50 %.1f us (n=%d)\n",
           (double)t_bad[n_bad / 10] / 1000.0, (double)t_bad[n_bad / 2] / 1000.0, n_bad);
    printf("case 3: cap refusal       p10 %.1f us, p50 %.1f us (n=%d)\n",
           (double)t_full[n_full / 10] / 1000.0, (double)t_full[n_full / 2] / 1000.0, n_full);
    printf("case 3: p10 difference    %.1f us (module 9 measured a 15 us tell from one log line)\n",
           ((double)t_full[n_full / 10] - (double)t_bad[n_bad / 10]) / 1000.0);
#undef SCALE_PROBES

    scale_fixture_destroy(&fx);
}

/* ------------------------------------------------------------------ */
/* 4. The cap's arithmetic, as an assertion                             */
/* ------------------------------------------------------------------ */

/* THE NUMBER IS SPELLED OUT, deliberately, in the same discipline
 * test_server_stack.c case 11 uses for the replay capacity: asserting
 * against the symbol would derive both sides of the comparison from the
 * same constant and let it be changed by any factor without failing.
 *
 * The second assertion is the derivation from cloak/registry.h written as
 * arithmetic: 4 connections per session times the default per-connection
 * send-queue cap times the session cap is the 1 GiB backlog budget the
 * number was chosen to bound. Change the cap, or change the queue cap,
 * and this fails -- which is the point. The budget is the ONE input in
 * that comment not read off another constant, so it is the one that has
 * to be restated here to be checkable at all. */
static void test_the_cap_still_means_what_it_says(void) {
    ASSERT_EQ_INT(1024, CLOAK_REGISTRY_MAX_SESSIONS);

    const unsigned long long conns_per_session = 4;
    const unsigned long long budget =
        (unsigned long long)CLOAK_REGISTRY_MAX_SESSIONS * conns_per_session *
        (unsigned long long)CLOAK_SERVER_STACK_DEFAULT_CONN_SEND_QUEUE_CAP;
    ASSERT_TRUE(budget == 1024ull * 1024ull * 1024ull);

    /* The active-user table is derived from the session cap rather than
     * picked separately (cloak/userpanel.h says why), so a change to one
     * that forgot the other shows up here. */
    ASSERT_EQ_INT(CLOAK_REGISTRY_MAX_SESSIONS, CLOAK_USERPANEL_MAX_ACTIVE_USERS);

    /* Load factors, so that a future change to the cap which leaves the
     * bucket counts behind is caught by arithmetic rather than by case
     * 2's bracket quietly drifting toward its ceiling. */
    ASSERT_TRUE(CLOAK_REGISTRY_KEY_BUCKETS >= 2 * CLOAK_REGISTRY_MAX_SESSIONS);
    ASSERT_TRUE(CLOAK_REGISTRY_UID_BUCKETS >= CLOAK_REGISTRY_MAX_SESSIONS);
}

/* ------------------------------------------------------------------ */
/* 5. The two chains agree, at full occupancy, through a teardown       */
/* ------------------------------------------------------------------ */

/* The registry is now reached by two different chains through the same
 * entries, and cloak/registry.h's answer to "a second structure can
 * disagree with the table" is that they ARE the table. This is the test
 * that keeps that honest: an uneven distribution of sessions across uids,
 * filled to the cap, then partly closed, with every uid's count checked
 * against what this test knows it created and the total checked against
 * the registry's own count.
 *
 * A key-chain unlink that forgot the uid chain, or a uid chain that
 * relinked an entry into the wrong bucket, leaves cloak_server_registry_-
 * find working perfectly and fails here. */
static void test_uid_and_key_chains_agree(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    cloak_server_registry_t reg;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&reg, r, scale_on_broken, NULL));

    cloak_obfuscator_t obfs;
    scale_make_obfuscator(&obfs);
    cloak_session_config_t cfg;
    scale_base_config(&cfg, &obfs);

    /* 1 + 2 + 3 + ... sessions per uid until the cap is reached: uid u
     * gets (u % 7) + 1 of them. */
    static unsigned per_uid[CLOAK_REGISTRY_MAX_SESSIONS];
    unsigned uids = 0, total = 0;
    while (total < CLOAK_REGISTRY_MAX_SESSIONS) {
        unsigned want = (uids % 7u) + 1u;
        if (total + want > CLOAK_REGISTRY_MAX_SESSIONS) {
            want = CLOAK_REGISTRY_MAX_SESSIONS - total;
        }
        uint8_t uid[CLOAK_UID_LEN];
        scale_uid(uid, uids);
        for (unsigned k = 0; k < want; k++) {
            int created = 0;
            ASSERT_TRUE(cloak_server_registry_get_or_create(&reg, uid, 500u + k, &cfg, &created) !=
                        NULL);
            ASSERT_EQ_INT(1, created);
        }
        per_uid[uids] = want;
        total += want;
        uids++;
    }
    ASSERT_EQ_INT(CLOAK_REGISTRY_MAX_SESSIONS, (int)total);
    ASSERT_EQ_INT(CLOAK_REGISTRY_MAX_SESSIONS, (int)cloak_server_registry_count(&reg));

    unsigned sum = 0;
    for (unsigned u = 0; u < uids; u++) {
        uint8_t uid[CLOAK_UID_LEN];
        scale_uid(uid, u);
        ASSERT_EQ_INT((int)per_uid[u], (int)cloak_server_registry_count_for_uid(&reg, uid));
        sum += per_uid[u];
    }
    ASSERT_EQ_INT((int)sum, (int)cloak_server_registry_count(&reg));

    /* Close the first session of every third uid through
     * cloak_server_registry_close (the key chain), and assert the UID
     * chain noticed. */
    unsigned closed = 0;
    for (unsigned u = 0; u < uids; u += 3) {
        uint8_t uid[CLOAK_UID_LEN];
        scale_uid(uid, u);
        cloak_server_registry_close(&reg, uid, 500u);
        per_uid[u]--;
        closed++;
        ASSERT_EQ_INT((int)per_uid[u], (int)cloak_server_registry_count_for_uid(&reg, uid));
        ASSERT_TRUE(cloak_server_registry_find(&reg, uid, 500u) == NULL);
    }
    ASSERT_EQ_INT((int)(total - closed), (int)cloak_server_registry_count(&reg));

    /* And close whole uids through the UID chain, asserting the key chain
     * noticed. */
    for (unsigned u = 1; u < uids; u += 5) {
        uint8_t uid[CLOAK_UID_LEN];
        scale_uid(uid, u);
        size_t n = cloak_server_registry_close_all_for_uid(&reg, uid, NULL, NULL);
        ASSERT_EQ_INT((int)per_uid[u], (int)n);
        ASSERT_EQ_INT(0, (int)cloak_server_registry_count_for_uid(&reg, uid));
        for (unsigned k = 0; k < per_uid[u]; k++) {
            ASSERT_TRUE(cloak_server_registry_find(&reg, uid, 500u + k) == NULL);
        }
        closed += per_uid[u];
        per_uid[u] = 0;
    }
    ASSERT_EQ_INT((int)(total - closed), (int)cloak_server_registry_count(&reg));

    /* The freed budget is real: the table takes new sessions again,
     * exactly as many as were closed and not one more. */
    uint8_t fresh[CLOAK_UID_LEN];
    scale_uid(fresh, 0xABCDu);
    for (unsigned k = 0; k < closed; k++) {
        int created = 0;
        ASSERT_TRUE(cloak_server_registry_get_or_create(&reg, fresh, 90000u + k, &cfg, &created) !=
                    NULL);
    }
    ASSERT_EQ_INT(CLOAK_REGISTRY_MAX_SESSIONS, (int)cloak_server_registry_count(&reg));
    int created = 0;
    ASSERT_TRUE(cloak_server_registry_get_or_create(&reg, fresh, 99999u, &cfg, &created) == NULL);

    cloak_server_registry_destroy(&reg);
    cloak_reactor_destroy(r);
}

/* ------------------------------------------------------------------ */
/* 6. The hash really is SipHash-2-4                                    */
/* ------------------------------------------------------------------ */

/* libcloak-server/src/hash_internal.h claims to be SipHash-2-4 and claims
 * to agree with replay_cache.c's specialised copy. The first claim is
 * checkable against the reference vector from the SipHash paper (key
 * 00..0f, message 00..0e), and this is the test the header cites.
 *
 * WHY IT MATTERS THAT IT IS THE REAL THING: a mixer that merely looked
 * like a hash could still distribute a test's tidy inputs evenly and pass
 * case 2, while leaving an attacker with a bucket function they can
 * evaluate offline once they learn its shape. The keying argument in
 * cloak/registry.h rests on this being a PRF, so the primitive is pinned
 * rather than trusted. */
static void test_hash_is_siphash24(void) {
    uint8_t k[16], m[16];
    for (int i = 0; i < 16; i++) {
        k[i] = (uint8_t)i;
        m[i] = (uint8_t)i;
    }
    ASSERT_TRUE(cloak_siphash24(k, m, 15) == 0xa129ca6149be45e5ull);

    /* And it is actually keyed: one bit of key changes the answer. */
    k[0] ^= 1;
    ASSERT_TRUE(cloak_siphash24(k, m, 15) != 0xa129ca6149be45e5ull);

    /* AND THE REGISTRY REALLY DRAWS ONE. This is the assertion that kills
     * the mutation the rest of this file sleeps through: replacing
     * cloak_random_bytes(reg->hash_key, ...) in cloak_server_registry_init
     * with a memset to zero leaves every functional test in this tree
     * green -- a constant-keyed hash distributes tidy test inputs exactly
     * as well as a random one -- while handing an attacker a bucket
     * function they can evaluate offline, which is the whole of the
     * security argument at CLOAK_REGISTRY_KEY_BUCKETS. It is the same
     * defect cloak/replay_cache.h records being found in this tree
     * before, in the same shape: a "keyed" hash whose key was a
     * compile-time constant.
     *
     * Two registries, two keys, and they differ. A false failure needs a
     * 128-bit collision. */
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    cloak_server_registry_t a, b;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&a, r, scale_on_broken, NULL));
    ASSERT_EQ_INT(0, cloak_server_registry_init(&b, r, scale_on_broken, NULL));
    ASSERT_MEM_NE(a.hash_key, b.hash_key, sizeof(a.hash_key));

    /* Not all-zero either, which is what a memset mutation would leave
     * and what two registries sharing one constant key would also pass
     * the assertion above with if the constant were per-call. */
    uint8_t zero[16];
    memset(zero, 0, sizeof(zero));
    ASSERT_MEM_NE(a.hash_key, zero, sizeof(zero));

    cloak_server_registry_destroy(&a);
    cloak_server_registry_destroy(&b);
    cloak_reactor_destroy(r);
}

/* ------------------------------------------------------------------ */
/* 7. The panel's index agrees with the panel                           */
/* ------------------------------------------------------------------ */

static void scale_panel_on_registry_broken(cloak_server_registry_t *reg, cloak_session_t *sesh,
                                           const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                                           void *userdata) {
    (void)sesh;
    (void)session_id;
    cloak_userpanel_registry_broken(reg, sesh, uid, session_id, userdata);
}

static int64_t scale_fake_now(void *userdata) {
    return *(const int64_t *)userdata;
}

/* cloak_userpanel_t's active-user index IS a second structure beside the
 * `active` array -- unlike the registry's chains, which replaced their
 * array outright -- so the disagreement cloak/userpanel.h's old comment
 * warned about is a real possibility there and is answered by measurement
 * rather than by argument.
 *
 * The panel's internals are private, so the cross-check is against a
 * model this test maintains itself: after a workload of activations and
 * terminations, every UID must be found if and only if this test believes
 * it is active, and cloak_userpanel_active_count must equal the number
 * this test believes is active. A chain that lost an entry, or an
 * n_active that drifted from the slots, fails one or the other.
 *
 * 300 users rather than the full 1024: the cost here is a real SQLite row
 * per user and a real authenticate per activation, and 300 is already
 * more than the OLD session cap -- which is the number this whole commit
 * is about. */
static void test_panel_index_agrees_with_the_panel(void) {
    char path[512];
    const char *dir = getenv("TMPDIR");
    if (dir == NULL || *dir == '\0') {
        dir = "/tmp";
    }
    snprintf(path, sizeof(path), "%s/cloak_scale_%ld.db", dir, (long)getpid());
    unlink(path);

    int64_t now = 1600000000;
    char err[256] = {0};
    cloak_usermanager_t *m = NULL;
    ASSERT_EQ_INT(0, cloak_usermanager_open(&m, path, scale_fake_now, &now, err, sizeof(err)));

#define SCALE_USERS 300
    for (unsigned i = 0; i < SCALE_USERS; i++) {
        cloak_user_info_t u;
        memset(&u, 0, sizeof(u));
        scale_uid(u.uid, i);
        u.sessions_cap = 4;
        u.up_credit = 1000000;
        u.down_credit = 1000000;
        u.expiry_time = now + 100000;
        ASSERT_EQ_INT(0, cloak_usermanager_write(m, &u, CLOAK_USER_FIELD_ALL));
    }

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    cloak_server_registry_t reg;
    cloak_userpanel_t *panel = NULL;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&reg, r, scale_panel_on_registry_broken, NULL));

    cloak_userpanel_config_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.manager = m;
    pcfg.registry = &reg;
    pcfg.reactor = r;
    pcfg.upload_interval_ms = 600000; /* nothing here wants a tick */
    pcfg.now_fn = scale_fake_now;
    pcfg.now_userdata = &now;
    pcfg.no_relays = 1;
    ASSERT_EQ_INT(0, cloak_userpanel_open(&panel, &pcfg));

    static int active[SCALE_USERS];
    unsigned n_active = 0;
    for (unsigned i = 0; i < SCALE_USERS; i++) {
        uint8_t uid[CLOAK_UID_LEN];
        scale_uid(uid, i);
        cloak_userpanel_user_t *u = NULL;
        ASSERT_EQ_INT(0, cloak_userpanel_get_user(panel, uid, &u));
        ASSERT_TRUE(u != NULL);
        active[i] = 1;
        n_active++;
    }
    ASSERT_EQ_INT((int)n_active, (int)cloak_userpanel_active_count(panel));

    /* Terminate every third, then re-activate every seventh of those, so
     * that entries are removed from and re-added to the chains in an
     * order that is not the order they were created in. */
    for (unsigned i = 0; i < SCALE_USERS; i += 3) {
        uint8_t uid[CLOAK_UID_LEN];
        scale_uid(uid, i);
        cloak_userpanel_user_t *u = cloak_userpanel_find(panel, uid);
        ASSERT_TRUE(u != NULL);
        cloak_userpanel_terminate(panel, u, "scale test");
        active[i] = 0;
        n_active--;
    }
    ASSERT_EQ_INT((int)n_active, (int)cloak_userpanel_active_count(panel));

    for (unsigned i = 0; i < SCALE_USERS; i += 21) {
        uint8_t uid[CLOAK_UID_LEN];
        scale_uid(uid, i);
        cloak_userpanel_user_t *u = NULL;
        ASSERT_EQ_INT(0, cloak_userpanel_get_user(panel, uid, &u));
        ASSERT_TRUE(u != NULL);
        if (!active[i]) {
            active[i] = 1;
            n_active++;
        }
    }

    /* THE CROSS-CHECK. */
    unsigned found = 0;
    for (unsigned i = 0; i < SCALE_USERS; i++) {
        uint8_t uid[CLOAK_UID_LEN];
        scale_uid(uid, i);
        cloak_userpanel_user_t *u = cloak_userpanel_find(panel, uid);
        ASSERT_EQ_INT(active[i], u != NULL ? 1 : 0);
        if (u != NULL) {
            ASSERT_MEM_EQ(u->uid, uid, CLOAK_UID_LEN); /* the RIGHT user, not just a user */
            found++;
        }
    }
    ASSERT_EQ_INT((int)n_active, (int)found);
    ASSERT_EQ_INT((int)n_active, (int)cloak_userpanel_active_count(panel));
#undef SCALE_USERS

    cloak_userpanel_close(panel);
    cloak_server_registry_destroy(&reg);
    cloak_reactor_destroy(r);
    cloak_usermanager_close(m);
    unlink(path);
}

TEST_MAIN_BEGIN()
    test_sessions_to_the_cap_all_establish();
    test_lookup_cost_is_bounded_at_the_cap();
    test_lookup_cost_is_bounded_when_one_user_holds_many_sessions();
    test_refusal_at_the_cap_is_indistinguishable();
    test_the_cap_still_means_what_it_says();
    test_uid_and_key_chains_agree();
    test_hash_is_siphash24();
    test_panel_index_agrees_with_the_panel();
TEST_MAIN_END()
