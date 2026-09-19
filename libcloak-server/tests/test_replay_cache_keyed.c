/* THE REPLAY CACHE AS AN ADVERSARY SEES IT.
 *
 * test_replay_cache.c is the functional suite: insert, replay, age out,
 * backwards clock, zero capacity. Every one of its assertions passed on
 * the shipped code that case 1 below breaks, which is the whole reason
 * this file is separate -- the defect was not a wrong answer to any
 * question that suite asked, it was a question nobody asked.
 *
 * THE DEFECT, as shipped up to the commit that added this file:
 *
 *   - the slot was fnv1a(key, 32) % capacity -- an UNKEYED,
 *     non-cryptographic hash over 32 bytes chosen entirely by whoever
 *     sent the ClientHello;
 *   - capacity was 1024;
 *   - and the cache is written BEFORE authentication, deliberately
 *     (libcloak-server/src/dispatcher.c step 3, "against the RAW,
 *     not-yet-authenticated ch.random -- BEFORE any decryption"; Go
 *     does the same at internal/server/auth.go:76, before
 *     decryptClientInfo at :81). That ordering is CORRECT and is not
 *     what changed here.
 *
 * Put together: an UNAUTHENTICATED prober that has captured one real
 * handshake could compute, offline and in about 1024 trials of a hash
 * it runs itself, a second 32-byte string landing in that handshake's
 * slot -- and evict the victim with ONE packet. It could then replay
 * the captured ClientHello and have the server accept it, which is
 * precisely how an active prober confirms a host is a circumvention
 * proxy rather than a web server.
 *
 * The header's own argument is what hid this. It reasoned that flooding
 * collisions "only weakens (never strengthens) an attacker's ability to
 * replay a key they don't already possess a valid, not-yet-expired
 * ciphertext for". A censor DOES possess one: it watched a real client
 * connect. That carve-out excluded exactly the adversary this port
 * exists to defeat, so the sentence is gone from replay_cache.h.
 *
 * Case 4 is the one that catches a DECORATIVE fix. This project has
 * twice shipped a "random" value that was not one (module 8's
 * hardcoded key pair, module 9's recoverable connection pick), and a
 * keyed hash whose key is a compile-time constant would pass cases 1,
 * 2 and 3 and be worth nothing.
 */

#include "cloak/registry.h"
#include "cloak/replay_cache.h"
#include "cloak/server_auth.h"
#include "cloak/server_stack.h"
#include "test_framework.h"

#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* The attacker's offline model of the slot function                    */
/* ------------------------------------------------------------------ */

/* replay_cache.c's hash EXACTLY AS SHIPPED BEFORE THIS FIX, copied here
 * on purpose. This is not production code duplicated into a test to be
 * refactored away later: it is the ADVERSARY'S MODEL of the server, and
 * the entire content of the fix is that the model stops predicting. It
 * must never be updated to follow replay_cache.c, because an attacker
 * cannot update it -- what it is now missing is a secret, not a
 * constant. */
static uint64_t attacker_fnv1a(const uint8_t *data, size_t len) {
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* A deterministic 32-byte key from a counter. Deterministic on purpose:
 * every number this file reports -- trial counts, survivor counts --
 * has to mean the same thing on the next run and on the next machine,
 * and the randomness whose absence would matter (the cache's own hash
 * key) comes from the cache, not from here. */
static void fill_key(uint8_t key[32], uint64_t seed) {
    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)((seed >> (8 * (i % 8))) ^ (uint64_t)(i * 31 + 7));
    }
}

static size_t occupied_slots(const cloak_replay_cache_t *cache) {
    size_t n = 0;
    for (size_t i = 0; i < cache->capacity; i++) {
        if (cache->slots[i].inserted_at != 0) {
            n++;
        }
    }
    return n;
}

/* The slot a cache is really using for the one entry it holds. Every
 * insert sets inserted_at to a non-zero timestamp, so on a freshly
 * initialised cache holding exactly one entry the occupied slot is
 * unique, and finding it by scanning needs no access to the hash at all
 * -- which is what lets case 4 observe the slot index without the
 * implementation having to expose it. Returns (size_t)-1 if the number
 * of occupied slots is not exactly one, so a scan that silently found
 * nothing cannot be mistaken for slot 0. */
static size_t sole_occupied_slot(const cloak_replay_cache_t *cache) {
    size_t found = (size_t)-1;
    size_t n = 0;
    for (size_t i = 0; i < cache->capacity; i++) {
        if (cache->slots[i].inserted_at != 0) {
            found = i;
            n++;
        }
    }
    return (n == 1) ? found : (size_t)-1;
}

/* ------------------------------------------------------------------ */
/* The shipped capacity and the arithmetic behind it                    */
/* ------------------------------------------------------------------ */

/* Spelled as a literal exactly once, for the reason test_server_stack.c's
 * own capacity test gives: an assertion that derived both sides from
 * CLOAK_SERVER_STACK_DEFAULT_REPLAY_CACHE_CAPACITY would let the
 * constant be divided by 512 without failing. Everything below derives
 * its arithmetic from the symbol so the numbers move with it; this one
 * line is what stops it moving DOWN. */
#define SHIPPED_CAPACITY_FLOOR ((size_t)2097152)

#define SHIPPED_CAPACITY CLOAK_SERVER_STACK_DEFAULT_REPLAY_CACHE_CAPACITY
#define OLD_CAPACITY ((size_t)1024)

/* The window over which a captured ciphertext is replayable AT ALL, and
 * therefore the only window over which this cache has to retain an
 * entry to be doing its job: twice the timestamp tolerance, because a
 * client's clock may legitimately run up to the tolerance ahead of the
 * server's. cloak/server_auth.h:14-22 makes exactly this argument to
 * justify the 12-hour age limit; it is the same argument here, used for
 * the other side of the same tradeoff. Outside this window a replay is
 * refused by cloak_server_auth_decrypt's timestamp check whatever the
 * cache says. */
#define REPLAY_WINDOW_SECONDS ((size_t)(2 * CLOAK_SERVER_AUTH_TIMESTAMP_TOLERANCE_SECONDS))

/* The handshake rate the table is sized for, and where it comes from.
 * CLOAK_REGISTRY_MAX_SESSIONS sessions, each with the four connections
 * a multi-connection client opens, is the server's CONCURRENT
 * connection ceiling -- and that product, back when the cap was 256,
 * was 1024, which WAS the old capacity: the defect in one line, a
 * number that counted concurrency and forgot time. Sizing assumption on
 * top of it: complete turnover of those connections every 120 s, a
 * mobile/NAT reconnect interval. server_stack.h carries the same
 * derivation; both are written out so that a change to one shows up as
 * a failure of the other -- WHICH IS WHAT HAPPENED. Raising
 * CLOAK_REGISTRY_MAX_SESSIONS from 256 to 1024 quadrupled this rate and
 * broke the assertion below against the old 2^19 capacity; the shipped
 * capacity moved to 2^21 in the same commit, and the two literals in
 * this file moved with the two constants they are derived from. */
#define SIZED_CONCURRENT_CONNECTIONS ((size_t)CLOAK_REGISTRY_MAX_SESSIONS * 4)
#define SIZED_TURNOVER_SECONDS ((size_t)120)
#define SIZED_INSERTS_PER_REPLAY_WINDOW \
    (SIZED_CONCURRENT_CONNECTIONS * (REPLAY_WINDOW_SECONDS / SIZED_TURNOVER_SECONDS))

static void test_shipped_capacity_meets_its_floor(void) {
    ASSERT_TRUE(SHIPPED_CAPACITY >= SHIPPED_CAPACITY_FLOOR);
    /* 360 s / 120 s = 3 turnovers, so 3072 inserts in the window that
     * matters. If the tolerance or the turnover assumption ever changes
     * so that this stops being a whole number, the sizing comment in
     * server_stack.h is stale and this is where it shows. */
    ASSERT_EQ_INT(360, (int)REPLAY_WINDOW_SECONDS);
    ASSERT_EQ_INT(12288, (int)SIZED_INSERTS_PER_REPLAY_WINDOW);
    /* 1 - (1 - 1/C)^N >= 99 % survival needs C >= N / 0.01005 =
     * 1,222,686. 2^21 = 2,097,152 clears it; the check is written as the integer
     * inequality C * 1005 >= N * 100000 so it has no floating point in
     * it. */
    ASSERT_TRUE(SHIPPED_CAPACITY * 1005ULL >= (unsigned long long)SIZED_INSERTS_PER_REPLAY_WINDOW * 100000ULL);
}

/* ------------------------------------------------------------------ */
/* Case 1: TARGETED EVICTION -- the actual attack                       */
/* ------------------------------------------------------------------ */

/* Searches for a 32-byte string other than `victim` that the ATTACKER'S
 * model puts in the victim's slot. Returns the number of trials it
 * took, or 0 if the bound was reached. Expected cost is one slot's
 * worth of trials -- about `capacity` of them -- and that number is
 * what makes this an attack rather than a curiosity: it is offline,
 * needs nothing from the server, and costs microseconds. */
static unsigned long find_colliding_key(uint8_t out[32], const uint8_t victim[32], size_t capacity,
                                        unsigned long max_trials) {
    uint64_t target = attacker_fnv1a(victim, 32) % (uint64_t)capacity;
    for (unsigned long t = 1; t <= max_trials; t++) {
        fill_key(out, 0xA11CE000ULL + t);
        if (memcmp(out, victim, 32) == 0) {
            continue;
        }
        if (attacker_fnv1a(out, 32) % (uint64_t)capacity == target) {
            return t;
        }
    }
    return 0;
}

/* One packet, and the victim's replay protection is gone. Run at TWO
 * capacities on purpose: at the old 1024 and at the shipped one. The
 * second is what proves that RAISING THE CAPACITY ALONE WOULD NOT HAVE
 * FIXED THIS -- the offline search is linear in the capacity, so a
 * 512-fold bigger table costs the attacker half a million hash
 * evaluations, which is still microseconds. Only the key makes the
 * search impossible. */
static void targeted_eviction_survives(size_t capacity, const char *label) {
    cloak_replay_cache_t cache;
    ASSERT_EQ_INT(0, cloak_replay_cache_init(&cache, capacity));

    uint8_t victim[32];
    fill_key(victim, 0x5EC0DE01ULL);

    /* The captured handshake, seen once. */
    ASSERT_EQ_INT(0, cloak_replay_cache_check_and_insert(
                         &cache, victim, 1000000, CLOAK_SERVER_AUTH_REPLAY_CACHE_AGE_LIMIT_SECONDS));

    uint8_t collider[32];
    unsigned long trials = find_colliding_key(collider, victim, capacity, 64UL * capacity);
    /* The search itself must succeed, or the case is vacuous -- a
     * "victim survives" that only held because the attacker never found
     * a key is not evidence of anything. */
    ASSERT_TRUE(trials != 0);
    ASSERT_TRUE(trials <= 16UL * capacity);
    printf("case 1 [%s]: offline collision found in %lu trials (capacity %zu)\n", label, trials,
           capacity);

    /* ONE packet from an unauthenticated prober. */
    ASSERT_EQ_INT(0, cloak_replay_cache_check_and_insert(
                         &cache, collider, 1000001,
                         CLOAK_SERVER_AUTH_REPLAY_CACHE_AGE_LIMIT_SECONDS));

    /* THE ASSERTION. The captured handshake is replayed one second
     * later, well inside the timestamp tolerance, and must still be
     * recognised. Before the fix this returned 0 -- the victim had been
     * evicted and the replay was accepted as novel. */
    ASSERT_EQ_INT(1, cloak_replay_cache_check_and_insert(
                         &cache, victim, 1000002,
                         CLOAK_SERVER_AUTH_REPLAY_CACHE_AGE_LIMIT_SECONDS));

    cloak_replay_cache_destroy(&cache);
}

static void test_case1_targeted_eviction(void) {
    targeted_eviction_survives(OLD_CAPACITY, "old capacity 1024");
    targeted_eviction_survives(SHIPPED_CAPACITY, "shipped capacity");
}

/* ------------------------------------------------------------------ */
/* Case 2: whole-table eviction, and what it now costs                  */
/* ------------------------------------------------------------------ */

/* WITH THE ARITHMETIC, AND MEASURED RATHER THAN ASSERTED.
 *
 * Blind flooding is the only eviction left once the hash is keyed. A
 * flood of N random inserts evicts a chosen victim with probability
 * 1 - (1 - 1/C)^N, so the N that reaches even a COIN FLIP is
 * ln(2) * C = 0.693 * 2,097,152 = 1,453,635 handshakes -- and every one
 * of them must arrive inside REPLAY_WINDOW_SECONDS, because outside it the
 * captured ciphertext is refused on its timestamp whatever this cache
 * says. That is 4037 full handshakes per second, sustained, against one
 * server, to reach a 50 % chance -- versus ONE packet before the fix.
 * (These three numbers are 4x what they were when this case was written,
 * for the reason SIZED_CONCURRENT_CONNECTIONS above now gives: the
 * session cap moved and the capacity moved with it. The case itself is
 * unchanged -- it derives everything from SHIPPED_CAPACITY.)
 *
 * HONEST ABOUT WHAT THIS IS NOT. 4037 handshakes/s is not beyond a
 * state-level adversary's bandwidth; the brief's word for the result
 * was "infeasible" and that is not what was measured. What IS measured
 * is a cost ratio of 1.5e6, and a change of KIND: the pre-fix attack
 * was one silent packet indistinguishable from a client connecting, and
 * the post-fix attack is a sustained flood that is a denial of service
 * in its own right and looks like one. The claim here is the ratio and
 * the change of kind, not impossibility.
 *
 * The law 1 - (1 - 1/C)^N is what the arithmetic rests on, so it is
 * measured rather than trusted: 32 independent trials, each planting a
 * victim and flooding with exactly ln(2) * C inserts, must evict the
 * victim somewhere near half the time. The bracket [4, 28] out of 32 is
 * wide on purpose -- under the binomial null it fires with probability
 * about 1.9e-5 -- and it still bites hard on the failure that matters:
 * an unkeyed or degenerate hash would evict on a targeted insert every
 * time (32), and a hash that ignored the input would never collide (0).
 */
static void test_case2_whole_table_flood_cost(void) {
    const size_t c = SHIPPED_CAPACITY;
    /* ln(2) in integer arithmetic: 693147 / 1000000. */
    const size_t flood_for_half = (size_t)(((unsigned long long)c * 693147ULL) / 1000000ULL);
    const size_t rate_per_second = flood_for_half / REPLAY_WINDOW_SECONDS;

    printf("case 2: evicting one chosen entry at 50%% needs %zu inserts inside the %zu s "
           "replay window = %zu handshakes/s (was: 1 packet)\n",
           flood_for_half, REPLAY_WINDOW_SECONDS, rate_per_second);

    ASSERT_TRUE(flood_for_half >= 300000);
    ASSERT_TRUE(rate_per_second >= 800);

    const int trials = 32;
    int evicted = 0;
    for (int t = 0; t < trials; t++) {
        cloak_replay_cache_t cache;
        ASSERT_EQ_INT(0, cloak_replay_cache_init(&cache, c));
        uint8_t victim[32];
        fill_key(victim, 0xF100D000ULL + (uint64_t)t);
        ASSERT_EQ_INT(0, cloak_replay_cache_check_and_insert(
                             &cache, victim, 2000000,
                             CLOAK_SERVER_AUTH_REPLAY_CACHE_AGE_LIMIT_SECONDS));
        for (size_t i = 0; i < flood_for_half; i++) {
            uint8_t k[32];
            fill_key(k, 0xBEEF000000000000ULL + (uint64_t)t * 1000000007ULL + i);
            (void)cloak_replay_cache_check_and_insert(
                &cache, k, 2000001, CLOAK_SERVER_AUTH_REPLAY_CACHE_AGE_LIMIT_SECONDS);
        }
        /* A survivor answers "replay"; an evicted victim answers
         * "novel". Read once, at the end of the trial, so the reading
         * cannot perturb the next one. */
        int still_there = cloak_replay_cache_check_and_insert(
            &cache, victim, 2000002, CLOAK_SERVER_AUTH_REPLAY_CACHE_AGE_LIMIT_SECONDS);
        if (still_there == 0) {
            evicted++;
        }
        cloak_replay_cache_destroy(&cache);
    }
    printf("case 2: ln(2)*C inserts evicted the victim in %d of %d trials (expected ~16)\n",
           evicted, trials);
    ASSERT_TRUE(evicted >= 4 && evicted <= 28);
}

/* ------------------------------------------------------------------ */
/* Case 3: steady state -- a MEASURED bracket                           */
/* ------------------------------------------------------------------ */

/* The claim under test is that a server busier than the old capacity
 * allowed no longer loses entries it still needs. Measured as a
 * bracket, old against new, over the same insert count.
 *
 * Survivors are counted by scanning the table for occupied slots rather
 * than by re-querying each key: every insert here is ours and every
 * insert sets a non-zero inserted_at, so the occupied-slot count IS the
 * number of entries that were not evicted -- and, unlike re-querying,
 * counting it does not itself insert anything and cannot perturb what
 * it is measuring. */
static size_t survivors_after(size_t capacity, size_t inserts, uint64_t salt) {
    cloak_replay_cache_t cache;
    if (cloak_replay_cache_init(&cache, capacity) != 0) {
        return 0;
    }
    for (size_t i = 0; i < inserts; i++) {
        uint8_t k[32];
        fill_key(k, salt + i);
        (void)cloak_replay_cache_check_and_insert(&cache, k, 3000000,
                                                  CLOAK_SERVER_AUTH_REPLAY_CACHE_AGE_LIMIT_SECONDS);
    }
    size_t n = occupied_slots(&cache);
    cloak_replay_cache_destroy(&cache);
    return n;
}

static void test_case3_steady_state_bracket(void) {
    const size_t n = SIZED_INSERTS_PER_REPLAY_WINDOW; /* 3072 -- 3x the old capacity */

    size_t old_survivors = survivors_after(OLD_CAPACITY, n, 0x51EADEF0ULL);
    size_t new_survivors = survivors_after(SHIPPED_CAPACITY, n, 0x51EADEF0ULL);

    printf("case 3: %zu handshakes in the %zu s window -- capacity %zu keeps %zu (%.1f%%), "
           "capacity %zu keeps %zu (%.1f%%)\n",
           n, REPLAY_WINDOW_SECONDS, OLD_CAPACITY, old_survivors,
           100.0 * (double)old_survivors / (double)n, SHIPPED_CAPACITY, new_survivors,
           100.0 * (double)new_survivors / (double)n);

    /* THE OLD SIDE OF THE BRACKET is not a statistical claim at all: a
     * 1024-slot table cannot hold 3072 entries, so at most a third
     * survive by pigeonhole. Asserted as a measurement anyway, because
     * a bracket with only one measured end is a claim with a decoration
     * on it. */
    ASSERT_TRUE(old_survivors <= OLD_CAPACITY);
    ASSERT_TRUE(old_survivors * 3 <= n); /* 1024 * 3 == 3072 == n, exactly */

    /* THE NEW SIDE. Expected collisions among N inserts into C slots is
     * about N^2 / 2C = 3072^2 / 1048576 = 9, so about 3063 of 3072
     * survive -- 99.7 %. The assertion is 99 %, which leaves room for
     * the hash key drawn this run to be an unlucky one while still
     * failing outright at any capacity below about 2^17. */
    ASSERT_TRUE(new_survivors * 100 >= n * 99);

    /* And the 12-hour horizon, stated rather than hidden: at the sized
     * rate the table takes 8.53 * 43200 = 368,640 inserts over a full
     * age window, which is 0.70 of its slots -- fewer inserts than
     * slots, where the old table took 360 times its own size. The cache
     * still turns over across 12 hours; what it now does is retain
     * across the 360 s in which retention has any effect. */
    const size_t age_window_inserts =
        SIZED_CONCURRENT_CONNECTIONS *
        ((size_t)CLOAK_SERVER_AUTH_REPLAY_CACHE_AGE_LIMIT_SECONDS / SIZED_TURNOVER_SECONDS);
    printf("case 3: over the full %d s age limit the sized rate delivers %zu inserts into %zu "
           "slots (load %.2f); the old table took %.0fx its own size\n",
           CLOAK_SERVER_AUTH_REPLAY_CACHE_AGE_LIMIT_SECONDS, age_window_inserts, SHIPPED_CAPACITY,
           (double)age_window_inserts / (double)SHIPPED_CAPACITY,
           (double)age_window_inserts / (double)OLD_CAPACITY);
    ASSERT_TRUE(age_window_inserts <= SHIPPED_CAPACITY);
}

/* ------------------------------------------------------------------ */
/* Case 4: the key is PER INSTANCE, which is what makes it real         */
/* ------------------------------------------------------------------ */

/* THE CASE THAT CATCHES A DECORATIVE FIX. A hash "keyed" with a
 * compile-time constant, or with a key drawn once per process and
 * shared, passes cases 1, 2 and 3 exactly as well as the real fix does:
 * case 1 only needs the slot to be unpredictable to someone who cannot
 * read the binary, and a constant in the binary is unpredictable to the
 * test. Only this case can tell them apart, and it does it by observing
 * the SLOT, not the key material -- a key field that is filled with
 * randomness and then not used in the hash would pass an assertion
 * about the key and fail this one.
 *
 * Per INSTANCE is strictly stronger than the per-process property the
 * plan asked for, and it is what makes the property testable at all
 * without forking: two caches in one process must disagree.
 *
 * Two assertions, because they fail on different mutations:
 *
 *   (a) PAIRWISE. Eight independent pairs; at least one must disagree.
 *       Under a real key the chance all eight agree is (1/4096)^8,
 *       about 1e-29. Under a constant key all eight agree every time.
 *
 *   (b) SPREAD. Sixty-four independent instances must put the same key
 *       in at least 40 distinct slots. This is the one that survives a
 *       key with almost no entropy in it -- a "random" byte, say, or a
 *       key derived from a counter -- which (a) alone would pass. With
 *       64 draws from 4096 slots the expected number of distinct slots
 *       is 63.5, so 40 is far below the null and far above the 1 that a
 *       constant key gives and the handful that a low-entropy key
 *       gives.
 */
#define CASE4_CAPACITY ((size_t)4096)

static size_t slot_for_fresh_instance(const uint8_t key[32]) {
    cloak_replay_cache_t cache;
    if (cloak_replay_cache_init(&cache, CASE4_CAPACITY) != 0) {
        return (size_t)-1;
    }
    (void)cloak_replay_cache_check_and_insert(&cache, key, 4000000,
                                              CLOAK_SERVER_AUTH_REPLAY_CACHE_AGE_LIMIT_SECONDS);
    size_t slot = sole_occupied_slot(&cache);
    cloak_replay_cache_destroy(&cache);
    return slot;
}

static void test_case4_key_is_per_instance(void) {
    uint8_t key[32];
    fill_key(key, 0xD1FFE125ULL);

    int disagreements = 0;
    for (int pair = 0; pair < 8; pair++) {
        size_t a = slot_for_fresh_instance(key);
        size_t b = slot_for_fresh_instance(key);
        ASSERT_TRUE(a != (size_t)-1 && b != (size_t)-1);
        if (a != b) {
            disagreements++;
        }
    }
    printf("case 4: %d of 8 instance pairs put the same 32-byte key in different slots\n",
           disagreements);
    ASSERT_TRUE(disagreements >= 1);

    /* A fresh instance must still be SELF-consistent: the same key twice
     * into the same cache is the same slot, which is what makes it a
     * replay at all. Without this, "randomise the slot on every call"
     * would pass (a). */
    {
        cloak_replay_cache_t cache;
        ASSERT_EQ_INT(0, cloak_replay_cache_init(&cache, CASE4_CAPACITY));
        ASSERT_EQ_INT(0, cloak_replay_cache_check_and_insert(
                             &cache, key, 4000000,
                             CLOAK_SERVER_AUTH_REPLAY_CACHE_AGE_LIMIT_SECONDS));
        ASSERT_EQ_INT(1, cloak_replay_cache_check_and_insert(
                             &cache, key, 4000001,
                             CLOAK_SERVER_AUTH_REPLAY_CACHE_AGE_LIMIT_SECONDS));
        cloak_replay_cache_destroy(&cache);
    }

    /* (b) the spread. */
    unsigned char seen[CASE4_CAPACITY];
    memset(seen, 0, sizeof(seen));
    size_t distinct = 0;
    for (int i = 0; i < 64; i++) {
        size_t s = slot_for_fresh_instance(key);
        ASSERT_TRUE(s != (size_t)-1);
        if (s < CASE4_CAPACITY && !seen[s]) {
            seen[s] = 1;
            distinct++;
        }
    }
    printf("case 4: 64 instances put the same key in %zu distinct slots of %zu (expected ~63, "
           "a constant key gives 1)\n",
           distinct, CASE4_CAPACITY);
    ASSERT_TRUE(distinct >= 40);
}

/* ------------------------------------------------------------------ */
/* The hash really is SipHash-2-4, pinned against OpenSSL               */
/* ------------------------------------------------------------------ */

/* WHY THIS EXISTS, and it is the gap the four cases above leave open.
 * Cases 1-4 all pass against ANY keyed function that spreads well --
 * including a SipHash with a rotation constant typed wrong, which still
 * returns a number, still spreads, and still hides the slot from an
 * attacker. replay_cache.c's own comment says "getting it wrong is
 * silent", and this is what makes that not merely an assertion. A
 * miswired SipHash is probably still adequate FOR THIS USE; what is not
 * adequate is a source file claiming to implement a named primitive and
 * nothing checking that it does.
 *
 * WHERE THE EXPECTED VALUES CAME FROM: an INDEPENDENT implementation,
 * not this one. OpenSSL 3.0.20's SIPHASH MAC, as shipped in this
 * project's own build image, run as
 *
 *   openssl mac -macopt size:8 -macopt hexkey:<KEY> -in <FILE> SIPHASH
 *
 * The same command on the canonical 15-byte SipHash-2-4 reference input
 * (key 000102...0f, message 000102...0e) returns E545BE4961CA29A1, which
 * is how OpenSSL was confirmed to be the right oracle before its answers
 * for the two 32-byte inputs below were taken.
 *
 * MIND THE BYTE ORDER, because getting it wrong here is what happened on
 * the first run of this test. `openssl mac` prints the MAC's BYTES, and
 * SipHash serialises its 64-bit result little-endian, so OpenSSL's
 * E545BE4961CA29A1 is the integer 0xa129ca6149be45e5 -- the published
 * vector -- read backwards. The constants below are the integers, i.e.
 * OpenSSL's hex string with its bytes reversed. Both were independently
 * recomputed by a third implementation (a short Python SipHash-2-4
 * written from the specification), which agreed with OpenSSL on all
 * three inputs; the first failure of this test was this transcription,
 * not replay_cache.c.
 *
 * HOW IT IS OBSERVED. siphash24_32 is static in replay_cache.c and the
 * public API returns a replay verdict, not a hash. So the test overwrites
 * cache.hash_key after init -- deliberately doing the one thing
 * replay_cache.h tells callers not to do, which is sound only because the
 * point here is to make the function deterministic -- inserts the vector's
 * message as the 32-byte key, and reads the slot back. At capacity 65536
 * the slot IS the digest's low 16 bits, so two vectors pin 32 bits of the
 * function: a miswiring survives with probability 2^-32. */
static void siphash_vector(const char *hexkey_note, const uint8_t k[16], const uint8_t msg[32],
                           uint64_t expect) {
    const size_t cap = 65536; /* a power of two, so slot == digest & 0xffff */
    cloak_replay_cache_t cache;
    ASSERT_EQ_INT(0, cloak_replay_cache_init(&cache, cap));
    memcpy(cache.hash_key, k, 16);
    ASSERT_EQ_INT(0, cloak_replay_cache_check_and_insert(
                         &cache, msg, 5000000, CLOAK_SERVER_AUTH_REPLAY_CACHE_AGE_LIMIT_SECONDS));
    size_t slot = sole_occupied_slot(&cache);
    printf("siphash vector [%s]: slot %zu, expected %zu\n", hexkey_note, slot,
           (size_t)(expect % cap));
    ASSERT_EQ_INT((int)(expect % cap), (int)slot);
    cloak_replay_cache_destroy(&cache);
}

static void test_hash_is_siphash24(void) {
    uint8_t k1[16], m1[32], k2[16], m2[32];
    for (int i = 0; i < 16; i++) {
        k1[i] = (uint8_t)i;          /* 000102...0f */
        k2[i] = (uint8_t)(15 - i);   /* 0f0e0d...00 */
    }
    for (int i = 0; i < 32; i++) {
        m1[i] = (uint8_t)i;              /* 000102...1f */
        m2[i] = (uint8_t)(0xff - i);     /* fffefd...e0 */
    }
    siphash_vector("key 000102..0f, msg 000102..1f", k1, m1, 0x7127512F72F27CCEULL);
    siphash_vector("key 0f0e0d..00, msg fffefd..e0", k2, m2, 0x77E5A9E509102DFCULL);
}

TEST_MAIN_BEGIN()
    test_shipped_capacity_meets_its_floor();
    test_case1_targeted_eviction();
    test_case2_whole_table_flood_cost();
    test_case3_steady_state_bracket();
    test_case4_key_is_per_instance();
    test_hash_is_siphash24();
TEST_MAIN_END()
