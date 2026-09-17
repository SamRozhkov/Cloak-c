#define _POSIX_C_SOURCE 200809L
#include "cloak/registry.h"

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cloak/common.h"
#include "test_framework.h"

/* This registry needs real sessions to exercise, so it builds on the
 * same paired-session harness style as libcloak-mux/tests/test_stream_data_cb.c
 * (two sessions wired to each other over a socketpair, or one session
 * plus a raw peer-disconnect via close()) rather than inventing a second
 * shape for the same job. */

static void make_obfuscator(cloak_obfuscator_t *o) {
    o->method = CLOAK_AEAD_AES_256_GCM;
    cloak_random_bytes(o->session_key, sizeof(o->session_key));
}

/* An inactivity_timeout_ms of 60000ms is generous relative to every
 * reactor loop bound below (at most ~500ms of simulated time each), so no
 * test here is ever at risk of the inactivity timer firing and confusing
 * it with the break this file triggers deliberately. */
static void base_config(cloak_session_config_t *cfg, const cloak_obfuscator_t *obfs) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->obfuscator = *obfs;
    cfg->ordering = CLOAK_SESSION_ORDERING_ORDERED;
    cfg->max_on_wire_size = 16401;
    cfg->stream_recv_capacity = 65536;
    cfg->stream_max_pending_frames = 64;
    cfg->conn_send_queue_cap = 262144;
    cfg->inactivity_timeout_ms = 60000;
    /* on_broken deliberately left NULL: cloak_server_registry_get_or_create
     * overwrites it unconditionally regardless of what's set here, which
     * is exactly the behaviour case 2 below pins. */
}

/* Records everything a dispatcher-shaped consumer would want to observe
 * about cloak_registry_broken_cb firing, plus two optional actions to
 * perform from inside the callback (release_stream and close_from_inside)
 * so the same callback can serve every test below. */
typedef struct {
    int broken_calls;
    cloak_server_registry_t *last_reg;
    cloak_session_t *last_sesh;
    uint8_t last_uid[CLOAK_UID_LEN];
    uint32_t last_session_id;

    /* If non-NULL when on_broken fires, released from inside the
     * callback -- proves sesh is still genuinely usable then, not merely
     * a non-NULL pointer (this reaches into sesh's stream table and
     * frees the stream's memory; under ASan a freed sesh would fault
     * here immediately). Cleared back to NULL once done, so a test can
     * assert the release actually ran. */
    cloak_stream_t *stream_to_release;

    /* If set, cloak_server_registry_close(close_uid, close_session_id) is
     * called from inside the callback -- case 4: must be a no-op, not a
     * second teardown. */
    int close_from_inside;
    uint8_t close_uid[CLOAK_UID_LEN];
    uint32_t close_session_id;

    /* If set, cloak_server_registry_destroy(reg) is called from inside
     * the callback -- review finding 1: destroy must leave reg safe
     * (specifically: must not let the sweep this on_broken call is about
     * to arm actually get armed against an already-destroyed reg). This
     * also calls cloak_reactor_stop(reg->reactor) immediately afterward,
     * for a reason that belongs here rather than at the call site: see
     * test_destroy_registry_from_inside_on_broken_is_safe's own top
     * comment for why the discriminating assertion needs the reactor's
     * end-of-turn timer processing suppressed for this exact dispatch. */
    int destroy_reg_from_inside;
} broken_ctx_t;

static void on_registry_broken(cloak_server_registry_t *reg, cloak_session_t *sesh,
                                const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                                void *userdata) {
    broken_ctx_t *ctx = userdata;
    ctx->broken_calls++;
    ctx->last_reg = reg;
    ctx->last_sesh = sesh;
    memcpy(ctx->last_uid, uid, CLOAK_UID_LEN);
    ctx->last_session_id = session_id;

    if (ctx->stream_to_release != NULL) {
        cloak_session_release_stream(sesh, ctx->stream_to_release);
        ctx->stream_to_release = NULL;
    }

    if (ctx->close_from_inside) {
        cloak_server_registry_close(reg, ctx->close_uid, ctx->close_session_id);
    }

    if (ctx->destroy_reg_from_inside) {
        cloak_server_registry_destroy(reg);
        /* Freeze this reactor turn right here: cloak_reactor_run_once
         * calls process_expired_timers() at the END of the SAME turn
         * that dispatched the fd event which led here, so a zero-delay
         * timer armed by registry_arm_sweep (called by
         * registry_on_session_broken right after this callback returns)
         * would otherwise fire and reset itself to CLOAK_TIMER_INVALID
         * before the test ever gets to look at it -- making a plain
         * post-loop check of reg->sweep_timer pass identically whether
         * or not the guard this callback is testing actually ran.
         * cloak_reactor_stop is documented as callable from within a
         * callback and, per cloak_reactor_run_once's own doc, is
         * observed but not cleared by run_once -- so this reliably
         * suppresses process_expired_timers for the rest of THIS turn
         * (reg->reactor is still the live reactor here: destroy() does
         * not touch that field). */
        cloak_reactor_stop(reg->reactor);
    }
}

/* Captures on_new_stream/on_stream_data/on_writable firing, draining
 * whatever data arrived like test_stream_data_cb.c's own `struct
 * endpoint` does. */
struct capture_ep {
    cloak_stream_t *accepted;
    int new_stream_calls;
    int data_calls;
    int last_data_len;
    int writable_calls;
};

static void cap_on_new_stream(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    struct capture_ep *ep = userdata;
    ep->new_stream_calls++;
    ep->accepted = stream;
}

static void cap_on_stream_data(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    struct capture_ep *ep = userdata;
    ep->data_calls++;
    uint8_t buf[4096];
    long n = cloak_stream_read(stream, buf, sizeof(buf));
    ep->last_data_len = n > 0 ? (int)n : 0;
}

static void cap_on_writable(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    struct capture_ep *ep = userdata;
    ep->writable_calls++;
}

/* 1. get_or_create returns a new session the first time (out_created ==
 * 1) and the same pointer for the same (uid, session_id) afterwards
 * (out_created == 0). A different session_id for the same uid, and the
 * same session_id for a different uid, both get their own session. */
static void test_get_or_create_identity(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    broken_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    cloak_server_registry_t reg;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&reg, r, on_registry_broken, &ctx));

    cloak_obfuscator_t obfs;
    make_obfuscator(&obfs);
    cloak_session_config_t cfg;
    base_config(&cfg, &obfs);

    uint8_t uid_a[CLOAK_UID_LEN];
    uint8_t uid_b[CLOAK_UID_LEN];
    memset(uid_a, 0xAA, sizeof(uid_a));
    memset(uid_b, 0xBB, sizeof(uid_b));

    int created = -1;
    cloak_session_t *s1 = cloak_server_registry_get_or_create(&reg, uid_a, 1, &cfg, &created);
    ASSERT_TRUE(s1 != NULL);
    ASSERT_EQ_INT(1, created);

    created = -1;
    cloak_session_t *s1_again = cloak_server_registry_get_or_create(&reg, uid_a, 1, &cfg, &created);
    ASSERT_TRUE(s1_again == s1);
    ASSERT_EQ_INT(0, created);

    /* Same uid, different session_id -- keying on uid alone would wrongly
     * collapse this into s1. */
    created = -1;
    cloak_session_t *s2 = cloak_server_registry_get_or_create(&reg, uid_a, 2, &cfg, &created);
    ASSERT_TRUE(s2 != NULL);
    ASSERT_EQ_INT(1, created);
    ASSERT_TRUE(s2 != s1);

    /* Different uid, same session_id -- keying on session_id alone would
     * wrongly collapse this into s1. */
    created = -1;
    cloak_session_t *s3 = cloak_server_registry_get_or_create(&reg, uid_b, 1, &cfg, &created);
    ASSERT_TRUE(s3 != NULL);
    ASSERT_EQ_INT(1, created);
    ASSERT_TRUE(s3 != s1);
    ASSERT_TRUE(s3 != s2);

    ASSERT_EQ_INT(3, (int)cloak_server_registry_count(&reg));

    cloak_server_registry_destroy(&reg);
    cloak_reactor_destroy(r);
}

/* 2. The caller's config fields survive: a config with a recognisable
 * on_new_stream/on_stream_data/on_writable and their userdata actually
 * gets carried into the session get_or_create hands back. on_new_stream
 * and on_stream_data are pinned behaviourally (driving real frames through
 * and observing them fire), which is the point -- a registry that
 * clobbered the wiring would leave the session mute. on_writable is
 * additionally pinned by reading it straight off the (fully public,
 * non-opaque) cloak_session_t struct cloak_session_init copied it into:
 * genuinely exercising it needs a kernel-socket-buffer-filling backpressure
 * scenario (see libcloak-mux/tests/test_stream_relay.c's own
 * test_large_transfer_survives_backpressure for how heavy that is) that
 * would add nothing here beyond what that suite already covers -- the
 * thing actually in question is only whether get_or_create passed the
 * pointer through unmolested. */
static void test_config_fields_survive(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    broken_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    cloak_server_registry_t reg;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&reg, r, on_registry_broken, &ctx));

    cloak_obfuscator_t obfs;
    make_obfuscator(&obfs);

    uint8_t uid_a[CLOAK_UID_LEN];
    uint8_t uid_b[CLOAK_UID_LEN];
    memset(uid_a, 0x11, sizeof(uid_a));
    memset(uid_b, 0x22, sizeof(uid_b));

    struct capture_ep ep_a;
    struct capture_ep ep_b;
    memset(&ep_a, 0, sizeof(ep_a));
    memset(&ep_b, 0, sizeof(ep_b));

    cloak_session_config_t cfg_a;
    cloak_session_config_t cfg_b;
    base_config(&cfg_a, &obfs);
    base_config(&cfg_b, &obfs);
    cfg_b.on_new_stream = cap_on_new_stream;
    cfg_b.on_new_stream_userdata = &ep_b;
    cfg_b.on_stream_data = cap_on_stream_data;
    cfg_b.on_stream_data_userdata = &ep_b;
    cfg_b.on_writable = cap_on_writable;
    cfg_b.on_writable_userdata = &ep_b;

    int created = 0;
    cloak_session_t *sesh_a = cloak_server_registry_get_or_create(&reg, uid_a, 1, &cfg_a, &created);
    ASSERT_TRUE(sesh_a != NULL);
    cloak_session_t *sesh_b = cloak_server_registry_get_or_create(&reg, uid_b, 1, &cfg_b, &created);
    ASSERT_TRUE(sesh_b != NULL);

    /* Struct-field check for on_writable/on_writable_userdata -- see this
     * test's own top comment for why this one field is pinned this way
     * instead of behaviourally. */
    ASSERT_TRUE(sesh_b->on_writable == cap_on_writable);
    ASSERT_TRUE(sesh_b->on_writable_userdata == &ep_b);

    int fds[2];
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
    ASSERT_EQ_INT(0, cloak_session_add_conn(sesh_a, fds[0]));
    ASSERT_EQ_INT(0, cloak_session_add_conn(sesh_b, fds[1]));

    cloak_stream_t *s = cloak_session_open_stream(sesh_a, NULL);
    ASSERT_TRUE(s != NULL);

    /* First frame reveals the stream to b: on_new_stream fires. */
    ASSERT_EQ_INT(5, (int)cloak_stream_write(s, (const uint8_t *)"hello", 5));
    for (int i = 0; i < 50 && ep_b.new_stream_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, ep_b.new_stream_calls);
    ASSERT_TRUE(ep_b.accepted != NULL);

    /* Drain what the first frame delivered, so the next assertion is
     * about the second frame's bytes and not leftovers (on_new_stream
     * deliberately does not drain -- see cap_on_new_stream). */
    uint8_t buf[64];
    ASSERT_EQ_INT(5, (int)cloak_stream_read(ep_b.accepted, buf, sizeof(buf)));
    ASSERT_MEM_EQ(buf, "hello", 5);

    /* Second frame lands on a stream b already knows: on_stream_data
     * fires and can actually read the registry-untouched bytes. */
    ASSERT_EQ_INT(6, (int)cloak_stream_write(s, (const uint8_t *)"world!", 6));
    for (int i = 0; i < 50 && ep_b.data_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, ep_b.data_calls);
    ASSERT_EQ_INT(6, ep_b.last_data_len);

    cloak_session_release_stream(sesh_b, ep_b.accepted);
    cloak_session_release_stream(sesh_a, s);
    cloak_server_registry_destroy(&reg);
    cloak_reactor_destroy(r);
}

/* 3. When a session breaks, the owner's on_broken fires exactly once,
 * with the right uid and session_id, and the session is still usable for
 * the duration of that callback. Afterwards, find() returns NULL and
 * count() has dropped. */
static void test_broken_fires_once_and_session_stays_usable(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    broken_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    cloak_server_registry_t reg;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&reg, r, on_registry_broken, &ctx));

    cloak_obfuscator_t obfs;
    make_obfuscator(&obfs);

    uint8_t uid_b[CLOAK_UID_LEN];
    memset(uid_b, 0x42, sizeof(uid_b));

    struct capture_ep ep_b;
    memset(&ep_b, 0, sizeof(ep_b));
    cloak_session_config_t cfg_b;
    base_config(&cfg_b, &obfs);
    cfg_b.on_new_stream = cap_on_new_stream;
    cfg_b.on_new_stream_userdata = &ep_b;

    int created = 0;
    cloak_session_t *sesh_b = cloak_server_registry_get_or_create(&reg, uid_b, 1, &cfg_b, &created);
    ASSERT_TRUE(sesh_b != NULL);
    ASSERT_EQ_INT(1, created);

    /* Plain, non-registry-managed peer session, on the same reactor --
     * only its disconnect matters, to drive sesh_b into breaking. */
    cloak_session_t sesh_a;
    cloak_session_config_t cfg_a;
    base_config(&cfg_a, &obfs);
    ASSERT_EQ_INT(0, cloak_session_init(&sesh_a, 99, r, &cfg_a));

    int fds[2];
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&sesh_a, fds[0]));
    ASSERT_EQ_INT(0, cloak_session_add_conn(sesh_b, fds[1]));

    cloak_stream_t *s = cloak_session_open_stream(&sesh_a, NULL);
    ASSERT_TRUE(s != NULL);
    ASSERT_EQ_INT(5, (int)cloak_stream_write(s, (const uint8_t *)"hello", 5));
    for (int i = 0; i < 50 && ep_b.new_stream_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, ep_b.new_stream_calls);
    ASSERT_TRUE(ep_b.accepted != NULL);

    /* This is the window under test: sesh_b's own on_broken (the
     * dispatcher's chance to stop every relay bound to it) releases the
     * stream it is still holding. */
    ctx.stream_to_release = ep_b.accepted;

    cloak_session_release_stream(&sesh_a, s);
    cloak_session_destroy(&sesh_a); /* peer vanishes -> sesh_b sees EOF and breaks */

    for (int i = 0; i < 50 && ctx.broken_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, ctx.broken_calls);
    ASSERT_TRUE(ctx.last_sesh == sesh_b);
    ASSERT_MEM_EQ(ctx.last_uid, uid_b, CLOAK_UID_LEN);
    ASSERT_EQ_INT(1, (int)ctx.last_session_id);
    ASSERT_TRUE(ctx.stream_to_release == NULL); /* release genuinely ran, inside the callback */

    ASSERT_TRUE(cloak_server_registry_find(&reg, uid_b, 1) == NULL);
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count(&reg));

    /* Let the deferred sweep actually run; must not fire on_broken again
     * or crash. */
    for (int i = 0; i < 20; i++) {
        cloak_reactor_run_once(r, 5);
    }
    ASSERT_EQ_INT(1, ctx.broken_calls);

    cloak_server_registry_destroy(&reg);
    cloak_reactor_destroy(r);
}

/* 4. Calling cloak_server_registry_close from inside the owner's
 * on_broken is a no-op rather than a double teardown. Run under ASan --
 * this is the exact shape of the use-after-free class this project keeps
 * producing. */
static void test_close_from_inside_on_broken_is_noop(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    uint8_t uid_b[CLOAK_UID_LEN];
    memset(uid_b, 0x55, sizeof(uid_b));

    broken_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.close_from_inside = 1;
    memcpy(ctx.close_uid, uid_b, CLOAK_UID_LEN);
    ctx.close_session_id = 1;

    cloak_server_registry_t reg;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&reg, r, on_registry_broken, &ctx));

    cloak_obfuscator_t obfs;
    make_obfuscator(&obfs);
    cloak_session_config_t cfg_b;
    base_config(&cfg_b, &obfs);

    int created = 0;
    cloak_session_t *sesh_b = cloak_server_registry_get_or_create(&reg, uid_b, 1, &cfg_b, &created);
    ASSERT_TRUE(sesh_b != NULL);
    ASSERT_EQ_INT(1, created);

    int fds[2];
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
    ASSERT_EQ_INT(0, cloak_session_add_conn(sesh_b, fds[0]));
    close(fds[1]); /* peer vanishes -> sesh_b sees EOF and breaks */

    for (int i = 0; i < 50 && ctx.broken_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, ctx.broken_calls);
    ASSERT_TRUE(cloak_server_registry_find(&reg, uid_b, 1) == NULL);
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count(&reg));

    /* Let the deferred sweep run too -- if the in-callback close() had
     * actually torn the entry down a second time, this is where a double
     * free would surface under ASan. */
    for (int i = 0; i < 20; i++) {
        cloak_reactor_run_once(r, 5);
    }
    ASSERT_EQ_INT(1, ctx.broken_calls);

    cloak_server_registry_destroy(&reg);
    cloak_reactor_destroy(r);
}

/* Fires cloak_reactor_stop on the reactor it's given -- used below as a
 * bounded watchdog so a cloak_reactor_run call cannot hang forever. */
static void stop_reactor_timer_cb(cloak_reactor_t *r, void *userdata) {
    (void)userdata;
    cloak_reactor_stop(r);
}

/* 4b (review finding 1). Destroying the registry from INSIDE the owner's
 * on_broken -- reachable in practice, and dangerous specifically because
 * registry_on_session_broken still has a registry_arm_sweep(reg) call to
 * make after the owner's callback returns. Before the destroyed flag, that
 * arm call would succeed against an already-destroyed reg, arming a
 * fresh zero-delay timer with reg as userdata; if the owner went on to
 * free reg's own storage, that timer firing later would read and write
 * freed memory.
 *
 * THIS TEST USED TO CHECK reg.sweep_timer RIGHT AFTER THE BREAK LOOP,
 * WITH NO cloak_reactor_stop CALL, AND THAT DID NOT WORK: a scoped
 * re-review found it passed identically with the destroyed guard removed
 * from registry_arm_sweep, because it never actually observed an armed
 * timer. Traced why: cloak_reactor_run_once calls process_expired_timers
 * at the END of the SAME turn that dispatched the fd event that broke the
 * session -- so a zero-delay timer armed by registry_arm_sweep during
 * that same turn's dispatch fires and resets itself to
 * CLOAK_TIMER_INVALID before run_once even returns to this test's loop.
 * Confirmed directly: temporarily removing the `if (reg->destroyed)`
 * guard from registry_arm_sweep and instrumenting it with fprintf showed
 * add_timer legitimately returning a live, non-invalid id, immediately
 * followed (same run_once call, via process_expired_timers re-checking
 * its heap against a `now` captured once at the top of that function)
 * by registry_sweep_timer_cb firing and resetting reg->sweep_timer back
 * to CLOAK_TIMER_INVALID -- all before the test's own next line ran. A
 * plain post-loop check of reg.sweep_timer is therefore exactly the kind
 * of non-discriminating assertion this whole exercise was trying to
 * eliminate, just moved one layer down.
 *
 * The fix: on_registry_broken (see its own comment on
 * destroy_reg_from_inside) calls cloak_reactor_stop(reg->reactor)
 * immediately after cloak_server_registry_destroy(reg), from within the
 * SAME callback invocation, i.e. before registry_arm_sweep has even run
 * for this entry. cloak_reactor_stop is documented as safe to call from
 * within a callback, and cloak_reactor_run_once's own doc states the stop
 * flag is observed but not cleared by run_once -- so once set, it
 * suppresses process_expired_timers for the REST of this turn (checked
 * with `if (!r->stopped)` after the fd-dispatch loop, in reactor.c). That
 * happens after registry_arm_sweep has already run (arm_sweep doesn't
 * check the stop flag itself), so reg.sweep_timer reliably holds
 * whatever arm_sweep just set it to -- a live id pre-fix, CLOAK_TIMER_INVALID
 * post-fix -- by the time run_once returns here, with no self-firing race. */
static void test_destroy_registry_from_inside_on_broken_is_safe(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    uint8_t uid_b[CLOAK_UID_LEN];
    memset(uid_b, 0x66, sizeof(uid_b));

    broken_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.destroy_reg_from_inside = 1;

    cloak_server_registry_t reg;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&reg, r, on_registry_broken, &ctx));

    cloak_obfuscator_t obfs;
    make_obfuscator(&obfs);
    cloak_session_config_t cfg_b;
    base_config(&cfg_b, &obfs);

    int created = 0;
    cloak_session_t *sesh_b = cloak_server_registry_get_or_create(&reg, uid_b, 1, &cfg_b, &created);
    ASSERT_TRUE(sesh_b != NULL);
    ASSERT_EQ_INT(1, created);

    int fds[2];
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
    ASSERT_EQ_INT(0, cloak_session_add_conn(sesh_b, fds[0]));
    close(fds[1]); /* peer vanishes -> sesh_b sees EOF and breaks */

    /* The turn that dispatches this break is also the turn
     * on_registry_broken calls cloak_reactor_stop on, per the mechanism
     * explained above -- so as soon as this loop observes the break,
     * reg.sweep_timer is frozen at whatever value arm_sweep just gave
     * it, immune to process_expired_timers for the rest of this turn. */
    for (int i = 0; i < 50 && ctx.broken_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, ctx.broken_calls);

    /* THE discriminating assertion. */
    ASSERT_EQ_INT((int)CLOAK_TIMER_INVALID, (int)reg.sweep_timer);

    /* Corroborating evidence, made to actually mean something rather than
     * being a guaranteed no-op: r's stop flag is now set and
     * cloak_reactor_run_once never clears it (see the comment above), so
     * plain run_once calls from here on would dispatch and fire nothing
     * at all regardless of what reg.sweep_timer held -- not a real pump.
     * cloak_reactor_run DOES clear the flag on entry, so drive a real,
     * bounded turn through it instead, guarded by a watchdog timer so it
     * cannot hang: if the guard in registry_arm_sweep were absent (the
     * pre-fix case above), the id already sitting in reg.sweep_timer
     * would come due and registry_sweep_timer_cb would run for real
     * here, harmlessly sweeping the already-empty table -- proving that
     * even a leaked pre-fix timer doesn't crash *this* test (reg is
     * never freed here; only cloak_server_registry_destroy's own storage-
     * management is exercised, per the coordinator's explicit
     * instruction not to free reg's backing memory from inside
     * on_broken -- see registry.h's cloak_registry_broken_cb doc for why
     * that specifically remains unsafe even with this fix in place). */
    cloak_timer_id_t watchdog = cloak_reactor_add_timer(r, 50, stop_reactor_timer_cb, NULL);
    ASSERT_TRUE(watchdog != CLOAK_TIMER_INVALID);
    cloak_reactor_run(r);
    ASSERT_EQ_INT(1, ctx.broken_calls);

    /* A second, ordinary destroy call must still be safe and idempotent
     * -- this is the caller's own eventual cleanup, exactly like every
     * other test in this file, and must not double-free anything. */
    cloak_server_registry_destroy(&reg);
    cloak_reactor_destroy(r);
}

/* 5. cloak_server_registry_close on a live session tears it down, fires
 * nothing (it is the owner's own action, not a failure), and removes it
 * from the table. */
static void test_close_live_session_fires_nothing(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    broken_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    cloak_server_registry_t reg;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&reg, r, on_registry_broken, &ctx));

    cloak_obfuscator_t obfs;
    make_obfuscator(&obfs);
    cloak_session_config_t cfg;
    base_config(&cfg, &obfs);

    uint8_t uid[CLOAK_UID_LEN];
    memset(uid, 0x77, sizeof(uid));

    int created = 0;
    cloak_session_t *sesh = cloak_server_registry_get_or_create(&reg, uid, 1, &cfg, &created);
    ASSERT_TRUE(sesh != NULL);
    ASSERT_EQ_INT(1, created);
    ASSERT_EQ_INT(1, (int)cloak_server_registry_count(&reg));

    cloak_server_registry_close(&reg, uid, 1);

    ASSERT_EQ_INT(0, ctx.broken_calls);
    ASSERT_TRUE(cloak_server_registry_find(&reg, uid, 1) == NULL);
    ASSERT_EQ_INT(0, (int)cloak_server_registry_count(&reg));

    /* A second close on the now-absent session must also be a no-op. */
    cloak_server_registry_close(&reg, uid, 1);
    ASSERT_EQ_INT(0, ctx.broken_calls);

    cloak_server_registry_destroy(&reg);
    cloak_reactor_destroy(r);
}

/* 6. Filling the table to CLOAK_REGISTRY_MAX_SESSIONS and asking for one
 * more returns NULL, and the existing sessions are untouched. */
static void test_table_full_returns_null(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    broken_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    cloak_server_registry_t reg;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&reg, r, on_registry_broken, &ctx));

    cloak_obfuscator_t obfs;
    make_obfuscator(&obfs);
    cloak_session_config_t cfg;
    base_config(&cfg, &obfs);

    cloak_session_t *first = NULL;
    uint8_t first_uid[CLOAK_UID_LEN];
    memset(first_uid, 0, sizeof(first_uid));

    for (int i = 0; i < CLOAK_REGISTRY_MAX_SESSIONS; i++) {
        uint8_t uid[CLOAK_UID_LEN];
        memset(uid, 0, sizeof(uid));
        uid[0] = (uint8_t)(i & 0xFF);
        uid[1] = (uint8_t)((i >> 8) & 0xFF);

        int created = 0;
        cloak_session_t *s = cloak_server_registry_get_or_create(&reg, uid, 1, &cfg, &created);
        ASSERT_TRUE(s != NULL);
        ASSERT_EQ_INT(1, created);

        if (i == 0) {
            first = s;
            memcpy(first_uid, uid, CLOAK_UID_LEN);
        }
    }
    ASSERT_EQ_INT(CLOAK_REGISTRY_MAX_SESSIONS, (int)cloak_server_registry_count(&reg));

    uint8_t overflow_uid[CLOAK_UID_LEN];
    memset(overflow_uid, 0xFF, sizeof(overflow_uid));
    int created = -1;
    cloak_session_t *overflow = cloak_server_registry_get_or_create(&reg, overflow_uid, 1, &cfg, &created);
    ASSERT_TRUE(overflow == NULL);

    /* The existing sessions are untouched: same pointer, still findable,
     * count unchanged by the failed attempt. */
    ASSERT_TRUE(cloak_server_registry_find(&reg, first_uid, 1) == first);
    ASSERT_EQ_INT(CLOAK_REGISTRY_MAX_SESSIONS, (int)cloak_server_registry_count(&reg));

    cloak_server_registry_destroy(&reg);
    cloak_reactor_destroy(r);
}

/* 7. cloak_server_registry_destroy with live sessions destroys them all
 * and leaves nothing leaked -- run under ASan, with at least one session
 * that has an open stream. */
static void test_destroy_with_live_sessions_and_open_stream(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    broken_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    cloak_server_registry_t reg;
    ASSERT_EQ_INT(0, cloak_server_registry_init(&reg, r, on_registry_broken, &ctx));

    cloak_obfuscator_t obfs;
    make_obfuscator(&obfs);

    uint8_t uid1[CLOAK_UID_LEN];
    uint8_t uid2[CLOAK_UID_LEN];
    memset(uid1, 0x01, sizeof(uid1));
    memset(uid2, 0x02, sizeof(uid2));

    struct capture_ep ep1;
    memset(&ep1, 0, sizeof(ep1));
    cloak_session_config_t cfg1;
    base_config(&cfg1, &obfs);
    cfg1.on_new_stream = cap_on_new_stream;
    cfg1.on_new_stream_userdata = &ep1;

    cloak_session_config_t cfg2;
    base_config(&cfg2, &obfs);

    int created = 0;
    cloak_session_t *sesh1 = cloak_server_registry_get_or_create(&reg, uid1, 1, &cfg1, &created);
    ASSERT_TRUE(sesh1 != NULL);
    cloak_session_t *sesh2 = cloak_server_registry_get_or_create(&reg, uid2, 1, &cfg2, &created);
    ASSERT_TRUE(sesh2 != NULL);

    /* Plain peer session so sesh1 ends up with a genuinely live, never
     * released stream at destroy time -- cloak_server_registry_destroy
     * must reach it via cloak_session_destroy's own still-ACTIVE-stream
     * sweep, exactly like an ordinary cloak_session_destroy call would. */
    cloak_session_t sesh_peer;
    cloak_session_config_t cfg_peer;
    base_config(&cfg_peer, &obfs);
    ASSERT_EQ_INT(0, cloak_session_init(&sesh_peer, 99, r, &cfg_peer));

    int fds[2];
    ASSERT_EQ_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
    ASSERT_EQ_INT(0, cloak_session_add_conn(&sesh_peer, fds[0]));
    ASSERT_EQ_INT(0, cloak_session_add_conn(sesh1, fds[1]));

    cloak_stream_t *s = cloak_session_open_stream(&sesh_peer, NULL);
    ASSERT_TRUE(s != NULL);
    ASSERT_EQ_INT(4, (int)cloak_stream_write(s, (const uint8_t *)"data", 4));
    for (int i = 0; i < 50 && ep1.new_stream_calls == 0; i++) {
        cloak_reactor_run_once(r, 10);
    }
    ASSERT_EQ_INT(1, ep1.new_stream_calls);
    ASSERT_TRUE(ep1.accepted != NULL); /* live, never released */

    cloak_server_registry_destroy(&reg);
    ASSERT_EQ_INT(0, ctx.broken_calls); /* destroy is not a failure notification */

    cloak_session_release_stream(&sesh_peer, s);
    cloak_session_destroy(&sesh_peer);
    cloak_reactor_destroy(r);
}

/* 8 (review finding 6). cloak_server_registry_init rejects a NULL
 * on_broken and leaves reg safe to pass to cloak_server_registry_destroy
 * -- the ordering registry.h singles out as "the source of a real crash
 * on this branch more than once". reg starts filled with 0xAA (never
 * zeroed by the test itself) so the assertion can only pass if init
 * actually memset it. */
static void test_init_rejects_null_on_broken_and_leaves_destroy_safe(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    cloak_server_registry_t reg;
    memset(&reg, 0xAA, sizeof(reg));
    ASSERT_EQ_INT(-1, cloak_server_registry_init(&reg, r, NULL, NULL));

    cloak_server_registry_destroy(&reg); /* must not crash */

    cloak_reactor_destroy(r);
}

TEST_MAIN_BEGIN()
    test_get_or_create_identity();
    test_config_fields_survive();
    test_broken_fires_once_and_session_stays_usable();
    test_close_from_inside_on_broken_is_noop();
    test_destroy_registry_from_inside_on_broken_is_safe();
    test_close_live_session_fires_nothing();
    test_table_full_returns_null();
    test_destroy_with_live_sessions_and_open_stream();
    test_init_rejects_null_on_broken_and_leaves_destroy_safe();
TEST_MAIN_END()
