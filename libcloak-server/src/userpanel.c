#define _POSIX_C_SOURCE 200809L
#include "cloak/userpanel.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cloak/base64.h"
#include "cloak/log.h"

/* One UID's accumulated usage between two uploads. Separate from
 * cloak_userpanel_user_t on purpose -- see cloak_userpanel_upload_now's
 * doc comment ("THE QUEUE OUTLIVES THE ACTIVE USER"). */
struct panel_queue_entry {
    uint8_t uid[CLOAK_UID_LEN];
    int64_t up_usage, down_usage; /* the USER's vocabulary; converted once, at the drain */
};

struct cloak_userpanel {
    cloak_userpanel_config_t cfg; /* copied by value, defaults already filled in */

    /* NULL slots are free. Entries are heap-allocated and never moved:
     * their embedded valve's address is handed to every session that user
     * holds. See cloak_userpanel_user_t's own comment. */
    cloak_userpanel_user_t *active[CLOAK_USERPANEL_MAX_ACTIVE_USERS];

    /* Compacted: queue_n entries at the front, no holes. */
    struct panel_queue_entry queue[CLOAK_USERPANEL_MAX_QUEUED_USERS];
    size_t queue_n;

    /* Scratch for one upload cycle, sized for the WORST case (a full
     * queue) rather than a plausible one, and held here rather than on
     * the stack: cloak_usermanager_upload_status reports the TRUE number
     * of terminates even when it exceeds the buffer, so a buffer sized
     * for the average case would silently drop terminations for users who
     * had run out of credit -- i.e. hand out free service -- exactly when
     * the server was busiest. At this size *out_n can never exceed the
     * cap, which is what makes the clamp in panel_commit unreachable
     * rather than load-bearing. */
    cloak_user_status_t statuses[CLOAK_USERPANEL_MAX_QUEUED_USERS];
    cloak_user_terminate_t terminates[CLOAK_USERPANEL_MAX_QUEUED_USERS];

    cloak_timer_id_t upload_timer;

    /* Set for the whole of one upload cycle -- the drain, the commit and
     * the terminations it orders. It is what refuses a nested cycle: both
     * `queue` and `terminates` are panel-wide scratch that a second cycle
     * would rewrite underneath the first. See cloak_userpanel_upload_now's
     * doc comment. */
    int in_cycle;
};

static int panel_run_cycle(cloak_userpanel_t *p);
static int panel_cycle_body(cloak_userpanel_t *p);

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

/* Go logs UIDs base64-encoded; keeping the same encoding means a panel
 * log line reads the same in both implementations, which matters when an
 * operator is comparing a C server against a Go one. */
static void panel_uid_str(const uint8_t uid[CLOAK_UID_LEN], char out[33]) {
    if (cloak_base64_encode(uid, CLOAK_UID_LEN, out, 33) != 0) {
        out[0] = '?';
        out[1] = '\0';
    }
}

static int64_t panel_now(const cloak_userpanel_t *p) {
    if (p->cfg.now_fn != NULL) {
        return p->cfg.now_fn(p->cfg.now_userdata);
    }
    return (int64_t)time(NULL);
}

/* Saturating, because a wrapped usage would be a NEGATIVE usage, and
 * cloak_usermanager_upload_status treats a negative usage as a malformed
 * entry it clamps to zero -- i.e. the user would be billed nothing at all
 * for the interval that overflowed. Unreachable in practice (it needs
 * ~8 exabytes on one UID between two uploads); it costs one branch. */
static int64_t panel_add_sat(int64_t a, int64_t b) {
    if (b > 0 && a > INT64_MAX - b) {
        return INT64_MAX;
    }
    return a + b;
}

/* ------------------------------------------------------------------ */
/* The active-user table                                               */
/* ------------------------------------------------------------------ */

/* Linear over a fixed table, like cloak_server_registry_find and
 * cloak_proxy_t's own scans, and for the same reason: the table is small
 * and a second index keyed on UID could disagree with it.
 *
 * Entries marked terminating are skipped -- from the outside such a user
 * has already stopped being active, and handing back an entry whose valve
 * is about to be freed is exactly the use-after-free this rule prevents.
 * It is also what makes a reentrant cloak_userpanel_notify_session_closed
 * a no-op without needing a second flag. */
static cloak_userpanel_user_t *panel_find(const cloak_userpanel_t *p,
                                          const uint8_t uid[CLOAK_UID_LEN]) {
    for (size_t i = 0; i < CLOAK_USERPANEL_MAX_ACTIVE_USERS; i++) {
        cloak_userpanel_user_t *u = p->active[i];
        if (u != NULL && !u->terminating && memcmp(u->uid, uid, CLOAK_UID_LEN) == 0) {
            return u;
        }
    }
    return NULL;
}

/* Allocates and installs a new active user. Returns NULL and writes the
 * reason through *out_err (CLOAK_USERPANEL_ERR_FULL or _ALLOC). */
static cloak_userpanel_user_t *panel_new_user(cloak_userpanel_t *p,
                                              const uint8_t uid[CLOAK_UID_LEN], int bypass,
                                              int *out_err) {
    size_t slot = CLOAK_USERPANEL_MAX_ACTIVE_USERS;
    for (size_t i = 0; i < CLOAK_USERPANEL_MAX_ACTIVE_USERS; i++) {
        if (p->active[i] == NULL) {
            slot = i;
            break;
        }
    }
    if (slot == CLOAK_USERPANEL_MAX_ACTIVE_USERS) {
        *out_err = CLOAK_USERPANEL_ERR_FULL;
        return NULL;
    }

    cloak_userpanel_user_t *u = malloc(sizeof(*u));
    if (u == NULL) {
        *out_err = CLOAK_USERPANEL_ERR_ALLOC;
        return NULL;
    }
    memset(u, 0, sizeof(*u)); /* zeroed valve == a valid empty valve; see cloak/valve.h */
    memcpy(u->uid, uid, CLOAK_UID_LEN);
    u->bypass = bypass;

    p->active[slot] = u;
    *out_err = 0;
    return u;
}

/* ------------------------------------------------------------------ */
/* The usage queue                                                     */
/* ------------------------------------------------------------------ */

/* The queue entry for uid, creating a zeroed one if there is room.
 * Returns NULL only when the queue is at its cap and this uid has no
 * entry yet.
 *
 * Callers must obtain the slot BEFORE nullifying a valve, never after: a
 * drain that read the valve, found no room and put the bytes nowhere
 * would silently hand out free traffic, and doing it in this order makes
 * that unrepresentable rather than merely avoided. */
static struct panel_queue_entry *panel_queue_slot(cloak_userpanel_t *p,
                                                  const uint8_t uid[CLOAK_UID_LEN]) {
    for (size_t i = 0; i < p->queue_n; i++) {
        if (memcmp(p->queue[i].uid, uid, CLOAK_UID_LEN) == 0) {
            return &p->queue[i];
        }
    }
    if (p->queue_n == CLOAK_USERPANEL_MAX_QUEUED_USERS) {
        return NULL;
    }
    struct panel_queue_entry *e = &p->queue[p->queue_n++];
    memset(e, 0, sizeof(*e));
    memcpy(e->uid, uid, CLOAK_UID_LEN);
    return e;
}

/* Go's updateUsageQueueForOne. Moves everything in this user's valve onto
 * the queue and zeroes the valve, in one step.
 *
 * THIS IS THE ONE PLACE THE SERVER'S rx/tx BECOMES THE USER'S up/down.
 * A user's UPLOAD is the server's RX; a user's DOWNLOAD is the server's
 * TX. cloak/valve.h forbids a second conversion site, and getting this
 * backwards meters the wrong direction against the wrong limit with no
 * error raised anywhere.
 *
 * A bypass user is skipped entirely, matching Go's updateUsageQueue --
 * its valve is NULL, so there would be nothing to move in any case.
 *
 * from_terminate distinguishes the two callers only for the log line: on
 * the periodic path a full queue costs nothing (the bytes stay in the
 * valve and are drained at a later tick), whereas on the terminate path
 * the valve is about to be freed and the usage is genuinely lost. */
static void panel_drain_user(cloak_userpanel_t *p, cloak_userpanel_user_t *u, int from_terminate) {
    if (u->bypass) {
        return;
    }
    struct panel_queue_entry *e = panel_queue_slot(p, u->uid);
    if (e == NULL && from_terminate && !p->in_cycle) {
        /* The periodic path can afford to leave the bytes in the valve
         * and try again next tick; a terminate cannot, because the valve
         * is about to be freed. Force the upload now instead of dropping
         * the usage: a successful commit empties the queue, and the retry
         * below then always finds room.
         *
         * u CANNOT BE FREED BY THIS CALL even though it runs the
         * terminations the manager orders: u->terminating was set by
         * cloak_userpanel_terminate before it called us, so panel_find
         * cannot return it and the terminate loop cannot reach it. The
         * !p->in_cycle guard is what stops this recursing -- a terminate
         * reached FROM a cycle finds the flag set, skips the flush, and
         * takes the warn-and-drop path below. */
        (void)panel_run_cycle(p);
        e = panel_queue_slot(p, u->uid);
    }
    if (e == NULL) {
        char b64[33];
        panel_uid_str(u->uid, b64);
        if (from_terminate) {
            CLOAK_LOGW("userpanel: usage queue full (%d entries) and the forced upload did not "
                       "free it -- usage for terminating user %s is lost",
                       (int)CLOAK_USERPANEL_MAX_QUEUED_USERS, b64);
        } else {
            CLOAK_LOGW("userpanel: usage queue full (%d entries) -- user %s not drained this "
                       "interval; its bytes stay metered in its valve",
                       (int)CLOAK_USERPANEL_MAX_QUEUED_USERS, b64);
        }
        return;
    }

    int64_t rx = 0, tx = 0;
    cloak_valve_nullify(&u->valve, &rx, &tx);
    e->up_usage = panel_add_sat(e->up_usage, rx);   /* user's UPLOAD == server's RX */
    e->down_usage = panel_add_sat(e->down_usage, tx); /* user's DOWNLOAD == server's TX */
}

/* ------------------------------------------------------------------ */
/* Lifetime                                                            */
/* ------------------------------------------------------------------ */

static void panel_upload_timer_cb(cloak_reactor_t *r, void *userdata);

static void panel_arm_timer(cloak_userpanel_t *p) {
    p->upload_timer = cloak_reactor_add_timer(p->cfg.reactor, p->cfg.upload_interval_ms,
                                              panel_upload_timer_cb, p);
}

static void panel_upload_timer_cb(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_userpanel_t *p = userdata;
    p->upload_timer = CLOAK_TIMER_INVALID; /* this timer has fired -- nothing left to cancel */

    (void)cloak_userpanel_upload_now(p);

    /* Re-armed AFTER the cycle, not before: the reactor's timers are
     * one-shot, and arming first would let a slow upload stack a second
     * cycle on top of itself. A failure here is logged rather than
     * retried, because there is no later event that would retry it -- the
     * panel keeps authorising and metering, it just stops settling. */
    panel_arm_timer(p);
    if (p->upload_timer == CLOAK_TIMER_INVALID) {
        CLOAK_LOGE("userpanel: could not re-arm the upload timer -- usage will accumulate but "
                   "will no longer be settled into the database");
    }
}

int cloak_userpanel_open(cloak_userpanel_t **out, const cloak_userpanel_config_t *cfg) {
    /* *out first, before validating anything, so a caller whose cleanup
     * path calls cloak_userpanel_close(*out) after a rejected open closes
     * NULL rather than an uninitialized pointer. */
    if (out != NULL) {
        *out = NULL;
    }
    if (out == NULL || cfg == NULL || cfg->manager == NULL || cfg->registry == NULL ||
        cfg->reactor == NULL) {
        return CLOAK_USER_ERR_ARG;
    }
    if (cfg->on_session_closing == NULL && !cfg->no_relays) {
        /* CONTAINMENT BY CONSTRUCTION, not a style check. Closing a
         * user's sessions by UID fires no on_broken, which is the only
         * window in which a cloak_stream_relay_t bound to them can still
         * be stopped -- so a caller that runs a cloak_proxy_t and forgot
         * this hook gets a use-after-free on the next upstream byte after
         * the first out-of-credit user is terminated. A NULL field in a
         * memset(0) config is invisible at every other moment; refusing
         * the open is the only point at which it can still be cheap.
         * See cloak_userpanel_session_closing_cb and no_relays. */
        CLOAK_LOGE("userpanel: config has no on_session_closing and does not set no_relays -- "
                   "refusing to open. Every session this panel closes would go down without "
                   "the owner being given the one window in which relays bound to it can be "
                   "stopped.");
        return CLOAK_USER_ERR_ARG;
    }

    cloak_userpanel_t *p = calloc(1, sizeof(*p));
    if (p == NULL) {
        return CLOAK_USERPANEL_ERR_ALLOC;
    }
    p->cfg = *cfg;
    if (p->cfg.upload_interval_ms == 0) {
        p->cfg.upload_interval_ms = CLOAK_USERPANEL_DEFAULT_UPLOAD_INTERVAL_MS;
    }

    panel_arm_timer(p);
    if (p->upload_timer == CLOAK_TIMER_INVALID) {
        /* A panel that cannot run its timer never bills anybody, which is
         * a silent free-service bug rather than a degraded mode -- fail
         * the open instead. */
        free(p);
        return CLOAK_USERPANEL_ERR_ALLOC;
    }

    *out = p;
    return 0;
}

void cloak_userpanel_close(cloak_userpanel_t *p) {
    if (p == NULL) {
        return;
    }
    cloak_reactor_cancel_timer(p->cfg.reactor, p->upload_timer);
    p->upload_timer = CLOAK_TIMER_INVALID;

    /* Frees every active user WITHOUT closing its sessions -- see this
     * function's doc comment for the ordering that makes that safe (the
     * registry must already be gone). */
    for (size_t i = 0; i < CLOAK_USERPANEL_MAX_ACTIVE_USERS; i++) {
        free(p->active[i]);
        p->active[i] = NULL;
    }
    free(p);
}

/* ------------------------------------------------------------------ */
/* Users                                                               */
/* ------------------------------------------------------------------ */

cloak_valve_t *cloak_userpanel_user_valve(cloak_userpanel_user_t *u) {
    if (u == NULL || u->bypass) {
        return NULL; /* cloak/valve.h: NULL means "not metered" */
    }
    return &u->valve;
}

int cloak_userpanel_get_user(cloak_userpanel_t *p, const uint8_t uid[CLOAK_UID_LEN],
                             cloak_userpanel_user_t **out) {
    if (out != NULL) {
        *out = NULL;
    }
    if (p == NULL || uid == NULL || out == NULL) {
        return CLOAK_USER_ERR_ARG;
    }

    cloak_userpanel_user_t *existing = panel_find(p, uid);
    if (existing != NULL) {
        *out = existing;
        return 0;
    }

    /* The cap is checked BEFORE the manager is consulted, not after: an
     * authenticate is a synchronous SQLite read on the reactor thread
     * (cloak/usermanager.h), and a full table would otherwise let anyone
     * who can reach the handshake force one per connection attempt for a
     * user that can never be admitted anyway. */
    int has_room = 0;
    for (size_t i = 0; i < CLOAK_USERPANEL_MAX_ACTIVE_USERS && !has_room; i++) {
        has_room = p->active[i] == NULL;
    }
    if (!has_room) {
        return CLOAK_USERPANEL_ERR_FULL;
    }

    int64_t up_rate = 0, down_rate = 0;
    int rc = cloak_usermanager_authenticate(p->cfg.manager, uid, &up_rate, &down_rate);
    if (rc != 0) {
        return rc; /* the manager's own code, verbatim; nothing created */
    }

    int err = 0;
    cloak_userpanel_user_t *u = panel_new_user(p, uid, 0, &err);
    if (u == NULL) {
        return err;
    }
    u->up_rate = up_rate;
    u->down_rate = down_rate;

    /* THIS IS THE SINGLE POINT AT WHICH A USER'S up/down BECOMES THE
     * SERVER'S rx/tx ON THE WAY IN -- the only other conversion in this
     * tree is panel_drain_user above, which does the same conversion in
     * the same direction on the way OUT. A user's UPLOAD is the server's
     * RX; a user's DOWNLOAD is the server's TX. So up_rate paces rx and
     * down_rate paces tx, and transposing them would throttle every
     * user's download against their upload allowance with no error
     * raised anywhere. cloak/valve.h states the rule and forbids a third
     * site.
     *
     * THE TEST THAT PINS THIS LINE is
     * test_rates_reach_the_valve_in_the_right_direction, in
     * libcloak-server/tests/test_userpanel.c. It gives one user an
     * up_rate and no down_rate and another the mirror image, so a
     * transposition cannot produce the same numbers in either half.
     * Nothing else in the suite catches it: before that case existed,
     * swapping these two arguments left all 45 tests green.
     *
     * A rate of 0 (unthrottled, and what every row that never set one
     * holds) leaves the bucket doing no arithmetic at all, which is why
     * this is unconditional rather than guarded. */
    cloak_valve_set_rates(&u->valve, /* rx = */ up_rate, /* tx = */ down_rate);

    char b64[33];
    panel_uid_str(uid, b64);
    CLOAK_LOGI("userpanel: new active user %s", b64);

    *out = u;
    return 0;
}

int cloak_userpanel_get_bypass_user(cloak_userpanel_t *p, const uint8_t uid[CLOAK_UID_LEN],
                                    cloak_userpanel_user_t **out) {
    if (out != NULL) {
        *out = NULL;
    }
    if (p == NULL || uid == NULL || out == NULL) {
        return CLOAK_USER_ERR_ARG;
    }

    cloak_userpanel_user_t *existing = panel_find(p, uid);
    if (existing != NULL) {
        /* Returned as-is even if it is a metered, non-bypass user: see
         * the doc comment. */
        *out = existing;
        return 0;
    }

    int err = 0;
    cloak_userpanel_user_t *u = panel_new_user(p, uid, 1, &err);
    if (u == NULL) {
        return err;
    }

    char b64[33];
    panel_uid_str(uid, b64);
    CLOAK_LOGI("userpanel: new active bypass user %s", b64);

    *out = u;
    return 0;
}

cloak_userpanel_user_t *cloak_userpanel_find(cloak_userpanel_t *p,
                                             const uint8_t uid[CLOAK_UID_LEN]) {
    if (p == NULL || uid == NULL) {
        return NULL;
    }
    return panel_find(p, uid);
}

cloak_usermanager_t *cloak_userpanel_manager(cloak_userpanel_t *p) {
    return p == NULL ? NULL : p->cfg.manager;
}

size_t cloak_userpanel_active_count(const cloak_userpanel_t *p) {
    if (p == NULL) {
        return 0;
    }
    size_t n = 0;
    for (size_t i = 0; i < CLOAK_USERPANEL_MAX_ACTIVE_USERS; i++) {
        if (p->active[i] != NULL) {
            n++;
        }
    }
    return n;
}

/* A cloak_registry_closing_cb: forwards each session about to be closed
 * to the owner's on_session_closing, which is where a proxy stops the
 * relays bound to it. See cloak_userpanel_session_closing_cb. */
static void panel_on_session_closing(cloak_server_registry_t *reg, cloak_session_t *sesh,
                                     const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                                     void *userdata) {
    (void)reg;
    (void)sesh;
    cloak_userpanel_t *p = userdata;
    if (p->cfg.on_session_closing != NULL) {
        p->cfg.on_session_closing(uid, session_id, p->cfg.on_session_closing_userdata);
    }
}

void cloak_userpanel_terminate(cloak_userpanel_t *p, cloak_userpanel_user_t *user,
                               const char *reason) {
    if (p == NULL || user == NULL) {
        return;
    }
    if (user->terminating) {
        /* THE RE-ENTRANCY GUARD. Reached when on_session_closing (owner
         * code, invoked from the close below) calls back into this module
         * -- directly, or through cloak_userpanel_notify_session_closed.
         * Without this, the nested call would drain a valve that is about
         * to be freed and then free the entry a second time. See the doc
         * comment for why a guard rather than genuine re-entrancy. */
        return;
    }
    user->terminating = 1;

    char b64[33];
    panel_uid_str(user->uid, b64);
    CLOAK_LOGI("userpanel: terminating active user %s (%s)", b64,
               reason != NULL ? reason : "no reason given");

    /* 1. Bill what this user moved. Must happen before the sessions go:
     * they are what is still adding to the valve.
     *
     * KNOWN AND ACCEPTED: the bytes step 2 itself causes are lost.
     * session_close_internal's closing-session frame goes out through
     * cloak_switchboard_send, which adds them to a valve that step 3 then
     * frees, so they reach no queue entry and no database row. Draining
     * again after step 2 would recover them, at the cost of a second
     * conversion site for the same user's usage -- the exact thing
     * cloak/valve.h forbids -- and a second queue slot that a full queue
     * could refuse with nowhere to put the bytes. It is a few padded
     * frames per termination, charged to nobody, and only for users who
     * have already run out of credit. Recorded rather than fixed. */
    panel_drain_user(p, user, 1);

    /* 2. Close every session -- including any that is itself mid-teardown,
     * which is why this cannot be a loop over
     * cloak_server_registry_close. Synchronous and complete: when this
     * returns, nothing holds a pointer to user->valve any more, which is
     * what makes the free in step 3 safe.
     *
     * Note it passes user->uid, the panel's OWN copy, never a uid pointer
     * a caller handed in: the common caller is
     * cloak_userpanel_notify_session_closed reached from a
     * cloak_registry_broken_cb, whose uid argument points INTO the
     * registry entry this call is about to free. */
    (void)cloak_server_registry_close_all_for_uid(p->cfg.registry, user->uid,
                                                  panel_on_session_closing, p);

    /* 3. Unlink and free. The entry is found by identity, not by UID: a
     * reentrant get_user during step 2 can legitimately have installed a
     * SECOND entry for the same UID (panel_find skips this terminating
     * one), and freeing that one instead would leave a live session
     * pointing at a freed valve. */
    for (size_t i = 0; i < CLOAK_USERPANEL_MAX_ACTIVE_USERS; i++) {
        if (p->active[i] == user) {
            p->active[i] = NULL;
            break;
        }
    }
    free(user);
}

void cloak_userpanel_notify_session_closed(cloak_userpanel_t *p,
                                           const uint8_t uid[CLOAK_UID_LEN]) {
    if (p == NULL || uid == NULL) {
        return;
    }
    cloak_userpanel_user_t *user = panel_find(p, uid);
    if (user == NULL) {
        return; /* not active, or already being terminated */
    }
    if (cloak_server_registry_count_for_uid(p->cfg.registry, uid) > 0) {
        return; /* other sessions of this user are still up */
    }
    cloak_userpanel_terminate(p, user, "no session left");
}

void cloak_userpanel_registry_broken(cloak_server_registry_t *reg, cloak_session_t *sesh,
                                     const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                                     void *userdata) {
    (void)reg;
    (void)sesh;
    (void)session_id;
    if (userdata == NULL || uid == NULL) {
        return;
    }
    cloak_userpanel_notify_session_closed(userdata, uid);
}

/* ------------------------------------------------------------------ */
/* The periodic upload                                                 */
/* ------------------------------------------------------------------ */

/* Does this UID have usage sitting in the queue that has not been
 * settled? A zeroed entry (one the drain created for an idle user) does
 * not count: it carries nothing anyone could lose. */
static int panel_has_queued_usage(const cloak_userpanel_t *p, const uint8_t uid[CLOAK_UID_LEN]) {
    for (size_t i = 0; i < p->queue_n; i++) {
        if (memcmp(p->queue[i].uid, uid, CLOAK_UID_LEN) == 0) {
            return p->queue[i].up_usage != 0 || p->queue[i].down_usage != 0;
        }
    }
    return 0;
}

/* Step 4 of the cycle: terminate every active, non-bypass user that holds
 * no sessions and has nothing outstanding in the queue.
 *
 * This is a PROPERTY, not a path. cloak_server_registry_close fires no
 * on_broken and no other notification, and it is the function the
 * dispatcher calls most often on its unwind routes -- so an entry created
 * by cloak_userpanel_get_user can lose its session without the panel ever
 * being told, and would otherwise occupy a table slot for the rest of the
 * process. Enumerating those routes is what the previous branch tried;
 * the same leak was found three times, once per route. See
 * cloak_userpanel_upload_now's doc comment, including the one obligation
 * this places on callers (a user acquires its first session in the same
 * reactor turn it is created in).
 *
 * The "nothing outstanding" half is what keeps this from interacting with
 * a failed upload: a user whose bytes are still queued stays active for
 * one more cycle, so its status line still reports active = 1 for the
 * interval in which it actually moved them. */
static void panel_reap_sessionless(cloak_userpanel_t *p) {
    for (size_t i = 0; i < CLOAK_USERPANEL_MAX_ACTIVE_USERS; i++) {
        cloak_userpanel_user_t *u = p->active[i];
        if (u == NULL || u->bypass || u->terminating) {
            continue;
        }
        if (cloak_server_registry_count_for_uid(p->cfg.registry, u->uid) != 0) {
            continue;
        }
        if (panel_has_queued_usage(p, u->uid)) {
            continue;
        }
        if (cloak_valve_rx(&u->valve) != 0 || cloak_valve_tx(&u->valve) != 0) {
            /* NOT "nothing queued" -- "nothing to lose". At the queue cap
             * the drain above deliberately leaves a user's bytes in its
             * valve and creates no queue entry, so "no queued usage" is
             * ALSO true of a user carrying a full interval of unbilled
             * traffic. Reaping that user would free the valve, and the
             * terminate doing it runs with in_cycle set, so the forced
             * flush that would otherwise rescue the bytes is skipped and
             * they are dropped with a warning: traffic billed to nobody.
             * Leaving such a user active costs one table slot until room
             * appears, which is what happened before the reaper existed. */
            continue;
        }
        /* Frees p->active[i] and clears that slot; no other slot moves,
         * so continuing the scan from here is safe. */
        cloak_userpanel_terminate(p, u, "no sessions left (reaped)");
    }
}

/* One whole cycle. The caller must have established that no cycle is
 * already running -- panel_run_cycle sets and clears in_cycle itself. */
static int panel_run_cycle(cloak_userpanel_t *p) {
    p->in_cycle = 1;
    int rc = panel_cycle_body(p);
    p->in_cycle = 0;
    return rc;
}

int cloak_userpanel_upload_now(cloak_userpanel_t *p) {
    if (p == NULL) {
        return CLOAK_USER_ERR_ARG;
    }
    if (p->in_cycle) {
        /* Refused rather than allowed to rewrite the queue and terminate
         * list the outer cycle is still using -- see this function's doc
         * comment. Reached from an owner's on_session_closing, which is
         * documented as forbidden; this is the containment, not the
         * permission. */
        CLOAK_LOGW("userpanel: upload requested from inside an upload cycle -- refused (it "
                   "would rewrite the batch the outer cycle is committing)");
        return 0;
    }
    return panel_run_cycle(p);
}

static int panel_cycle_body(cloak_userpanel_t *p) {
    /* 1. DRAIN every active, non-bypass user. Go's updateUsageQueue. */
    for (size_t i = 0; i < CLOAK_USERPANEL_MAX_ACTIVE_USERS; i++) {
        cloak_userpanel_user_t *u = p->active[i];
        if (u != NULL && !u->terminating) {
            panel_drain_user(p, u, 0);
        }
    }

    /* Matches Go's early return: no transaction at all. Step 4 still
     * runs -- a leaked entry has no usage to send, so an early return
     * that skipped the reap would skip exactly the case the reap exists
     * for. */
    if (p->queue_n == 0) {
        panel_reap_sessionless(p);
        return 0;
    }

    /* 2. COMMIT. The queue may well contain UIDs that are no longer
     * active -- that is the whole reason it is a separate structure --
     * and those are reported with active = 0 and num_session = 0. */
    int64_t now = panel_now(p);
    for (size_t i = 0; i < p->queue_n; i++) {
        cloak_user_status_t *s = &p->statuses[i];
        memset(s, 0, sizeof(*s));
        memcpy(s->uid, p->queue[i].uid, CLOAK_UID_LEN);
        s->up_usage = p->queue[i].up_usage;
        s->down_usage = p->queue[i].down_usage;
        s->active = cloak_userpanel_find(p, p->queue[i].uid) != NULL;
        s->num_session =
            s->active ? (int)cloak_server_registry_count_for_uid(p->cfg.registry, s->uid) : 0;
        s->timestamp = now;
    }

    size_t n_term = 0;
    int rc = cloak_usermanager_upload_status(p->cfg.manager, p->statuses, p->queue_n,
                                            p->terminates, CLOAK_USERPANEL_MAX_QUEUED_USERS,
                                            &n_term);
    if (rc != 0) {
        /* THE QUEUE IS KEPT, NOT DISCARDED. upload_status is one
         * transaction, so on failure nothing was written and re-sending
         * the same totals next tick is correct rather than a double
         * charge. The common cause is another writer holding the database
         * lock (busy_timeout is 0 by design), which clears by itself.
         * Go empties its queue before uploading and therefore loses the
         * interval; this deliberately does not. */
        CLOAK_LOGW("userpanel: upload of %d usage record(s) failed (%d) -- kept queued for the "
                   "next interval",
                   (int)p->queue_n, rc);
        /* The reap does not depend on the upload having succeeded: a
         * sessionless user with nothing outstanding is leaked whether or
         * not the database is reachable, and a sustained failure is
         * precisely when the table must not also fill up. */
        panel_reap_sessionless(p);
        return rc;
    }

    /* Cleared only now, and BEFORE the terminations below: terminating a
     * user drains its valve onto this same queue, and that usage belongs
     * to the NEXT batch, not to the one just committed. */
    p->queue_n = 0;

    /* Defensive only: out_cap is the queue's own cap and n_term can never
     * exceed the number of updates sent, which is at most that. */
    if (n_term > CLOAK_USERPANEL_MAX_QUEUED_USERS) {
        n_term = CLOAK_USERPANEL_MAX_QUEUED_USERS;
    }

    /* 3. TERMINATE whoever the database says has run out. */
    for (size_t i = 0; i < n_term; i++) {
        cloak_userpanel_user_t *u = cloak_userpanel_find(p, p->terminates[i].uid);
        if (u != NULL) {
            cloak_userpanel_terminate(p, u, p->terminates[i].reason);
        }
    }

    /* 4. REAP whoever nothing ever told us about. */
    panel_reap_sessionless(p);
    return 0;
}
