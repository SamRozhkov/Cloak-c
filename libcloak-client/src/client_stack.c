#define _POSIX_C_SOURCE 200809L

#include "cloak/client_stack.h"

#include "cloak/common.h"
#include "cloak/log.h"
#include "cloak/session.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* THE ENTIRE POINT OF THIS FILE is that the nine edges, the five
 * callbacks and the reconnect loop live in ONE place and a caller cannot
 * reach any of them. Read cloak/client_stack.h first; the argument for
 * every decision below is there, next to the field or function it
 * governs, rather than here.
 *
 * THE STRUCT IS DEFINED HERE, NOT IN THE HEADER, and that is
 * load-bearing rather than tidiness: cloak_client_piper_t and
 * cloak_client_connector_t are both PUBLIC structs with writable wiring
 * fields, so a stack held by value would let a caller write
 * `st.piper.cfg.chain = ...` -- displacing the piper's own on_broken,
 * which is a use-after-free rather than a customisation -- or
 * `st.piper.sesh = NULL` mid-flight. cloak/server_stack.h's header
 * records the review that established this, and what it cost.
 *
 * NOTHING AT FILE SCOPE IS MUTABLE, and that is a requirement rather
 * than a style: singleplex creates and destroys one of everything below
 * per accepted local connection, with overlapping lifetimes. Every
 * bring-up's state lives in its own heap block. */

/* ------------------------------------------------------------------ */
/* One bring-up, and the session it produces                           */
/* ------------------------------------------------------------------ */

typedef enum {
    /* A connector is dialling or handshaking, or the slot is waiting out
     * a backoff between rounds. */
    SLOT_PENDING = 0,
    /* sesh holds a live session that the piper has been given. */
    SLOT_LIVE = 1,
} slot_state_t;

typedef struct stack_slot {
    cloak_client_stack_t *st;

    /* SINGLEPLEX: the piper context this bring-up exists FOR, until it
     * has been answered or cancelled. NULL for the shared slot, and NULL
     * again the instant either answer is given -- which is how edge E6
     * ("exactly one answer, and none after cancel_session") is kept by
     * construction rather than by discipline. Never dereferenced: it is
     * an opaque key, exactly as cloak/client_piper.h says. */
    cloak_client_piper_conn_t *ctx;
    int shared;

    slot_state_t state;

    cloak_client_connector_t c;
    int connector_ready;

    /* The session's storage. It must be at a FIXED address from
     * cloak_client_connector_init until the session is destroyed, which
     * is exactly why every slot is its own heap block and not an entry
     * in an array this module might grow. */
    cloak_session_t sesh;
    int session_live;

    uint32_t session_id;
    int round; /* rounds STARTED for this bring-up, 1-based */
    cloak_timer_id_t retry_timer;

    struct stack_slot *prev, *next;
} stack_slot_t;

struct cloak_client_stack {
    /* Set to the struct's own address at open. A handle is heap-allocated
     * and its definition is private, so a caller cannot copy one. This
     * turns a wild pointer into a refusal rather than a wild write. */
    void *self;

    cloak_client_stack_config_t cfg; /* copied by value, defaults filled in */

    /* THE STACK'S OWN COPY OF THE CLIENT CONFIG, and the reason the
     * caller's may die the moment open returns: every bring-up reads the
     * uid, the server key, the proxy method and the server name out of
     * it, and in singleplex that happens on the accept path. It is a pure
     * POD, so one memcpy removes the whole class. */
    cloak_client_config_t config;

    cloak_reactor_t *reactor; /* borrowed */

    /* EDGE E5: resolved ONCE, at open, because cloak_net_resolve blocks
     * and singleplex would otherwise put a synchronous DNS lookup on the
     * accept path. */
    cloak_addr_t remote;

    cloak_client_piper_t piper;
    int piper_ready;

    cloak_listener_t local;
    int have_local;
    int local_port;

    stack_slot_t *slots; /* intrusive list; one entry per bring-up */
    size_t pending;
    size_t live;

    size_t rounds_started;
    size_t reconnects;
    size_t sessions_up;
    size_t sessions_failed;
    size_t sessions_down;
};

/* Every accessor goes through this, so a handle that did not come from
 * cloak_client_stack_open answers like a NULL one instead of being
 * dereferenced. */
static int stack_valid(const cloak_client_stack_t *s) {
    return s != NULL && s->self == (const void *)s;
}

/* ------------------------------------------------------------------ */
/* Error reporting                                                      */
/* ------------------------------------------------------------------ */

const char *cloak_client_stack_strerror(int code) {
    switch (code) {
    case 0:
        return "ok";
    case CLOAK_CLIENT_STACK_ERR_ARG:
        return "argument";
    case CLOAK_CLIENT_STACK_ERR_CONFIG:
        return "client config";
    case CLOAK_CLIENT_STACK_ERR_TEMPLATE:
        return "session template";
    case CLOAK_CLIENT_STACK_ERR_RESOLVE:
        return "remote address";
    case CLOAK_CLIENT_STACK_ERR_PIPER:
        return "local piper";
    case CLOAK_CLIENT_STACK_ERR_LISTEN:
        return "local address";
    case CLOAK_CLIENT_STACK_ERR_CONNECTOR:
        return "first bring-up";
    default:
        return "unknown";
    }
}

const char *cloak_client_stack_event_name(cloak_client_stack_event_t ev) {
    switch (ev) {
    case CLOAK_CLIENT_STACK_EVENT_ROUND_STARTED:
        return "round started";
    case CLOAK_CLIENT_STACK_EVENT_ROUND_FAILED:
        return "round failed";
    case CLOAK_CLIENT_STACK_EVENT_SESSION_UP:
        return "session up";
    case CLOAK_CLIENT_STACK_EVENT_SESSION_DOWN:
        return "session down";
    case CLOAK_CLIENT_STACK_EVENT_GAVE_UP:
        return "gave up";
    default:
        return "unknown";
    }
}

/* Every failure path goes through this, so every one of them NAMES ITS
 * EDGE rather than reporting that something, somewhere, returned -1. */
static void stack_err(char *err, size_t err_cap, const char *fmt, ...) {
    if (err == NULL || err_cap == 0) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(err, err_cap, fmt, ap);
    va_end(ap);
    err[err_cap - 1] = '\0';
}

static void stack_emit(cloak_client_stack_t *s, cloak_client_stack_event_t ev, uint32_t session_id,
                       int round, uint64_t retry_in_ms) {
    if (s->cfg.on_event == NULL) {
        return;
    }
    s->cfg.on_event(s, ev, session_id, round, retry_in_ms, s->cfg.on_event_userdata);
}

/* ------------------------------------------------------------------ */
/* Session ids -- edge E4                                               */
/* ------------------------------------------------------------------ */

/* Is id one this stack is already using? The predicate is its own
 * function, and not folded into the draw below, because it is the half
 * that can be tested directly: a draw is random and a mutation to it
 * hides in the noise, whereas this answers a question with one right
 * answer for a list a test can build by hand. */
static int stack_id_in_use(const cloak_client_stack_t *s, uint32_t id) {
    for (const stack_slot_t *sl = s->slots; sl != NULL; sl = sl->next) {
        if (sl->session_id == id) {
            return 1;
        }
    }
    return 0;
}

/* A fresh session id, distinct from every id this stack currently holds.
 *
 * WHY NOT ZERO: the server calls a session ADMIN when the uid is the
 * admin uid AND the session id is 0 (cloak/dispatcher.h), so an id of 0
 * would route an ordinary client holding an admin uid into the admin API
 * instead of the proxy. Cheap to exclude, and the alternative is a
 * failure that only appears for one particular uid.
 *
 * WHY DISTINCT: the server's registry is keyed by (uid, session id), so
 * two of this client's live sessions sharing an id are ATTACHED TO EACH
 * OTHER on the server -- in singleplex, silently undoing the isolation
 * the mode exists to provide.
 *
 * AND THAT IS WHY A RECONNECT'S ID DIFFERS FROM THE ONE IT REPLACES
 * STRUCTURALLY RATHER THAN PROBABILISTICALLY: the slot carrying the id
 * being replaced is still in the list when the new one is drawn, both on
 * the retry path (the same slot keeps its old id until this returns) and
 * on the broken-session path (the replacement slot is seeded with the
 * dead session's id before its first round). A 1-in-2^32 coincidence
 * cannot make a reconnect reuse an id.
 *
 * The draw is bounded at 64 tries and returns the last non-zero
 * candidate if every one of them collided, which with at most a few
 * hundred live ids out of 2^32-1 is not an outcome that happens; the
 * bound is there so that a broken CSPRNG is a wrong id rather than a
 * hung reactor. */
static uint32_t stack_pick_session_id(const cloak_client_stack_t *s) {
    uint32_t id = 1;
    for (int i = 0; i < 64; i++) {
        uint32_t cand = 0;
        cloak_random_bytes((uint8_t *)&cand, sizeof(cand));
        if (cand == 0) {
            continue;
        }
        id = cand;
        if (!stack_id_in_use(s, cand)) {
            break;
        }
    }
    return id;
}

/* ------------------------------------------------------------------ */
/* The backoff ladder                                                   */
/* ------------------------------------------------------------------ */

/* The delay BEFORE round `round`. Round 1 runs immediately; round 2
 * waits base, round 3 waits 2*base, doubling to the cap, then jittered
 * by +/-CLOAK_CLIENT_STACK_RECONNECT_JITTER_PCT around that value.
 *
 * IT TAKES THE BASE RATHER THAN THE STACK so that the ladder can be
 * tested for what it is -- a function of two numbers -- without standing
 * a client up. See cloak/client_stack.h for why the cap is 30 s rather
 * than the connector's 8 s, and why the jitter is symmetric.
 *
 * The jitter draws one byte and scales, exactly as the connector's
 * backoff_ms does: the quantity being randomised is a delay whose
 * distribution matters not at all (only that nothing retries in
 * lockstep), so 1/256 granularity is ample and the two ladders stay
 * legible as one idea. */
static uint64_t stack_backoff_ms(uint64_t base, int round) {
    if (round <= 1) {
        return 0;
    }
    uint64_t delay = base;
    for (int i = 2; i < round && delay < CLOAK_CLIENT_STACK_MAX_RECONNECT_DELAY_MS; i++) {
        delay *= 2;
    }
    if (delay > CLOAK_CLIENT_STACK_MAX_RECONNECT_DELAY_MS) {
        delay = CLOAK_CLIENT_STACK_MAX_RECONNECT_DELAY_MS;
    }
    uint8_t r = 0;
    cloak_random_bytes(&r, 1);
    /* [delay - span, delay + span), centred on delay. */
    uint64_t span = delay * (uint64_t)CLOAK_CLIENT_STACK_RECONNECT_JITTER_PCT / 100u;
    return delay - span + (2u * span) * (uint64_t)r / 256u;
}

/* ------------------------------------------------------------------ */
/* Slots                                                                */
/* ------------------------------------------------------------------ */

static stack_slot_t *stack_slot_new(cloak_client_stack_t *s, cloak_client_piper_conn_t *ctx,
                                    int shared) {
    stack_slot_t *sl = calloc(1, sizeof(*sl));
    if (sl == NULL) {
        return NULL;
    }
    sl->st = s;
    sl->ctx = ctx;
    sl->shared = shared;
    sl->state = SLOT_PENDING;
    sl->retry_timer = CLOAK_TIMER_INVALID;
    sl->next = s->slots;
    if (s->slots != NULL) {
        s->slots->prev = sl;
    }
    s->slots = sl;
    s->pending++;
    return sl;
}

/* Releases everything one bring-up holds, in the one order that works,
 * and frees the slot. The ONLY place any of it is released.
 *
 * The connector is destroyed before the session because
 * cloak_client_connector_destroy tears down dials and handshakes WITHOUT
 * firing on_done (edge E7) and, after a DONE completion, does not touch
 * the session at all -- so the two steps are independent in that order
 * and only in that order. */
static void stack_slot_destroy(cloak_client_stack_t *s, stack_slot_t *sl) {
    if (sl->prev != NULL) {
        sl->prev->next = sl->next;
    } else {
        s->slots = sl->next;
    }
    if (sl->next != NULL) {
        sl->next->prev = sl->prev;
    }
    sl->prev = NULL;
    sl->next = NULL;

    if (sl->state == SLOT_PENDING) {
        s->pending--;
    } else {
        s->live--;
    }

    if (sl->retry_timer != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(s->reactor, sl->retry_timer);
        sl->retry_timer = CLOAK_TIMER_INVALID;
    }
    if (sl->connector_ready) {
        cloak_client_connector_destroy(&sl->c);
        sl->connector_ready = 0;
    }
    if (sl->session_live) {
        /* EDGE E8: a session is reaped HERE and nowhere else. The piper
         * only ever CLOSES a singleplex session (cloak/client_piper.h);
         * the storage and the destroy are this module's. */
        cloak_session_destroy(&sl->sesh);
        sl->session_live = 0;
    }
    free(sl);
}

static stack_slot_t *stack_find_by_session(cloak_client_stack_t *s, const cloak_session_t *sesh) {
    for (stack_slot_t *sl = s->slots; sl != NULL; sl = sl->next) {
        if (sl->session_live && &sl->sesh == sesh) {
            return sl;
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* The reconnect loop                                                   */
/* ------------------------------------------------------------------ */

static void stack_conn_done(cloak_client_connector_t *c, cloak_client_connector_status_t status,
                            cloak_session_t *session, void *userdata);

static cloak_client_browser_t stack_browser(cloak_browser_t b) {
    /* Mapped rather than cast. The two enumerations happen to agree
     * today, and a cast would keep compiling on the day one of them
     * gains a member -- producing a fingerprint nobody chose. */
    switch (b) {
    case CLOAK_BROWSER_FIREFOX:
        return CLOAK_CLIENT_BROWSER_FIREFOX;
    case CLOAK_BROWSER_SAFARI:
        return CLOAK_CLIENT_BROWSER_SAFARI;
    case CLOAK_BROWSER_CHROME:
    default:
        return CLOAK_CLIENT_BROWSER_CHROME;
    }
}

/* Starts ONE round of one bring-up: a fresh session id, a fresh
 * connector over the resolved remote, and the piper installed into the
 * session template it is about to copy.
 *
 * Returns 0 if the round started (its outcome arrives at
 * stack_conn_done, never from inside this call), -1 if it could not be
 * started at all. */
static int stack_start_round(cloak_client_stack_t *s, stack_slot_t *sl, int by_reconnect) {
    const cloak_client_config_t *c = &s->config;

    /* EDGE E4, and the order matters: the id is drawn while this slot is
     * still in the list carrying the PREVIOUS one, which is what makes a
     * reconnect's id structurally different rather than probably
     * different. */
    sl->session_id = stack_pick_session_id(s);
    sl->round++;

    cloak_client_connector_config_t cc;
    memset(&cc, 0, sizeof(cc));
    cc.reactor = s->reactor;
    cc.remote = s->remote; /* EDGE E5: resolved once, at open */
    cc.num_conn = c->num_conn;
    cc.session = &sl->sesh;
    cc.browser = stack_browser(c->browser);
    cc.transport = c->transport;
    cc.server_name = c->server_name;
    memcpy(cc.server_pub, c->server_pub_key, CLOAK_X25519_KEY_LEN);
    memcpy(cc.uid, c->uid, CLOAK_UID_LEN);
    cc.proxy_method = c->proxy_method;
    cc.encryption_method = (uint8_t)c->encryption_method;
    cc.session_id = sl->session_id;
    cc.unordered = c->udp;
    cc.dial_timeout_ms = s->cfg.dial_timeout_ms;
    cc.handshake_timeout_ms = s->cfg.handshake_timeout_ms;
    cc.max_attempts = s->cfg.connector_max_attempts;
    cc.retry_base_ms = s->cfg.connector_retry_base_ms;
    cc.now_fn = s->cfg.now_fn;
    cc.now_userdata = s->cfg.now_userdata;
    cc.session_template = s->cfg.session_template;
    cc.on_done = stack_conn_done;
    cc.on_done_userdata = sl;

    /* EDGES E1 AND E3, AND THE ONE THAT FAILS SILENTLY. This has to
     * happen BEFORE cloak_client_connector_init, which copies the
     * template by value: a session built from a template with no
     * callbacks in it establishes perfectly and then carries nothing,
     * forever, with no error anywhere. E3 is that this runs for EVERY
     * round, not only the first -- a replacement session wired without
     * it is the same silent failure arriving minutes later. */
    cloak_client_piper_install(&s->piper, &cc.session_template);

    if (cloak_client_connector_init(&sl->c, &cc) != 0) {
        return -1;
    }
    sl->connector_ready = 1;
    if (cloak_client_connector_start(&sl->c) != 0) {
        cloak_client_connector_destroy(&sl->c);
        sl->connector_ready = 0;
        return -1;
    }

    s->rounds_started++;
    if (by_reconnect) {
        s->reconnects++;
    }
    stack_emit(s, CLOAK_CLIENT_STACK_EVENT_ROUND_STARTED, sl->session_id, sl->round, 0);
    return 0;
}

/* This bring-up is over and produced nothing. In singleplex that closes
 * ONE local connection and affects nothing else; in shared mode the
 * client has no session until a caller closes and reopens the stack. */
static void stack_give_up(cloak_client_stack_t *s, stack_slot_t *sl) {
    uint32_t id = sl->session_id;
    int round = sl->round;
    cloak_client_piper_conn_t *ctx = sl->ctx;
    sl->ctx = NULL; /* EDGE E6: answered exactly once, below */

    s->sessions_failed++;
    stack_slot_destroy(s, sl);
    stack_emit(s, CLOAK_CLIENT_STACK_EVENT_GAVE_UP, id, round, 0);

    if (ctx != NULL) {
        /* Closes that one local connection. May free ctx; it is not used
         * again. */
        cloak_client_piper_conn_session_failed(ctx);
    }
}

static void stack_retry_timer(cloak_reactor_t *r, void *userdata);

/* Arms the ladder for sl's next round. Returns 1 if one is scheduled and
 * 0 if there will not be one, writing the jittered delay to *delay_out
 * either way.
 *
 * THE BOUND IS CHECKED AGAINST THE ROUND THAT WILL ACTUALLY RUN
 * (sl->round + 1) WHILE THE DELAY IS COMPUTED FOR delay_round, and those
 * are deliberately two different numbers on one path: a replacement
 * after a BREAK restarts the ladder at round 1 -- the session worked, so
 * the network was fine a moment ago -- but still waits one base interval
 * rather than re-dialling inside a millisecond of the far end going
 * away. Folding them into one argument is how that path would silently
 * acquire either a hot loop or a spent bound. */
static int stack_arm_round(cloak_client_stack_t *s, stack_slot_t *sl, int delay_round,
                           uint64_t *delay_out) {
    *delay_out = 0;
    int next = sl->round + 1;
    if (s->cfg.max_rounds != CLOAK_CLIENT_STACK_ROUNDS_UNBOUNDED && next > s->cfg.max_rounds) {
        return 0;
    }
    uint64_t delay = stack_backoff_ms(s->cfg.reconnect_base_ms, delay_round);
    sl->retry_timer = cloak_reactor_add_timer(s->reactor, delay, stack_retry_timer, sl);
    if (sl->retry_timer == CLOAK_TIMER_INVALID) {
        return 0;
    }
    *delay_out = delay;
    return 1;
}

static void stack_retry_timer(cloak_reactor_t *r, void *userdata) {
    (void)r;
    stack_slot_t *sl = userdata;
    cloak_client_stack_t *s = sl->st;
    sl->retry_timer = CLOAK_TIMER_INVALID; /* fired */

    if (stack_start_round(s, sl, 1) == 0) {
        return;
    }
    /* A round that could not be STARTED is an allocation or a reactor
     * timer, not a network condition, so it is not worth another rung of
     * a ladder built for network conditions. */
    stack_emit(s, CLOAK_CLIENT_STACK_EVENT_ROUND_FAILED, sl->session_id, sl->round, 0);
    stack_give_up(s, sl);
}

/* THE CONNECTOR'S on_done -- one of the five callbacks this module owns.
 * It fires exactly once per successful start and never from inside that
 * start (cloak/client_connector.h guarantees the deferral structurally),
 * so everything here runs from reactor dispatch. */
static void stack_conn_done(cloak_client_connector_t *c, cloak_client_connector_status_t status,
                            cloak_session_t *session, void *userdata) {
    stack_slot_t *sl = userdata;
    cloak_client_stack_t *s = sl->st;

    /* Legal from inside on_done, and it never touches a session that has
     * been handed over (cloak/client_connector.h). Doing it here rather
     * than at teardown is what keeps a singleplex client from holding one
     * connector's worth of per-connection state for the whole life of
     * every local connection. */
    cloak_client_connector_destroy(c);
    sl->connector_ready = 0;

    if (status == CLOAK_CLIENT_CONNECTOR_DONE) {
        sl->session_live = 1;
        sl->state = SLOT_LIVE;
        s->pending--;
        s->live++;
        s->sessions_up++;
        stack_emit(s, CLOAK_CLIENT_STACK_EVENT_SESSION_UP, sl->session_id, sl->round, 0);

        if (sl->shared) {
            cloak_client_piper_set_session(&s->piper, &sl->sesh);
            return;
        }
        cloak_client_piper_conn_t *ctx = sl->ctx;
        sl->ctx = NULL; /* EDGE E6 */
        if (ctx != NULL) {
            /* May tear that context down synchronously if the stream
             * cannot be opened; sl is not touched again on this path. */
            cloak_client_piper_conn_session_ready(ctx, session);
        }
        return;
    }

    /* THE ROUND FAILED, which is the case this whole module exists for.
     * The connector has already spent its own bounded ladder; this one
     * decides whether there is another ROUND, and every round gets a
     * fresh session id because the server may still be holding the one
     * this round abandoned. */
    uint64_t delay = 0;
    int armed = stack_arm_round(s, sl, sl->round + 1, &delay);
    stack_emit(s, CLOAK_CLIENT_STACK_EVENT_ROUND_FAILED, sl->session_id, sl->round, delay);
    if (!armed) {
        stack_give_up(s, sl);
    }
}

/* THE PIPER'S chain -- the owner's link of the broken-session chain,
 * invoked AFTER the piper has stopped every relay bound to the dying
 * session, which is the only window in which that was still possible.
 * Reaping the session is this module's job (edge E8). */
static void stack_on_broken(cloak_session_t *sesh, void *userdata) {
    cloak_client_stack_t *s = userdata;
    stack_slot_t *sl = stack_find_by_session(s, sesh);
    if (sl == NULL) {
        return;
    }
    int shared = sl->shared;
    uint32_t dead_id = sl->session_id;

    s->sessions_down++;
    stack_slot_destroy(s, sl);
    stack_emit(s, CLOAK_CLIENT_STACK_EVENT_SESSION_DOWN, dead_id, 0, 0);

    if (!shared) {
        /* SINGLEPLEX: the local connection that owned this session is
         * already gone -- its stream ending is what closed the session --
         * so there is nothing to reconnect FOR. The next local connection
         * asks for its own. */
        return;
    }

    /* SHARED: bring a replacement up, with a FRESH id and a delay.
     *
     * THE LADDER RESTARTS AT ROUND 1 rather than continuing the previous
     * one: this session worked, so the network was fine a moment ago and
     * treating the break as the fifth failure in a row would punish a
     * client for a server that merely restarted.
     *
     * IT STILL WAITS ONE BASE INTERVAL. Re-dialling inside a millisecond
     * of a session dying produces a dial storm against exactly the far
     * end least able to absorb one, and a server that closes sessions
     * for a reason that persists would have this client in a hot loop.
     *
     * The replacement slot is SEEDED WITH THE DEAD SESSION'S ID before
     * its first round, so that stack_pick_session_id excludes it: the
     * replacement's id differs from the id it replaces structurally, not
     * with probability 1 - 2^-32. */
    stack_slot_t *ns = stack_slot_new(s, NULL, 1);
    if (ns == NULL) {
        s->sessions_failed++;
        stack_emit(s, CLOAK_CLIENT_STACK_EVENT_GAVE_UP, dead_id, 0, 0);
        return;
    }
    ns->session_id = dead_id;
    uint64_t delay = 0;
    if (!stack_arm_round(s, ns, 2, &delay)) {
        stack_give_up(s, ns);
    }
}

/* THE PIPER'S new_session -- singleplex only. One local connection has
 * sent its first byte and needs a session of its own.
 *
 * The answer must NOT be delivered from inside this call, and is not:
 * cloak_client_connector_start defers its first dial to a reactor timer,
 * so stack_conn_done cannot run before this returns. */
static int stack_new_session(cloak_client_piper_conn_t *ctx, void *userdata) {
    cloak_client_stack_t *s = userdata;
    stack_slot_t *sl = stack_slot_new(s, ctx, 0);
    if (sl == NULL) {
        return -1;
    }
    if (stack_start_round(s, sl, 0) != 0) {
        /* The piper closes that one connection itself on a -1 return, and
         * will NOT call cancel_session for a ctx it was never told about,
         * so this slot must go now. */
        sl->ctx = NULL;
        stack_slot_destroy(s, sl);
        return -1;
    }
    return 0;
}

/* THE PIPER'S cancel_session -- edge E7. "Forget ctx: the connection it
 * was for is gone." It reaches here when a singleplex connection's
 * first-byte deadline expires mid-bring-up, when the local peer goes
 * away, and from cloak_client_piper_destroy.
 *
 * cloak_client_connector_destroy is exactly the shape this needs: it
 * tears down dials and handshakes in flight WITHOUT firing on_done, so
 * nothing can later answer a ctx the piper has already freed. */
static void stack_cancel_session(cloak_client_piper_conn_t *ctx, void *userdata) {
    cloak_client_stack_t *s = userdata;
    for (stack_slot_t *sl = s->slots; sl != NULL; sl = sl->next) {
        if (sl->ctx == ctx) {
            sl->ctx = NULL; /* EDGE E6: never answered again */
            stack_slot_destroy(s, sl);
            return;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Defaults                                                            */
/* ------------------------------------------------------------------ */

static void fill_template_defaults(cloak_session_config_t *t) {
    if (t->max_on_wire_size == 0) {
        t->max_on_wire_size = CLOAK_CLIENT_STACK_DEFAULT_MAX_ON_WIRE_SIZE;
    }
    if (t->stream_recv_capacity == 0) {
        t->stream_recv_capacity = CLOAK_CLIENT_STACK_DEFAULT_STREAM_RECV_CAPACITY;
    }
    if (t->stream_max_pending_frames == 0) {
        t->stream_max_pending_frames = CLOAK_CLIENT_STACK_DEFAULT_STREAM_MAX_PENDING;
    }
    if (t->conn_send_queue_cap == 0) {
        t->conn_send_queue_cap = CLOAK_CLIENT_STACK_DEFAULT_CONN_SEND_QUEUE_CAP;
    }
    if (t->inactivity_timeout_ms == 0) {
        t->inactivity_timeout_ms = CLOAK_CLIENT_STACK_DEFAULT_INACTIVITY_TIMEOUT_MS;
    }

    /* MADE TRUE RATHER THAN DOCUMENTED. The header says these fields are
     * ignored; clearing them is what makes that a fact. The connector
     * overwrites the obfuscator with the agreed key, the valve is a
     * server-side concept, and all four callbacks belong to the piper --
     * an on_broken of a caller's own left here would displace the one
     * window in which a relay bound to a dying session can be stopped,
     * which is a use-after-free rather than a customisation. */
    memset(&t->obfuscator, 0, sizeof(t->obfuscator));
    t->valve = NULL;
    t->on_broken = NULL;
    t->on_broken_userdata = NULL;
    t->on_new_stream = NULL;
    t->on_new_stream_userdata = NULL;
    t->on_stream_data = NULL;
    t->on_stream_data_userdata = NULL;
    t->on_writable = NULL;
    t->on_writable_userdata = NULL;
}

/* "host:port", bracketing an IPv6 literal the way every other consumer
 * of cloak_net_split_hostport expects to read it back. */
static void join_hostport(char *out, size_t cap, const char *host, const char *port) {
    if (strchr(host, ':') != NULL) {
        (void)snprintf(out, cap, "[%s]:%s", host, port);
    } else {
        (void)snprintf(out, cap, "%s:%s", host, port);
    }
}

/* ------------------------------------------------------------------ */
/* Construction                                                        */
/* ------------------------------------------------------------------ */

int cloak_client_stack_open(cloak_client_stack_t **out, const cloak_client_stack_config_t *cfg,
                            char *err, size_t err_cap) {
    if (err != NULL && err_cap > 0) {
        err[0] = '\0';
    }
    if (out == NULL) {
        stack_err(err, err_cap, "argument: the out pointer is NULL");
        return CLOAK_CLIENT_STACK_ERR_ARG;
    }

    /* INITIALIZE BEFORE VALIDATING: *out is NULL from here on unless this
     * function succeeds, so a caller whose cleanup runs
     * cloak_client_stack_close(*out) on every path closes NULL rather
     * than an uninitialized pointer. */
    *out = NULL;

    if (cfg == NULL) {
        stack_err(err, err_cap, "argument: the cloak_client_stack_config_t is NULL");
        return CLOAK_CLIENT_STACK_ERR_ARG;
    }
    if (cfg->reactor == NULL) {
        stack_err(err, err_cap, "argument: the reactor is NULL and is required");
        return CLOAK_CLIENT_STACK_ERR_ARG;
    }
    if (cfg->config == NULL) {
        stack_err(err, err_cap, "argument: the parsed client config is NULL and is required");
        return CLOAK_CLIENT_STACK_ERR_ARG;
    }

    cloak_client_stack_t *s = calloc(1, sizeof(*s));
    if (s == NULL) {
        stack_err(err, err_cap, "argument: out of memory allocating the stack");
        return CLOAK_CLIENT_STACK_ERR_ARG;
    }
    s->self = s;
    s->cfg = *cfg;
    s->reactor = cfg->reactor;

    /* THE COPY. From here on the caller's cloak_client_config_t is never
     * read again -- see the field's own comment. */
    s->config = *cfg->config;
    s->cfg.config = &s->config;
    const cloak_client_config_t *c = &s->config;

    if (s->cfg.reconnect_base_ms == 0) {
        s->cfg.reconnect_base_ms = CLOAK_CLIENT_STACK_DEFAULT_RECONNECT_BASE_MS;
    }
    if (s->cfg.max_rounds < 0) {
        s->cfg.max_rounds = CLOAK_CLIENT_STACK_ROUNDS_UNBOUNDED;
    }
    fill_template_defaults(&s->cfg.session_template);

    /* ---- EDGE: the configuration itself, checked here because every
     * one of these otherwise surfaces as a connector error on the first
     * bring-up, minutes later and with a different name. */
    if (c->num_conn < 1 || c->num_conn > CLOAK_CLIENT_CONNECTOR_MAX_CONN) {
        stack_err(err, err_cap, "client config: NumConn %d is outside 1..%d", c->num_conn,
                  CLOAK_CLIENT_CONNECTOR_MAX_CONN);
        cloak_client_stack_close(s);
        return CLOAK_CLIENT_STACK_ERR_CONFIG;
    }
    if (c->singleplex && c->num_conn != 1) {
        /* Go's singleplex IS one connection per session, and the parser
         * can only produce the pair together. This catches a hand-built
         * config whose two halves disagree, which would otherwise spend a
         * full N-connection handshake per local connection while calling
         * itself the cheap-isolation mode. */
        stack_err(err, err_cap,
                  "client config: singleplex is set with NumConn %d; singleplex is one "
                  "connection per session",
                  c->num_conn);
        cloak_client_stack_close(s);
        return CLOAK_CLIENT_STACK_ERR_CONFIG;
    }
    if (c->remote_host[0] == '\0' || c->remote_port[0] == '\0') {
        stack_err(err, err_cap, "client config: RemoteHost and RemotePort are both required");
        cloak_client_stack_close(s);
        return CLOAK_CLIENT_STACK_ERR_CONFIG;
    }
    if (c->local_port[0] == '\0') {
        stack_err(err, err_cap, "client config: LocalPort is required");
        cloak_client_stack_close(s);
        return CLOAK_CLIENT_STACK_ERR_CONFIG;
    }
    if (c->proxy_method[0] == '\0') {
        stack_err(err, err_cap, "client config: ProxyMethod is required");
        cloak_client_stack_close(s);
        return CLOAK_CLIENT_STACK_ERR_CONFIG;
    }
    if (c->transport != CLOAK_TRANSPORT_DIRECT) {
        /* cloak_client_connector_init refuses every non-direct transport
         * (the WebSocket half of the CDN path is not written), and it
         * refuses it once per bring-up, forever, as a HANDSHAKE error. */
        stack_err(err, err_cap,
                  "client config: Transport \"cdn\" is not supported by this build");
        cloak_client_stack_close(s);
        return CLOAK_CLIENT_STACK_ERR_CONFIG;
    }
    if (c->stream_timeout_sec < 0) {
        stack_err(err, err_cap, "client config: StreamTimeout %d is negative",
                  c->stream_timeout_sec);
        cloak_client_stack_close(s);
        return CLOAK_CLIENT_STACK_ERR_CONFIG;
    }

    /* ---- EDGE: the session template, validated BY THE ONLY AUTHORITY ON
     * IT. Re-deriving the mux layer's bounds here would be a second copy
     * that could disagree with the first, so: build one throwaway session
     * with this template and destroy it again. Without this the rejection
     * first happens inside the first bring-up, where the connector
     * reports CLOAK_CLIENT_CONNECTOR_ERR_SESSION and nothing more. */
    {
        cloak_session_t probe;
        if (cloak_session_init(&probe, 1, s->reactor, &s->cfg.session_template) != 0) {
            stack_err(err, err_cap,
                      "session template: cloak_session_init rejected it "
                      "(max_on_wire_size=%zu, stream_recv_capacity=%zu, "
                      "stream_max_pending_frames=%zu, conn_send_queue_cap=%zu)",
                      s->cfg.session_template.max_on_wire_size,
                      s->cfg.session_template.stream_recv_capacity,
                      s->cfg.session_template.stream_max_pending_frames,
                      s->cfg.session_template.conn_send_queue_cap);
            cloak_client_stack_close(s);
            return CLOAK_CLIENT_STACK_ERR_TEMPLATE;
        }
        cloak_session_destroy(&probe);
    }

    /* ================= EDGE E5: resolve ONCE =================
     * This BLOCKS on DNS, which is permitted here and only here
     * (cloak/net.h). The address is then copied into every connector this
     * stack ever builds, including the one singleplex builds on the
     * accept path. */
    {
        char addr[CLOAK_MAX_HOST_LEN + CLOAK_MAX_PORT_LEN + 4];
        char sub[200] = {0};
        join_hostport(addr, sizeof(addr), c->remote_host, c->remote_port);
        if (cloak_net_resolve(addr, 0, &s->remote, sub, sizeof(sub)) != 0) {
            stack_err(err, err_cap, "remote address: \"%s\": %s", addr,
                      sub[0] != '\0' ? sub : "could not be resolved");
            cloak_client_stack_close(s);
            return CLOAK_CLIENT_STACK_ERR_RESOLVE;
        }
    }

    /* ================= the piper =================
     * EDGE E2: it takes all four session callbacks, including on_broken,
     * and the owner's own bookkeeping goes to cloak_client_stack_event_cb
     * instead of displacing it. The first-byte deadline comes from the
     * config's StreamTimeout rather than from a knob of this module's
     * own, so the bound on a singleplex connection's SESSION wait cannot
     * disagree with the bound on its FIRST BYTE -- they are the same
     * deadline, and cloak/client_piper.h is explicit that in singleplex
     * it is cancelled when a stream opens rather than when the byte
     * arrives. */
    {
        cloak_client_piper_config_t pc;
        memset(&pc, 0, sizeof(pc));
        pc.reactor = s->reactor;
        pc.relay_buf_cap = s->cfg.relay_buf_cap;
        pc.first_byte_timeout_ms = (uint64_t)c->stream_timeout_sec * 1000u;
        pc.retry_delay_ms = s->cfg.piper_retry_delay_ms;
        pc.max_retries = s->cfg.piper_max_retries;
        pc.max_local_conns = s->cfg.max_local_conns;
        pc.chain = stack_on_broken;
        pc.chain_userdata = s;
        pc.singleplex = c->singleplex ? 1 : 0;
        pc.new_session = stack_new_session;
        pc.cancel_session = stack_cancel_session;
        pc.session_userdata = s;
        if (cloak_client_piper_init(&s->piper, &pc) != 0) {
            stack_err(err, err_cap, "local piper: cloak_client_piper_init failed");
            cloak_client_stack_close(s);
            return CLOAK_CLIENT_STACK_ERR_PIPER;
        }
        s->piper_ready = 1;
    }

    /* ================= the local listener =================
     * BEFORE any session, and it stays open for the life of the stack:
     * an application is configured to point at a port, so a listener that
     * came and went with the session would not have a stable one. See the
     * header for what an accept arriving with no session does. */
    {
        char addr[CLOAK_MAX_HOST_LEN + CLOAK_MAX_PORT_LEN + 4];
        char sub[200] = {0};
        join_hostport(addr, sizeof(addr), c->local_host, c->local_port);
        if (cloak_listener_open(&s->local, s->reactor, addr, cloak_client_piper_on_accept,
                                &s->piper, sub, sizeof(sub)) != 0) {
            stack_err(err, err_cap, "local address: \"%s\": %s", addr,
                      sub[0] != '\0' ? sub : "listen failed");
            cloak_client_stack_close(s);
            return CLOAK_CLIENT_STACK_ERR_LISTEN;
        }
        s->have_local = 1;
        s->local_port = cloak_listener_port(&s->local);
    }

    /* ================= shared mode: round 1 =================
     * SINGLEPLEX DOES NOTHING HERE. A singleplex client with no local
     * connections holds no session, dials nothing and is invisible on the
     * wire, which is the mode's whole point; its first bring-up is
     * requested by the first local connection's first byte. */
    if (!c->singleplex) {
        stack_slot_t *sl = stack_slot_new(s, NULL, 1);
        if (sl == NULL || stack_start_round(s, sl, 0) != 0) {
            stack_err(err, err_cap,
                      "first bring-up: the shared session's first round could not be started");
            cloak_client_stack_close(s);
            return CLOAK_CLIENT_STACK_ERR_CONNECTOR;
        }
    }

    *out = s;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Teardown                                                            */
/* ------------------------------------------------------------------ */

void cloak_client_stack_close(cloak_client_stack_t *s) {
    if (!stack_valid(s)) {
        return;
    }

    /* THE ORDER IS THE WHOLE FUNCTION -- see cloak/client_stack.h for the
     * argument behind each step. Every step is flag-guarded, so this runs
     * correctly on a partially built stack, which is what every failure
     * path of cloak_client_stack_open hands it. */

    /* 1. the local listener: nothing new arrives mid-teardown. */
    if (s->have_local) {
        cloak_listener_close(&s->local);
        s->have_local = 0;
    }

    /* 2. THE PIPER, BEFORE ANY SESSION. cloak_client_piper_destroy stops
     * every cloak_stream_relay_t, which cloak/stream_relay.h requires to
     * happen before the session a relay is bound to is destroyed --
     * reversed, it is a heap-use-after-free under ASan with traffic in
     * flight. It also fires cancel_session for every singleplex bring-up
     * still in flight, which is what stops an in-flight connector from
     * later answering a context that no longer exists, so it removes
     * those slots from the list step 3 is about to walk.
     *
     * NOTHING IN THIS STEP RE-ENTERS THIS MODULE'S CHAIN: the piper
     * closes each singleplex session it owned, and cloak_session_broken_cb
     * is guaranteed to fire OUTSIDE any session callback's own stack
     * (cloak/session.h) -- i.e. on a later reactor turn, which will not
     * come, because step 3 destroys those sessions. */
    if (s->piper_ready) {
        cloak_client_piper_destroy(&s->piper);
        s->piper_ready = 0;
    }

    /* 3. every slot left: its retry timer, its connector (which tears
     * down dials and handshakes without firing on_done) and its session.
     * stack_slot_destroy unlinks as it goes, so this walk is written
     * against the head rather than against a saved `next`. */
    while (s->slots != NULL) {
        stack_slot_destroy(s, s->slots);
    }

    /* 4. the handle. The reactor is borrowed and is not touched. */
    s->self = NULL;
    free(s);
}

/* ------------------------------------------------------------------ */
/* Accessors                                                           */
/* ------------------------------------------------------------------ */

int cloak_client_stack_local_port(const cloak_client_stack_t *s) {
    return (stack_valid(s) && s->have_local) ? s->local_port : -1;
}

uint32_t cloak_client_stack_session_id(const cloak_client_stack_t *s) {
    if (!stack_valid(s) || s->config.singleplex) {
        return 0;
    }
    for (const stack_slot_t *sl = s->slots; sl != NULL; sl = sl->next) {
        if (sl->shared && sl->state == SLOT_LIVE) {
            return sl->session_id;
        }
    }
    return 0;
}

int cloak_client_stack_session_up(const cloak_client_stack_t *s) {
    return (stack_valid(s) && s->live > 0) ? 1 : 0;
}

size_t cloak_client_stack_live_sessions(const cloak_client_stack_t *s) {
    return stack_valid(s) ? s->live : 0;
}

size_t cloak_client_stack_pending_sessions(const cloak_client_stack_t *s) {
    return stack_valid(s) ? s->pending : 0;
}

size_t cloak_client_stack_rounds_started(const cloak_client_stack_t *s) {
    return stack_valid(s) ? s->rounds_started : 0;
}

size_t cloak_client_stack_reconnects(const cloak_client_stack_t *s) {
    return stack_valid(s) ? s->reconnects : 0;
}

size_t cloak_client_stack_sessions_up(const cloak_client_stack_t *s) {
    return stack_valid(s) ? s->sessions_up : 0;
}

size_t cloak_client_stack_sessions_failed(const cloak_client_stack_t *s) {
    return stack_valid(s) ? s->sessions_failed : 0;
}

size_t cloak_client_stack_sessions_down(const cloak_client_stack_t *s) {
    return stack_valid(s) ? s->sessions_down : 0;
}

size_t cloak_client_stack_local_conns(const cloak_client_stack_t *s) {
    return stack_valid(s) ? cloak_client_piper_conn_count(&s->piper) : 0;
}

size_t cloak_client_stack_local_streams(const cloak_client_stack_t *s) {
    return stack_valid(s) ? cloak_client_piper_stream_count(&s->piper) : 0;
}
