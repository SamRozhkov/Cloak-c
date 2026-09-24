#define _POSIX_C_SOURCE 200809L

#include "cloak/server_stack.h"

#include "cloak/adminapi.h"
#include "cloak/net.h"
#include "cloak/proxy.h"
#include "cloak/server.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* THE ENTIRE POINT OF THIS FILE is that the nine objects, the four-link
 * chain, the three trampolines and the teardown order live in ONE place
 * and a caller cannot reach any of them. Read cloak/server_stack.h first;
 * the argument for every ordering decision below is there, next to the
 * field it governs, rather than here.
 *
 * THE STRUCT IS DEFINED HERE, NOT IN THE HEADER, and that is load-bearing
 * rather than tidiness: cloak_server_registry_t, cloak_proxy_t,
 * cloak_adminapi_t and cloak_dispatcher_t are all PUBLIC structs with
 * writable wiring fields, so a stack held by value would let a caller
 * write the very assignments this module exists to own. See the header's
 * "THE STACK IS AN OPAQUE HANDLE" paragraph for the review that found
 * that, and for what it cost. */

struct cloak_server_stack {
    /* Set to the struct's own address at open. A handle is heap-allocated
     * and its definition is private, so a caller cannot copy one -- `*b =
     * *a` needs the complete type. This field therefore guards only the
     * cases that remain: a handle built by something other than
     * cloak_server_stack_open, and a byte-wise copy made by code that
     * declared its own layout. Cheap, and it turns a wild pointer into a
     * refusal rather than a wild write. */
    void *self;

    cloak_server_stack_config_t cfg; /* copied by value, defaults filled in */

    /* THE STACK'S OWN COPY OF THE SERVER CONFIG, and the reason the
     * caller's may die the moment open returns. cloak_server_t borrows
     * its config for its whole life and authentication reads it on every
     * handshake (cloak_server_lookup_proxy walks the ProxyBook names,
     * cloak_server_is_admin reads admin_uid), so a binary that parsed
     * into a local and returned would have a dangling read on the hot
     * path. cloak_server_config_t is a pure POD -- fixed arrays, no
     * pointers -- so one memcpy removes the whole class. */
    cloak_server_config_t config;

    cloak_reactor_t *reactor; /* borrowed */

    cloak_server_t srv;
    int srv_ready;

    cloak_usermanager_t *mgr;

    cloak_server_registry_t registry;
    int registry_ready;

    cloak_userpanel_t *panel;

    cloak_adminapi_t api;
    int api_ready;

    cloak_proxy_t proxy;
    int proxy_ready;

    cloak_dispatcher_t dispatcher;
    int dispatcher_ready;

    cloak_listener_t listeners[CLOAK_MAX_BIND_ADDR];
    size_t listener_count;
};

/* Every accessor goes through this, so a handle that did not come from
 * cloak_server_stack_open answers like a NULL one instead of being
 * dereferenced. */
static int stack_valid(const cloak_server_stack_t *s) {
    return s != NULL && s->self == (const void *)s;
}

/* ------------------------------------------------------------------ */
/* Error reporting                                                      */
/* ------------------------------------------------------------------ */

const char *cloak_server_stack_strerror(int code) {
    switch (code) {
    case 0:
        return "ok";
    case CLOAK_SERVER_STACK_ERR_ARG:
        return "argument";
    case CLOAK_SERVER_STACK_ERR_CONFIG:
        return "server config";
    case CLOAK_SERVER_STACK_ERR_TEMPLATE:
        return "session template";
    case CLOAK_SERVER_STACK_ERR_RETRY_LADDER:
        return "proxy retry ladder";
    case CLOAK_SERVER_STACK_ERR_SERVER:
        return "server state";
    case CLOAK_SERVER_STACK_ERR_DATABASE:
        return "user database";
    case CLOAK_SERVER_STACK_ERR_REGISTRY:
        return "session registry";
    case CLOAK_SERVER_STACK_ERR_PANEL:
        return "user panel";
    case CLOAK_SERVER_STACK_ERR_ADMINAPI:
        return "admin API";
    case CLOAK_SERVER_STACK_ERR_PROXY:
        return "proxy";
    case CLOAK_SERVER_STACK_ERR_DISPATCHER:
        return "dispatcher";
    case CLOAK_SERVER_STACK_ERR_LISTEN:
        return "bind address";
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

/* ------------------------------------------------------------------ */
/* The three trampolines the stack owns                                 */
/* ------------------------------------------------------------------ */

/* EDGE E7. The dispatcher has exactly ONE prepare_session hook and two
 * modules that want it; info->is_admin is the dispatcher's own verdict
 * (cloak/dispatcher.h) and this branch on it is the only definition of
 * "admin" anywhere in this module. */
static int stack_prepare_session(cloak_dispatcher_t *d, const cloak_server_clientinfo_t *info,
                                 cloak_session_config_t *config, void *userdata) {
    cloak_server_stack_t *s = userdata;
    if (info->is_admin) {
        return cloak_adminapi_prepare_session(&s->api, info->uid, info->session_id, config);
    }
    return cloak_proxy_prepare_session(d, info, config, &s->proxy);
}

/* EDGE E6. One abandoned-session hook, two modules that allocated a
 * context before the session existed. Omitting either is an unbounded,
 * remotely reachable leak -- one context per abandoned handshake -- which
 * cloak/adminapi.h and cloak/proxy.h both say and neither can enforce.
 * Both halves are pinned by mutation; see the task report. */
static void stack_session_aborted(cloak_dispatcher_t *d, const uint8_t uid[CLOAK_UID_LEN],
                                  uint32_t session_id, void *userdata) {
    cloak_server_stack_t *s = userdata;
    cloak_proxy_session_aborted(d, uid, session_id, &s->proxy);
    cloak_adminapi_session_aborted(&s->api, uid, session_id);
}

/* EDGE E5, AND THE ONE THE PROJECT ALREADY ENFORCED HALF OF. A
 * termination closes sessions through
 * cloak_server_registry_close_all_for_uid, which fires no on_broken --
 * so this hook is the ONLY notification either module gets, and a relay
 * not stopped here is a use-after-free on the next upstream byte after
 * the first out-of-credit user is terminated. cloak_userpanel_open
 * already refuses to start without SOME callback here; what it cannot
 * check is that the callback tells BOTH modules. Here it always does,
 * and both halves are pinned by mutation.
 *
 * ONE UID REALLY CAN HOLD BOTH, which is why "both" is not a theoretical
 * requirement: the dispatcher calls a session admin only when the UID is
 * the admin UID AND session_id == 0, so the same admin UID's other
 * session ids are ordinary proxy sessions. Terminating that UID closes
 * an admin session and a proxy session in the same walk.
 *
 * d is NULL: there is no connection being dispatched, and
 * cloak_proxy_session_aborted documents that it only forwards d. */
static void stack_session_closing(const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                                  void *userdata) {
    cloak_server_stack_t *s = userdata;
    cloak_proxy_session_aborted(NULL, uid, session_id, &s->proxy);
    cloak_adminapi_session_aborted(&s->api, uid, session_id);
}

/* ------------------------------------------------------------------ */
/* Defaults                                                            */
/* ------------------------------------------------------------------ */

static void fill_template_defaults(cloak_session_config_t *t) {
    if (t->max_on_wire_size == 0) {
        t->max_on_wire_size = CLOAK_SERVER_STACK_DEFAULT_MAX_ON_WIRE_SIZE;
    }
    if (t->stream_recv_capacity == 0) {
        t->stream_recv_capacity = CLOAK_SERVER_STACK_DEFAULT_STREAM_RECV_CAPACITY;
    }
    if (t->stream_max_pending_frames == 0) {
        t->stream_max_pending_frames = CLOAK_SERVER_STACK_DEFAULT_STREAM_MAX_PENDING;
    }
    if (t->conn_send_queue_cap == 0) {
        t->conn_send_queue_cap = CLOAK_SERVER_STACK_DEFAULT_CONN_SEND_QUEUE_CAP;
    }
    if (t->inactivity_timeout_ms == 0) {
        t->inactivity_timeout_ms = CLOAK_SERVER_STACK_DEFAULT_INACTIVITY_TIMEOUT_MS;
    }

    /* MADE TRUE RATHER THAN DOCUMENTED. The header says these fields of
     * the template are ignored; clearing them is what makes that a fact.
     * The obfuscator and the valve are per SESSION and per USER
     * respectively and are installed by the dispatcher (cloak/
     * dispatcher.h step 8b); on_broken belongs to the registry, which
     * overwrites it unconditionally (cloak/registry.h); and the three
     * stream callbacks are installed by whichever prepare_session runs.
     * A template carrying any of them would either be silently discarded
     * -- inviting the reader to believe it was honoured -- or, in the
     * valve's case, meter every session on the server into one shared
     * counter.
     *
     * THE ORDERING MODE is in this list for the sharpest version of that
     * reason: it is declared by the CLIENT, once per session, in the flag
     * byte of its auth record, and the dispatcher sets it from there
     * (step 8b, beside the obfuscator). One server serves ordered and
     * unordered clients at the same time, so there is no server-wide
     * answer for a template to carry. Cleared to
     * CLOAK_SESSION_ORDERING_INVALID rather than to either real mode: if
     * anything ever builds a session straight from this template without
     * asking the handshake, it fails construction instead of quietly
     * serving every client in one mode. */
    memset(&t->obfuscator, 0, sizeof(t->obfuscator));
    t->ordering = CLOAK_SESSION_ORDERING_INVALID;
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

/* ------------------------------------------------------------------ */
/* Construction                                                        */
/* ------------------------------------------------------------------ */

int cloak_server_stack_open(cloak_server_stack_t **out, const cloak_server_stack_config_t *cfg,
                            char *err, size_t err_cap) {
    if (err != NULL && err_cap > 0) {
        err[0] = '\0';
    }
    if (out == NULL) {
        stack_err(err, err_cap, "argument: the out pointer is NULL");
        return CLOAK_SERVER_STACK_ERR_ARG;
    }

    /* INITIALIZE BEFORE VALIDATING: *out is NULL from here on unless this
     * function succeeds, so a caller whose cleanup runs
     * cloak_server_stack_close(*out) on every path closes NULL rather
     * than an uninitialized pointer. */
    *out = NULL;

    if (cfg == NULL) {
        stack_err(err, err_cap, "argument: the cloak_server_stack_config_t is NULL");
        return CLOAK_SERVER_STACK_ERR_ARG;
    }
    if (cfg->reactor == NULL) {
        stack_err(err, err_cap, "argument: the reactor is NULL and is required");
        return CLOAK_SERVER_STACK_ERR_ARG;
    }
    if (cfg->config == NULL) {
        stack_err(err, err_cap, "argument: the parsed server config is NULL and is required");
        return CLOAK_SERVER_STACK_ERR_ARG;
    }

    cloak_server_stack_t *s = calloc(1, sizeof(*s));
    if (s == NULL) {
        stack_err(err, err_cap, "argument: out of memory allocating the stack");
        return CLOAK_SERVER_STACK_ERR_ARG;
    }
    s->self = s;
    s->cfg = *cfg;
    s->reactor = cfg->reactor;

    /* THE COPY. From here on the caller's cloak_server_config_t is never
     * read again -- see the field's own comment. */
    s->config = *cfg->config;
    s->cfg.config = &s->config;
    const cloak_server_config_t *c = &s->config;

    if (s->cfg.replay_cache_capacity == 0) {
        s->cfg.replay_cache_capacity = CLOAK_SERVER_STACK_DEFAULT_REPLAY_CACHE_CAPACITY;
    }
    fill_template_defaults(&s->cfg.session_config_template);
    /* The one session-template field that is not a "0 means default"
     * number but a switch, and whose value comes from the operator's
     * config rather than a constant: "FlowControl": false is what the
     * Go-interoperability tests set so our binaries speak only frame
     * types Go knows. See cloak_session_config_t.disable_flow_control. */
    s->cfg.session_config_template.disable_flow_control = s->cfg.config->disable_flow_control;

    /* ---- EDGE: a server that binds nothing is a silent server, not a
     * degraded one. Nothing below this line would ever complain: the
     * listener loop simply runs zero times and the process sits there. */
    if (c->num_bind_addr == 0) {
        stack_err(err, err_cap, "server config: BindAddr names no address to listen on");
        cloak_server_stack_close(s);
        return CLOAK_SERVER_STACK_ERR_CONFIG;
    }
    if (c->num_bind_addr > CLOAK_MAX_BIND_ADDR) {
        stack_err(err, err_cap,
                  "server config: BindAddr count %zu exceeds CLOAK_MAX_BIND_ADDR (%d)",
                  c->num_bind_addr, (int)CLOAK_MAX_BIND_ADDR);
        cloak_server_stack_close(s);
        return CLOAK_SERVER_STACK_ERR_CONFIG;
    }

    /* ---- EDGE: the session template, validated BY THE ONLY AUTHORITY ON
     * IT. Re-deriving the mux layer's bounds here would be a second copy
     * of them that could disagree with the first (cloak/conn.h records
     * exactly that drift happening once already, between three validators
     * that were supposed to agree). So: build one throwaway session with
     * this template and destroy it again. Exact, and it stays exact.
     *
     * WITHOUT THIS the rejection first happens inside
     * cloak_server_registry_get_or_create on the FIRST client's
     * connection, where the dispatcher turns a NULL session into a
     * redirect to the cover site -- every client on the server silently
     * and correctly redirected, forever, with no error emitted anywhere. */
    {
        /* The ordering mode is the one field the probe supplies itself:
         * the template deliberately does not carry one (see
         * fill_template_defaults), because it is the client's per-session
         * declaration. ORDERED is an arbitrary but sufficient choice
         * TODAY, when the two modes differ in nothing this validation
         * touches. A later task that gives unordered mode its own bounds
         * must probe both -- a second probe added now would be
         * indistinguishable from its own absence, which is how a check
         * rots. */
        cloak_session_config_t probe_cfg = s->cfg.session_config_template;
        probe_cfg.ordering = CLOAK_SESSION_ORDERING_ORDERED;
        cloak_session_t probe;
        if (cloak_session_init(&probe, 0, s->reactor, &probe_cfg) != 0) {
            stack_err(err, err_cap,
                      "session template: cloak_session_init rejected it "
                      "(max_on_wire_size=%zu, stream_recv_capacity=%zu, "
                      "stream_max_pending_frames=%zu, conn_send_queue_cap=%zu)",
                      s->cfg.session_config_template.max_on_wire_size,
                      s->cfg.session_config_template.stream_recv_capacity,
                      s->cfg.session_config_template.stream_max_pending_frames,
                      s->cfg.session_config_template.conn_send_queue_cap);
            cloak_server_stack_close(s);
            return CLOAK_SERVER_STACK_ERR_TEMPLATE;
        }
        cloak_session_destroy(&probe);
    }

    /* ---- EDGE: the retry ladder outlasting the session it belongs to.
     * cloak/proxy.h states this invariant and then says, in as many
     * words, that nothing there can check it "because the session config
     * belongs to the dispatcher, not to this module". This struct owns
     * both halves, so this is the first place in the project where it CAN
     * be checked.
     *
     * THE EFFECTIVE VALUES, NOT THE CONFIGURED ONES. A binary that
     * accepts the proxy's defaults writes 0 in both fields, so a check
     * against the raw config would compute a ladder of zero and pass
     * everything -- which is the ONLY case most deployments are in. The
     * substitution below is therefore part of the check, not a
     * convenience, and it is pinned by its own mutation. */
    {
        uint64_t delay = s->cfg.proxy_retry_delay_ms != 0 ? s->cfg.proxy_retry_delay_ms
                                                          : CLOAK_PROXY_DEFAULT_RETRY_DELAY_MS;
        uint64_t retries = s->cfg.proxy_max_retries != 0
                               ? (uint64_t)s->cfg.proxy_max_retries
                               : (uint64_t)CLOAK_PROXY_DEFAULT_MAX_RETRIES;
        uint64_t ladder = delay * retries;
        uint64_t inactivity = s->cfg.session_config_template.inactivity_timeout_ms;
        if (ladder >= inactivity) {
            stack_err(err, err_cap,
                      "proxy retry ladder: retry_delay_ms * max_retries (%llu ms) must be "
                      "below the session inactivity timeout (%llu ms)",
                      (unsigned long long)ladder, (unsigned long long)inactivity);
            cloak_server_stack_close(s);
            return CLOAK_SERVER_STACK_ERR_RETRY_LADDER;
        }
    }

    /* ================= 1. the server's runtime state =================
     * Resolves RedirAddr and every ProxyBook entry, which BLOCKS. That is
     * permitted here and only here (cloak/server.h): this runs once, at
     * startup, and it is why the data path can dial without a lookup.
     * Pointed at the stack's OWN copy of the config. */
    {
        char sub[200] = {0};
        if (cloak_server_init(&s->srv, &s->config, s->cfg.replay_cache_capacity, sub,
                              sizeof(sub)) != 0) {
            stack_err(err, err_cap, "server state: %s", sub);
            cloak_server_stack_close(s);
            return CLOAK_SERVER_STACK_ERR_SERVER;
        }
        s->srv_ready = 1;
    }

    /* ================= 2. the user database =================
     * An EMPTY DatabasePath is a VOID manager, not a failure: the server
     * then serves its bypass and admin UIDs and nobody else, which
     * cloak/usermanager.h and cloak/adminapi.h both call a legitimate
     * deployment. Blocks, for the same startup-only reason as above. */
    {
        char sub[200] = {0};
        const char *path = c->database_path[0] != '\0' ? c->database_path : NULL;
        if (cloak_usermanager_open(&s->mgr, path, s->cfg.now_fn, s->cfg.now_userdata, sub,
                                   sizeof(sub)) != 0 ||
            s->mgr == NULL) {
            stack_err(err, err_cap, "user database: %s", sub[0] != '\0' ? sub : "open failed");
            cloak_server_stack_close(s);
            return CLOAK_SERVER_STACK_ERR_DATABASE;
        }
    }

    /* ================= 3. the registry =================
     * EDGE E1, and the one that has been got wrong every time: the head
     * of the chain IS the proxy's callback, because a cloak_stream_relay_t
     * must be stopped while its session is still alive and the broken
     * callback is the only window in which that is possible. The proxy
     * does not exist yet and does not need to: the registry stores this
     * pointer and never dereferences it until a session breaks
     * (cloak/registry.h), and nothing can break before there is a
     * listener. */
    if (cloak_server_registry_init(&s->registry, s->reactor, cloak_proxy_registry_broken,
                                   &s->proxy) != 0) {
        stack_err(err, err_cap, "session registry: cloak_server_registry_init failed");
        cloak_server_stack_close(s);
        return CLOAK_SERVER_STACK_ERR_REGISTRY;
    }
    s->registry_ready = 1;

    /* ================= 4. the user panel =================
     * EDGE E4 (its chain slot is the OWNER's, and only the owner's) and
     * EDGE E5 (the on_session_closing trampoline). */
    {
        cloak_userpanel_config_t pc;
        memset(&pc, 0, sizeof(pc));
        pc.manager = s->mgr;
        pc.registry = &s->registry;
        pc.reactor = s->reactor;
        pc.upload_interval_ms = s->cfg.upload_interval_ms;
        pc.now_fn = s->cfg.now_fn;
        pc.now_userdata = s->cfg.now_userdata;
        pc.on_session_closing = stack_session_closing;
        pc.on_session_closing_userdata = s;
        pc.chain = s->cfg.on_session_broken;
        pc.chain_userdata = s->cfg.on_session_broken_userdata;
        if (cloak_userpanel_open(&s->panel, &pc) != 0 || s->panel == NULL) {
            stack_err(err, err_cap, "user panel: cloak_userpanel_open failed");
            cloak_server_stack_close(s);
            return CLOAK_SERVER_STACK_ERR_PANEL;
        }
    }

    /* ================= 5. the admin API =================
     * EDGE E3: its chain is the panel's, which must therefore already
     * exist. */
    {
        cloak_adminapi_config_t ac;
        memset(&ac, 0, sizeof(ac));
        ac.reactor = s->reactor;
        ac.manager = s->mgr;
        ac.request_timeout_ms = s->cfg.adminapi_request_timeout_ms;
        ac.chain = cloak_userpanel_registry_broken;
        ac.chain_userdata = s->panel;
        if (cloak_adminapi_init(&s->api, &ac) != 0) {
            stack_err(err, err_cap, "admin API: cloak_adminapi_init failed");
            cloak_server_stack_close(s);
            return CLOAK_SERVER_STACK_ERR_ADMINAPI;
        }
        s->api_ready = 1;
    }

    /* ================= 6. the proxy =================
     * EDGE E2: its chain is the admin API's, which must therefore already
     * exist. */
    {
        cloak_proxy_config_t pxc;
        memset(&pxc, 0, sizeof(pxc));
        pxc.reactor = s->reactor;
        pxc.srv = &s->srv;
        pxc.dial_timeout_ms = s->cfg.proxy_dial_timeout_ms;
        pxc.retry_delay_ms = s->cfg.proxy_retry_delay_ms;
        pxc.max_retries = s->cfg.proxy_max_retries;
        pxc.max_streams_per_session = s->cfg.proxy_max_streams_per_session;
        pxc.max_streams_total = s->cfg.proxy_max_streams_total;
        pxc.chain = cloak_adminapi_registry_broken;
        pxc.chain_userdata = &s->api;
        if (cloak_proxy_init(&s->proxy, &pxc) != 0) {
            stack_err(err, err_cap, "proxy: cloak_proxy_init failed");
            cloak_server_stack_close(s);
            return CLOAK_SERVER_STACK_ERR_PROXY;
        }
        s->proxy_ready = 1;
    }

    /* ================= 7. the dispatcher =================
     * EDGE E8 (the panel it authorises through is the one that owns the
     * valves), plus the two trampolines. */
    {
        cloak_dispatcher_config_t dc;
        memset(&dc, 0, sizeof(dc));
        dc.reactor = s->reactor;
        dc.srv = &s->srv;
        dc.registry = &s->registry;
        dc.panel = s->panel;
        dc.session_config_template = s->cfg.session_config_template;
        dc.prepare_session = stack_prepare_session;
        dc.prepare_session_userdata = s;
        dc.session_aborted = stack_session_aborted;
        dc.session_aborted_userdata = s;
        dc.attached = s->cfg.attached;
        dc.attached_userdata = s->cfg.attached_userdata;
        dc.handshake_timeout_ms = s->cfg.handshake_timeout_ms;
        dc.redirect_dial_timeout_ms = s->cfg.redirect_dial_timeout_ms;
        dc.max_pending_conns = s->cfg.max_pending_conns;
        if (cloak_dispatcher_init(&s->dispatcher, &dc) != 0) {
            stack_err(err, err_cap, "dispatcher: cloak_dispatcher_init failed");
            cloak_server_stack_close(s);
            return CLOAK_SERVER_STACK_ERR_DISPATCHER;
        }
        s->dispatcher_ready = 1;
    }

    /* ================= 8. one listener per BindAddr =================
     * LAST, so that nothing can arrive before everything that serves it
     * exists. One dispatcher serves them all: cloak_dispatcher_accept
     * reads each connection's own local port from the listener it is
     * handed (cloak/dispatcher.h), which is what lets a RedirAddr with no
     * port of its own follow the port the client reached. */
    for (size_t i = 0; i < c->num_bind_addr; i++) {
        char sub[200] = {0};
        if (cloak_listener_open(&s->listeners[i], s->reactor, c->bind_addr[i],
                                cloak_dispatcher_accept, &s->dispatcher, sub, sizeof(sub)) != 0) {
            stack_err(err, err_cap, "bind address: BindAddr[%zu] \"%s\": %s", i, c->bind_addr[i],
                      sub[0] != '\0' ? sub : "listen failed");
            cloak_server_stack_close(s);
            return CLOAK_SERVER_STACK_ERR_LISTEN;
        }
        s->listener_count++;
    }

    *out = s;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Teardown                                                            */
/* ------------------------------------------------------------------ */

void cloak_server_stack_close(cloak_server_stack_t *s) {
    if (!stack_valid(s)) {
        return;
    }

    /* THE ORDER IS THE WHOLE FUNCTION, and it is NOT the reverse of
     * construction -- see cloak/server_stack.h for the argument behind
     * each step, including which of the two inversions is observable
     * today and which is not. Every step is flag-guarded, so this runs
     * correctly on a partially built stack, which is what every failure
     * path of cloak_server_stack_open hands it. */

    /* 1. listeners: nothing new arrives mid-teardown. */
    while (s->listener_count > 0) {
        cloak_listener_close(&s->listeners[--s->listener_count]);
    }

    /* 2. the dispatcher: a connection still mid-handshake can call into
     * the registry, and this is what unwinds those. */
    if (s->dispatcher_ready) {
        cloak_dispatcher_destroy(&s->dispatcher);
        s->dispatcher_ready = 0;
    }

    /* 3. THE PROXY, BEFORE THE REGISTRY. Stops every live relay, which
     * cloak/stream_relay.h requires to happen before the session a relay
     * is bound to is destroyed. Reversed, this is a heap-use-after-free
     * under ASan with traffic in flight -- pinned by mutation, not
     * assumed. */
    if (s->proxy_ready) {
        cloak_proxy_destroy(&s->proxy);
        s->proxy_ready = 0;
    }

    /* 4. THE ADMIN API, BEFORE THE REGISTRY, for the same shape of
     * reason: releasing a stream needs a live session, and its per-stream
     * deadline timers are armed against streams the registry is about to
     * free. */
    if (s->api_ready) {
        cloak_adminapi_destroy(&s->api);
        s->api_ready = 0;
    }

    /* 5. the registry, which destroys every session left. */
    if (s->registry_ready) {
        cloak_server_registry_destroy(&s->registry);
        s->registry_ready = 0;
    }

    /* 6. the panel, after the registry. cloak/userpanel.h requires this
     * -- the panel frees every active user's valve without closing
     * anybody's sessions -- but see the header: swapping 5 and 6 is not
     * observable today, because a valve is read only on the switchboard's
     * data path and no reactor turn runs between these two statements.
     * Kept because the rule is real at the level of the objects and
     * because any future step here that yields to the reactor makes it
     * observable at once. */
    if (s->panel != NULL) {
        cloak_userpanel_close(s->panel);
        s->panel = NULL;
    }

    /* 7. the manager, after the panel that reads it. */
    if (s->mgr != NULL) {
        cloak_usermanager_close(s->mgr);
        s->mgr = NULL;
    }

    /* 8. the server state the proxy and the dispatcher borrowed, and then
     * the handle. */
    if (s->srv_ready) {
        cloak_server_destroy(&s->srv);
        s->srv_ready = 0;
    }

    s->self = NULL;
    free(s);
}

int cloak_server_stack_upload_now(cloak_server_stack_t *s) {
    if (!stack_valid(s) || s->panel == NULL) {
        return -1;
    }
    return cloak_userpanel_upload_now(s->panel);
}

/* ------------------------------------------------------------------ */
/* Accessors                                                           */
/* ------------------------------------------------------------------ */

size_t cloak_server_stack_listener_count(const cloak_server_stack_t *s) {
    return stack_valid(s) ? s->listener_count : 0;
}

int cloak_server_stack_listener_port(const cloak_server_stack_t *s, size_t i) {
    if (!stack_valid(s) || i >= s->listener_count) {
        return -1;
    }
    return cloak_listener_port(&s->listeners[i]);
}

size_t cloak_server_stack_session_count(const cloak_server_stack_t *s) {
    return stack_valid(s) ? cloak_server_registry_count(&s->registry) : 0;
}

size_t cloak_server_stack_session_count_for_uid(const cloak_server_stack_t *s,
                                                const uint8_t uid[CLOAK_UID_LEN]) {
    return stack_valid(s) ? cloak_server_registry_count_for_uid(&s->registry, uid) : 0;
}

size_t cloak_server_stack_proxy_session_count(const cloak_server_stack_t *s) {
    return stack_valid(s) ? cloak_proxy_session_count(&s->proxy) : 0;
}

size_t cloak_server_stack_proxy_stream_count(const cloak_server_stack_t *s) {
    return stack_valid(s) ? cloak_proxy_stream_count(&s->proxy) : 0;
}

size_t cloak_server_stack_admin_session_count(const cloak_server_stack_t *s) {
    return stack_valid(s) ? cloak_adminapi_session_count(&s->api) : 0;
}

size_t cloak_server_stack_admin_stream_count(const cloak_server_stack_t *s) {
    return stack_valid(s) ? cloak_adminapi_stream_count(&s->api) : 0;
}

/* Reported out of the cache cloak_server_init ACTUALLY allocated, not out
 * of this module's copy of the request. The two can only differ if the
 * request never reached the allocation, which is exactly the mistake
 * worth catching. */
size_t cloak_server_stack_replay_cache_capacity(const cloak_server_stack_t *s) {
    return (stack_valid(s) && s->srv_ready) ? s->srv.replay.capacity : 0;
}

cloak_userpanel_t *cloak_server_stack_panel(cloak_server_stack_t *s) {
    return stack_valid(s) ? s->panel : NULL;
}

cloak_usermanager_t *cloak_server_stack_manager(cloak_server_stack_t *s) {
    return stack_valid(s) ? s->mgr : NULL;
}
