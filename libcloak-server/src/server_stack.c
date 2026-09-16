#define _POSIX_C_SOURCE 200809L

#include "cloak/server_stack.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* THE ENTIRE POINT OF THIS FILE is that the nine objects, the four-link
 * chain, the three trampolines and the teardown order live in ONE place
 * and a caller cannot reach any of them. Read cloak/server_stack.h first;
 * the argument for every ordering decision below is there, next to the
 * field it governs, rather than here. */

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
 * cloak/adminapi.h and cloak/proxy.h both say and neither can enforce. */
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
 * check is that the callback tells BOTH modules. Here it always does.
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
     * counter. */
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

/* ------------------------------------------------------------------ */
/* Construction                                                        */
/* ------------------------------------------------------------------ */

int cloak_server_stack_init(cloak_server_stack_t *s, const cloak_server_stack_config_t *cfg,
                            char *err, size_t err_cap) {
    if (err != NULL && err_cap > 0) {
        err[0] = '\0';
    }
    if (s == NULL) {
        stack_err(err, err_cap, "argument: the cloak_server_stack_t is NULL");
        return CLOAK_SERVER_STACK_ERR_ARG;
    }

    /* INITIALIZE BEFORE VALIDATING, so that EVERY return below -- the
     * rejected-argument ones included -- leaves a struct
     * cloak_server_stack_destroy is safe on. Five earlier constructors on
     * this project had this backwards and it was a crash every time a
     * caller's own cleanup ran. */
    memset(s, 0, sizeof(*s));

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

    s->cfg = *cfg;
    s->reactor = cfg->reactor;
    const cloak_server_config_t *c = cfg->config;

    if (s->cfg.replay_cache_capacity == 0) {
        s->cfg.replay_cache_capacity = CLOAK_SERVER_STACK_DEFAULT_REPLAY_CACHE_CAPACITY;
    }
    fill_template_defaults(&s->cfg.session_config_template);

    /* ---- EDGE: a server that binds nothing is a silent server, not a
     * degraded one. Nothing below this line would ever complain: the
     * listener loop simply runs zero times and the process sits there. */
    if (c->num_bind_addr == 0) {
        stack_err(err, err_cap, "server config: BindAddr names no address to listen on");
        return CLOAK_SERVER_STACK_ERR_CONFIG;
    }
    if (c->num_bind_addr > CLOAK_MAX_BIND_ADDR) {
        stack_err(err, err_cap,
                  "server config: BindAddr count %zu exceeds CLOAK_MAX_BIND_ADDR (%d)",
                  c->num_bind_addr, (int)CLOAK_MAX_BIND_ADDR);
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
        cloak_session_t probe;
        if (cloak_session_init(&probe, 0, s->reactor, &s->cfg.session_config_template) != 0) {
            stack_err(err, err_cap,
                      "session template: cloak_session_init rejected it "
                      "(max_on_wire_size=%zu, stream_recv_capacity=%zu, "
                      "stream_max_pending_frames=%zu, conn_send_queue_cap=%zu)",
                      s->cfg.session_config_template.max_on_wire_size,
                      s->cfg.session_config_template.stream_recv_capacity,
                      s->cfg.session_config_template.stream_max_pending_frames,
                      s->cfg.session_config_template.conn_send_queue_cap);
            return CLOAK_SERVER_STACK_ERR_TEMPLATE;
        }
        cloak_session_destroy(&probe);
    }

    /* ---- EDGE: the retry ladder outlasting the session it belongs to.
     * cloak/proxy.h states this invariant and then says, in as many
     * words, that nothing there can check it "because the session config
     * belongs to the dispatcher, not to this module". This struct owns
     * both halves, so this is the first place in the project where it CAN
     * be checked. Above the session's inactivity timeout, a stream that
     * can NEVER start (a conn_send_queue_cap smaller than one worst-case
     * frame -- a misconfiguration, not congestion) is reclaimed by the
     * session's timeout instead of by the stream path, holding a
     * connected upstream descriptor the whole way. */
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
            return CLOAK_SERVER_STACK_ERR_RETRY_LADDER;
        }
    }

    /* ================= 1. the server's runtime state =================
     * Resolves RedirAddr and every ProxyBook entry, which BLOCKS. That is
     * permitted here and only here (cloak/server.h): this runs once, at
     * startup, and it is why the data path can dial without a lookup. */
    {
        char sub[200] = {0};
        if (cloak_server_init(&s->srv, c, s->cfg.replay_cache_capacity, sub, sizeof(sub)) != 0) {
            stack_err(err, err_cap, "server state: %s", sub);
            cloak_server_stack_destroy(s);
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
            cloak_server_stack_destroy(s);
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
        cloak_server_stack_destroy(s);
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
            cloak_server_stack_destroy(s);
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
            cloak_server_stack_destroy(s);
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
            cloak_server_stack_destroy(s);
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
            cloak_server_stack_destroy(s);
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
            cloak_server_stack_destroy(s);
            return CLOAK_SERVER_STACK_ERR_LISTEN;
        }
        s->listener_count++;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Teardown                                                            */
/* ------------------------------------------------------------------ */

void cloak_server_stack_destroy(cloak_server_stack_t *s) {
    if (s == NULL) {
        return;
    }

    /* THE ORDER IS THE WHOLE FUNCTION, and it is NOT the reverse of
     * construction -- see cloak/server_stack.h for the argument behind
     * each step. Every step is flag-guarded, so this is idempotent and
     * safe on a zeroed struct, which is what makes it usable as the
     * failure path of cloak_server_stack_init as well as a binary's
     * shutdown. */

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

    /* 3. THE PROXY, BEFORE THE REGISTRY -- inversion one. Stops every
     * live relay, which cloak/stream_relay.h requires to happen before
     * the session a relay is bound to is destroyed. Reversed, the next
     * upstream byte lands on a freed cloak_stream_t. */
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

    /* 6. THE PANEL, AFTER THE REGISTRY -- inversion two, and the one the
     * construction order actively invites getting wrong (the panel was
     * built BEFORE the registry). It frees every active user's
     * cloak_valve_t without closing anybody's sessions, and every live
     * session holds a borrowed pointer to one. */
    if (s->panel != NULL) {
        cloak_userpanel_close(s->panel);
        s->panel = NULL;
    }

    /* 7. the manager, after the panel that reads it. */
    if (s->mgr != NULL) {
        cloak_usermanager_close(s->mgr);
        s->mgr = NULL;
    }

    /* 8. the server state the proxy and the dispatcher borrowed. */
    if (s->srv_ready) {
        cloak_server_destroy(&s->srv);
        s->srv_ready = 0;
    }
}

/* ------------------------------------------------------------------ */
/* Accessors                                                           */
/* ------------------------------------------------------------------ */

int cloak_server_stack_listener_port(const cloak_server_stack_t *s, size_t i) {
    if (s == NULL || i >= s->listener_count) {
        return -1;
    }
    return cloak_listener_port(&s->listeners[i]);
}

size_t cloak_server_stack_listener_count(const cloak_server_stack_t *s) {
    return s == NULL ? 0 : s->listener_count;
}
