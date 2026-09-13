#define _POSIX_C_SOURCE 200809L
#include "cloak/server.h"

#include "cloak/server_auth.h"

#include <assert.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

/* Matches the convention used throughout this project (see e.g.
 * libcloak-common/src/dial.c): vsnprintf into a possibly-NULL buffer,
 * always returns -1 so a caller can `return set_err(...)` directly. */
static int set_err(char *err, size_t err_cap, const char *fmt, ...) {
    if (err != NULL && err_cap > 0) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, err_cap, fmt, ap);
        va_end(ap);
    }
    return -1;
}

/* True when addr is a bare (unbracketed) IPv6 literal, e.g. "::1" or
 * "fe80::1". cloak_net_split_hostport rejects any unbracketed address with
 * more than one colon as an ambiguous bare IPv6 literal rather than a
 * host:port pair -- this recognizes exactly that same shape so the
 * portless-RedirAddr placeholder below can bracket it before adding a
 * port, instead of producing "::1:443", which is just as ambiguous and
 * would fail to resolve. A single colon (ordinary "host:port") or none
 * (a plain host or an IPv4 literal) is not this case -- and would in any
 * event already have taken the has-a-port branch above when there is
 * exactly one. */
static int is_bare_ipv6_literal(const char *addr) {
    const char *first_colon = strchr(addr, ':');
    if (first_colon == NULL) {
        return 0;
    }
    return strchr(first_colon + 1, ':') != NULL;
}

int cloak_server_init(cloak_server_t *srv, const cloak_server_config_t *cfg,
                      size_t replay_cache_capacity, char *err, size_t err_cap) {
    if (srv == NULL) {
        return set_err(err, err_cap, "server: srv is NULL");
    }
    /* Immediately after the NULL check, before validating anything else:
     * every failure path below must leave a struct cloak_server_destroy
     * can safely take, and the only way to guarantee that is to zero it
     * before anything can fail. */
    memset(srv, 0, sizeof(*srv));

    if (cfg == NULL) {
        return set_err(err, err_cap, "server: cfg is NULL");
    }
    srv->cfg = cfg;

    /* Resolve RedirAddr once, here, so the accept path never has to. A
     * bare host with no port is legitimate -- Go's parseRedirAddr accepts
     * one, and goWeb substitutes the port the client actually connected
     * to (see cloak_server_redir_addr). cloak_net_split_hostport succeeds
     * only when a port is present, so it doubles as the detector. */
    char redir_host[CLOAK_MAX_HOST_LEN];
    char redir_port[CLOAK_MAX_PORT_LEN];
    if (cloak_net_split_hostport(cfg->redir_addr, redir_host, sizeof(redir_host),
                                 redir_port, sizeof(redir_port)) == 0) {
        if (cloak_net_resolve(cfg->redir_addr, 0, &srv->redir, err, err_cap) != 0) {
            return -1;
        }
        srv->redir_has_port = 1;
    } else {
        /* No port supplied. Resolve with a placeholder service so the
         * (possibly blocking) DNS lookup still happens exactly once, at
         * startup; the placeholder port itself is never used, since
         * redir_has_port is 0 and cloak_server_redir_addr always patches
         * it in per connection.
         *
         * A bare IPv6 literal must be bracketed before ":443" is appended
         * -- "::1:443" is exactly as ambiguous as "::1" was, and
         * cloak_net_split_hostport/cloak_net_resolve would reject it for
         * the same reason. An address already written bracketed (e.g.
         * "[::1]", an operator's natural way to write a portless IPv6
         * RedirAddr) is left alone; ":443" alone completes it. */
        char placeholder[CLOAK_MAX_HOST_LEN + 8];
        int n;
        if (cfg->redir_addr[0] != '[' && is_bare_ipv6_literal(cfg->redir_addr)) {
            n = snprintf(placeholder, sizeof(placeholder), "[%s]:443", cfg->redir_addr);
        } else {
            n = snprintf(placeholder, sizeof(placeholder), "%s:443", cfg->redir_addr);
        }
        if (n < 0 || (size_t)n >= sizeof(placeholder)) {
            return set_err(err, err_cap, "server: RedirAddr \"%s\" is too long",
                          cfg->redir_addr);
        }
        if (cloak_net_resolve(placeholder, 0, &srv->redir, err, err_cap) != 0) {
            return -1;
        }
        srv->redir_has_port = 0;
    }

    /* Resolve every ProxyBook entry. cfg->num_proxy_entries is bounded by
     * CLOAK_MAX_PROXY_BOOK by construction (a successful parse enforces
     * it), matching srv->proxy's size. */
    for (size_t i = 0; i < cfg->num_proxy_entries; i++) {
        const cloak_proxy_entry_t *entry = &cfg->proxy_book[i];
        char reason[CLOAK_CONFIG_ERR_LEN];
        reason[0] = '\0';
        if (cloak_net_resolve(entry->addr, entry->is_udp, &srv->proxy[i], reason,
                              sizeof(reason)) != 0) {
            return set_err(err, err_cap, "server: proxy book entry \"%s\" (%s): %s",
                          entry->name, entry->addr, reason);
        }
    }

    /* The bypass union Go performs in InitState: cfg->bypass_uid
     * deliberately excludes admin_uid (see cloak/config.h), so this is
     * the one place that folds it back in. srv->bypass is sized
     * CLOAK_MAX_BYPASS_UID + 1 precisely so this cannot overflow, but the
     * count is asserted rather than trusted -- cfg is caller-supplied and
     * this project would rather trap on a violated invariant than write
     * past the array. */
    size_t n = cfg->num_bypass_uid;
    assert(n <= CLOAK_MAX_BYPASS_UID);
    memcpy(srv->bypass, cfg->bypass_uid, n * CLOAK_UID_LEN);
    if (cfg->has_admin_uid) {
        memcpy(srv->bypass[n], cfg->admin_uid, CLOAK_UID_LEN);
        n++;
    }
    srv->num_bypass = n;

    if (cloak_replay_cache_init(&srv->replay, replay_cache_capacity) != 0) {
        return set_err(err, err_cap, "server: failed to allocate replay cache "
                                     "(%zu slots)", replay_cache_capacity);
    }

    return 0;
}

void cloak_server_destroy(cloak_server_t *srv) {
    if (srv == NULL) {
        return;
    }
    /* Safe on a zeroed struct (cloak_replay_cache_destroy tolerates a
     * zero-initialized cache -- see cloak/replay_cache.h) and idempotent
     * (free(NULL) is a no-op, and the cache is left zeroed afterwards). */
    cloak_replay_cache_destroy(&srv->replay);
}

int cloak_server_is_bypass(const cloak_server_t *srv, const uint8_t uid[CLOAK_UID_LEN]) {
    if (srv == NULL || uid == NULL) {
        return 0;
    }
    /* Plain equality, not constant-time: uid has already been
     * authenticated by the time this is called (matching Go, which also
     * uses plain byte comparison here), so there is no secret being
     * compared against attacker-controlled timing. */
    for (size_t i = 0; i < srv->num_bypass; i++) {
        if (memcmp(srv->bypass[i], uid, CLOAK_UID_LEN) == 0) {
            return 1;
        }
    }
    return 0;
}

int cloak_server_is_admin(const cloak_server_t *srv, const uint8_t uid[CLOAK_UID_LEN]) {
    if (srv == NULL || srv->cfg == NULL || uid == NULL || !srv->cfg->has_admin_uid) {
        return 0;
    }
    /* Plain equality; see cloak_server_is_bypass's comment. */
    return memcmp(srv->cfg->admin_uid, uid, CLOAK_UID_LEN) == 0;
}

const cloak_addr_t *cloak_server_lookup_proxy(const cloak_server_t *srv,
                                               const char *proxy_method) {
    if (srv == NULL || srv->cfg == NULL || proxy_method == NULL) {
        return NULL;
    }
    /* proxy_method arrives from an authenticated but attacker-chosen wire
     * payload; strnlen bounds the read even if it were somehow not
     * NUL-terminated within CLOAK_PROXY_METHOD_LEN bytes, and the
     * explicit length comparison (rather than relying on strncasecmp's
     * embedded-NUL behaviour alone) makes it unambiguous that "shadow"
     * cannot match a configured "shadowsocks". */
    size_t method_len = strnlen(proxy_method, CLOAK_PROXY_METHOD_LEN);
    for (size_t i = 0; i < srv->cfg->num_proxy_entries; i++) {
        const char *name = srv->cfg->proxy_book[i].name;
        size_t name_len = strnlen(name, CLOAK_PROXY_METHOD_LEN);
        if (method_len == name_len && strncasecmp(name, proxy_method, method_len) == 0) {
            return &srv->proxy[i];
        }
    }
    return NULL;
}

int cloak_server_redir_addr(const cloak_server_t *srv, uint16_t local_port,
                             cloak_addr_t *out) {
    if (srv == NULL || out == NULL) {
        return -1;
    }
    *out = srv->redir;
    if (!srv->redir_has_port) {
        struct sockaddr *sa = (struct sockaddr *)&out->ss;
        switch (sa->sa_family) {
        case AF_INET:
            ((struct sockaddr_in *)sa)->sin_port = htons(local_port);
            break;
        case AF_INET6:
            ((struct sockaddr_in6 *)sa)->sin6_port = htons(local_port);
            break;
        default:
            break;
        }
    }
    return 0;
}

int cloak_server_check_replay(cloak_server_t *srv, const uint8_t random[32],
                               int64_t now_unix) {
    if (srv == NULL || random == NULL) {
        return 0;
    }
    return cloak_replay_cache_check_and_insert(&srv->replay, random, now_unix,
                                               CLOAK_SERVER_AUTH_REPLAY_CACHE_AGE_LIMIT_SECONDS);
}
