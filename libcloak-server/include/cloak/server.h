#ifndef CLOAK_SERVER_H
#define CLOAK_SERVER_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/config.h"
#include "cloak/net.h"
#include "cloak/replay_cache.h"

/* The server's runtime state: everything derived once, at startup, from a
 * parsed cloak_server_config_t so the data path never has to block or
 * re-derive it. This is the equivalent of Go Cloak's InitState
 * (internal/server/state.go).
 *
 * It borrows the config rather than copying it: cfg must outlive the
 * cloak_server_t. */
typedef struct {
    const cloak_server_config_t *cfg;

    cloak_replay_cache_t replay;

    /* Resolved once. redir_has_port records whether the config supplied
     * one; when it did not, cloak_server_redir_addr patches in the port
     * the client connected to. */
    cloak_addr_t redir;
    int redir_has_port;

    /* Parallel to cfg->proxy_book, resolved. */
    cloak_addr_t proxy[CLOAK_MAX_PROXY_BOOK];

    /* The config's BypassUID entries PLUS admin_uid when the config had
     * one -- the union Go performs in InitState. cfg->bypass_uid
     * deliberately does not include the admin UID; see cloak/config.h. */
    uint8_t bypass[CLOAK_MAX_BYPASS_UID + 1][CLOAK_UID_LEN];
    size_t num_bypass;
} cloak_server_t;

/* Derives runtime state from cfg. Resolves RedirAddr and every ProxyBook
 * entry, which BLOCKS -- that is permitted here and only here, because
 * this runs at startup, and it is why the data path can dial without a
 * lookup. Allocates the replay cache with replay_cache_capacity slots.
 *
 * Returns 0 on success, -1 with the reason in err on an unresolvable
 * address, an allocation failure, cfg being NULL, or cfg->num_proxy_entries
 * / cfg->num_bypass_uid exceeding CLOAK_MAX_PROXY_BOOK /
 * CLOAK_MAX_BYPASS_UID respectively (a real, checked error, not an
 * assert() -- cloak/config.h's structs are PODs a caller can build by
 * hand, so an out-of-range count from a hand-built cfg is realistic, not
 * merely a violated invariant from a trusted parser). On failure srv is
 * left safe to pass to cloak_server_destroy. */
int cloak_server_init(cloak_server_t *srv, const cloak_server_config_t *cfg,
                      size_t replay_cache_capacity, char *err, size_t err_cap);

/* Frees the replay cache. Idempotent, and safe on a zeroed struct. Does
 * not touch cfg, which the caller owns. */
void cloak_server_destroy(cloak_server_t *srv);

/* 1 if uid is exempt from credit and bandwidth accounting. The admin UID
 * always is. srv == NULL or uid == NULL returns 0. */
int cloak_server_is_bypass(const cloak_server_t *srv, const uint8_t uid[CLOAK_UID_LEN]);

/* 1 if uid is the configured admin UID. Go gates its admin API on this
 * together with session id 0. srv == NULL or uid == NULL returns 0. */
int cloak_server_is_admin(const cloak_server_t *srv, const uint8_t uid[CLOAK_UID_LEN]);

/* The resolved upstream for a proxy method, or NULL if the ProxyBook has
 * no such entry. proxy_method arrives from an authenticated but
 * attacker-chosen payload: the comparison is case-insensitive (the config
 * parser lower-cases its keys) and bounded, and a name that is merely a
 * prefix of a configured one does not match. srv == NULL or
 * proxy_method == NULL returns NULL, the same as a genuine no-match. */
const cloak_addr_t *cloak_server_lookup_proxy(const cloak_server_t *srv,
                                               const char *proxy_method);

/* Writes the redirection target to *out. local_port is the port the
 * client connected to, used only when the config's RedirAddr carried no
 * port of its own -- so a prober reaching :443 is forwarded to the cover
 * site's :443 and one reaching :80 to its :80, matching Go's goWeb.
 * Returns 0 on success, -1 if srv or out is NULL. */
int cloak_server_redir_addr(const cloak_server_t *srv, uint16_t local_port,
                             cloak_addr_t *out);

/* Records random as seen. Returns 1 if it was already seen within the
 * replay window (reject this handshake) and 0 otherwise. Wraps
 * cloak_replay_cache_check_and_insert with the age limit
 * cloak/server_auth.h requires; call it BEFORE decrypting, matching Go's
 * AuthFirstPacket, which checks replay against the raw not-yet-
 * authenticated random. srv or random NULL returns 0 (fails open, i.e.
 * "not a replay") rather than crashing -- consistent with
 * cloak_replay_cache_check_and_insert's own fail-open behaviour when the
 * cache's capacity is 0. (cloak/replay_cache.h itself requires capacity >
 * 0 for cloak_replay_cache_init and says nothing about capacity == 0 at
 * check-and-insert time; that behaviour is documented where it's
 * implemented, in replay_cache.c, not in the header.) */
int cloak_server_check_replay(cloak_server_t *srv, const uint8_t random[32],
                               int64_t now_unix);

#endif
