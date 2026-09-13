#define _POSIX_C_SOURCE 200809L
#include "cloak/server.h"
#include "cloak/server_auth.h"
#include "test_framework.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

/* Base64 of 32 bytes of key material, reused from
 * libcloak-common/tests/test_config_server.c's convention -- the server
 * config parser does not validate the private key cryptographically, so
 * any 32-byte value is fine here. */
#define PRIV_B64 "cHJpdmF0ZS1rZXktbWF0ZXJpYWwtZXhhY3RseS0zMiE="

/* base64("adminUID-16byte!") and base64("bypassUID-16byt!") -- the same
 * literal 16-byte UIDs test_config_server.c uses, so a mismatch between
 * the two test files' expectations would be obvious. */
#define ADMIN_B64 "YWRtaW5VSUQtMTZieXRlIQ=="
#define BYPASS_B64 "YnlwYXNzVUlELTE2Ynl0IQ=="

static const uint8_t ADMIN_UID[CLOAK_UID_LEN] = "adminUID-16byte!";

static void parse_or_die(const char *json, cloak_server_config_t *cfg) {
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    int rc = cloak_server_config_parse_json(json, cfg, err, sizeof(err));
    if (rc != 0) {
        fprintf(stderr, "test setup: config parse failed: %s\n", err);
    }
    ASSERT_EQ_INT(0, rc);
}

/* 1. The admin UID is folded into the bypass set, while the config struct
 * itself keeps reporting only the file's own BypassUID entries. This is
 * the carried-forward InitState obligation -- assert both halves so a
 * future change that "simplifies" either layer fails here. */
static void test_admin_uid_is_added_to_bypass_set(void) {
    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"127.0.0.1:1\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"127.0.0.1:8443\","
             "\"PrivateKey\":\"%s\",\"AdminUID\":\"%s\",\"BypassUID\":[\"%s\"]}",
             PRIV_B64, ADMIN_B64, BYPASS_B64);

    cloak_server_config_t cfg;
    parse_or_die(json, &cfg);
    ASSERT_EQ_INT(1, (int)cfg.num_bypass_uid);

    cloak_server_t srv;
    char err[256] = {0};
    ASSERT_EQ_INT(0, cloak_server_init(&srv, &cfg, 16, err, sizeof(err)));

    /* both halves of the obligation */
    ASSERT_EQ_INT(1, (int)cfg.num_bypass_uid);
    ASSERT_EQ_INT(1, cloak_server_is_bypass(&srv, cfg.bypass_uid[0]));
    ASSERT_EQ_INT(1, cloak_server_is_bypass(&srv, cfg.admin_uid));
    ASSERT_EQ_INT(1, cloak_server_is_admin(&srv, cfg.admin_uid));
    ASSERT_EQ_INT(0, cloak_server_is_admin(&srv, cfg.bypass_uid[0]));

    cloak_server_destroy(&srv);
}

/* 2. No AdminUID in the config: the bypass set is exactly the file's
 * entries, and is_admin is 0 for everything, including a bypass UID. */
static void test_no_admin_uid_leaves_bypass_set_untouched(void) {
    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"127.0.0.1:1\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"127.0.0.1:8443\","
             "\"PrivateKey\":\"%s\",\"BypassUID\":[\"%s\"]}",
             PRIV_B64, BYPASS_B64);

    cloak_server_config_t cfg;
    parse_or_die(json, &cfg);
    ASSERT_EQ_INT(0, cfg.has_admin_uid);
    ASSERT_EQ_INT(1, (int)cfg.num_bypass_uid);

    cloak_server_t srv;
    char err[256] = {0};
    ASSERT_EQ_INT(0, cloak_server_init(&srv, &cfg, 16, err, sizeof(err)));

    ASSERT_EQ_INT(1, (int)srv.num_bypass);
    ASSERT_EQ_INT(1, cloak_server_is_bypass(&srv, cfg.bypass_uid[0]));
    ASSERT_EQ_INT(0, cloak_server_is_admin(&srv, cfg.bypass_uid[0]));
    ASSERT_EQ_INT(0, cloak_server_is_admin(&srv, ADMIN_UID));
    ASSERT_EQ_INT(0, cloak_server_is_bypass(&srv, ADMIN_UID));

    cloak_server_destroy(&srv);
}

/* 3. Proxy lookup is case-insensitive, and a prefix of a real name is not
 * a match. */
static void test_proxy_lookup_is_case_insensitive_and_bounded(void) {
    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ShadowSocks\":[\"tcp\",\"127.0.0.1:1\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"127.0.0.1:8443\","
             "\"PrivateKey\":\"%s\"}",
             PRIV_B64);

    cloak_server_config_t cfg;
    parse_or_die(json, &cfg);
    /* the parser lower-cases ProxyBook keys */
    ASSERT_EQ_INT(0, strcmp(cfg.proxy_book[0].name, "shadowsocks"));

    cloak_server_t srv;
    char err[256] = {0};
    ASSERT_EQ_INT(0, cloak_server_init(&srv, &cfg, 16, err, sizeof(err)));

    const cloak_addr_t *found_lower = cloak_server_lookup_proxy(&srv, "shadowsocks");
    const cloak_addr_t *found_upper = cloak_server_lookup_proxy(&srv, "SHADOWSOCKS");
    const cloak_addr_t *found_mixed = cloak_server_lookup_proxy(&srv, "ShadowSocks");
    ASSERT_TRUE(found_lower != NULL);
    ASSERT_TRUE(found_upper != NULL);
    ASSERT_TRUE(found_mixed != NULL);
    ASSERT_TRUE(found_lower == &srv.proxy[0]);
    ASSERT_TRUE(found_upper == &srv.proxy[0]);
    ASSERT_TRUE(found_mixed == &srv.proxy[0]);

    ASSERT_TRUE(cloak_server_lookup_proxy(&srv, "wireguard") == NULL);
    /* a prefix of a real name must not match */
    ASSERT_TRUE(cloak_server_lookup_proxy(&srv, "shadow") == NULL);

    cloak_server_destroy(&srv);
}

static uint16_t sockaddr_port(const cloak_addr_t *a) {
    const struct sockaddr *sa = (const struct sockaddr *)&a->ss;
    if (sa->sa_family == AF_INET) {
        return ntohs(((const struct sockaddr_in *)sa)->sin_port);
    }
    if (sa->sa_family == AF_INET6) {
        return ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
    }
    ASSERT_TRUE(0); /* unexpected family */
    return 0;
}

/* 4. RedirAddr with an explicit port always resolves to that port;
 * RedirAddr without one takes the per-connection local_port. Assert on
 * the port actually present in the returned sockaddr. */
static void test_redir_addr_port_handling(void) {
    char json_with_port[1024];
    snprintf(json_with_port, sizeof(json_with_port),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"127.0.0.1:1\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"127.0.0.1:9443\","
             "\"PrivateKey\":\"%s\"}",
             PRIV_B64);
    cloak_server_config_t cfg_with_port;
    parse_or_die(json_with_port, &cfg_with_port);

    cloak_server_t srv_with_port;
    char err[256] = {0};
    ASSERT_EQ_INT(0, cloak_server_init(&srv_with_port, &cfg_with_port, 16, err, sizeof(err)));

    cloak_addr_t out;
    memset(&out, 0, sizeof(out));
    ASSERT_EQ_INT(0, cloak_server_redir_addr(&srv_with_port, 8080, &out));
    ASSERT_EQ_INT(9443, (int)sockaddr_port(&out));

    memset(&out, 0, sizeof(out));
    ASSERT_EQ_INT(0, cloak_server_redir_addr(&srv_with_port, 80, &out));
    ASSERT_EQ_INT(9443, (int)sockaddr_port(&out));

    cloak_server_destroy(&srv_with_port);

    char json_no_port[1024];
    snprintf(json_no_port, sizeof(json_no_port),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"127.0.0.1:1\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"127.0.0.1\","
             "\"PrivateKey\":\"%s\"}",
             PRIV_B64);
    cloak_server_config_t cfg_no_port;
    parse_or_die(json_no_port, &cfg_no_port);

    cloak_server_t srv_no_port;
    ASSERT_EQ_INT(0, cloak_server_init(&srv_no_port, &cfg_no_port, 16, err, sizeof(err)));

    memset(&out, 0, sizeof(out));
    ASSERT_EQ_INT(0, cloak_server_redir_addr(&srv_no_port, 8080, &out));
    ASSERT_EQ_INT(8080, (int)sockaddr_port(&out));

    memset(&out, 0, sizeof(out));
    ASSERT_EQ_INT(0, cloak_server_redir_addr(&srv_no_port, 80, &out));
    ASSERT_EQ_INT(80, (int)sockaddr_port(&out));

    cloak_server_destroy(&srv_no_port);
}

/* 5. Replay wiring: same random accepted once, rejected the second time;
 * a different random is accepted; an entry older than the configured age
 * limit is accepted again. */
static void test_replay_wiring(void) {
    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"127.0.0.1:1\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"127.0.0.1:8443\","
             "\"PrivateKey\":\"%s\"}",
             PRIV_B64);
    cloak_server_config_t cfg;
    parse_or_die(json, &cfg);

    cloak_server_t srv;
    char err[256] = {0};
    ASSERT_EQ_INT(0, cloak_server_init(&srv, &cfg, 16, err, sizeof(err)));

    uint8_t rnd[32];
    memset(rnd, 0xAB, sizeof(rnd));
    uint8_t rnd2[32];
    memset(rnd2, 0xCD, sizeof(rnd2));

    int64_t t0 = 1700000000;
    ASSERT_EQ_INT(0, cloak_server_check_replay(&srv, rnd, t0));
    ASSERT_EQ_INT(1, cloak_server_check_replay(&srv, rnd, t0));
    ASSERT_EQ_INT(0, cloak_server_check_replay(&srv, rnd2, t0));

    /* an entry older than the age limit is no longer a replay */
    int64_t t1 = t0 + CLOAK_SERVER_AUTH_REPLAY_CACHE_AGE_LIMIT_SECONDS + 1;
    ASSERT_EQ_INT(0, cloak_server_check_replay(&srv, rnd, t1));

    cloak_server_destroy(&srv);
}

/* 6. An unresolvable RedirAddr is rejected, with the reason in err, and
 * leaves srv safe to pass to cloak_server_destroy. srv starts filled with
 * 0xAA (never zeroed by the test itself) so that the assertion can only
 * pass if cloak_server_init actually memset it -- a struct a previous
 * successful call had already zeroed would pass either way. */
static void test_init_rejects_unresolvable_redir_addr(void) {
    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"127.0.0.1:1\"]},"
             "\"BindAddr\":[\":443\"],"
             "\"RedirAddr\":\"this-host-does-not-exist.invalid\","
             "\"PrivateKey\":\"%s\"}",
             PRIV_B64);
    cloak_server_config_t cfg;
    parse_or_die(json, &cfg);

    cloak_server_t srv;
    memset(&srv, 0xAA, sizeof(srv));
    char err[256] = {0};
    ASSERT_EQ_INT(-1, cloak_server_init(&srv, &cfg, 16, err, sizeof(err)));
    ASSERT_TRUE(err[0] != '\0');
    ASSERT_TRUE(strstr(err, "this-host-does-not-exist.invalid") != NULL);

    /* directly assert the sentinel is gone: srv was memset to zero, and
     * nothing after that (cfg is set immediately, then RedirAddr
     * resolution fails before anything else runs) so every field but cfg
     * must be back to all-zero bytes. Comparing byte-for-byte against a
     * struct that only has cfg set catches an init that forgot the
     * memset (0xAA would still be sitting there) just as well as it
     * catches one that memset late, after some other field was already
     * written. */
    cloak_server_t expected;
    memset(&expected, 0, sizeof(expected));
    expected.cfg = &cfg;
    ASSERT_MEM_EQ(&srv, &expected, sizeof(srv));

    /* must be safe to pass to destroy */
    cloak_server_destroy(&srv);
}

/* 7. cloak_server_destroy is idempotent and safe on a zeroed struct. */
static void test_destroy_is_idempotent_on_zeroed_struct(void) {
    cloak_server_t srv;
    memset(&srv, 0, sizeof(srv));
    cloak_server_destroy(&srv);
    cloak_server_destroy(&srv);
}

/* 8 (review fix, finding 1). A bare IPv6 RedirAddr -- unbracketed, no
 * port, e.g. "::1" -- must still start the server: Go's parseRedirAddr
 * has an explicit "ipv6 without port" branch for exactly this shape.
 * Also covers the bracketed-but-portless spelling ("[::1]") an operator
 * who knows IPv6 is likely to write instead. Both must resolve to an
 * AF_INET6 address with the per-connection port patched in -- this is
 * also what makes the IPv6 branch of cloak_server_redir_addr reachable
 * through the real cloak_server_init path, closing that coverage gap. */
static void test_bare_ipv6_redir_addr_starts_and_patches_port(void) {
    const char *redir_addrs[] = {"::1", "[::1]"};
    for (size_t i = 0; i < sizeof(redir_addrs) / sizeof(redir_addrs[0]); i++) {
        char json[1024];
        snprintf(json, sizeof(json),
                 "{\"ProxyBook\":{\"ss\":[\"tcp\",\"127.0.0.1:1\"]},"
                 "\"BindAddr\":[\":443\"],\"RedirAddr\":\"%s\","
                 "\"PrivateKey\":\"%s\"}",
                 redir_addrs[i], PRIV_B64);

        cloak_server_config_t cfg;
        parse_or_die(json, &cfg);

        cloak_server_t srv;
        char err[256] = {0};
        int rc = cloak_server_init(&srv, &cfg, 16, err, sizeof(err));
        if (rc != 0) {
            fprintf(stderr, "test failure detail (RedirAddr=\"%s\"): %s\n",
                    redir_addrs[i], err);
        }
        ASSERT_EQ_INT(0, rc);

        cloak_addr_t out;
        memset(&out, 0, sizeof(out));
        ASSERT_EQ_INT(0, cloak_server_redir_addr(&srv, 12345, &out));
        ASSERT_EQ_INT(AF_INET6, ((const struct sockaddr *)&out.ss)->sa_family);
        ASSERT_EQ_INT(12345, (int)sockaddr_port(&out));

        cloak_server_destroy(&srv);
    }
}

TEST_MAIN_BEGIN()
    test_admin_uid_is_added_to_bypass_set();
    test_no_admin_uid_leaves_bypass_set_untouched();
    test_proxy_lookup_is_case_insensitive_and_bounded();
    test_redir_addr_port_handling();
    test_replay_wiring();
    test_init_rejects_unresolvable_redir_addr();
    test_destroy_is_idempotent_on_zeroed_struct();
    test_bare_ipv6_redir_addr_starts_and_patches_port();
TEST_MAIN_END()
