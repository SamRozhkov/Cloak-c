#define _POSIX_C_SOURCE 200809L
#include "cloak/config.h"
#include "test_framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define PRIV_B64 "cHJpdmF0ZS1rZXktbWF0ZXJpYWwtZXhhY3RseS0zMiE="
#define ADMIN_B64 "YWRtaW5VSUQtMTZieXRlIQ=="
#define BYPASS_B64 "YnlwYXNzVUlELTE2Ynl0IQ=="

static const char *minimal_json(void) {
    static char buf[1024];
    snprintf(buf, sizeof(buf),
             "{"
             "\"ProxyBook\":{\"shadowsocks\":[\"tcp\",\"localhost:51443\"]},"
             "\"BindAddr\":[\":443\"],"
             "\"RedirAddr\":\"www.bing.com\","
             "\"PrivateKey\":\"%s\""
             "}",
             PRIV_B64);
    return buf;
}

static void test_parses_a_minimal_config(void) {
    cloak_server_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};

    ASSERT_EQ_INT(0, cloak_server_config_parse_json(minimal_json(), &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(1, (int)cfg.num_proxy_entries);
    ASSERT_EQ_INT(0, strcmp(cfg.proxy_book[0].name, "shadowsocks"));
    ASSERT_EQ_INT(0, cfg.proxy_book[0].is_udp);
    ASSERT_EQ_INT(0, strcmp(cfg.proxy_book[0].addr, "localhost:51443"));
    ASSERT_EQ_INT(1, (int)cfg.num_bind_addr);
    ASSERT_EQ_INT(0, strcmp(cfg.bind_addr[0], ":443"));
    ASSERT_EQ_INT(0, strcmp(cfg.redir_addr, "www.bing.com"));
    ASSERT_EQ_INT(0, cfg.has_admin_uid);
    ASSERT_EQ_INT(0, (int)cfg.num_bypass_uid);
    ASSERT_EQ_INT(0, cfg.database_path[0]);
    ASSERT_EQ_INT(-1, cfg.keep_alive_sec);
    ASSERT_MEM_EQ(cfg.private_key, "private-key-material-exactly-32!",
                  CLOAK_X25519_KEY_LEN);
}

static void test_proxy_book_lowercases_names_and_reads_udp(void) {
    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ShadowSocks\":[\"TCP\",\"localhost:1\"],"
             "\"wireguard\":[\"udp\",\"localhost:2\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"a.com\",\"PrivateKey\":\"%s\"}",
             PRIV_B64);

    cloak_server_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(2, (int)cfg.num_proxy_entries);

    /* order follows the JSON document order */
    ASSERT_EQ_INT(0, strcmp(cfg.proxy_book[0].name, "shadowsocks"));
    ASSERT_EQ_INT(0, cfg.proxy_book[0].is_udp);
    ASSERT_EQ_INT(0, strcmp(cfg.proxy_book[1].name, "wireguard"));
    ASSERT_EQ_INT(1, cfg.proxy_book[1].is_udp);
}

static void test_reads_admin_and_bypass_uids(void) {
    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"localhost:1\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"a.com\",\"PrivateKey\":\"%s\","
             "\"AdminUID\":\"%s\",\"BypassUID\":[\"%s\"],"
             "\"DatabasePath\":\"/var/lib/cloak/userinfo.db\",\"KeepAlive\":30}",
             PRIV_B64, ADMIN_B64, BYPASS_B64);

    cloak_server_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(1, cfg.has_admin_uid);
    ASSERT_EQ_INT(1, (int)cfg.num_bypass_uid);
    ASSERT_EQ_INT(0, strcmp(cfg.database_path, "/var/lib/cloak/userinfo.db"));
    ASSERT_EQ_INT(30, cfg.keep_alive_sec);
    ASSERT_MEM_EQ(cfg.admin_uid, "adminUID-16byte!", CLOAK_UID_LEN);
    ASSERT_MEM_EQ(cfg.bypass_uid[0], "bypassUID-16byt!", CLOAK_UID_LEN);
}

static void test_missing_required_fields(void) {
    cloak_server_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN];
    char json[1024];

    /* no PrivateKey */
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"localhost:1\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"a.com\"}");
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "PrivateKey") != NULL);

    /* no RedirAddr */
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"localhost:1\"]},"
             "\"BindAddr\":[\":443\"],\"PrivateKey\":\"%s\"}",
             PRIV_B64);
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "RedirAddr") != NULL);

    /* no BindAddr */
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"localhost:1\"]},"
             "\"RedirAddr\":\"a.com\",\"PrivateKey\":\"%s\"}",
             PRIV_B64);
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "BindAddr") != NULL);
}

static void test_rejects_bad_proxy_book_entries(void) {
    cloak_server_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN];
    char json[1024];

    /* pair with one element */
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"a.com\",\"PrivateKey\":\"%s\"}",
             PRIV_B64);
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "ss") != NULL);

    /* unknown network */
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"sctp\",\"localhost:1\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"a.com\",\"PrivateKey\":\"%s\"}",
             PRIV_B64);
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "sctp") != NULL);

    /* method name longer than the 12-byte wire field */
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"thirteenchars\":[\"tcp\",\"localhost:1\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"a.com\",\"PrivateKey\":\"%s\"}",
             PRIV_B64);
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "thirteenchars") != NULL);
}

static void test_proxy_book_overflow_is_rejected(void) {
    /* one more entry than CLOAK_MAX_PROXY_BOOK allows */
    char entries[2048];
    size_t off = 0;
    for (int i = 0; i <= CLOAK_MAX_PROXY_BOOK; i++) {
        off += (size_t)snprintf(entries + off, sizeof(entries) - off,
                                "%s\"p%d\":[\"tcp\",\"localhost:1\"]",
                                i == 0 ? "" : ",", i);
    }

    char json[4096];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{%s},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"a.com\",\"PrivateKey\":\"%s\"}",
             entries, PRIV_B64);

    cloak_server_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(-1, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "ProxyBook") != NULL);
}

static void test_bind_addr_overflow_is_rejected(void) {
    /* one more entry than CLOAK_MAX_BIND_ADDR allows */
    char entries[1024];
    size_t off = 0;
    for (int i = 0; i <= CLOAK_MAX_BIND_ADDR; i++) {
        off += (size_t)snprintf(entries + off, sizeof(entries) - off, "%s\":%d\"",
                                i == 0 ? "" : ",", 1000 + i);
    }

    char json[2048];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"localhost:1\"]},"
             "\"BindAddr\":[%s],\"RedirAddr\":\"a.com\",\"PrivateKey\":\"%s\"}",
             entries, PRIV_B64);

    cloak_server_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(-1, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "BindAddr") != NULL);
}

static void test_bypass_uid_overflow_is_rejected(void) {
    /* one more entry than CLOAK_MAX_BYPASS_UID allows */
    char entries[4096];
    size_t off = 0;
    for (int i = 0; i <= CLOAK_MAX_BYPASS_UID; i++) {
        off += (size_t)snprintf(entries + off, sizeof(entries) - off, "%s\"%s\"",
                                i == 0 ? "" : ",", BYPASS_B64);
    }

    char json[8192];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"localhost:1\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"a.com\",\"PrivateKey\":\"%s\","
             "\"BypassUID\":[%s]}",
             PRIV_B64, entries);

    cloak_server_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(-1, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "BypassUID") != NULL);
}

static void test_err_may_be_null_on_failure(void) {
    /* no PrivateKey -- a guaranteed parse failure. err may be NULL per
     * cloak/config.h; a failing parse must never touch it. */
    const char *json = "{\"ProxyBook\":{\"ss\":[\"tcp\",\"localhost:1\"]},"
                       "\"BindAddr\":[\":443\"],\"RedirAddr\":\"a.com\"}";
    cloak_server_config_t cfg;
    ASSERT_EQ_INT(-1, cloak_server_config_parse_json(json, &cfg, NULL, 0));
}

static void test_rejects_cnc_mode(void) {
    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"localhost:1\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"a.com\",\"PrivateKey\":\"%s\","
             "\"CncMode\":true}",
             PRIV_B64);

    cloak_server_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(-1, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "CncMode") != NULL);
}

static void test_rejects_wrong_length_keys(void) {
    cloak_server_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN];
    char json[1024];

    /* PrivateKey decoding to 3 bytes rather than 32 */
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"localhost:1\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"a.com\",\"PrivateKey\":\"Zm9v\"}");
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "PrivateKey") != NULL);

    /* AdminUID decoding to the wrong length */
    snprintf(json, sizeof(json),
             "{\"ProxyBook\":{\"ss\":[\"tcp\",\"localhost:1\"]},"
             "\"BindAddr\":[\":443\"],\"RedirAddr\":\"a.com\",\"PrivateKey\":\"%s\","
             "\"AdminUID\":\"Zm9v\"}",
             PRIV_B64);
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_server_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "AdminUID") != NULL);
}

static void test_parse_file_round_trip(void) {
    char path[] = "/tmp/cloak_server_cfg_XXXXXX";
    int fd = mkstemp(path);
    ASSERT_TRUE(fd >= 0);
    if (fd < 0) {
        return;
    }
    const char *json = minimal_json();
    ASSERT_TRUE(write(fd, json, strlen(json)) == (ssize_t)strlen(json));
    close(fd);

    cloak_server_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_server_config_parse_file(path, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(0, strcmp(cfg.redir_addr, "www.bing.com"));
    unlink(path);
}

TEST_MAIN_BEGIN()
    test_parses_a_minimal_config();
    test_proxy_book_lowercases_names_and_reads_udp();
    test_reads_admin_and_bypass_uids();
    test_missing_required_fields();
    test_rejects_bad_proxy_book_entries();
    test_proxy_book_overflow_is_rejected();
    test_bind_addr_overflow_is_rejected();
    test_bypass_uid_overflow_is_rejected();
    test_err_may_be_null_on_failure();
    test_rejects_cnc_mode();
    test_rejects_wrong_length_keys();
    test_parse_file_round_trip();
TEST_MAIN_END()
