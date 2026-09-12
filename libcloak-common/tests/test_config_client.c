#define _POSIX_C_SOURCE 200809L
#include "cloak/config.h"
#include "test_framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* 16 raw bytes -> 24 base64 chars; 32 raw bytes -> 44 base64 chars */
#define UID_B64 "SGVsbG9DbG9ha1VJRCEhIQ=="
#define PUB_B64 "bG9uZ2VyLWtleS1tYXRlcmlhbC1leGFjdGx5LTMyISE="

static const char *minimal_json(void) {
    static char buf[1024];
    snprintf(buf, sizeof(buf),
             "{"
             "\"ServerName\":\"www.bing.com\","
             "\"ProxyMethod\":\"shadowsocks\","
             "\"EncryptionMethod\":\"aes-gcm\","
             "\"UID\":\"%s\","
             "\"PublicKey\":\"%s\","
             "\"RemoteHost\":\"1.2.3.4\","
             "\"RemotePort\":\"443\","
             "\"LocalHost\":\"127.0.0.1\","
             "\"LocalPort\":\"1984\""
             "}",
             UID_B64, PUB_B64);
    return buf;
}

static void test_parses_a_minimal_config(void) {
    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};

    ASSERT_EQ_INT(0, cloak_client_config_parse_json(minimal_json(), &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(0, strcmp(cfg.server_name, "www.bing.com"));
    ASSERT_EQ_INT(0, strcmp(cfg.proxy_method, "shadowsocks"));
    ASSERT_EQ_INT(CLOAK_AEAD_AES_256_GCM, cfg.encryption_method);
    ASSERT_EQ_INT(0, strcmp(cfg.remote_host, "1.2.3.4"));
    ASSERT_EQ_INT(0, strcmp(cfg.remote_port, "443"));
    ASSERT_EQ_INT(0, strcmp(cfg.local_host, "127.0.0.1"));
    ASSERT_EQ_INT(0, strcmp(cfg.local_port, "1984"));
}

static void test_applies_documented_defaults(void) {
    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};

    ASSERT_EQ_INT(0, cloak_client_config_parse_json(minimal_json(), &cfg, err, sizeof(err)));
    /* NumConn <= 0 means singleplex with a single connection (Go: ProcessRawConfig) */
    ASSERT_EQ_INT(1, cfg.num_conn);
    ASSERT_EQ_INT(1, cfg.singleplex);
    ASSERT_EQ_INT(CLOAK_TRANSPORT_DIRECT, cfg.transport);
    ASSERT_EQ_INT(CLOAK_BROWSER_CHROME, cfg.browser);
    ASSERT_EQ_INT(0, cfg.udp);
    ASSERT_EQ_INT(300, cfg.stream_timeout_sec);
    ASSERT_EQ_INT(-1, cfg.keep_alive_sec);
    ASSERT_EQ_INT(0, (int)cfg.num_alt_names);
}

static void test_num_conn_above_zero_disables_singleplex(void) {
    char json[1200];
    snprintf(json, sizeof(json),
             "{\"ServerName\":\"a.com\",\"ProxyMethod\":\"ss\","
             "\"EncryptionMethod\":\"plain\",\"UID\":\"%s\",\"PublicKey\":\"%s\","
             "\"RemoteHost\":\"h\",\"RemotePort\":\"443\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"1984\","
             "\"NumConn\":4}",
             UID_B64, PUB_B64);

    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_client_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(4, cfg.num_conn);
    ASSERT_EQ_INT(0, cfg.singleplex);
}

static void test_decodes_uid_and_public_key(void) {
    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_client_config_parse_json(minimal_json(), &cfg, err, sizeof(err)));

    ASSERT_MEM_EQ(cfg.uid, "HelloCloakUID!!!", CLOAK_UID_LEN);
    ASSERT_MEM_EQ(cfg.server_pub_key, "longer-key-material-exactly-32!!",
                  CLOAK_X25519_KEY_LEN);
}

static void test_all_encryption_method_names(void) {
    struct {
        const char *name;
        cloak_aead_method_t expected;
    } cases[] = {
        {"plain", CLOAK_AEAD_NONE},
        {"aes-gcm", CLOAK_AEAD_AES_256_GCM},
        {"aes-256-gcm", CLOAK_AEAD_AES_256_GCM},
        {"AES-256-GCM", CLOAK_AEAD_AES_256_GCM},
        {"aes-128-gcm", CLOAK_AEAD_AES_128_GCM},
        {"chacha20-poly1305", CLOAK_AEAD_CHACHA20_POLY1305},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char json[1200];
        snprintf(json, sizeof(json),
                 "{\"ServerName\":\"a.com\",\"ProxyMethod\":\"ss\","
                 "\"EncryptionMethod\":\"%s\",\"UID\":\"%s\",\"PublicKey\":\"%s\","
                 "\"RemoteHost\":\"h\",\"RemotePort\":\"443\","
                 "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"1984\"}",
                 cases[i].name, UID_B64, PUB_B64);

        cloak_client_config_t cfg;
        char err[CLOAK_CONFIG_ERR_LEN] = {0};
        ASSERT_EQ_INT(0, cloak_client_config_parse_json(json, &cfg, err, sizeof(err)));
        ASSERT_EQ_INT(cases[i].expected, cfg.encryption_method);
    }
}

static void test_browser_and_transport_names(void) {
    struct {
        const char *browser;
        cloak_browser_t expected;
    } cases[] = {
        {"chrome", CLOAK_BROWSER_CHROME},
        {"Firefox", CLOAK_BROWSER_FIREFOX},
        {"safari", CLOAK_BROWSER_SAFARI},
        {"nonsense", CLOAK_BROWSER_CHROME}, /* Go falls back to chrome */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char json[1200];
        snprintf(json, sizeof(json),
                 "{\"ServerName\":\"a.com\",\"ProxyMethod\":\"ss\","
                 "\"EncryptionMethod\":\"plain\",\"UID\":\"%s\",\"PublicKey\":\"%s\","
                 "\"RemoteHost\":\"h\",\"RemotePort\":\"443\","
                 "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"1984\","
                 "\"BrowserSig\":\"%s\"}",
                 UID_B64, PUB_B64, cases[i].browser);

        cloak_client_config_t cfg;
        char err[CLOAK_CONFIG_ERR_LEN] = {0};
        ASSERT_EQ_INT(0, cloak_client_config_parse_json(json, &cfg, err, sizeof(err)));
        ASSERT_EQ_INT(cases[i].expected, cfg.browser);
    }
}

static void test_cdn_transport_defaults_ws_path(void) {
    char json[1300];
    snprintf(json, sizeof(json),
             "{\"ServerName\":\"a.com\",\"ProxyMethod\":\"ss\","
             "\"EncryptionMethod\":\"plain\",\"UID\":\"%s\",\"PublicKey\":\"%s\","
             "\"RemoteHost\":\"h\",\"RemotePort\":\"443\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"1984\","
             "\"Transport\":\"cdn\",\"CDNOriginHost\":\"origin.example\"}",
             UID_B64, PUB_B64);

    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_client_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(CLOAK_TRANSPORT_CDN, cfg.transport);
    ASSERT_EQ_INT(0, strcmp(cfg.cdn_origin_host, "origin.example"));
    ASSERT_EQ_INT(0, strcmp(cfg.cdn_ws_url_path, "/"));
}

static void test_alternative_names_are_collected_and_empties_dropped(void) {
    char json[1400];
    snprintf(json, sizeof(json),
             "{\"ServerName\":\"a.com\",\"ProxyMethod\":\"ss\","
             "\"EncryptionMethod\":\"plain\",\"UID\":\"%s\",\"PublicKey\":\"%s\","
             "\"RemoteHost\":\"h\",\"RemotePort\":\"443\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"1984\","
             "\"AlternativeNames\":[\"b.com\",\"\",\"c.com\"]}",
             UID_B64, PUB_B64);

    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_client_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(2, (int)cfg.num_alt_names);
    ASSERT_EQ_INT(0, strcmp(cfg.alt_names[0], "b.com"));
    ASSERT_EQ_INT(0, strcmp(cfg.alt_names[1], "c.com"));
}

static void test_alternative_names_overflow_is_rejected(void) {
    /* one more entry than CLOAK_MAX_ALT_NAMES allows */
    char entries[2048];
    size_t off = 0;
    for (int i = 0; i <= CLOAK_MAX_ALT_NAMES; i++) {
        off += (size_t)snprintf(entries + off, sizeof(entries) - off,
                                "%s\"alt%d.example\"", i == 0 ? "" : ",", i);
    }

    char json[4096];
    snprintf(json, sizeof(json),
             "{\"ServerName\":\"a.com\",\"ProxyMethod\":\"ss\","
             "\"EncryptionMethod\":\"plain\",\"UID\":\"%s\",\"PublicKey\":\"%s\","
             "\"RemoteHost\":\"h\",\"RemotePort\":\"443\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"1984\","
             "\"AlternativeNames\":[%s]}",
             UID_B64, PUB_B64, entries);

    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(-1, cloak_client_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "AlternativeNames") != NULL);
}

static void test_err_may_be_null_on_failure(void) {
    /* not JSON at all -- a guaranteed parse failure. err may be NULL per
     * cloak/config.h; a failing parse must never touch it. */
    cloak_client_config_t cfg;
    ASSERT_EQ_INT(-1, cloak_client_config_parse_json("not json", &cfg, NULL, 0));
}

static void test_missing_required_fields_are_named_in_the_error(void) {
    struct {
        const char *drop;
        const char *expect_in_err;
    } cases[] = {
        {"\"ServerName\":\"a.com\",", "ServerName"},
        {"\"ProxyMethod\":\"ss\",", "ProxyMethod"},
        {"\"RemoteHost\":\"h\",", "RemoteHost"},
        {"\"RemotePort\":\"443\",", "RemotePort"},
        {"\"LocalHost\":\"127.0.0.1\",", "LocalHost"},
        {"\"LocalPort\":\"1984\",", "LocalPort"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char full[1400];
        snprintf(full, sizeof(full),
                 "{\"ServerName\":\"a.com\",\"ProxyMethod\":\"ss\","
                 "\"EncryptionMethod\":\"plain\",\"UID\":\"%s\",\"PublicKey\":\"%s\","
                 "\"RemoteHost\":\"h\",\"RemotePort\":\"443\","
                 "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"1984\",\"NumConn\":1}",
                 UID_B64, PUB_B64);

        /* remove the field under test from the JSON text */
        char *at = strstr(full, cases[i].drop);
        ASSERT_TRUE(at != NULL);
        if (at == NULL) {
            continue;
        }
        memmove(at, at + strlen(cases[i].drop), strlen(at + strlen(cases[i].drop)) + 1);

        cloak_client_config_t cfg;
        char err[CLOAK_CONFIG_ERR_LEN] = {0};
        ASSERT_EQ_INT(-1, cloak_client_config_parse_json(full, &cfg, err, sizeof(err)));
        ASSERT_TRUE(strstr(err, cases[i].expect_in_err) != NULL);
    }
}

static void test_rejects_bad_values(void) {
    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN];
    char json[1400];

    /* unknown encryption method */
    snprintf(json, sizeof(json),
             "{\"ServerName\":\"a.com\",\"ProxyMethod\":\"ss\","
             "\"EncryptionMethod\":\"rot13\",\"UID\":\"%s\",\"PublicKey\":\"%s\","
             "\"RemoteHost\":\"h\",\"RemotePort\":\"443\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"1984\"}",
             UID_B64, PUB_B64);
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_client_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "EncryptionMethod") != NULL);

    /* UID that is not 16 bytes once decoded */
    snprintf(json, sizeof(json),
             "{\"ServerName\":\"a.com\",\"ProxyMethod\":\"ss\","
             "\"EncryptionMethod\":\"plain\",\"UID\":\"Zm9v\",\"PublicKey\":\"%s\","
             "\"RemoteHost\":\"h\",\"RemotePort\":\"443\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"1984\"}",
             PUB_B64);
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_client_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "UID") != NULL);

    /* PublicKey that is not valid base64 */
    snprintf(json, sizeof(json),
             "{\"ServerName\":\"a.com\",\"ProxyMethod\":\"ss\","
             "\"EncryptionMethod\":\"plain\",\"UID\":\"%s\",\"PublicKey\":\"not!base64\","
             "\"RemoteHost\":\"h\",\"RemotePort\":\"443\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"1984\"}",
             UID_B64);
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_client_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "PublicKey") != NULL);

    /* ProxyMethod longer than the 12-byte wire field */
    snprintf(json, sizeof(json),
             "{\"ServerName\":\"a.com\",\"ProxyMethod\":\"thirteenchars\","
             "\"EncryptionMethod\":\"plain\",\"UID\":\"%s\",\"PublicKey\":\"%s\","
             "\"RemoteHost\":\"h\",\"RemotePort\":\"443\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"1984\"}",
             UID_B64, PUB_B64);
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_client_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "ProxyMethod") != NULL);

    /* wrong JSON type for a string field */
    snprintf(json, sizeof(json),
             "{\"ServerName\":7,\"ProxyMethod\":\"ss\","
             "\"EncryptionMethod\":\"plain\",\"UID\":\"%s\",\"PublicKey\":\"%s\","
             "\"RemoteHost\":\"h\",\"RemotePort\":\"443\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"1984\"}",
             UID_B64, PUB_B64);
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_client_config_parse_json(json, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "ServerName") != NULL);

    /* not JSON at all */
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_client_config_parse_json("this is not json", &cfg, err, sizeof(err)));
    ASSERT_TRUE(err[0] != '\0');

    /* JSON, but not an object */
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_client_config_parse_json("[1,2,3]", &cfg, err, sizeof(err)));
    ASSERT_TRUE(err[0] != '\0');
}

static void test_parse_file_round_trip(void) {
    char path[] = "/tmp/cloak_client_cfg_XXXXXX";
    int fd = mkstemp(path);
    ASSERT_TRUE(fd >= 0);
    if (fd < 0) {
        return;
    }
    const char *json = minimal_json();
    ASSERT_TRUE(write(fd, json, strlen(json)) == (ssize_t)strlen(json));
    close(fd);

    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_client_config_parse_file(path, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(0, strcmp(cfg.server_name, "www.bing.com"));
    unlink(path);

    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_client_config_parse_file("/nonexistent/cloak.json", &cfg,
                                                     err, sizeof(err)));
    ASSERT_TRUE(err[0] != '\0');
}

TEST_MAIN_BEGIN()
    test_parses_a_minimal_config();
    test_applies_documented_defaults();
    test_num_conn_above_zero_disables_singleplex();
    test_decodes_uid_and_public_key();
    test_all_encryption_method_names();
    test_browser_and_transport_names();
    test_cdn_transport_defaults_ws_path();
    test_alternative_names_are_collected_and_empties_dropped();
    test_alternative_names_overflow_is_rejected();
    test_err_may_be_null_on_failure();
    test_missing_required_fields_are_named_in_the_error();
    test_rejects_bad_values();
    test_parse_file_round_trip();
TEST_MAIN_END()
