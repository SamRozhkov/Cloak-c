#define _POSIX_C_SOURCE 200809L
#include "cloak/config.h"
#include "test_framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define UID_B64 "SGVsbG9DbG9ha1VJRCEhIQ=="
#define PUB_B64 "bG9uZ2VyLWtleS1tYXRlcmlhbC1leGFjdGx5LTMyISE="

static const char *minimal_ssv(void) {
    static char buf[1024];
    snprintf(buf, sizeof(buf),
             "ServerName=www.bing.com;ProxyMethod=shadowsocks;"
             "EncryptionMethod=plain;UID=%s;PublicKey=%s;"
             "RemoteHost=1.2.3.4;RemotePort=443;LocalHost=127.0.0.1;LocalPort=1984",
             UID_B64, PUB_B64);
    return buf;
}

static void test_parses_a_minimal_ssv(void) {
    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};

    ASSERT_EQ_INT(0, cloak_client_config_parse_ssv(minimal_ssv(), &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(0, strcmp(cfg.server_name, "www.bing.com"));
    ASSERT_EQ_INT(0, strcmp(cfg.proxy_method, "shadowsocks"));
    ASSERT_EQ_INT(CLOAK_AEAD_NONE, cfg.encryption_method);
    ASSERT_EQ_INT(0, strcmp(cfg.remote_port, "443"));
    ASSERT_EQ_INT(1, cfg.num_conn);
    ASSERT_EQ_INT(1, cfg.singleplex);
}

static void test_numeric_and_boolean_options_are_typed(void) {
    char ssv[1200];
    snprintf(ssv, sizeof(ssv), "%s;NumConn=4;StreamTimeout=60;KeepAlive=15;UDP=true",
             minimal_ssv());

    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_client_config_parse_ssv(ssv, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(4, cfg.num_conn);
    ASSERT_EQ_INT(0, cfg.singleplex);
    ASSERT_EQ_INT(60, cfg.stream_timeout_sec);
    ASSERT_EQ_INT(15, cfg.keep_alive_sec);
    ASSERT_EQ_INT(1, cfg.udp);
}

static void test_alternative_names_split_on_commas(void) {
    char ssv[1200];
    snprintf(ssv, sizeof(ssv), "%s;AlternativeNames=b.com,c.com,d.com", minimal_ssv());

    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_client_config_parse_ssv(ssv, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(3, (int)cfg.num_alt_names);
    ASSERT_EQ_INT(0, strcmp(cfg.alt_names[0], "b.com"));
    ASSERT_EQ_INT(0, strcmp(cfg.alt_names[2], "d.com"));
}

static void test_single_alternative_name_without_comma(void) {
    char ssv[1200];
    snprintf(ssv, sizeof(ssv), "%s;AlternativeNames=b.com", minimal_ssv());

    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_client_config_parse_ssv(ssv, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(1, (int)cfg.num_alt_names);
    ASSERT_EQ_INT(0, strcmp(cfg.alt_names[0], "b.com"));
}

static void test_escapes_are_unescaped(void) {
    char ssv[1200];
    /* a CDN path containing an escaped semicolon and equals sign */
    snprintf(ssv, sizeof(ssv), "%s;Transport=cdn;CDNWsUrlPath=/a\\;b\\=c", minimal_ssv());

    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_client_config_parse_ssv(ssv, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(CLOAK_TRANSPORT_CDN, cfg.transport);
    ASSERT_EQ_INT(0, strcmp(cfg.cdn_ws_url_path, "/a;b=c"));
}

static void test_escaped_backslash(void) {
    char ssv[1200];
    snprintf(ssv, sizeof(ssv), "%s;CDNOriginHost=a\\\\b", minimal_ssv());

    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_client_config_parse_ssv(ssv, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(0, strcmp(cfg.cdn_origin_host, "a\\b"));
}

static void test_trailing_semicolon_is_tolerated(void) {
    char ssv[1200];
    snprintf(ssv, sizeof(ssv), "%s;", minimal_ssv());

    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};
    ASSERT_EQ_INT(0, cloak_client_config_parse_ssv(ssv, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(0, strcmp(cfg.server_name, "www.bing.com"));
}

static void test_rejects_malformed_options(void) {
    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN];

    /* an option with no '=' */
    char ssv[1200];
    snprintf(ssv, sizeof(ssv), "%s;JustAKey", minimal_ssv());
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_client_config_parse_ssv(ssv, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "JustAKey") != NULL);

    /* a non-numeric value for a numeric option */
    snprintf(ssv, sizeof(ssv), "%s;NumConn=lots", minimal_ssv());
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_client_config_parse_ssv(ssv, &cfg, err, sizeof(err)));
    ASSERT_TRUE(strstr(err, "NumConn") != NULL);

    /* an empty string */
    err[0] = '\0';
    ASSERT_EQ_INT(-1, cloak_client_config_parse_ssv("", &cfg, err, sizeof(err)));
    ASSERT_TRUE(err[0] != '\0');
}

static void test_err_may_be_null_on_failure(void) {
    /* an empty ssv string is a guaranteed parse failure. err may be NULL
     * per cloak/config.h; a failing parse must never touch it. */
    cloak_client_config_t cfg;
    ASSERT_EQ_INT(-1, cloak_client_config_parse_ssv("", &cfg, NULL, 0));
}

static void test_load_dispatches_on_shape(void) {
    cloak_client_config_t cfg;
    char err[CLOAK_CONFIG_ERR_LEN] = {0};

    /* contains both ';' and '=' -> treated as ssv */
    ASSERT_EQ_INT(0, cloak_client_config_load(minimal_ssv(), &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(0, strcmp(cfg.server_name, "www.bing.com"));

    /* otherwise a path */
    char path[] = "/tmp/cloak_load_cfg_XXXXXX";
    int fd = mkstemp(path);
    ASSERT_TRUE(fd >= 0);
    if (fd < 0) {
        return;
    }
    char json[1024];
    snprintf(json, sizeof(json),
             "{\"ServerName\":\"from.file\",\"ProxyMethod\":\"ss\","
             "\"EncryptionMethod\":\"plain\",\"UID\":\"%s\",\"PublicKey\":\"%s\","
             "\"RemoteHost\":\"h\",\"RemotePort\":\"443\","
             "\"LocalHost\":\"127.0.0.1\",\"LocalPort\":\"1984\"}",
             UID_B64, PUB_B64);
    ASSERT_TRUE(write(fd, json, strlen(json)) == (ssize_t)strlen(json));
    close(fd);

    err[0] = '\0';
    ASSERT_EQ_INT(0, cloak_client_config_load(path, &cfg, err, sizeof(err)));
    ASSERT_EQ_INT(0, strcmp(cfg.server_name, "from.file"));
    unlink(path);
}

TEST_MAIN_BEGIN()
    test_parses_a_minimal_ssv();
    test_numeric_and_boolean_options_are_typed();
    test_alternative_names_split_on_commas();
    test_single_alternative_name_without_comma();
    test_escapes_are_unescaped();
    test_escaped_backslash();
    test_trailing_semicolon_is_tolerated();
    test_rejects_malformed_options();
    test_err_may_be_null_on_failure();
    test_load_dispatches_on_shape();
TEST_MAIN_END()
