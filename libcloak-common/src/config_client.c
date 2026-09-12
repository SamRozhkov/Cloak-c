#define _POSIX_C_SOURCE 200809L
#include "config_internal.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

static int parse_encryption_method(const char *name, cloak_aead_method_t *out) {
    if (strcasecmp(name, "plain") == 0) {
        *out = CLOAK_AEAD_NONE;
    } else if (strcasecmp(name, "aes-gcm") == 0 ||
               strcasecmp(name, "aes-256-gcm") == 0) {
        *out = CLOAK_AEAD_AES_256_GCM;
    } else if (strcasecmp(name, "aes-128-gcm") == 0) {
        *out = CLOAK_AEAD_AES_128_GCM;
    } else if (strcasecmp(name, "chacha20-poly1305") == 0) {
        *out = CLOAK_AEAD_CHACHA20_POLY1305;
    } else {
        return -1;
    }
    return 0;
}

/* Unknown browser names fall back to chrome, matching Go's switch default. */
static cloak_browser_t parse_browser(const char *name) {
    if (strcasecmp(name, "firefox") == 0) {
        return CLOAK_BROWSER_FIREFOX;
    }
    if (strcasecmp(name, "safari") == 0) {
        return CLOAK_BROWSER_SAFARI;
    }
    return CLOAK_BROWSER_CHROME;
}

static int parse_alt_names(const cJSON *root, cloak_client_config_t *cfg, char *err,
                           size_t err_cap) {
    const cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "AlternativeNames");
    if (arr == NULL || cJSON_IsNull(arr)) {
        return 0;
    }
    if (!cJSON_IsArray(arr)) {
        return cloak_config_set_err(err, err_cap,
                                    "AlternativeNames must be an array of strings");
    }

    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, arr) {
        if (!cJSON_IsString(item) || item->valuestring == NULL) {
            return cloak_config_set_err(err, err_cap,
                                        "AlternativeNames must be an array of strings");
        }
        /* Go filters empty entries out rather than rejecting them */
        if (item->valuestring[0] == '\0') {
            continue;
        }
        if (cfg->num_alt_names >= CLOAK_MAX_ALT_NAMES) {
            return cloak_config_set_err(err, err_cap,
                                        "AlternativeNames has more than %d entries",
                                        CLOAK_MAX_ALT_NAMES);
        }
        size_t len = strlen(item->valuestring);
        if (len + 1 > CLOAK_MAX_HOST_LEN) {
            return cloak_config_set_err(err, err_cap,
                                        "AlternativeNames entry is too long (%zu bytes)",
                                        len);
        }
        memcpy(cfg->alt_names[cfg->num_alt_names], item->valuestring, len + 1);
        cfg->num_alt_names++;
    }
    return 0;
}

int cloak_client_config_from_cjson(const cJSON *root, cloak_client_config_t *cfg,
                                   char *err, size_t err_cap) {
    if (root == NULL || cfg == NULL) {
        return cloak_config_set_err(err, err_cap, "internal: null config input");
    }
    if (!cJSON_IsObject(root)) {
        return cloak_config_set_err(err, err_cap, "config must be a JSON object");
    }

    memset(cfg, 0, sizeof(*cfg));

    int found = 0;

    if (cloak_config_get_string(root, "ServerName", cfg->server_name,
                                sizeof(cfg->server_name), &found, err, err_cap) != 0) {
        return -1;
    }
    if (!found || cfg->server_name[0] == '\0') {
        return cloak_config_set_err(err, err_cap, "ServerName cannot be empty");
    }

    if (parse_alt_names(root, cfg, err, err_cap) != 0) {
        return -1;
    }

    if (cloak_config_get_string(root, "ProxyMethod", cfg->proxy_method,
                                sizeof(cfg->proxy_method), &found, err, err_cap) != 0) {
        /* a too-long ProxyMethod lands here, and the message already names
         * the field and the limit */
        return -1;
    }
    if (!found || cfg->proxy_method[0] == '\0') {
        return cloak_config_set_err(err, err_cap, "ProxyMethod cannot be empty");
    }

    char enc_name[64] = {0};
    if (cloak_config_get_string(root, "EncryptionMethod", enc_name, sizeof(enc_name),
                                &found, err, err_cap) != 0) {
        return -1;
    }
    if (!found || enc_name[0] == '\0') {
        return cloak_config_set_err(err, err_cap, "EncryptionMethod cannot be empty");
    }
    if (parse_encryption_method(enc_name, &cfg->encryption_method) != 0) {
        return cloak_config_set_err(err, err_cap, "unknown EncryptionMethod %s",
                                    enc_name);
    }

    if (cloak_config_get_b64(root, "UID", cfg->uid, CLOAK_UID_LEN, &found, err,
                             err_cap) != 0) {
        return -1;
    }
    if (!found) {
        return cloak_config_set_err(err, err_cap, "UID cannot be empty");
    }

    if (cloak_config_get_b64(root, "PublicKey", cfg->server_pub_key,
                             CLOAK_X25519_KEY_LEN, &found, err, err_cap) != 0) {
        return -1;
    }
    if (!found) {
        return cloak_config_set_err(err, err_cap, "PublicKey cannot be empty");
    }

    if (cloak_config_get_string(root, "RemoteHost", cfg->remote_host,
                                sizeof(cfg->remote_host), &found, err, err_cap) != 0) {
        return -1;
    }
    if (!found || cfg->remote_host[0] == '\0') {
        return cloak_config_set_err(err, err_cap, "RemoteHost cannot be empty");
    }

    if (cloak_config_get_string(root, "RemotePort", cfg->remote_port,
                                sizeof(cfg->remote_port), &found, err, err_cap) != 0) {
        return -1;
    }
    if (!found || cfg->remote_port[0] == '\0') {
        return cloak_config_set_err(err, err_cap, "RemotePort cannot be empty");
    }

    if (cloak_config_get_string(root, "LocalHost", cfg->local_host,
                                sizeof(cfg->local_host), &found, err, err_cap) != 0) {
        return -1;
    }
    if (!found || cfg->local_host[0] == '\0') {
        return cloak_config_set_err(err, err_cap, "LocalHost cannot be empty");
    }

    if (cloak_config_get_string(root, "LocalPort", cfg->local_port,
                                sizeof(cfg->local_port), &found, err, err_cap) != 0) {
        return -1;
    }
    if (!found || cfg->local_port[0] == '\0') {
        return cloak_config_set_err(err, err_cap, "LocalPort cannot be empty");
    }

    int num_conn = 0;
    if (cloak_config_get_int(root, "NumConn", &num_conn, &found, err, err_cap) != 0) {
        return -1;
    }
    if (!found || num_conn <= 0) {
        cfg->num_conn = 1;
        cfg->singleplex = 1;
    } else {
        cfg->num_conn = num_conn;
        cfg->singleplex = 0;
    }

    cfg->udp = 0;
    if (cloak_config_get_bool(root, "UDP", &cfg->udp, &found, err, err_cap) != 0) {
        return -1;
    }

    char browser_name[64] = {0};
    if (cloak_config_get_string(root, "BrowserSig", browser_name, sizeof(browser_name),
                                &found, err, err_cap) != 0) {
        return -1;
    }
    cfg->browser = found && browser_name[0] != '\0' ? parse_browser(browser_name)
                                                    : CLOAK_BROWSER_CHROME;

    char transport_name[64] = {0};
    if (cloak_config_get_string(root, "Transport", transport_name,
                                sizeof(transport_name), &found, err, err_cap) != 0) {
        return -1;
    }
    /* Go: "cdn" selects the CDN transport, everything else (including an
     * empty string and an unrecognised name) means direct */
    cfg->transport = (found && strcasecmp(transport_name, "cdn") == 0)
                         ? CLOAK_TRANSPORT_CDN
                         : CLOAK_TRANSPORT_DIRECT;

    if (cloak_config_get_string(root, "CDNOriginHost", cfg->cdn_origin_host,
                                sizeof(cfg->cdn_origin_host), &found, err,
                                err_cap) != 0) {
        return -1;
    }

    if (cloak_config_get_string(root, "CDNWsUrlPath", cfg->cdn_ws_url_path,
                                sizeof(cfg->cdn_ws_url_path), &found, err,
                                err_cap) != 0) {
        return -1;
    }
    if (!found || cfg->cdn_ws_url_path[0] == '\0') {
        cfg->cdn_ws_url_path[0] = '/';
        cfg->cdn_ws_url_path[1] = '\0';
    }

    int stream_timeout = 0;
    if (cloak_config_get_int(root, "StreamTimeout", &stream_timeout, &found, err,
                             err_cap) != 0) {
        return -1;
    }
    cfg->stream_timeout_sec = (found && stream_timeout != 0) ? stream_timeout : 300;
    if (cfg->stream_timeout_sec < 0) {
        return cloak_config_set_err(err, err_cap, "StreamTimeout cannot be negative");
    }

    int keep_alive = 0;
    if (cloak_config_get_int(root, "KeepAlive", &keep_alive, &found, err, err_cap) != 0) {
        return -1;
    }
    cfg->keep_alive_sec = (found && keep_alive > 0) ? keep_alive : -1;

    return 0;
}

int cloak_client_config_parse_json(const char *text, cloak_client_config_t *cfg,
                                   char *err, size_t err_cap) {
    if (text == NULL) {
        return cloak_config_set_err(err, err_cap, "no config text given");
    }
    cJSON *root = cJSON_Parse(text);
    if (root == NULL) {
        const char *at = cJSON_GetErrorPtr();
        return cloak_config_set_err(err, err_cap, "malformed JSON near '%.20s'",
                                    at != NULL ? at : "");
    }
    int rc = cloak_client_config_from_cjson(root, cfg, err, err_cap);
    cJSON_Delete(root);
    return rc;
}

int cloak_client_config_parse_file(const char *path, cloak_client_config_t *cfg,
                                   char *err, size_t err_cap) {
    char *text = cloak_config_read_file(path, err, err_cap);
    if (text == NULL) {
        return -1;
    }
    int rc = cloak_client_config_parse_json(text, cfg, err, err_cap);
    free(text);
    return rc;
}
