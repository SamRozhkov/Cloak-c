#define _POSIX_C_SOURCE 200809L
#include "config_internal.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "cloak/base64.h"

static void lowercase_in_place(char *s) {
    for (; *s != '\0'; s++) {
        *s = (char)tolower((unsigned char)*s);
    }
}

static int parse_proxy_book(const cJSON *root, cloak_server_config_t *cfg, char *err,
                            size_t err_cap) {
    const cJSON *book = cJSON_GetObjectItemCaseSensitive(root, "ProxyBook");
    if (book == NULL || cJSON_IsNull(book)) {
        return 0; /* Go tolerates an absent ProxyBook; it just proxies nothing */
    }
    if (!cJSON_IsObject(book)) {
        return cloak_config_set_err(err, err_cap, "ProxyBook must be an object");
    }

    const cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, book) {
        if (entry->string == NULL) {
            return cloak_config_set_err(err, err_cap, "ProxyBook has an unnamed entry");
        }
        if (!cJSON_IsArray(entry) || cJSON_GetArraySize(entry) != 2) {
            return cloak_config_set_err(
                err, err_cap,
                "ProxyBook entry %s must be a [network, address] pair", entry->string);
        }
        const cJSON *network = cJSON_GetArrayItem(entry, 0);
        const cJSON *addr = cJSON_GetArrayItem(entry, 1);
        if (!cJSON_IsString(network) || network->valuestring == NULL ||
            !cJSON_IsString(addr) || addr->valuestring == NULL) {
            return cloak_config_set_err(
                err, err_cap,
                "ProxyBook entry %s must be a [network, address] pair of strings",
                entry->string);
        }

        if (cfg->num_proxy_entries >= CLOAK_MAX_PROXY_BOOK) {
            return cloak_config_set_err(err, err_cap,
                                        "ProxyBook has more than %d entries",
                                        CLOAK_MAX_PROXY_BOOK);
        }
        cloak_proxy_entry_t *slot = &cfg->proxy_book[cfg->num_proxy_entries];

        size_t name_len = strlen(entry->string);
        if (name_len == 0 || name_len > CLOAK_PROXY_METHOD_LEN) {
            return cloak_config_set_err(
                err, err_cap,
                "ProxyBook name %s must be 1 to %d bytes (it travels in a fixed-width "
                "wire field)",
                entry->string, CLOAK_PROXY_METHOD_LEN);
        }
        memcpy(slot->name, entry->string, name_len + 1);
        lowercase_in_place(slot->name);

        if (strcasecmp(network->valuestring, "tcp") == 0) {
            slot->is_udp = 0;
        } else if (strcasecmp(network->valuestring, "udp") == 0) {
            slot->is_udp = 1;
        } else {
            return cloak_config_set_err(err, err_cap,
                                        "ProxyBook entry %s has unknown network %s",
                                        entry->string, network->valuestring);
        }

        size_t addr_len = strlen(addr->valuestring);
        if (addr_len == 0 || addr_len + 1 > sizeof(slot->addr)) {
            return cloak_config_set_err(err, err_cap,
                                        "ProxyBook entry %s has an unusable address",
                                        entry->string);
        }
        memcpy(slot->addr, addr->valuestring, addr_len + 1);

        cfg->num_proxy_entries++;
    }
    return 0;
}

static int parse_bind_addr(const cJSON *root, cloak_server_config_t *cfg, char *err,
                           size_t err_cap) {
    const cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "BindAddr");
    if (arr == NULL || cJSON_IsNull(arr) || !cJSON_IsArray(arr)) {
        return cloak_config_set_err(err, err_cap,
                                    "BindAddr must be a non-empty array of strings");
    }

    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, arr) {
        if (!cJSON_IsString(item) || item->valuestring == NULL ||
            item->valuestring[0] == '\0') {
            return cloak_config_set_err(err, err_cap,
                                        "BindAddr must be an array of non-empty strings");
        }
        if (cfg->num_bind_addr >= CLOAK_MAX_BIND_ADDR) {
            return cloak_config_set_err(err, err_cap, "BindAddr has more than %d entries",
                                        CLOAK_MAX_BIND_ADDR);
        }
        size_t len = strlen(item->valuestring);
        if (len + 1 > CLOAK_MAX_HOST_LEN) {
            return cloak_config_set_err(err, err_cap, "BindAddr entry is too long");
        }
        memcpy(cfg->bind_addr[cfg->num_bind_addr], item->valuestring, len + 1);
        cfg->num_bind_addr++;
    }

    if (cfg->num_bind_addr == 0) {
        return cloak_config_set_err(err, err_cap, "BindAddr cannot be empty");
    }
    return 0;
}

static int parse_bypass_uid(const cJSON *root, cloak_server_config_t *cfg, char *err,
                            size_t err_cap) {
    const cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "BypassUID");
    if (arr == NULL || cJSON_IsNull(arr)) {
        return 0;
    }
    if (!cJSON_IsArray(arr)) {
        return cloak_config_set_err(err, err_cap,
                                    "BypassUID must be an array of base64 strings");
    }

    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, arr) {
        if (!cJSON_IsString(item) || item->valuestring == NULL) {
            return cloak_config_set_err(err, err_cap,
                                        "BypassUID must be an array of base64 strings");
        }
        if (cfg->num_bypass_uid >= CLOAK_MAX_BYPASS_UID) {
            return cloak_config_set_err(err, err_cap, "BypassUID has more than %d entries",
                                        CLOAK_MAX_BYPASS_UID);
        }
        uint8_t decoded[64];
        size_t decoded_len = 0;
        if (cloak_base64_decode(item->valuestring, decoded, sizeof(decoded),
                                &decoded_len) != 0) {
            return cloak_config_set_err(
                err, err_cap,
                "BypassUID entry is not valid base64, or is too long to decode");
        }
        if (decoded_len != CLOAK_UID_LEN) {
            return cloak_config_set_err(
                err, err_cap, "BypassUID entry must decode to %d bytes, got %zu",
                CLOAK_UID_LEN, decoded_len);
        }
        memcpy(cfg->bypass_uid[cfg->num_bypass_uid], decoded, CLOAK_UID_LEN);
        cfg->num_bypass_uid++;
    }
    return 0;
}

int cloak_server_config_from_cjson(const cJSON *root, cloak_server_config_t *cfg,
                                   char *err, size_t err_cap) {
    if (root == NULL || cfg == NULL) {
        return cloak_config_set_err(err, err_cap, "internal: null config input");
    }
    if (!cJSON_IsObject(root)) {
        return cloak_config_set_err(err, err_cap, "config must be a JSON object");
    }

    memset(cfg, 0, sizeof(*cfg));
    int found = 0;

    int cnc_mode = 0;
    if (cloak_config_get_bool(root, "CncMode", &cnc_mode, &found, err, err_cap) != 0) {
        return -1;
    }
    if (cnc_mode) {
        return cloak_config_set_err(err, err_cap,
                                    "CncMode (command & control mode) is not implemented");
    }

    if (parse_proxy_book(root, cfg, err, err_cap) != 0) {
        return -1;
    }
    if (parse_bind_addr(root, cfg, err, err_cap) != 0) {
        return -1;
    }
    if (parse_bypass_uid(root, cfg, err, err_cap) != 0) {
        return -1;
    }

    if (cloak_config_get_string(root, "RedirAddr", cfg->redir_addr,
                                sizeof(cfg->redir_addr), &found, err, err_cap) != 0) {
        return -1;
    }
    if (!found || cfg->redir_addr[0] == '\0') {
        return cloak_config_set_err(err, err_cap, "RedirAddr cannot be empty");
    }

    if (cloak_config_get_b64(root, "PrivateKey", cfg->private_key,
                             CLOAK_X25519_KEY_LEN, &found, err, err_cap) != 0) {
        return -1;
    }
    if (!found) {
        return cloak_config_set_err(
            err, err_cap,
            "PrivateKey cannot be empty; generate one with ck-server -key");
    }

    if (cloak_config_get_b64(root, "AdminUID", cfg->admin_uid, CLOAK_UID_LEN, &found,
                             err, err_cap) != 0) {
        return -1;
    }
    cfg->has_admin_uid = found;

    /* Go's InitState folds AdminUID into its runtime BypassUID set (a map,
     * so a duplicate costs nothing there) so the admin is never subject to
     * accounting. This struct mirrors RawConfig instead: bypass_uid holds
     * exactly the configured BypassUID list, and admin_uid/has_admin_uid
     * carry the admin identity separately. Folding them together is the
     * accounting layer's job at the point it builds its lookup set, not
     * the config parser's -- doing it here would silently double an entry
     * whenever AdminUID also appears in BypassUID, and would need its own
     * capacity-overflow rule that nothing else here exercises. */

    if (cloak_config_get_string(root, "DatabasePath", cfg->database_path,
                                sizeof(cfg->database_path), &found, err, err_cap) != 0) {
        return -1;
    }

    int keep_alive = 0;
    if (cloak_config_get_int(root, "KeepAlive", &keep_alive, &found, err, err_cap) != 0) {
        return -1;
    }
    cfg->keep_alive_sec = (found && keep_alive > 0) ? keep_alive : -1;

    return 0;
}

int cloak_server_config_parse_json(const char *text, cloak_server_config_t *cfg,
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
    int rc = cloak_server_config_from_cjson(root, cfg, err, err_cap);
    cJSON_Delete(root);
    return rc;
}

int cloak_server_config_parse_file(const char *path, cloak_server_config_t *cfg,
                                   char *err, size_t err_cap) {
    char *text = cloak_config_read_file(path, err, err_cap);
    if (text == NULL) {
        return -1;
    }
    int rc = cloak_server_config_parse_json(text, cfg, err, err_cap);
    free(text);
    return rc;
}
