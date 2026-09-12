#define _POSIX_C_SOURCE 200809L
#include "config_internal.h"

#include <stdlib.h>
#include <string.h>

/* Options whose values are JSON numbers or booleans rather than strings.
 * Mirrors Go's `unquoted` list in ssvToJson. */
static int is_unquoted_key(const char *key) {
    static const char *const unquoted[] = {"NumConn", "StreamTimeout", "KeepAlive", "UDP"};
    for (size_t i = 0; i < sizeof(unquoted) / sizeof(unquoted[0]); i++) {
        if (strcmp(key, unquoted[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Copies src into dst, resolving the three escapes ssv defines: "\\" -> '\',
 * "\=" -> '=', "\;" -> ';'. A backslash before any other character is kept
 * literally, matching Go's three-way string replacement. Returns -1 if the
 * result would not fit in dst_cap (including the NUL). */
static int unescape(const char *src, size_t src_len, char *dst, size_t dst_cap) {
    size_t o = 0;
    for (size_t i = 0; i < src_len; i++) {
        char c = src[i];
        if (c == '\\' && i + 1 < src_len) {
            char next = src[i + 1];
            if (next == '\\' || next == '=' || next == ';') {
                c = next;
                i++;
            }
        }
        if (o + 1 >= dst_cap) {
            return -1;
        }
        dst[o++] = c;
    }
    if (o >= dst_cap) {
        return -1;
    }
    dst[o] = '\0';
    return 0;
}

/* Splits value on commas and adds it as a JSON array of strings. */
static int add_comma_list(cJSON *obj, const char *key, const char *value, char *err,
                          size_t err_cap) {
    cJSON *arr = cJSON_AddArrayToObject(obj, key);
    if (arr == NULL) {
        return cloak_config_set_err(err, err_cap, "out of memory building %s", key);
    }
    const char *start = value;
    for (;;) {
        const char *comma = strchr(start, ',');
        size_t len = comma != NULL ? (size_t)(comma - start) : strlen(start);
        char item[CLOAK_MAX_HOST_LEN];
        if (len + 1 > sizeof(item)) {
            return cloak_config_set_err(err, err_cap, "%s entry is too long", key);
        }
        memcpy(item, start, len);
        item[len] = '\0';

        cJSON *str = cJSON_CreateString(item);
        if (str == NULL || !cJSON_AddItemToArray(arr, str)) {
            cJSON_Delete(str);
            return cloak_config_set_err(err, err_cap, "out of memory building %s", key);
        }

        if (comma == NULL) {
            break;
        }
        start = comma + 1;
    }
    return 0;
}

/* Adds one key/value option to obj with the JSON type the key calls for. */
static int add_option(cJSON *obj, const char *key, const char *value, char *err,
                      size_t err_cap) {
    if (strcmp(key, "AlternativeNames") == 0) {
        return add_comma_list(obj, key, value, err, err_cap);
    }

    if (is_unquoted_key(key)) {
        if (strcmp(value, "true") == 0 || strcmp(value, "false") == 0) {
            if (cJSON_AddBoolToObject(obj, key, strcmp(value, "true") == 0) == NULL) {
                return cloak_config_set_err(err, err_cap, "out of memory building %s", key);
            }
            return 0;
        }
        char *end = NULL;
        long parsed = strtol(value, &end, 10);
        if (end == value || *end != '\0') {
            return cloak_config_set_err(err, err_cap, "%s must be a number, got '%s'",
                                        key, value);
        }
        if (cJSON_AddNumberToObject(obj, key, (double)parsed) == NULL) {
            return cloak_config_set_err(err, err_cap, "out of memory building %s", key);
        }
        return 0;
    }

    if (cJSON_AddStringToObject(obj, key, value) == NULL) {
        return cloak_config_set_err(err, err_cap, "out of memory building %s", key);
    }
    return 0;
}

int cloak_client_config_parse_ssv(const char *ssv, cloak_client_config_t *cfg, char *err,
                                  size_t err_cap) {
    if (ssv == NULL || ssv[0] == '\0') {
        return cloak_config_set_err(err, err_cap, "empty plugin option string");
    }

    cJSON *obj = cJSON_CreateObject();
    if (obj == NULL) {
        return cloak_config_set_err(err, err_cap, "out of memory parsing options");
    }

    int rc = 0;
    const char *cursor = ssv;
    while (*cursor != '\0') {
        /* find the next unescaped ';' */
        const char *end = cursor;
        while (*end != '\0') {
            if (*end == '\\' && *(end + 1) != '\0') {
                end += 2;
                continue;
            }
            if (*end == ';') {
                break;
            }
            end++;
        }

        size_t field_len = (size_t)(end - cursor);
        if (field_len > 0) {
            /* split on the first unescaped '=' */
            const char *eq = cursor;
            const char *limit = cursor + field_len;
            while (eq < limit) {
                if (*eq == '\\' && eq + 1 < limit) {
                    eq += 2;
                    continue;
                }
                if (*eq == '=') {
                    break;
                }
                eq++;
            }

            char key[128];
            char value[CLOAK_MAX_PATH_LEN];
            if (eq >= limit) {
                char shown[128];
                size_t shown_len = field_len < sizeof(shown) - 1 ? field_len
                                                                 : sizeof(shown) - 1;
                memcpy(shown, cursor, shown_len);
                shown[shown_len] = '\0';
                rc = cloak_config_set_err(err, err_cap,
                                          "malformed option '%s': expected key=value",
                                          shown);
                break;
            }
            if (unescape(cursor, (size_t)(eq - cursor), key, sizeof(key)) != 0) {
                rc = cloak_config_set_err(err, err_cap, "option name is too long");
                break;
            }
            if (unescape(eq + 1, (size_t)(limit - (eq + 1)), value, sizeof(value)) != 0) {
                rc = cloak_config_set_err(err, err_cap, "value of %s is too long", key);
                break;
            }
            if (add_option(obj, key, value, err, err_cap) != 0) {
                rc = -1;
                break;
            }
        }

        if (*end == '\0') {
            break;
        }
        cursor = end + 1;
    }

    if (rc == 0) {
        rc = cloak_client_config_from_cjson(obj, cfg, err, err_cap);
    }
    cJSON_Delete(obj);
    return rc;
}

int cloak_client_config_load(const char *conf, cloak_client_config_t *cfg, char *err,
                             size_t err_cap) {
    if (conf == NULL || conf[0] == '\0') {
        return cloak_config_set_err(err, err_cap, "no config given");
    }
    if (strchr(conf, ';') != NULL && strchr(conf, '=') != NULL) {
        return cloak_client_config_parse_ssv(conf, cfg, err, err_cap);
    }
    return cloak_client_config_parse_file(conf, cfg, err, err_cap);
}
