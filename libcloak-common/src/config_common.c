#define _POSIX_C_SOURCE 200809L
#include "config_internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cloak/base64.h"

int cloak_config_set_err(char *err, size_t err_cap, const char *fmt, ...) {
    if (err != NULL && err_cap > 0) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, err_cap, fmt, ap);
        va_end(ap);
    }
    return -1;
}

/* Returns the named item, or NULL if it is absent or JSON null. */
static const cJSON *lookup(const cJSON *obj, const char *name) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, name);
    if (item == NULL || cJSON_IsNull(item)) {
        return NULL;
    }
    return item;
}

int cloak_config_get_string(const cJSON *obj, const char *name, char *dst,
                            size_t dst_cap, int *found, char *err, size_t err_cap) {
    if (found != NULL) {
        *found = 0;
    }
    const cJSON *item = lookup(obj, name);
    if (item == NULL) {
        return 0;
    }
    if (!cJSON_IsString(item) || item->valuestring == NULL) {
        return cloak_config_set_err(err, err_cap, "%s must be a string", name);
    }
    size_t len = strlen(item->valuestring);
    if (len + 1 > dst_cap) {
        return cloak_config_set_err(err, err_cap,
                                    "%s is too long (%zu bytes, limit %zu)", name,
                                    len, dst_cap - 1);
    }
    memcpy(dst, item->valuestring, len + 1);
    if (found != NULL) {
        *found = 1;
    }
    return 0;
}

int cloak_config_get_int(const cJSON *obj, const char *name, int *dst, int *found,
                         char *err, size_t err_cap) {
    if (found != NULL) {
        *found = 0;
    }
    const cJSON *item = lookup(obj, name);
    if (item == NULL) {
        return 0;
    }
    if (!cJSON_IsNumber(item)) {
        return cloak_config_set_err(err, err_cap, "%s must be a number", name);
    }
    double v = item->valuedouble;
    if (v < -2147483648.0 || v > 2147483647.0 || v != (double)(int)v) {
        return cloak_config_set_err(err, err_cap, "%s must be a whole 32-bit number",
                                    name);
    }
    *dst = (int)v;
    if (found != NULL) {
        *found = 1;
    }
    return 0;
}

int cloak_config_get_bool(const cJSON *obj, const char *name, int *dst, int *found,
                          char *err, size_t err_cap) {
    if (found != NULL) {
        *found = 0;
    }
    const cJSON *item = lookup(obj, name);
    if (item == NULL) {
        return 0;
    }
    if (!cJSON_IsBool(item)) {
        return cloak_config_set_err(err, err_cap, "%s must be true or false", name);
    }
    *dst = cJSON_IsTrue(item) ? 1 : 0;
    if (found != NULL) {
        *found = 1;
    }
    return 0;
}

int cloak_config_get_b64(const cJSON *obj, const char *name, uint8_t *dst,
                         size_t expected_len, int *found, char *err, size_t err_cap) {
    if (found != NULL) {
        *found = 0;
    }
    const cJSON *item = lookup(obj, name);
    if (item == NULL) {
        return 0;
    }
    if (!cJSON_IsString(item) || item->valuestring == NULL) {
        return cloak_config_set_err(err, err_cap, "%s must be a base64 string", name);
    }

    /* decode into a scratch buffer so a wrong length never half-fills dst */
    uint8_t scratch[256];
    if (expected_len > sizeof(scratch)) {
        return cloak_config_set_err(err, err_cap, "%s: unsupported expected length",
                                    name);
    }
    size_t decoded_len = 0;
    if (cloak_base64_decode(item->valuestring, scratch, sizeof(scratch),
                            &decoded_len) != 0) {
        return cloak_config_set_err(
            err, err_cap, "%s is not valid base64, or is too long to decode", name);
    }
    if (decoded_len != expected_len) {
        return cloak_config_set_err(err, err_cap,
                                    "%s must decode to %zu bytes, got %zu", name,
                                    expected_len, decoded_len);
    }
    memcpy(dst, scratch, expected_len);
    if (found != NULL) {
        *found = 1;
    }
    return 0;
}

char *cloak_config_read_file(const char *path, char *err, size_t err_cap) {
    if (path == NULL) {
        cloak_config_set_err(err, err_cap, "no config path given");
        return NULL;
    }
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        cloak_config_set_err(err, err_cap, "cannot open config file %s", path);
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        cloak_config_set_err(err, err_cap, "cannot seek config file %s", path);
        return NULL;
    }
    long size = ftell(f);
    if (size < 0) {
        fclose(f);
        cloak_config_set_err(err, err_cap, "cannot size config file %s", path);
        return NULL;
    }
    if ((unsigned long)size > CLOAK_CONFIG_MAX_FILE) {
        fclose(f);
        cloak_config_set_err(err, err_cap, "config file %s is too large (%ld bytes)",
                             path, size);
        return NULL;
    }
    rewind(f);

    char *buf = malloc((size_t)size + 1);
    if (buf == NULL) {
        fclose(f);
        cloak_config_set_err(err, err_cap, "out of memory reading %s", path);
        return NULL;
    }
    size_t got = fread(buf, 1, (size_t)size, f);
    fclose(f);
    if (got != (size_t)size) {
        free(buf);
        cloak_config_set_err(err, err_cap, "short read on config file %s", path);
        return NULL;
    }
    buf[got] = '\0';
    return buf;
}
