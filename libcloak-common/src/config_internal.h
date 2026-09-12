#ifndef CLOAK_CONFIG_INTERNAL_H
#define CLOAK_CONFIG_INTERNAL_H

/* Shared between config_common.c, config_client.c and config_server.c.
 * Not installed and not part of the public API. */

#include <stddef.h>
#include <stdint.h>

#include "cJSON.h"
#include "cloak/config.h"

/* Writes a printf-formatted message into err (which may be NULL).
 * Always returns -1, so callers can `return cloak_config_set_err(...)`. */
int cloak_config_set_err(char *err, size_t err_cap, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/* Field accessors. Each takes the object, the JSON field name, and the
 * destination. All of them:
 *   - return 0 and leave dst untouched when the field is absent or JSON
 *     null (the caller applies its own default and required-ness rule),
 *     setting *found (if non-NULL) to 0;
 *   - return 0, write dst and set *found to 1 on success;
 *   - return -1 with err set when the field is present but has the wrong
 *     type or an unusable value.
 * cloak_config_get_string additionally fails if the value does not fit in
 * dst_cap including the NUL. */
int cloak_config_get_string(const cJSON *obj, const char *name, char *dst,
                            size_t dst_cap, int *found, char *err, size_t err_cap);
int cloak_config_get_int(const cJSON *obj, const char *name, int *dst, int *found,
                         char *err, size_t err_cap);
int cloak_config_get_bool(const cJSON *obj, const char *name, int *dst, int *found,
                          char *err, size_t err_cap);

/* Reads a base64 string field and requires it to decode to exactly
 * expected_len bytes. Absent field: returns 0 with *found == 0. */
int cloak_config_get_b64(const cJSON *obj, const char *name, uint8_t *dst,
                         size_t expected_len, int *found, char *err, size_t err_cap);

/* Reads the whole file at path into a NUL-terminated heap buffer the
 * caller must free(). Returns NULL with err set on failure, including a
 * file larger than CLOAK_CONFIG_MAX_FILE bytes. */
#define CLOAK_CONFIG_MAX_FILE (1024 * 1024)
char *cloak_config_read_file(const char *path, char *err, size_t err_cap);

/* The single place each config's fields are read. Both the JSON and the
 * ssv front ends build a cJSON object and hand it to these. */
int cloak_client_config_from_cjson(const cJSON *root, cloak_client_config_t *cfg,
                                   char *err, size_t err_cap);
int cloak_server_config_from_cjson(const cJSON *root, cloak_server_config_t *cfg,
                                   char *err, size_t err_cap);

#endif
