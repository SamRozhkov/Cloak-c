#ifndef CLOAK_CLIENTHELLO_H
#define CLOAK_CLIENTHELLO_H

#include <stddef.h>
#include <stdint.h>

/* Describes a captured, byte-exact browser ClientHello (handshake message
 * only, no TLS record layer) and the byte offsets within it where Cloak's
 * own protocol data gets spliced in, or where the placeholder SNI hostname
 * lives. See the plan's Global Constraints for the exact patching model
 * cloak_clienthello_build implements. */
typedef struct {
    const uint8_t *bytes;
    size_t len;

    size_t random_off;             /* 32 bytes */
    size_t session_id_off;         /* 32 bytes */
    size_t keyshare_off;           /* 32 bytes: the X25519 sub-share inside the key_share extension */

    size_t extensions_length_off;  /* 2-byte big-endian */
    size_t sni_ext_length_off;     /* 2-byte big-endian */
    size_t sni_list_length_off;    /* 2-byte big-endian */
    size_t sni_host_length_off;    /* 2-byte big-endian */
    size_t sni_host_off;
    size_t sni_host_len;           /* length of the baked-in placeholder hostname */
} cloak_clienthello_template_t;

extern const cloak_clienthello_template_t cloak_clienthello_chrome;
extern const cloak_clienthello_template_t cloak_clienthello_firefox;
extern const cloak_clienthello_template_t cloak_clienthello_safari;

/* Builds a ClientHello handshake message (no TLS record layer) from tmpl:
 * splices random/session_id/x25519_key_share (each exactly 32 bytes) into
 * their template-defined positions, and replaces the template's baked-in
 * placeholder SNI hostname with server_name. server_name may be a
 * different length than the template's placeholder, in which case every
 * length field the SNI change affects, and every byte after the hostname,
 * is patched/shifted accordingly.
 *
 * server_name must be non-empty, NUL-terminated, and at most 253 bytes
 * (the DNS hostname length limit).
 *
 * Returns the number of bytes written to out (> 0) on success, or -1 on
 * failure (server_name empty or too long, or out_cap too small for the
 * result). */
long cloak_clienthello_build(const cloak_clienthello_template_t *tmpl,
                              const uint8_t random[32],
                              const uint8_t session_id[32],
                              const uint8_t x25519_key_share[32],
                              const char *server_name,
                              uint8_t *out, size_t out_cap);

#endif
