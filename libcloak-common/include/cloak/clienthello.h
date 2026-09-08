#ifndef CLOAK_CLIENTHELLO_H
#define CLOAK_CLIENTHELLO_H

#include <stddef.h>
#include <stdint.h>

/* Maximum size a caller must provide to cloak_clienthello_build for any
 * supported template and any valid (<=253 byte) server_name. Derived from
 * the largest template (chrome_template, 1720 bytes) plus the maximum
 * possible SNI growth (253 - 15 placeholder = 238 bytes), rounded up. */
#define CLOAK_CLIENTHELLO_MAX_BYTES 2048

#define CLOAK_CLIENTHELLO_MAX_RANDOM_REGIONS 3

/* A byte range within a template (and, after cloak_clienthello_build's SNI
 * shift, within the built output) that must be refilled with fresh random
 * bytes on every call -- content the real browser/uTLS regenerates every
 * handshake (post-quantum/hybrid key share material, Encrypted Client
 * Hello ephemeral key and ciphertext) which this project's captured,
 * static template would otherwise freeze identically across every
 * connection -- an exact-match DPI signature. */
typedef struct {
    size_t off; /* offset in the template, i.e. before any SNI-length shift */
    size_t len;
} cloak_clienthello_region_t;

/* Describes a captured, byte-exact browser ClientHello (handshake message
 * only, no TLS record layer) and the byte offsets within it where Cloak's
 * own protocol data gets spliced in, or where the placeholder SNI hostname
 * lives.
 *
 * Maintenance note: when browsers change their TLS fingerprint, these
 * templates (and every offset below) must be regenerated the same way
 * they were originally produced -- a throwaway Go program using an
 * updated github.com/refraction-networking/utls to build the ClientHello
 * via the same calls Go Cloak's own client uses, then locating each field
 * both by searching for a distinctive marker value planted before
 * marshaling and by an independent structural walk of the TLS wire
 * format, cross-checking the two agree. Never hand-edit these byte arrays
 * or offsets directly. */
typedef struct {
    const uint8_t *bytes;
    size_t len;

    size_t random_off;             /* 32 bytes: Cloak's ECDH ephemeral random */
    size_t session_id_off;         /* 32 bytes: Cloak's auth payload, part 1 */
    size_t keyshare_off;           /* 32 bytes: the X25519 sub-share inside the key_share extension -- Cloak's auth payload, part 2 */

    size_t extensions_length_off;  /* 2-byte big-endian */
    size_t sni_ext_length_off;     /* 2-byte big-endian */
    size_t sni_list_length_off;    /* 2-byte big-endian */
    size_t sni_host_length_off;    /* 2-byte big-endian */
    size_t sni_host_off;
    size_t sni_host_len;           /* length of the baked-in placeholder hostname */

    /* Regions needing fresh random bytes on every build (see
     * cloak_clienthello_region_t's doc comment above). */
    cloak_clienthello_region_t random_regions[CLOAK_CLIENTHELLO_MAX_RANDOM_REGIONS];
    size_t random_region_count;

    /* If nonzero, the offset (in the template) of a 65-byte uncompressed
     * secp256r1 public key point that must be replaced with a genuine,
     * freshly generated on-curve point on every build -- unlike the
     * random_regions above, a plain random 65-byte string is essentially
     * never a valid EC point, so filling it with cloak_random_bytes risks
     * distinguishing this traffic from genuine Firefox on any path that
     * actually decodes it. 0 = not applicable (Chrome and Safari templates
     * don't have this field). */
    size_t secp256r1_keyshare_off;

    /* If nonzero, the offset (in the template) of a TLS padding
     * extension's 4-byte header (type 0x0015 + 2-byte length). Real
     * BoringSSL-style clients (Safari here) size this extension
     * dynamically so the whole ClientHello lands at exactly 512 bytes
     * when it would otherwise be shorter (RFC 7685): pad_data_len =
     * max(1, 512 - unpadded_len - 4) if unpadded_len < 512, otherwise the
     * extension is omitted entirely. cloak_clienthello_build recomputes
     * this after the SNI-length shift, since changing the SNI changes
     * unpadded_len. The padding extension is always the LAST extension in
     * any template that has one. 0 = this template's unpadded size is
     * always >= 512 (Chrome, Firefox), so it never needs a padding
     * extension and this field is unused. */
    size_t padding_ext_off;
    /* The padding extension's ORIGINAL data length in the captured
     * template (used to compute unpadded_len before the recomputed value
     * is known). Unused if padding_ext_off == 0. */
    size_t padding_data_len;
} cloak_clienthello_template_t;

extern const cloak_clienthello_template_t cloak_clienthello_chrome;
extern const cloak_clienthello_template_t cloak_clienthello_firefox;
extern const cloak_clienthello_template_t cloak_clienthello_safari;

/* Builds a ClientHello handshake message (no TLS record layer) from tmpl:
 * splices random/session_id/x25519_key_share (each exactly 32 bytes) into
 * their template-defined positions, replaces the template's baked-in
 * placeholder SNI hostname with server_name (patching every length field
 * the change affects and shifting everything after the hostname), refills
 * every region in tmpl->random_regions with fresh random bytes, generates
 * a fresh on-curve secp256r1 point if tmpl->secp256r1_keyshare_off != 0,
 * and recomputes tmpl->padding_ext_off's padding extension if nonzero.
 *
 * server_name must be non-empty, NUL-terminated, and at most 253 bytes
 * (the DNS hostname length limit).
 *
 * Returns the number of bytes written to out (> 0) on success, or -1 on
 * failure (server_name empty or too long, out_cap too small for the
 * result, or a secp256r1 keygen failure). out_cap should be at least
 * CLOAK_CLIENTHELLO_MAX_BYTES to always succeed for any supported
 * template and any valid server_name. */
long cloak_clienthello_build(const cloak_clienthello_template_t *tmpl,
                              const uint8_t random[32],
                              const uint8_t session_id[32],
                              const uint8_t x25519_key_share[32],
                              const char *server_name,
                              uint8_t *out, size_t out_cap);

#endif
