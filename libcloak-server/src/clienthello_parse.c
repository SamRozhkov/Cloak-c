#include "cloak/clienthello_parse.h"

#define TLS_EXT_SERVER_NAME 0x0000
#define TLS_EXT_KEY_SHARE 0x0033
#define TLS_GROUP_X25519 0x001d
#define SNI_NAME_TYPE_HOST_NAME 0x00

typedef struct {
    const uint8_t *p;
    size_t remaining;
} cursor_t;

/* Returns 1 and advances c past n bytes, writing the pre-advance pointer to
 * *out, iff n bytes remain. Returns 0 (c unchanged) otherwise. This is the
 * single chokepoint every length-prefixed field goes through -- no other
 * function in this file indexes into the input directly. */
static int cursor_take(cursor_t *c, size_t n, const uint8_t **out) {
    if (n > c->remaining) {
        return 0;
    }
    *out = c->p;
    c->p += n;
    c->remaining -= n;
    return 1;
}

static int cursor_take_u8(cursor_t *c, uint8_t *out) {
    const uint8_t *p;
    if (!cursor_take(c, 1, &p)) {
        return 0;
    }
    *out = p[0];
    return 1;
}

static int cursor_take_u16(cursor_t *c, uint16_t *out) {
    const uint8_t *p;
    if (!cursor_take(c, 2, &p)) {
        return 0;
    }
    *out = (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
    return 1;
}

static int cursor_take_u24(cursor_t *c, uint32_t *out) {
    const uint8_t *p;
    if (!cursor_take(c, 3, &p)) {
        return 0;
    }
    *out = ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
    return 1;
}

/* Makes a sub-cursor over exactly the next n bytes of c, advancing c past
 * them. Used to scope extension/key_share-list walks so a malformed nested
 * length can never let one field's parsing wander into a sibling field's
 * bytes -- the sub-cursor's own remaining count is the hard ceiling. */
static int cursor_take_scoped(cursor_t *c, size_t n, cursor_t *scoped) {
    const uint8_t *p;
    if (!cursor_take(c, n, &p)) {
        return 0;
    }
    scoped->p = p;
    scoped->remaining = n;
    return 1;
}

/* Validates that n bytes remain and advances c past them, without
 * exposing them to the caller -- used for fields this parser must skip
 * over (with bounds checking) but never needs to read. */
static int cursor_skip(cursor_t *c, size_t n) {
    const uint8_t *unused;
    return cursor_take(c, n, &unused);
}

/* Walks a key_share extension's data looking for a group == 0x001d entry
 * with a 32-byte key_exchange. The data starts with its own 2-byte
 * "client_shares list length" prefix before the list of
 * {group, length, data} entries -- easy to miss (an earlier draft did) and
 * confirmed against Go's parseKeyShare, which does `totalLen :=
 * int(u16(input[0:2])); pointer := 2` before its loop. Returns 0 on
 * structural malformation (a length that overruns ext_cursor); "not found"
 * is reported via *out_key_share staying NULL, which is not itself a
 * failure return.
 *
 * If a ClientHello contains more than one server_name/key_share extension
 * (or, within key_share, more than one X25519 entry), the FIRST one found
 * wins. This differs from Go Cloak's reference parser, which uses a map and
 * so takes the LAST one -- not a bug, just a documented, deliberate choice
 * for this port. */
static int parse_key_share_ext(cursor_t ext_cursor, const uint8_t **out_key_share) {
    uint16_t list_len;
    cursor_t list;
    if (!cursor_take_u16(&ext_cursor, &list_len)) {
        return 0;
    }
    if (!cursor_take_scoped(&ext_cursor, list_len, &list)) {
        return 0;
    }
    while (list.remaining > 0) {
        uint16_t group;
        uint16_t klen;
        const uint8_t *kdata;
        if (!cursor_take_u16(&list, &group)) {
            return 0;
        }
        if (!cursor_take_u16(&list, &klen)) {
            return 0;
        }
        if (!cursor_take(&list, klen, &kdata)) {
            return 0;
        }
        if (group == TLS_GROUP_X25519 && klen == CLOAK_CLIENTHELLO_PARSE_X25519_LEN &&
            *out_key_share == NULL) {
            *out_key_share = kdata;
        }
    }
    return 1;
}

/* Walks a server_name extension's data looking for the first
 * name_type == 0 (host_name) entry. Same not-found-is-not-failure contract
 * as parse_key_share_ext.
 *
 * If a ClientHello contains more than one server_name extension, the FIRST
 * one found wins -- see the note on parse_key_share_ext for how this
 * differs from Go Cloak's reference (map-based, last-wins) parser. */
static int parse_server_name_ext(cursor_t ext_cursor, const uint8_t **out_sni, size_t *out_sni_len) {
    uint16_t list_len;
    cursor_t list;
    if (!cursor_take_u16(&ext_cursor, &list_len)) {
        return 0;
    }
    if (!cursor_take_scoped(&ext_cursor, list_len, &list)) {
        return 0;
    }
    while (list.remaining > 0) {
        uint8_t name_type;
        uint16_t name_len;
        const uint8_t *name;
        if (!cursor_take_u8(&list, &name_type)) {
            return 0;
        }
        if (!cursor_take_u16(&list, &name_len)) {
            return 0;
        }
        if (!cursor_take(&list, name_len, &name)) {
            return 0;
        }
        if (name_type == SNI_NAME_TYPE_HOST_NAME && *out_sni == NULL) {
            *out_sni = name;
            *out_sni_len = name_len;
        }
    }
    return 1;
}

static int parse_extensions(cursor_t exts, const uint8_t **out_sni, size_t *out_sni_len,
                             const uint8_t **out_key_share) {
    while (exts.remaining > 0) {
        uint16_t ext_type;
        uint16_t ext_len;
        cursor_t ext_data;
        if (!cursor_take_u16(&exts, &ext_type)) {
            return 0;
        }
        if (!cursor_take_u16(&exts, &ext_len)) {
            return 0;
        }
        if (!cursor_take_scoped(&exts, ext_len, &ext_data)) {
            return 0;
        }
        if (ext_type == TLS_EXT_SERVER_NAME) {
            if (!parse_server_name_ext(ext_data, out_sni, out_sni_len)) {
                return 0;
            }
        } else if (ext_type == TLS_EXT_KEY_SHARE) {
            if (!parse_key_share_ext(ext_data, out_key_share)) {
                return 0;
            }
        }
    }
    return 1;
}

int cloak_clienthello_parse(const uint8_t *data, size_t len, cloak_clienthello_parsed_t *out) {
    out->random = NULL;
    out->session_id = NULL;
    out->session_id_len = 0;
    out->x25519_key_share = NULL;
    out->sni = NULL;
    out->sni_len = 0;

    cursor_t c;
    c.p = data;
    c.remaining = len;

    const uint8_t *record_hdr;
    if (!cursor_take(&c, 5, &record_hdr)) {
        return -1;
    }
    /* content_type == handshake (0x16), legacy_record_version == {0x03,0x01} */
    if (record_hdr[0] != 0x16 || record_hdr[1] != 0x03 || record_hdr[2] != 0x01) {
        return -1;
    }
    /* record_hdr[3..5) is the record-layer length field -- deliberately
     * unchecked against c.remaining; see the header doc comment. */

    uint8_t handshake_type;
    if (!cursor_take_u8(&c, &handshake_type)) {
        return -1;
    }
    if (handshake_type != 0x01) {
        return -1;
    }

    uint32_t handshake_len;
    if (!cursor_take_u24(&c, &handshake_len)) {
        return -1;
    }
    if ((size_t)handshake_len != c.remaining) {
        return -1;
    }

    const uint8_t *client_version;
    if (!cursor_take(&c, 2, &client_version)) {
        return -1;
    }
    (void)client_version;

    const uint8_t *random;
    if (!cursor_take(&c, CLOAK_CLIENTHELLO_PARSE_RANDOM_LEN, &random)) {
        return -1;
    }

    uint8_t session_id_len;
    if (!cursor_take_u8(&c, &session_id_len)) {
        return -1;
    }
    const uint8_t *session_id = NULL;
    if (session_id_len > 0 && !cursor_take(&c, session_id_len, &session_id)) {
        return -1;
    }

    uint16_t cipher_suites_len;
    if (!cursor_take_u16(&c, &cipher_suites_len)) {
        return -1;
    }
    if (!cursor_skip(&c, cipher_suites_len)) {
        return -1;
    }

    uint8_t compression_methods_len;
    if (!cursor_take_u8(&c, &compression_methods_len)) {
        return -1;
    }
    if (!cursor_skip(&c, compression_methods_len)) {
        return -1;
    }

    /* extensions is scoped to exactly extensions_len bytes via
     * cursor_take_scoped, so parse_extensions can never walk past the
     * declared end of the extensions block. This is a deliberate, stricter
     * divergence from Go Cloak's parseClientHello, which passes
     * peeled[pointer:] -- every remaining byte in the message -- to
     * parseExtensions and never checks that extensions actually stop at the
     * declared extensionsLen boundary. A ClientHello with an X25519
     * key_share placed after the declared end of the extensions block will
     * not have that key_share found by this parser, where Go's would find
     * it. Not an oversight -- see the header's top-level doc comment. */
    uint16_t extensions_len;
    cursor_t extensions;
    if (!cursor_take_u16(&c, &extensions_len)) {
        return -1;
    }
    if (!cursor_take_scoped(&c, extensions_len, &extensions)) {
        return -1;
    }

    const uint8_t *sni = NULL;
    size_t sni_len = 0;
    const uint8_t *key_share = NULL;
    if (!parse_extensions(extensions, &sni, &sni_len, &key_share)) {
        return -1;
    }

    out->random = random;
    out->session_id = session_id;
    out->session_id_len = session_id_len;
    out->x25519_key_share = key_share;
    out->sni = sni;
    out->sni_len = sni_len;
    return 0;
}
