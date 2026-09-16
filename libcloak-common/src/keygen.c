#include "cloak/keygen.h"

#include "cloak/base64.h"
#include "cloak/common.h"
#include "cloak/crypto.h"

#include <stdint.h>

int cloak_keygen_uid(char *out, size_t out_cap) {
    if (out == NULL || out_cap < cloak_base64_encoded_size(CLOAK_KEYGEN_UID_LEN)) {
        return -1;
    }

    uint8_t uid[CLOAK_KEYGEN_UID_LEN];
    cloak_random_bytes(uid, sizeof(uid));

    return cloak_base64_encode(uid, sizeof(uid), out, out_cap);
}

int cloak_keygen_keypair(char *pub_out, size_t pub_cap, char *priv_out, size_t priv_cap) {
    if (pub_out == NULL || priv_out == NULL) {
        return -1;
    }
    size_t need = cloak_base64_encoded_size(CLOAK_X25519_KEY_LEN);
    if (pub_cap < need || priv_cap < need) {
        return -1;
    }

    uint8_t priv[CLOAK_X25519_KEY_LEN];
    uint8_t pub[CLOAK_X25519_KEY_LEN];
    if (cloak_x25519_generate_keypair(priv, pub) != 0) {
        return -1;
    }

    if (cloak_base64_encode(pub, sizeof(pub), pub_out, pub_cap) != 0) {
        return -1;
    }
    if (cloak_base64_encode(priv, sizeof(priv), priv_out, priv_cap) != 0) {
        return -1;
    }

    return 0;
}
