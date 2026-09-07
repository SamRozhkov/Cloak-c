#include "cloak/crypto.h"

#include <openssl/evp.h>

int cloak_x25519_generate_keypair(uint8_t priv[CLOAK_X25519_KEY_LEN],
                                   uint8_t pub[CLOAK_X25519_KEY_LEN]) {
    int ok = -1;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    size_t priv_len = CLOAK_X25519_KEY_LEN;
    size_t pub_len = CLOAK_X25519_KEY_LEN;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (pctx == NULL) goto done;
    if (EVP_PKEY_keygen_init(pctx) <= 0) goto done;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) goto done;

    if (EVP_PKEY_get_raw_private_key(pkey, priv, &priv_len) <= 0) goto done;
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len) <= 0) goto done;

    ok = 0;

done:
    if (pkey) EVP_PKEY_free(pkey);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    return ok;
}

int cloak_x25519_shared_secret(const uint8_t priv[CLOAK_X25519_KEY_LEN],
                                const uint8_t peer_pub[CLOAK_X25519_KEY_LEN],
                                uint8_t out_secret[CLOAK_X25519_KEY_LEN]) {
    int ok = -1;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *peer = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t secret_len = CLOAK_X25519_KEY_LEN;

    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, CLOAK_X25519_KEY_LEN);
    peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, CLOAK_X25519_KEY_LEN);
    if (pkey == NULL || peer == NULL) goto done;

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx == NULL) goto done;

    if (EVP_PKEY_derive_init(ctx) <= 0) goto done;
    if (EVP_PKEY_derive_set_peer(ctx, peer) <= 0) goto done;
    if (EVP_PKEY_derive(ctx, out_secret, &secret_len) <= 0) goto done;

    ok = 0;

done:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (peer) EVP_PKEY_free(peer);
    return ok;
}
