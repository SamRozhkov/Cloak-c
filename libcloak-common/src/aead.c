#include "cloak/crypto.h"

#include <openssl/evp.h>
#include <string.h>

static const EVP_CIPHER *pick_cipher(cloak_aead_method_t method) {
    switch (method) {
        case CLOAK_AEAD_AES_256_GCM:
            return EVP_aes_256_gcm();
        case CLOAK_AEAD_AES_128_GCM:
            return EVP_aes_128_gcm();
        case CLOAK_AEAD_CHACHA20_POLY1305:
            return EVP_chacha20_poly1305();
        default:
            return NULL;
    }
}

size_t cloak_aead_overhead(cloak_aead_method_t method) {
    if (method == CLOAK_AEAD_NONE) {
        return 0;
    }
    return CLOAK_AEAD_TAG_LEN;
}

int cloak_aead_seal(cloak_aead_method_t method,
                     const uint8_t key[CLOAK_AEAD_KEY_LEN],
                     const uint8_t nonce[CLOAK_AEAD_NONCE_LEN],
                     const uint8_t *plaintext, size_t plaintext_len,
                     uint8_t *out, size_t *out_len) {
    if (method == CLOAK_AEAD_NONE) {
        memmove(out, plaintext, plaintext_len);
        *out_len = plaintext_len;
        return 0;
    }

    const EVP_CIPHER *cipher = pick_cipher(method);
    if (cipher == NULL) {
        return -1;
    }

    int ok = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    int len = 0;
    int ciphertext_len = 0;
    uint8_t tag[CLOAK_AEAD_TAG_LEN];

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, CLOAK_AEAD_NONCE_LEN, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;

    if (plaintext_len > 0) {
        if (EVP_EncryptUpdate(ctx, out, &len, plaintext, (int)plaintext_len) != 1) goto done;
        ciphertext_len = len;
    }
    if (EVP_EncryptFinal_ex(ctx, out + ciphertext_len, &len) != 1) goto done;
    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, CLOAK_AEAD_TAG_LEN, tag) != 1) goto done;
    memcpy(out + ciphertext_len, tag, CLOAK_AEAD_TAG_LEN);

    *out_len = (size_t)ciphertext_len + CLOAK_AEAD_TAG_LEN;
    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

int cloak_aead_open(cloak_aead_method_t method,
                     const uint8_t key[CLOAK_AEAD_KEY_LEN],
                     const uint8_t nonce[CLOAK_AEAD_NONCE_LEN],
                     const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t *out_len) {
    if (method == CLOAK_AEAD_NONE) {
        memmove(out, in, in_len);
        *out_len = in_len;
        return 0;
    }

    if (in_len < CLOAK_AEAD_TAG_LEN) {
        return -1;
    }

    const EVP_CIPHER *cipher = pick_cipher(method);
    if (cipher == NULL) {
        return -1;
    }

    int ok = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    size_t ciphertext_len = in_len - CLOAK_AEAD_TAG_LEN;
    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, CLOAK_AEAD_NONCE_LEN, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;

    if (ciphertext_len > 0) {
        if (EVP_DecryptUpdate(ctx, out, &len, in, (int)ciphertext_len) != 1) goto done;
        plaintext_len = len;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, CLOAK_AEAD_TAG_LEN,
                             (void *)(in + ciphertext_len)) != 1) goto done;

    if (EVP_DecryptFinal_ex(ctx, out + plaintext_len, &len) != 1) goto done; /* auth failure lands here */
    plaintext_len += len;

    *out_len = (size_t)plaintext_len;
    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}
