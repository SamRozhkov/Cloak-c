#include "cloak/crypto.h"
#include "test_framework.h"
#include <string.h>

static void test_keypair_generation_is_not_all_zero(void) {
    uint8_t priv[CLOAK_X25519_KEY_LEN];
    uint8_t pub[CLOAK_X25519_KEY_LEN];
    uint8_t zeros[CLOAK_X25519_KEY_LEN];
    memset(zeros, 0, sizeof(zeros));

    int rc = cloak_x25519_generate_keypair(priv, pub);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_MEM_NE(priv, zeros, sizeof(priv));
    ASSERT_MEM_NE(pub, zeros, sizeof(pub));
}

static void test_two_keypairs_are_different(void) {
    uint8_t priv_a[CLOAK_X25519_KEY_LEN];
    uint8_t pub_a[CLOAK_X25519_KEY_LEN];
    uint8_t priv_b[CLOAK_X25519_KEY_LEN];
    uint8_t pub_b[CLOAK_X25519_KEY_LEN];

    cloak_x25519_generate_keypair(priv_a, pub_a);
    cloak_x25519_generate_keypair(priv_b, pub_b);

    ASSERT_MEM_NE(pub_a, pub_b, sizeof(pub_a));
}

static void test_ecdh_agreement(void) {
    uint8_t alice_priv[CLOAK_X25519_KEY_LEN];
    uint8_t alice_pub[CLOAK_X25519_KEY_LEN];
    uint8_t bob_priv[CLOAK_X25519_KEY_LEN];
    uint8_t bob_pub[CLOAK_X25519_KEY_LEN];

    ASSERT_EQ_INT(cloak_x25519_generate_keypair(alice_priv, alice_pub), 0);
    ASSERT_EQ_INT(cloak_x25519_generate_keypair(bob_priv, bob_pub), 0);

    uint8_t secret_from_alice[CLOAK_X25519_KEY_LEN];
    uint8_t secret_from_bob[CLOAK_X25519_KEY_LEN];

    ASSERT_EQ_INT(cloak_x25519_shared_secret(alice_priv, bob_pub, secret_from_alice), 0);
    ASSERT_EQ_INT(cloak_x25519_shared_secret(bob_priv, alice_pub, secret_from_bob), 0);

    ASSERT_MEM_EQ(secret_from_alice, secret_from_bob, CLOAK_X25519_KEY_LEN);
}

static void test_ecdh_with_wrong_peer_gives_different_secret(void) {
    uint8_t alice_priv[CLOAK_X25519_KEY_LEN];
    uint8_t alice_pub[CLOAK_X25519_KEY_LEN];
    uint8_t bob_priv[CLOAK_X25519_KEY_LEN];
    uint8_t bob_pub[CLOAK_X25519_KEY_LEN];
    uint8_t eve_priv[CLOAK_X25519_KEY_LEN];
    uint8_t eve_pub[CLOAK_X25519_KEY_LEN];

    cloak_x25519_generate_keypair(alice_priv, alice_pub);
    cloak_x25519_generate_keypair(bob_priv, bob_pub);
    cloak_x25519_generate_keypair(eve_priv, eve_pub);

    uint8_t secret_with_bob[CLOAK_X25519_KEY_LEN];
    uint8_t secret_with_eve[CLOAK_X25519_KEY_LEN];
    cloak_x25519_shared_secret(alice_priv, bob_pub, secret_with_bob);
    cloak_x25519_shared_secret(alice_priv, eve_pub, secret_with_eve);

    ASSERT_MEM_NE(secret_with_bob, secret_with_eve, CLOAK_X25519_KEY_LEN);
}

TEST_MAIN_BEGIN()
    test_keypair_generation_is_not_all_zero();
    test_two_keypairs_are_different();
    test_ecdh_agreement();
    test_ecdh_with_wrong_peer_gives_different_secret();
TEST_MAIN_END()
