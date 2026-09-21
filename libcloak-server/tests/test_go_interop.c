#define _POSIX_C_SOURCE 200809L

/* THE DIRECT TLS PATH AND THE WHOLE C CLIENT, AGAINST GO'S OWN BINARIES.
 *
 * WHY THIS FILE EXISTS. Eight modules in, every test in this tree had our
 * implementation on BOTH ends of the wire. The one time that changed --
 * module 8's WebSocket oracle, which put gorilla/websocket in front of our
 * server -- it discovered on its first day that this port could not
 * exchange a single data frame with the implementation it is a port of:
 * two header bytes were passed as AES-GCM associated data where Go passes
 * nil, so the handshake succeeded, the session key was correct, and every
 * frame was silently dropped. That defect had survived five modules for
 * exactly one reason -- a round trip between two copies of the same
 * mistake always agrees.
 *
 * The DIRECT (TLS-shaped) path and the C CLIENT had never had that
 * treatment at all. This file gives it to them, by driving Go Cloak's own
 * `ck-client` and `ck-server` binaries (v2.12.0, built into the dev image
 * by Dockerfile.dev's `gobuild` stage) as subprocesses at the far end.
 *
 * WHAT EACH CASE IS FOR, and what would have to break for it to fail:
 *
 *   1. GO ck-client -> C ck-server. A real Go client, a real C server, a
 *      TCP session, 128 KiB compared byte for byte in both directions.
 *      This exercises OUR ClientHello parser (on a uTLS-generated Chrome
 *      hello, which is over 1500 bytes and therefore arrives in several
 *      reads), OUR auth decrypt, OUR ServerHello composer, OUR frame
 *      DEcoder and OUR proxy relay.
 *
 *   2. C ck-client -> GO ck-server. The mirror. This exercises our
 *      ClientHello GENERATOR, our auth payload, our frame ENcoder and our
 *      local TCP listener -- and it is the only test in this tree that
 *      would notice if our sender misbehaved, because Go's receiver is the
 *      only receiver that is not also ours.
 *
 *   3. NEGATIVE CONTROL. Case 1 again, with exactly one byte of the C
 *      server's ServerHello flipped in flight, and nothing else changed.
 *      The Go client must REFUSE -- it must log its handshake failure and
 *      no application byte may cross. A positive-only interoperability
 *      test proves nothing: it cannot distinguish "the two implementations
 *      agree" from "the assertion cannot fail". Module 8's controls (an
 *      unmasked client and a masked server, both of which drew a "bad
 *      MASK" from gorilla) are what made its passes mean anything.
 *
 *   5. THE MIRROR OF THE CONTROL, ADDED AFTER REVIEW. Case 3 proves GO's
 *      client refuses; nothing proved OURS did. A C client that ignored
 *      the ServerHello's AES-GCM tag entirely passed all four of the
 *      original cases, because an honest Go server always produces a
 *      valid tag. So case 5 is case 2 with one bit flipped in a GO
 *      server's ServerHello, and our client must refuse it.
 *
 *   4. BYTE 41 IS 0 IN BOTH DIRECTIONS. The auth payload's flag byte
 *      (bit 0 = unordered) is read off the wire by this test itself -- it
 *      decrypts the ClientHello it relayed, using the server private key
 *      it generated the configuration with -- and asserted 0 for the Go
 *      client's hello and 0 for the C client's hello. Both are the ORDERED
 *      baseline module 9 task 7 has to flip; a task-7 change that sets the
 *      bit unconditionally, or that never sets it, is now visible here.
 *
 * HOW THE BYTES ARE OBSERVED AT ALL. Every case puts a man-in-the-middle
 * TCP relay of this test's own between the Cloak client and the Cloak
 * server. It is the only way to see the ClientHello (case 4) and the only
 * way to corrupt one byte of the ServerHello without editing either
 * implementation (case 3), and running it in the positive cases too means
 * case 3 differs from case 1 in ONE FLIPPED BIT and nothing else.
 *
 * WHAT THIS FILE DOES NOT COVER, stated so nobody reads more into a pass
 * than is there: no distribution of any kind (padding length, SNI choice,
 * connection pick) -- those need the chi-square assertions in
 * test_framework.h and their own test; no real reordering, since frames
 * over loopback essentially never arrive out of order; no CDN/WebSocket
 * leg (that is test_ws_interop's); and nothing about a real network.
 *
 * EVERY WAIT IS BOUNDED BY THE CLOCK, never by an iteration count, and
 * the binaries this file needs are checked for BEFORE any case runs, so a
 * missing oracle is reported in milliseconds as a named missing file
 * rather than as a two-minute ctest timeout. */

#include "go_oracle_harness.h"


/* ------------------------------------------------------------------ */
/* The cases                                                            */
/* ------------------------------------------------------------------ */

/* Filled in by cases 1 and 2, asserted by case 4. Static, not local:
 * captured_hellos_t is 64 KiB. */
static captured_hellos_t go_caps;
static captured_hellos_t c_caps;

static void test_go_client_to_c_server(void) {
    scenario_t sc = {
        .name = "go_client_to_c_server",
        .server_path = CK_SERVER_PATH,
        .server_ready = "ck-server ready",
        .server_is_go = 0,
        .client_path = GO_CK_CLIENT_PATH,
        .client_ready = "Listening on",
        .client_is_go = 1,
        .corrupt_at = -1,
        .num_conn = 2,
    };
    run_scenario(&sc, &go_caps);
    ASSERT_TRUE(go_caps.n > 0 && go_caps.lens[0] > 0);
}

static void test_c_client_to_go_server(void) {
    scenario_t sc = {
        .name = "c_client_to_go_server",
        .server_path = GO_CK_SERVER_PATH,
        .server_ready = "Listening on",
        .server_is_go = 1,
        .client_path = CK_CLIENT_PATH,
        .client_ready = "session up",
        .client_is_go = 0,
        .corrupt_at = -1,
        .num_conn = 2,
    };
    run_scenario(&sc, &c_caps);
    ASSERT_TRUE(c_caps.n > 0 && c_caps.lens[0] > 0);
}

/* Offset 11 of the server -> client stream is the FIRST BYTE OF THE
 * AES-GCM NONCE inside the ServerHello:
 *
 *   [0:5)   TLS record header
 *   [5:9)   handshake type (0x02) + 3-byte length
 *   [9:11)  legacy version
 *   [11:43) ServerHello.random == reply_nonce(12) || ciphertext[0:20)
 *
 * Go's client reads exactly those bytes (internal/client/TLS.go:
 * `encrypted := append(buf[6:38], buf[84:116]...)`, buf being the record
 * PAYLOAD, hence +5 here) and AES-GCM-decrypts them to recover the session
 * key. One flipped bit anywhere in that span must make the tag check fail.
 * Nothing else about this case differs from case 1. */
#define SERVERHELLO_NONCE_OFFSET 11

static void test_go_client_refuses_a_corrupted_serverhello(void) {
    scenario_t sc = {
        .name = "negative_control",
        .server_path = CK_SERVER_PATH,
        .server_ready = "ck-server ready",
        .server_is_go = 0,
        .client_path = GO_CK_CLIENT_PATH,
        .client_ready = "Listening on",
        .client_is_go = 1,
        .corrupt_at = SERVERHELLO_NONCE_OFFSET,
        .client_refusal = "Failed to prepare connection to remote",
        .require_reconnect = 0,
        .client_forbidden = NULL,
        .num_conn = 2,
    };
    run_scenario(&sc, NULL);
}

/* CASE 5: THE MIRROR OF CASE 3, AND THE REASON IT EXISTS.
 *
 * Case 3 proves GO's client refuses a ServerHello this port corrupted.
 * Nothing proved OURS does. That asymmetry was not theoretical: this
 * task's review made a C client that does not enforce the ServerHello's
 * AES-GCM tag at all -- it fell back to using the ciphertext as the
 * session key -- and it passed all four of this file's cases, because an
 * honest Go server always produces a valid tag. The only test in the tree
 * that caught it was test_client_transport.c's
 * test_wrong_key_reply_is_rejected, which corrupts a ServerHello produced
 * by OUR OWN fake server: exactly the "both ends are ours" condition this
 * whole file exists to end.
 *
 * So: case 2 again, with one bit flipped at the same offset 11 of a GO
 * server's reply, and nothing else changed. Our client must refuse.
 *
 * WHAT IS ASSERTED, and its one honest limit: ck-client narrates stack
 * events, so "round failed" is visible from outside the process, but the
 * specific CLOAK_CLIENT_HANDSHAKE_ERR_AUTH code is not -- it never
 * reaches stdout. That code is pinned in-process by
 * test_wrong_key_reply_is_rejected; this case pins that a REAL Go
 * server's corrupted reply reaches the same refusal, that "session up" is
 * never printed, that no application byte crosses, and that the reply
 * really was delivered first. Together the two cover both the code and
 * the interoperation; neither does it alone. */
static void test_c_client_refuses_a_corrupted_serverhello(void) {
    scenario_t sc = {
        .name = "negative_control_c_client",
        .server_path = GO_CK_SERVER_PATH,
        .server_ready = "Listening on",
        .server_is_go = 1,
        .client_path = CK_CLIENT_PATH,
        /* "ck-client ready", not "session up": the whole point is that the
         * session never comes up. The local listener is open before the
         * first handshake either way. */
        .client_ready = "ck-client ready",
        .client_is_go = 0,
        .corrupt_at = SERVERHELLO_NONCE_OFFSET,
        /* No marker: see require_reconnect's comment on scenario_t. */
        .client_refusal = NULL,
        .require_reconnect = 1,
        .client_forbidden = "session up",
        /* ONE CONNECTION, AND THE NUMBER IS LOAD-BEARING.
         *
         * With NumConn 2 this case PASSED against a client that had the
         * AEAD check removed entirely -- measured, by re-applying the
         * review's own mutation. Our connector has a defence Go does not
         * (internal/client/connector.go:52 stores every connection's key
         * into one atomic.Value and compares nothing):
         * cloak_client_connector's keys_agree() refuses a round whose N
         * connections did not derive the SAME session key
         * (CLOAK_CLIENT_CONNECTOR_ERR_KEY_MISMATCH). Each connection's
         * garbage key is different garbage, so the round failed on the
         * mismatch and never reached the tag check -- the case asserted a
         * refusal and got one, for the wrong reason.
         *
         * With ONE connection there is nothing to disagree with, so the
         * only thing that can reject this ServerHello is the AES-GCM tag
         * -- which is exactly the property this case exists to pin. The
         * masking is a real (and welcome) divergence from Go, recorded
         * here rather than in a comment nobody reads, and it is why a
         * mirror control written the obvious way would have proved
         * nothing. */
        .num_conn = 1,
    };
    run_scenario(&sc, NULL);
}

/* Byte 41 of the authentication payload, in both directions, with the
 * ordered value asserted exactly. Module 9 task 7 flips this bit when
 * unordered mode lands; until then a 1 in either hello is a defect, and a
 * task-7 implementation that sets the bit for every session -- or that
 * reads it from the wrong offset -- fails here. */
static void test_byte_41_is_zero_in_both_directions(void) {
    uint8_t priv[CLOAK_X25519_KEY_LEN];
    char pub_b64[64];
    derive_keys(priv, pub_b64, sizeof(pub_b64));

    uint8_t plain[48];
    if (go_caps.lens[0] == 0) {
        fprintf(stderr, "FAIL %s:%d: no ClientHello was captured from Go's ck-client\n",
                __FILE__, __LINE__);
        cloak_test_failures++;
    } else {
        int rc = auth_payload_from_hello(go_caps.hellos[0], go_caps.lens[0], priv, plain);
        ASSERT_EQ_INT(0, rc);
        if (rc == 0) {
            printf("-- Go ck-client auth payload: flag byte 41 = 0x%02x, proxy method \"%.12s\"\n",
                   plain[41], (const char *)plain + 16);
            ASSERT_EQ_INT(0, plain[41]);
            /* Not decoration: it proves the 48 bytes decrypted here really
             * are the authentication payload and not 48 bytes of anything
             * else that happened to authenticate. */
            ASSERT_EQ_INT(0, memcmp(plain + 16, "shadowsocks", 11));
        }
    }

    if (c_caps.lens[0] == 0) {
        fprintf(stderr, "FAIL %s:%d: no ClientHello was captured from our ck-client\n", __FILE__,
                __LINE__);
        cloak_test_failures++;
    } else {
        int rc = auth_payload_from_hello(c_caps.hellos[0], c_caps.lens[0], priv, plain);
        ASSERT_EQ_INT(0, rc);
        if (rc == 0) {
            printf("-- C  ck-client auth payload: flag byte 41 = 0x%02x, proxy method \"%.12s\"\n",
                   plain[41], (const char *)plain + 16);
            ASSERT_EQ_INT(0, plain[41]);
            ASSERT_EQ_INT(0, memcmp(plain + 16, "shadowsocks", 11));
        }
    }
}

int main(void) {
    /* The relay writes to sockets whose peer may already have gone -- a
     * refused handshake closes one under it by design. Without this the
     * negative control would kill the test process instead of asserting. */
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);

    if (!oracle_binaries_present()) {
        return 1;
    }

    test_go_client_to_c_server();
    test_c_client_to_go_server();
    test_go_client_refuses_a_corrupted_serverhello();
    test_c_client_refuses_a_corrupted_serverhello();
    test_byte_41_is_zero_in_both_directions();

    if (cloak_test_failures > 0) {
        fprintf(stderr, "%d assertion(s) failed\n", cloak_test_failures);
        return 1;
    }
    printf("All tests passed\n");
    return 0;
}
