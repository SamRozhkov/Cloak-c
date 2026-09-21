#define _POSIX_C_SOURCE 200809L

/* ALL THREE CLIENTHELLO TEMPLATES, AGAINST GO'S OWN PARSER, AND THE
 * ASSERTION THAT SAYS WHICH ONE ACTUALLY WENT OUT.
 *
 * WHY THIS FILE EXISTS. `test_go_interop.c` put Go Cloak's real ck-server
 * behind our real ck-client and proved the direct path interoperates --
 * for ONE point in configuration space: BrowserSig "chrome". The port
 * carries three captured browser templates
 * (cloak_clienthello_chrome/firefox/safari), and until this file TWO OF
 * THE THREE HAD NEVER BEEN READ BY AN IMPLEMENTATION NOBODY HERE WROTE.
 *
 * That gap has the exact shape of the defect module 8 found on its first
 * day: two header bytes passed as AES-GCM associated data where Go passes
 * nil. It survived five modules because both ends of every test were our
 * own code, and a round trip between two copies of one mistake always
 * agrees. A WRONG OFFSET IN THE FIREFOX OR SAFARI TABLE IS THE SAME KIND
 * OF DEFECT: `cloak_clienthello_build` splices the authentication payload
 * in at `session_id_off` and `keyshare_off`, and our own
 * `cloak_clienthello_parse` reads it back out of the same table, so a
 * table that is internally consistent and externally wrong passes every
 * C-to-C test in this repository. Go's internal/server/TLSAux.go finds
 * those same fields by an independent structural walk of the TLS wire
 * format and has never seen our table. That is the oracle.
 *
 * THE THREE THINGS THIS FILE DOES, and what each is for:
 *
 *   1. THE MATRIX. chrome, firefox and safari, each as our ck-client
 *      against a real Go ck-server, each asserting a COMPLETED SESSION
 *      AND 128 KiB THROUGH IN BOTH DIRECTIONS, transformed by an upstream
 *      that XORs rather than echoes. Not a connect, not a marker: a
 *      session built on the wrong key establishes cleanly and then drops
 *      every frame, so only transformed bytes coming back prove anything.
 *
 *   2. THE NEGATIVE CONTROL, one per template. One bit is flipped inside
 *      the X25519 key share of every ClientHello, at an offset found by
 *      PARSING THE RECORD THAT ARRIVED rather than by reading a template
 *      table, and Go must refuse. Without this, case 1 passing proves the
 *      templates parse -- not that the assertions would notice if they
 *      did not.
 *
 *   3. WHICH TEMPLATE WENT ON THE WIRE. This is the case that decides
 *      whether the other two are worth anything. If the client silently
 *      fell back to Chrome whenever it was asked for Firefox -- a
 *      plausible bug and exactly what an untested code path does -- then
 *      cases 1 and 2 would both pass while testing Chrome three times.
 *      So the fingerprint is read OFF THE RELAYED BYTES: the cipher-suite
 *      list and the extension type list, in order, out of the record the
 *      client actually transmitted, compared against literals for that
 *      browser. NOTHING here reads the BrowserSig this test set, and
 *      nothing here reads cloak_clienthello_chrome/firefox/safari. A
 *      client that ignored BrowserSig entirely fails at cipher suite 0.
 *
 * WHAT THIS FILE DOES NOT COVER. Encryption methods other than aes-gcm
 * and ordering modes other than ordered: those are other points of the
 * same configuration space and other tasks' work. The CDN/WebSocket leg
 * (test_ws_interop's). And it says nothing about whether the templates
 * still match what the browsers ship TODAY -- see the literals' own
 * comment, which is explicit that they were transcribed and not
 * re-captured.
 *
 * Every wait is bounded by CLOCK_MONOTONIC, every port is ephemeral, and
 * the oracle binaries are checked for before any case runs. */

#include "go_oracle_harness.h"

/* ------------------------------------------------------------------ */
/* The published fingerprints                                          */
/* ------------------------------------------------------------------ */

/* WHERE THESE NUMBERS COME FROM, stated plainly because the whole value
 * of case 3 rests on it.
 *
 * They are the cipher-suite lists and extension orders of the three
 * browsers whose ClientHellos uTLS reproduces, and they are the SAME
 * literals `libcloak-common/tests/test_clienthello.c` pins -- transcribed
 * from that file, which records that they were taken from the published
 * fingerprints and cross-checked against each capture when written, and
 * NOT read back out of the template byte arrays. They were not
 * re-captured from a running browser here; that is stated rather than
 * implied.
 *
 * THEY ARE NOT A DUPLICATE OF THAT TEST, because they answer a different
 * question. test_clienthello.c builds a hello FROM A TEMPLATE IT NAMES
 * and checks its shape -- it can never tell you which template a running
 * ck-client chose. This file never names a template: it reads the bytes a
 * real client put on a real socket and asks which of the three they are.
 * A silent Chrome fallback is invisible to that file and fatal here.
 *
 * WHAT MAKES THEM DISCRIMINATING, which is the property case 3 needs.
 * NOT the first entry: Chrome's and Safari's first cipher suite is a
 * GREASE codepoint, drawn fresh per connection since GREASE stopped
 * being frozen in the template, so the two can and sometimes do draw the
 * SAME value there. An earlier version of this comment named exactly
 * that as the discriminator, and it was wrong even then -- it was
 * describing a defect (a frozen GREASE constant) as a feature.
 *
 * What actually discriminates, with GREASE set aside: the lists are
 * different LENGTHS (16 / 17 / 21 suites, 18 / 15 / 16 extensions);
 * Firefox orders the TLS 1.3 suites 1301/1303/1302 where Chrome and
 * Safari order them 1301/1302/1303; Chrome and Safari diverge from each
 * other at the first NON-GREASE position where both have one
 * (0xc02b vs 0xc02c at index 4); Safari alone still offers the 3DES tail
 * (0xc008, 0xc012, 0x000a) and alone carries a padding extension; and
 * Chrome alone carries application_settings (0x44cd). That is asserted,
 * not assumed: test_the_wire_fingerprint_can_fail below runs every
 * captured hello against the other two browsers' literals and requires a
 * mismatch each time, and it runs on hellos whose GREASE was drawn at
 * random.
 *
 * TWO KNOWN, DELIBERATE DIVERGENCES FROM GO, recorded here because this
 * is the file that reads what a client really put on a socket.
 *
 * (a) GREASE VALUES -- no longer a divergence. Go Cloak's client builds
 *     its hello with utls.UClient (internal/client/TLS.go:66-80) and
 *     uTLS v1.8.0 draws BoringSSL-style GREASE per connection. This port
 *     froze one draw into each captured template until module 10b's fix
 *     wave; cloak_clienthello_build now re-draws it. The GREASE entries
 *     in the literals below are therefore matched BY FORM (0x?A?A), not
 *     by value -- see grease_slot() below.
 *
 * (b) CHROME'S EXTENSION ORDER -- STILL A DIVERGENCE, and this file's
 *     ext-order assertion for Chrome pins OUR fixed order, not Go's.
 *     Measured, not remembered: 200 utls.HelloChrome_Auto builds on the
 *     host with uTLS v1.8.0, GREASE codepoints normalised before
 *     comparing, gave 200 DISTINCT extension orders -- Chrome has
 *     shuffled its extensions since Chrome 110 and uTLS reproduces that,
 *     keeping only the GREASE extensions first and last. The same
 *     measurement gave 1 distinct order for Firefox and 1 for Safari, so
 *     their pinned orders are correct.
 *
 *     THE COST, stated plainly: our Chrome profile is distinguishable
 *     from real Chrome, and from Go Cloak's Chrome profile, by having an
 *     INVARIANT extension order. A censor that collects two hellos from
 *     the same client and sees an identical extension permutation has a
 *     signal real Chrome does not give it. This is not fixed on this
 *     branch -- the shuffle reaches into every pinned offset in
 *     clienthello.c (each extension's body would have to move, and the
 *     template's random_regions, keyshare, ECH and padding offsets are
 *     all absolute) -- and is carried as work. It is recorded rather
 *     than fixed, deliberately; see
 *     .superpowers/.../progress.md's carried-work list.
 *
 * WHEN A TEMPLATE IS REGENERATED, these are updated in the same commit,
 * from the same capture, and never by copying whatever the new template
 * happens to say. See cloak/clienthello.h's maintenance note. */

#define MAX_FP_SUITES 32
#define MAX_FP_EXTS 32

static const uint16_t chrome_suites[] = {
    0xfafa, /* GREASE -- matched by FORM, not value; see grease_slot() */
    0x1301, 0x1302, 0x1303,
    0xc02b, 0xc02f, 0xc02c, 0xc030,
    0xcca9, 0xcca8,
    0xc013, 0xc014,
    0x009c, 0x009d,
    0x002f, 0x0035,
};
static const uint16_t chrome_exts[] = {
    0xfafa, /* GREASE */
    0x0000, /* server_name */
    0x0005, /* status_request */
    0xff01, /* renegotiation_info */
    0x001b, /* compress_certificate */
    0x0010, /* application_layer_protocol_negotiation */
    0x44cd, /* application_settings (Chrome's private codepoint) */
    0x0017, /* extended_master_secret */
    0x0033, /* key_share */
    0x000b, /* ec_point_formats */
    0x0023, /* session_ticket */
    0x002d, /* psk_key_exchange_modes */
    0x000a, /* supported_groups */
    0x002b, /* supported_versions */
    0x000d, /* signature_algorithms */
    0xfe0d, /* encrypted_client_hello */
    0x0012, /* signed_certificate_timestamp */
    0x2a2a, /* GREASE */
};

static const uint16_t firefox_suites[] = {
    0x1301, 0x1303, 0x1302, /* note the 1303/1302 swap -- Firefox, not Chrome */
    0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030,
    0xc00a, 0xc009, 0xc013, 0xc014,
    0x009c, 0x009d,
    0x002f, 0x0035,
};
static const uint16_t firefox_exts[] = {
    0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005,
    0x0022, /* delegated_credentials -- Firefox only */
    0x0033, 0x002b, 0x000d, 0x002d,
    0x001c, /* record_size_limit -- Firefox only */
    0xfe0d,
};

static const uint16_t safari_suites[] = {
    0x2a2a, /* GREASE */
    0x1301, 0x1302, 0x1303,
    0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8,
    0xc00a, 0xc009, 0xc014, 0xc013,
    0x009d, 0x009c, 0x0035, 0x002f,
    0xc008, 0xc012, 0x000a, /* the 3DES tail Safari really does still offer */
};
static const uint16_t safari_exts[] = {
    0x2a2a, 0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x0005,
    0x000d, 0x0012, 0x0033, 0x002d, 0x002b, 0x001b,
    0x1a1a, /* GREASE */
    0x0015, /* padding -- always last */
};

typedef struct {
    const char *name; /* also the BrowserSig value written into the config */
    const uint16_t *suites;
    size_t suite_count;
    const uint16_t *exts;
    size_t ext_count;
} browser_fp_t;

#define FP(n, s, e)                                                                          \
    {                                                                                        \
        n, s, sizeof(s) / sizeof((s)[0]), e, sizeof(e) / sizeof((e)[0])                       \
    }

static const browser_fp_t browsers[] = {
    FP("chrome", chrome_suites, chrome_exts),
    FP("firefox", firefox_suites, firefox_exts),
    FP("safari", safari_suites, safari_exts),
};

#define NBROWSERS (sizeof(browsers) / sizeof(browsers[0]))

/* Go's own text for an authentication payload that did not open:
 * internal/server/auth.go's
 *   var ErrBadDecryption = errors.New("decryption/authentication failure")
 * wrapped at line 84 and logged by internal/server/dispatcher.go's
 * dispatchConnection. Transcribed from that source, in the tree this
 * image's go-ck-server was built from (Cloak v2.12.0). */
#define GO_BAD_DECRYPTION "decryption/authentication failure"

/* ------------------------------------------------------------------ */
/* Reading a fingerprint off the wire                                   */
/* ------------------------------------------------------------------ */

typedef struct {
    int ok;
    uint16_t legacy_version;
    size_t session_id_len;
    uint16_t suites[MAX_FP_SUITES];
    size_t suite_count;
    uint8_t compression[8];
    size_t compression_count;
    uint16_t ext_types[MAX_FP_EXTS];
    size_t ext_count;
} wire_fingerprint_t;

static uint16_t be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

/* A structural walk of a WHOLE TLS RECORD as it came off the socket --
 * record header included, which is what makes this a different function
 * from libcloak-common/tests/test_clienthello.c's read_fingerprint (that
 * one walks a bare handshake message a build call just returned).
 *
 * It deliberately does NOT use cloak_clienthello_parse. That parser is
 * the server's, it is ours, and it stops at the four fields Cloak's
 * protocol needs -- it never looks at a cipher suite. Walking the bytes
 * here keeps the fingerprint assertion independent of the code the same
 * suite tests elsewhere. */
static wire_fingerprint_t read_wire_fingerprint(const uint8_t *rec, size_t len) {
    wire_fingerprint_t f;
    memset(&f, 0, sizeof(f));
    /* 5 record header + 4 handshake header + 2 version + 32 random + 1 */
    if (len < 5 + 4 + 2 + 32 + 1) {
        return f;
    }
    if (rec[0] != 0x16 || rec[5] != 0x01) {
        return f; /* not a handshake record carrying a ClientHello */
    }
    size_t off = 5 + 4;
    f.legacy_version = be16(rec + off);
    off += 2;
    off += 32; /* random */
    f.session_id_len = rec[off];
    off += 1 + f.session_id_len;
    if (off + 2 > len) {
        return f;
    }
    size_t cs_len = be16(rec + off);
    off += 2;
    if (off + cs_len > len || (cs_len % 2) != 0 || cs_len / 2 > MAX_FP_SUITES) {
        return f;
    }
    for (size_t i = 0; i < cs_len / 2; i++) {
        f.suites[i] = be16(rec + off + 2 * i);
    }
    f.suite_count = cs_len / 2;
    off += cs_len;
    if (off >= len) {
        return f;
    }
    size_t cm_len = rec[off];
    off += 1;
    if (off + cm_len > len || cm_len > sizeof(f.compression)) {
        return f;
    }
    memcpy(f.compression, rec + off, cm_len);
    f.compression_count = cm_len;
    off += cm_len;
    if (off + 2 > len) {
        return f;
    }
    size_t ext_len = be16(rec + off);
    off += 2;
    size_t ext_end = off + ext_len;
    if (ext_end != len) {
        return f; /* the extensions must end exactly where the record does */
    }
    while (off < ext_end) {
        if (off + 4 > ext_end || f.ext_count >= MAX_FP_EXTS) {
            return f;
        }
        f.ext_types[f.ext_count++] = be16(rec + off);
        uint16_t dlen = be16(rec + off + 2);
        if (off + 4 + dlen > ext_end) {
            return f;
        }
        off += 4 + (size_t)dlen;
    }
    f.ok = 1;
    return f;
}

/* Counts how many ways `rec` disagrees with `want`. `report` is 0 for
 * test_the_wire_fingerprint_can_fail, which drives this with the WRONG
 * browser's literals on purpose: it must still count, but it must not
 * print FAIL lines, because a file that prints expected FAILs teaches a
 * reader to skim past real ones. */
/* A GREASE codepoint, RFC 8701's 0x?A?A form. */
static int grease_slot(uint16_t v) {
    return (v & 0x0f0fu) == 0x0a0au && (uint8_t)(v >> 8) == (uint8_t)(v & 0xffu);
}

/* Compares one fingerprint entry. Where the PINNED literal is a GREASE
 * codepoint the wire value must be a GREASE codepoint -- any of the
 * sixteen -- rather than that exact one, because the client re-draws
 * GREASE every connection the way uTLS does. Where the pinned literal is
 * anything else, the comparison is exact, as before.
 *
 * This is the ONLY place this file relaxes, it relaxes exactly as far as
 * the randomisation requires, and it still rejects a slot that is not a
 * legal GREASE value at all. cloak_clienthello_build_with_grease_seed
 * exists for tests that need byte-exactness; it is unusable here,
 * because these hellos come off a socket from a separately spawned
 * ck-client process. */
static int fp_entry_differs(uint16_t wire, uint16_t want) {
    if (grease_slot(want)) {
        return !grease_slot(wire);
    }
    return wire != want;
}

static int wire_fingerprint_mismatches(const char *who, const uint8_t *rec, size_t len,
                                       const browser_fp_t *want, int report) {
    int bad = 0;
    wire_fingerprint_t f = read_wire_fingerprint(rec, len);
    if (!f.ok) {
        if (report) {
            fprintf(stderr,
                    "FAIL %s:%d: %s: the %zu bytes the client put on the wire are not a "
                    "walkable ClientHello record\n",
                    __FILE__, __LINE__, who, len);
            cloak_test_failures++;
        }
        return 1;
    }
    if (f.legacy_version != 0x0303 || f.session_id_len != 32 || f.compression_count != 1 ||
        f.compression[0] != 0) {
        bad++;
        if (report) {
            fprintf(stderr,
                    "FAIL %s:%d: %s: legacy_version 0x%04x, session id %zu bytes, %zu "
                    "compression method(s) -- wanted 0x0303, 32, 1 (null)\n",
                    __FILE__, __LINE__, who, f.legacy_version, f.session_id_len,
                    f.compression_count);
            cloak_test_failures++;
        }
    }
    if (f.suite_count != want->suite_count) {
        bad++;
        if (report) {
            fprintf(stderr,
                    "FAIL %s:%d: %s: %zu cipher suites on the wire, %s offers %zu\n",
                    __FILE__, __LINE__, who, f.suite_count, want->name, want->suite_count);
            cloak_test_failures++;
        }
    }
    for (size_t i = 0; i < want->suite_count && i < f.suite_count; i++) {
        if (fp_entry_differs(f.suites[i], want->suites[i])) {
            bad++;
            if (report) {
                fprintf(stderr,
                        "FAIL %s:%d: %s: cipher suite %zu on the wire is 0x%04x, %s offers "
                        "0x%04x -- either this client sent a DIFFERENT browser's template "
                        "than it was asked for, or that template's shape changed\n",
                        __FILE__, __LINE__, who, i, f.suites[i], want->name,
                        want->suites[i]);
                cloak_test_failures++;
            }
        }
    }
    if (f.ext_count != want->ext_count) {
        bad++;
        if (report) {
            fprintf(stderr, "FAIL %s:%d: %s: %zu extensions on the wire, %s sends %zu\n",
                    __FILE__, __LINE__, who, f.ext_count, want->name, want->ext_count);
            cloak_test_failures++;
        }
    }
    for (size_t i = 0; i < want->ext_count && i < f.ext_count; i++) {
        if (fp_entry_differs(f.ext_types[i], want->exts[i])) {
            bad++;
            if (report) {
                fprintf(stderr,
                        "FAIL %s:%d: %s: extension %zu on the wire is 0x%04x, %s sends "
                        "0x%04x -- extension ORDER is part of the fingerprint\n",
                        __FILE__, __LINE__, who, i, f.ext_types[i], want->name,
                        want->exts[i]);
                cloak_test_failures++;
            }
        }
    }
    return bad;
}

/* ------------------------------------------------------------------ */
/* The cases                                                            */
/* ------------------------------------------------------------------ */

/* Filled by case 1, re-read by case 3's self-check. Static because
 * captured_hellos_t is 64 KiB apiece. */
static captured_hellos_t positive_caps[NBROWSERS];

/* CASE 1 + CASE 3. Each template, end to end against Go's own server,
 * with the template identified from the bytes that crossed.
 *
 * The fingerprint is asserted for EVERY connection the client opened, not
 * just the first: our connector's Chrome-to-Firefox fallback (D3, in
 * cloak_client_connector_conn_t::browser) is per connection, so a run in
 * which one connection quietly changed template would be invisible to a
 * check of connection 0 alone. */
static void test_every_template_reaches_go(void) {
    for (size_t b = 0; b < NBROWSERS; b++) {
        char name[64];
        snprintf(name, sizeof(name), "c_client_%s_to_go_server", browsers[b].name);
        scenario_t sc = {
            .name = name,
            .server_path = GO_CK_SERVER_PATH,
            .server_ready = "Listening on",
            .server_is_go = 1,
            .client_path = CK_CLIENT_PATH,
            .client_ready = "session up",
            .client_is_go = 0,
            .corrupt_at = -1,
            .num_conn = 2,
            .browser = browsers[b].name,
            /* THE MARKER THE NEGATIVE CONTROL LIVES ON, PROVEN TO
             * DISCRIMINATE. Go's ErrBadDecryption text must NOT appear
             * here -- if it were in the server's log on a run that
             * completed a session and moved 128 KiB, the control below
             * would be watching a string Go prints anyway. */
            .server_forbidden = GO_BAD_DECRYPTION,
        };
        run_scenario(&sc, &positive_caps[b]);

        if (positive_caps[b].n == 0) {
            fprintf(stderr,
                    "FAIL %s:%d: %s: the relay never saw a whole ClientHello, so nothing "
                    "can be said about which template was sent\n",
                    __FILE__, __LINE__, name);
            cloak_test_failures++;
            continue;
        }
        for (size_t i = 0; i < positive_caps[b].n; i++) {
            char who[96];
            snprintf(who, sizeof(who), "%s connection %zu", name, i);
            (void)wire_fingerprint_mismatches(who, positive_caps[b].hellos[i],
                                              positive_caps[b].lens[i], &browsers[b], 1);
        }
        printf("   %zu ClientHello(s) on the wire, all fingerprinted as %s\n",
               positive_caps[b].n, browsers[b].name);
    }
}

/* CASE 2: THE NEGATIVE CONTROL, ONE PER TEMPLATE.
 *
 * One bit is flipped inside the X25519 key share of every ClientHello the
 * relay forwards. Go's server finds those 32 bytes by walking the
 * key_share extension itself (internal/server/TLSAux.go parseKeyShare)
 * and AES-GCM-opens them together with the session id; one flipped bit
 * must make that tag check fail, and the session must never come up.
 *
 * WHAT THE REFUSAL IS READ FROM, and why it is the server's log and not
 * the client's. Go's dispatcher, on a failed AuthFirstPacket, warns and
 * then hands the connection to goWeb(), which dials RedirAddr, fails, and
 * RETURNS WITHOUT CLOSING (internal/server/dispatcher.go,
 * dispatchConnection). MEASURED, not read: a first draft of this case
 * waited for OUR client to reconnect and saw nothing in 8 s on all three
 * templates, because the client was still sitting on a socket Go had
 * neither answered nor closed. So the evidence is Go's own
 * ErrBadDecryption line (internal/server/auth.go), which is stronger than
 * a reconnect anyway: "decryption/authentication failure" is what Go
 * prints when it PARSED the ClientHello, found a 32-byte X25519 share and
 * a 32-byte session id where the TLS wire format says they are, and only
 * then failed the AEAD tag. A template Go could not parse at all would
 * print "Malformed ClientHello" and this assertion would fail. The
 * control therefore pins the parse as well as the refusal.
 *
 * WHY THE OFFSET IS FOUND BY PARSING AND NOT WRITTEN DOWN, twice over:
 * the three templates put key_share in three different places, so no
 * constant corrupts all three; and our connector falls back from Chrome
 * to Firefox after a failed handshake, so the Chrome run's RETRIES carry
 * a Firefox hello, which a Chrome-shaped constant would sail straight
 * past -- the control would then watch a client succeed and call it a
 * refusal.
 *
 * NumConn IS 1, because the refusal must be attributable. With 2 our
 * connector has a defence Go does not -- keys_agree() rejects a round
 * whose connections derived different session keys -- so a corrupted run
 * can fail for a reason that has nothing to do with the ClientHello. With
 * one connection there is nothing to disagree with. (It also halves the
 * hellos Go has to reject, and the case is already the expensive half of
 * this file.)
 *
 * WHAT IS ASSERTED, all of it: Go says ErrBadDecryption; our client never
 * says "session up"; no application byte crosses in QUIET_MS; the relay
 * really did corrupt at least one hello (run_scenario checks that itself,
 * so a control whose flipped bit never landed cannot pass); and the hello
 * on connection 0 really was this browser's template. */
static void test_go_refuses_every_corrupted_template(void) {
    for (size_t b = 0; b < NBROWSERS; b++) {
        char name[64];
        snprintf(name, sizeof(name), "corrupt_%s_keyshare", browsers[b].name);
        static captured_hellos_t caps;
        scenario_t sc = {
            .name = name,
            .server_path = GO_CK_SERVER_PATH,
            .server_ready = "Listening on",
            .server_is_go = 1,
            .client_path = CK_CLIENT_PATH,
            /* "ck-client ready", not "session up": the whole point is that
             * the session never comes up. */
            .client_ready = "ck-client ready",
            .client_is_go = 0,
            .corrupt_at = -1,
            .client_refusal = NULL,
            .require_reconnect = 0,
            .client_forbidden = "session up",
            .server_refusal = GO_BAD_DECRYPTION,
            .num_conn = 1,
            .browser = browsers[b].name,
            .corrupt_keyshare = 1,
        };
        run_scenario(&sc, &caps);

        /* THE CONTROL'S OWN CONTROL: the connection whose key share was
         * corrupted must really have carried THIS browser's template.
         * Connection 0 only -- the retries after it are Firefox by
         * design when b is chrome. */
        if (caps.n == 0) {
            fprintf(stderr,
                    "FAIL %s:%d: %s: the relay never saw a whole ClientHello, so it cannot "
                    "be said which template Go refused\n",
                    __FILE__, __LINE__, name);
            cloak_test_failures++;
        } else {
            char who[96];
            snprintf(who, sizeof(who), "%s connection 0", name);
            (void)wire_fingerprint_mismatches(who, caps.hellos[0], caps.lens[0], &browsers[b],
                                              1);
        }
    }
}

/* CASE 3's SELF-CHECK, and the reason it is not decoration.
 *
 * Case 1 asserts every captured hello MATCHES its own browser's
 * literals. A comparison that could not fail would satisfy that just as
 * well -- and "the loop never ran" (a zero-length list, a walk that
 * returned early) looks exactly like a pass. So every captured hello is
 * also run against the OTHER TWO browsers' literals, with reporting off,
 * and each of those comparisons is required to produce at least one
 * mismatch.
 *
 * That is the assertion that would fail if all three templates were
 * secretly the same bytes -- which is precisely the silent-fallback
 * failure mode this whole file exists to rule out. */
static void test_the_wire_fingerprint_can_fail(void) {
    for (size_t b = 0; b < NBROWSERS; b++) {
        if (positive_caps[b].n == 0) {
            fprintf(stderr,
                    "FAIL %s:%d: no %s ClientHello was captured, so the fingerprint's "
                    "ability to fail was never demonstrated\n",
                    __FILE__, __LINE__, browsers[b].name);
            cloak_test_failures++;
            continue;
        }
        for (size_t o = 0; o < NBROWSERS; o++) {
            if (o == b) {
                continue;
            }
            int bad = wire_fingerprint_mismatches("self-check", positive_caps[b].hellos[0],
                                                  positive_caps[b].lens[0], &browsers[o], 0);
            if (bad <= 0) {
                fprintf(stderr,
                        "FAIL %s:%d: the %s ClientHello captured off the wire is "
                        "indistinguishable from %s's published fingerprint, so case 1's "
                        "matching assertion proves nothing\n",
                        __FILE__, __LINE__, browsers[b].name, browsers[o].name);
                cloak_test_failures++;
            } else {
                printf("   %s hello vs %s literals: %d mismatch(es), as required\n",
                       browsers[b].name, browsers[o].name, bad);
            }
        }
    }
}

int main(void) {
    /* The relay writes to sockets whose peer may already have gone -- a
     * refused handshake closes one under it by design. Without this the
     * negative controls would kill the test process instead of
     * asserting. */
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);

    if (!oracle_binaries_present()) {
        return 1;
    }

    test_every_template_reaches_go();
    test_the_wire_fingerprint_can_fail();
    test_go_refuses_every_corrupted_template();

    if (cloak_test_failures > 0) {
        fprintf(stderr, "%d assertion(s) failed\n", cloak_test_failures);
        return 1;
    }
    printf("All tests passed\n");
    return 0;
}
