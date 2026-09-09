# libcloak-server ClientHello Parser Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the server-side ClientHello parser: a minimal, defensive parser (not a TLS stack) that extracts `random`, `session_id`, SNI, and the X25519 `key_share` from an incoming TLS record, mirroring Go Cloak's `internal/server/TLSAux.go`. This is the first module of a new library, `libcloak-server`.

**Architecture:** A single self-contained parser function, `cloak_clienthello_parse`, that walks an untrusted byte buffer through a bounds-checked "cursor" abstraction (every length-prefixed field goes through one chokepoint function that can never read past the buffer end) and populates an output struct with pointers *into* the input buffer -- no copying, no heap allocation. Unlike Go's implementation, which relies on `panic`/`recover` to turn out-of-bounds slice access into an error, this C port makes every bounds check explicit, since there is no equivalent safety net.

**Tech Stack:** C11, no external dependencies for the parser itself (no OpenSSL, no libcloak-common). CMake + CTest, following the `libcloak-mux` library-layout pattern. Docker-only build/test (`Dockerfile.dev`, image `cloak-c-dev`) -- Linux-only project.

## Global Constraints

- Linux-only; all builds and test runs happen via Docker (`docker build -q -f Dockerfile.dev -t cloak-c-dev .`, then `docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "..."`), matching every prior module in this repository.
- Zero compiler warnings (`-Wall -Wextra`, already set globally in the root `CMakeLists.txt`).
- This is a **defensive parser over attacker-controlled bytes**: it runs before any authentication step, on whatever arrives from any TCP connection (Cloak client or not). It must never read outside `data[0, len)` regardless of how malformed or adversarial the input is. No `panic`/`recover`-equivalent exists in C -- every length field must be validated against the actual remaining buffer *before* it is used to advance a pointer or size a read.
- Absence of the SNI extension or the X25519 `key_share` entry is **not** a parse failure -- only structural malformation is (wrong record type, wrong handshake type, or any length field inconsistent with the actual bytes present). A real Cloak client always sends both, but arbitrary non-Cloak traffic reaching this parser (e.g. during the server's future redirect-on-fail sniff) is not malformed just because it isn't Cloak's traffic; that policy decision belongs to a later module, not this parser.
- This function does **not** validate the record layer's own declared 2-byte length field against the buffer length -- it only checks the 3 magic bytes (`0x16 0x03 0x01`) and then validates the handshake message's own length field against the actual remaining bytes. This matches Go Cloak's own parser exactly, and assumes the caller has already delivered exactly one un-fragmented ClientHello record (a caller-level assumption, not something this parser enforces).
- No copying, no heap allocation anywhere in the parser: `cloak_clienthello_parsed_t`'s pointer fields point directly into the caller's `data` buffer, which must outlive the parsed struct.

---

## Provenance and verification (read this before touching any code)

This plan's code is not a fresh implementation -- it has already been written and verified against real, running code (compiled, tested, run under AddressSanitizer/UndefinedBehaviorSanitizer), following this project's standing rule that any parsing logic handling untrusted bytes must be verified this way before being trusted, not merely reasoned about.

**Reference implementation studied:** Go Cloak's `internal/server/TLSAux.go` (`parseClientHello`, `parseExtensions`, `parseKeyShare`) and its call sites in `internal/server/TLS.go` (`unmarshalClientHello` uses only `ch.random`, `ch.sessionId`, and `parseKeyShare(ch.extensions[0x0033])` -- Go's server never actually uses SNI anywhere, but this project's design spec explicitly asks for it to be extracted, so it is included here for parity/future use). Go's parser relies on `panic`/`recover` to turn any out-of-bounds slice access into a returned error; this C port cannot do that, so every read is instead routed through an explicit bounds-checked "cursor" -- the logic is equivalent to Go's, not a line-by-line translation of it.

**Verification performed (all passed, on real compiled/run code, not by inspection):**
1. **Go's own test vectors**, copied verbatim from `internal/server/TLSAux_test.go`'s `TestParseClientHello`: a real, valid Cloak ClientHello ("good Cloak ClientHello"), a structurally corrupted one ("Malformed ClientHello"), a wrong-record-type one ("not Handshake"), a wrong-record-version one ("wrong TLS record layer version"), and a TLS 1.2 ClientHello ("TLS 1.2"). All five produce the same accept/reject verdict as Go's own test expects.
   - One correction made along the way: the "Malformed ClientHello" vector's name suggests a semantic corruption (e.g. a flipped byte inside `random`), but diffing it against the good vector's hex string shows it is actually **one extra hex nibble inserted**, which desyncs every byte boundary after that point -- a genuine *structural* corruption (1035 hex characters vs. the good vector's 1034). This C parser correctly rejects it on structural grounds, matching Go.
2. **Truncation sweep**: the good vector, truncated to every possible length from 0 to its full 517 bytes (518 test cases), run under ASan+UBSan. Zero crashes, and every truncated prefix except the full-length one is correctly rejected.
3. **Byte-flip sweep**: every one of the 8 bits in every one of the good vector's 517 bytes flipped one at a time (4136 mutations), run under ASan+UBSan. Zero crashes on any mutation.
4. **Round-trip against this repository's own client-side code**: built real ClientHellos with the already-merged `cloak_clienthello_build` (all three templates -- Chrome, Firefox, Safari -- crossed with five SNI lengths including the 1-byte and 253-byte extremes), fed each one through this parser, and confirmed every extracted field (`random`, `session_id`, `x25519_key_share`, `sni`) matches byte-for-byte what was spliced in during building. This proves the client and server halves of this project agree on wire format.
5. **A real bug was found and fixed during this verification**, not by inspection: the first draft forgot that the `key_share` extension's data begins with its own 2-byte "length of the client_shares list" prefix *before* the list of `{group, length, data}` entries (Go: `totalLen := int(u16(input[0:2])); pointer := 2`). Without consuming that prefix, every subsequent read was shifted by 2 bytes and the X25519 entry was never found. The code below has this fix.

None of this needs to be re-derived or re-verified by the implementer -- copy the code below verbatim. If you find yourself wanting to change parsing logic, stop and flag it instead; this exact logic has already been fuzzed under sanitizers.

---

## File Structure

New library, `libcloak-server`, laid out exactly like the existing `libcloak-mux`:

- `libcloak-server/CMakeLists.txt` -- defines the `cloak-server` static library target.
- `libcloak-server/include/cloak/clienthello_parse.h` -- public interface: `cloak_clienthello_parsed_t`, `cloak_clienthello_parse`.
- `libcloak-server/src/clienthello_parse.c` -- the parser implementation (self-contained, no dependency on `libcloak-common`).
- `libcloak-server/tests/CMakeLists.txt` -- test target registration.
- `libcloak-server/tests/test_clienthello_parse.c` -- all tests: Go-parity vectors, truncation sweep, byte-flip sweep, and a round-trip test against `libcloak-common`'s `cloak_clienthello_build` (the only place this module touches `libcloak-common`, and only in tests).
- `CMakeLists.txt` (repo root) -- add `add_subdirectory(libcloak-server)`.

---

### Task 1: ClientHello parser, struct, and full test suite

**Files:**
- Create: `libcloak-server/include/cloak/clienthello_parse.h`
- Create: `libcloak-server/src/clienthello_parse.c`
- Create: `libcloak-server/CMakeLists.txt`
- Create: `libcloak-server/tests/CMakeLists.txt`
- Create: `libcloak-server/tests/test_clienthello_parse.c`
- Modify: `CMakeLists.txt` (repo root)

**Interfaces:**
- Produces: `cloak_clienthello_parsed_t` (struct), `cloak_clienthello_parse(const uint8_t *data, size_t len, cloak_clienthello_parsed_t *out)` (returns `int`, 0 on success / -1 on structural failure). `CLOAK_CLIENTHELLO_PARSE_RANDOM_LEN` (32), `CLOAK_CLIENTHELLO_PARSE_X25519_LEN` (32).
- Consumes (test-only, from the already-merged `libcloak-common`): `cloak_clienthello_build`, `cloak_clienthello_chrome`/`cloak_clienthello_firefox`/`cloak_clienthello_safari`, `CLOAK_CLIENTHELLO_MAX_BYTES` (all from `cloak/clienthello.h`), and `cloak_random_bytes` (from `cloak/common.h`).

- [ ] **Step 1: Write the header**

Create `libcloak-server/include/cloak/clienthello_parse.h`:

```c
#ifndef CLOAK_CLIENTHELLO_PARSE_H
#define CLOAK_CLIENTHELLO_PARSE_H

#include <stddef.h>
#include <stdint.h>

#define CLOAK_CLIENTHELLO_PARSE_RANDOM_LEN 32
#define CLOAK_CLIENTHELLO_PARSE_X25519_LEN 32

typedef struct {
    const uint8_t *random; /* always exactly CLOAK_CLIENTHELLO_PARSE_RANDOM_LEN bytes, points into data */
    const uint8_t *session_id; /* points into data; NULL if session_id_len == 0 */
    size_t session_id_len;     /* 0-255 (whatever the wire said; no TLS-legal-range enforcement here) */
    const uint8_t *x25519_key_share; /* points into data, always exactly CLOAK_CLIENTHELLO_PARSE_X25519_LEN bytes; NULL if no group 0x001d key_share entry was present */
    const uint8_t *sni;   /* points into data; NULL if no server_name/host_name extension was present */
    size_t sni_len;
} cloak_clienthello_parsed_t;

/* Parses a single TLS record (5-byte record header + one ClientHello
 * handshake message) out of data[0,len). Populates *out with pointers INTO
 * data -- no copying, no allocation; data must outlive out.
 *
 * Returns 0 on success, -1 if data is not a structurally valid ClientHello
 * this function can parse (wrong record type, wrong record-layer version,
 * wrong handshake type, or any length field -- handshake length, session_id
 * length, cipher_suites length, compression_methods length, extensions
 * length, or any individual extension's length -- that is inconsistent with
 * the actual bytes present). Absence of the SNI or X25519 key_share
 * extensions is NOT a parse failure -- out->sni and out->x25519_key_share
 * are simply left NULL; a real Cloak client always sends both, but this
 * function has no opinion on that, since arbitrary non-Cloak traffic
 * reaching this function (e.g. during the server's redirect-on-fail sniff)
 * is not malformed just because it isn't Cloak's traffic.
 *
 * This is a MINIMAL, DEFENSIVE parser, not a TLS stack: no cryptographic or
 * semantic validation, and it never reads outside data[0,len) regardless of
 * how adversarial the input is -- this function runs on unauthenticated,
 * attacker-controlled bytes from the network. It does not validate the
 * record layer's own declared length field against len; it assumes the
 * caller has already delivered exactly one un-fragmented ClientHello
 * record (matching Go Cloak's own parser, which makes the same
 * assumption). */
int cloak_clienthello_parse(const uint8_t *data, size_t len, cloak_clienthello_parsed_t *out);

#endif
```

- [ ] **Step 2: Write the implementation**

Create `libcloak-server/src/clienthello_parse.c`:

```c
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

/* Walks a key_share extension's data looking for a group == 0x001d entry
 * with a 32-byte key_exchange. The data starts with its own 2-byte
 * "client_shares list length" prefix before the list of
 * {group, length, data} entries -- easy to miss (an earlier draft did) and
 * confirmed against Go's parseKeyShare, which does `totalLen :=
 * int(u16(input[0:2])); pointer := 2` before its loop. Returns 0 on
 * structural malformation (a length that overruns ext_cursor); "not found"
 * is reported via *out_key_share staying NULL, which is not itself a
 * failure return. */
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
 * as parse_key_share_ext. */
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
    cursor_t cipher_suites;
    if (!cursor_take_u16(&c, &cipher_suites_len)) {
        return -1;
    }
    if (!cursor_take_scoped(&c, cipher_suites_len, &cipher_suites)) {
        return -1;
    }

    uint8_t compression_methods_len;
    cursor_t compression_methods;
    if (!cursor_take_u8(&c, &compression_methods_len)) {
        return -1;
    }
    if (!cursor_take_scoped(&c, compression_methods_len, &compression_methods)) {
        return -1;
    }

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
```

- [ ] **Step 3: Write the library's CMakeLists.txt**

Create `libcloak-server/CMakeLists.txt`:

```cmake
add_library(cloak-server STATIC
    src/clienthello_parse.c
)

target_include_directories(cloak-server PUBLIC include)

add_subdirectory(tests)
```

(No `target_link_libraries` -- the parser itself has no dependency on `libcloak-common` or OpenSSL. Only the test executable, below, links `cloak-common`, and only for its round-trip test.)

- [ ] **Step 4: Write the tests**

Create `libcloak-server/tests/test_clienthello_parse.c`. This merges three things: Go-parity test vectors + structural-malformation tests, an adversarial truncation/byte-flip sweep, and a round-trip test against `libcloak-common`'s already-merged client-side builder.

```c
#include "cloak/clienthello_parse.h"
#include "cloak/clienthello.h"
#include "cloak/common.h"
#include "test_framework.h"

#include <stdlib.h>
#include <string.h>

static size_t hex_decode(const char *hex, uint8_t *out) {
    size_t n = 0;
    size_t hlen = strlen(hex);
    for (size_t i = 0; i + 1 < hlen; i += 2) {
        unsigned int byte;
        sscanf(hex + i, "%2x", &byte);
        out[n++] = (uint8_t)byte;
    }
    return n;
}

/* Real, working Cloak ClientHello -- copied verbatim from Go Cloak's own
 * internal/server/TLSAux_test.go TestParseClientHello "good Cloak
 * ClientHello" case. */
static const char *GOOD_HEX =
    "1603010200010001fc03034986187cfaf4c55866a0d9b68f82505fd694a3f0fbf21ca3dcf260baad91d75e20c10e2d2c66f4f9366296678550ed769aa0c41cae7e5f480f59bd929b747ee48d0024130113031302c02bc02fcca9cca8c02cc030c00ac009c013c01400330039002f0035000a0100018f00000011000f00000c7777772e62696e672e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000033006b0069001d00208d7d5a544a72e67adb1bacde46aa147b086f714c073f8335688dc13b2a032986001700414e06fb9a27480a93159f3d6273afebb4d307c4a734d7107d883b6edacb58f7d289a95ad8aaedef1b5f76fe09267a14e6bee2b6db4506b43cf0a410a4645105f79f002b0009080304030303020301000d0018001604030503060308040805080604010501060102030201002d00020101001c00024001001500920000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

/* Go's "Malformed ClientHello" test case: verified by diffing against
 * GOOD_HEX that this is not a same-length byte substitution but an inserted
 * extra hex nibble (1035 hex chars vs GOOD_HEX's 1034), which desyncs every
 * byte boundary from that point on -- a genuine structural corruption, not
 * just a semantic one, so this MUST be rejected the same way Go's own
 * parser rejects it. */
static const char *CORRUPTED_RANDOM_HEX =
    "1603010200010001fc03034986187cfaf4c55866a0d9b68f82505fd694a3f0fb2f21ca3dcf260baad91d75e20c10e2d2c66f4f9366296678550ed769aa0c41cae7e5f480f59bd929b747ee48d0024130113031302c02bc02fcca9cca8c02cc030c00ac009c013c01400330039002f0035000a0100018f00000011000f00000c7777772e62696e672e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000033006b0069001d00208d7d5a544a72e67adb1bacde46aa147b086f714c073f8335688dc13b2a032986001700414e06fb9a27480a93159f3d6273afebb4d307c4a734d7107d883b6edacb58f7d289a95ad8aaedef1b5f76fe09267a14e6bee2b6db4506b43cf0a410a4645105f79f002b0009080304030303020301000d0018001604030503060308040805080604010501060102030201002d00020101001c00024001001500920000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

/* First byte 0xff instead of 0x16 -- not a handshake record. */
static const char *NOT_HANDSHAKE_HEX =
    "ff03010200010001fc03034986187cfaf4c55866a0d9b68f82505fd694a3f0fbf21ca3dcf260baad91d75e20c10e2d2c66f4f9366296678550ed769aa0c41cae7e5f480f59bd929b747ee48d0024130113031302c02bc02fcca9cca8c02cc030c00ac009c013c01400330039002f0035000a0100018f00000011000f00000c7777772e62696e672e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000033006b0069001d00208d7d5a544a72e67adb1bacde46aa147b086f714c073f8335688dc13b2a032986001700414e06fb9a27480a93159f3d6273afebb4d307c4a734d7107d883b6edacb58f7d289a95ad8aaedef1b5f76fe09267a14e6bee2b6db4506b43cf0a410a4645105f79f002b0009080304030303020301000d0018001604030503060308040805080604010501060102030201002d00020101001c00024001001500920000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

/* Record-layer version 0xff01 instead of 0x0301. */
static const char *WRONG_RECORD_VERSION_HEX =
    "16ff010200010001fc03034986187cfaf4c55866a0d9b68f82505fd694a3f0fbf21ca3dcf260baad91d75e20c10e2d2c66f4f9366296678550ed769aa0c41cae7e5f480f59bd929b747ee48d0024130113031302c02bc02fcca9cca8c02cc030c00ac009c013c01400330039002f0035000a0100018f00000011000f00000c7777772e62696e672e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000033006b0069001d00208d7d5a544a72e67adb1bacde46aa147b086f714c073f8335688dc13b2a032986001700414e06fb9a27480a93159f3d6273afebb4d307c4a734d7107d883b6edacb58f7d289a95ad8aaedef1b5f76fe09267a14e6bee2b6db4506b43cf0a410a4645105f79f002b0009080304030303020301000d0018001604030503060308040805080604010501060102030201002d00020101001c00024001001500920000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

/* A genuine TLS 1.2 ClientHello. Its record layer is {0x16, 0x03, 0x03} --
 * it fails this parser's magic-byte check (which requires {0x16, 0x03,
 * 0x01}) for that reason, not because of anything TLS-1.2-specific; Go's
 * parser rejects it for the same underlying reason (its own magic-byte
 * check). Both implementations agree it's an error either way. */
static const char *TLS12_HEX =
    "16030300bd010000b903035d5741ed86719917a932db1dc59a22c7166bf90f5bd693564341d091ffbac5db00002ac02cc02bc030c02f009f009ec024c023c028c027c00ac009c014c013009d009c003d003c0035002f000a0100006600000022002000001d6e61762e736d61727473637265656e2e6d6963726f736f66742e636f6d000500050100000000000a00080006001d00170018000b00020100000d001400120401050102010403050302030202060106030023000000170000ff01000100";

static void test_good(void) {
    uint8_t buf[4096];
    size_t n = hex_decode(GOOD_HEX, buf);
    cloak_clienthello_parsed_t out;
    int rc = cloak_clienthello_parse(buf, n, &out);
    ASSERT_EQ_INT(rc, 0);
    ASSERT_TRUE(out.random != NULL);
    ASSERT_TRUE(out.session_id != NULL);
    ASSERT_EQ_INT(out.session_id_len, 32);
    ASSERT_TRUE(out.x25519_key_share != NULL);
    ASSERT_TRUE(out.sni != NULL);
    ASSERT_EQ_INT(out.sni_len, 12);
    ASSERT_MEM_EQ(out.sni, "www.bing.com", 12);
}

static void test_corrupted_random_rejected(void) {
    uint8_t buf[4096];
    size_t n = hex_decode(CORRUPTED_RANDOM_HEX, buf);
    cloak_clienthello_parsed_t out;
    int rc = cloak_clienthello_parse(buf, n, &out);
    ASSERT_EQ_INT(rc, -1);
}

static void test_not_handshake(void) {
    uint8_t buf[4096];
    size_t n = hex_decode(NOT_HANDSHAKE_HEX, buf);
    cloak_clienthello_parsed_t out;
    ASSERT_EQ_INT(cloak_clienthello_parse(buf, n, &out), -1);
}

static void test_wrong_record_version(void) {
    uint8_t buf[4096];
    size_t n = hex_decode(WRONG_RECORD_VERSION_HEX, buf);
    cloak_clienthello_parsed_t out;
    ASSERT_EQ_INT(cloak_clienthello_parse(buf, n, &out), -1);
}

static void test_tls12(void) {
    uint8_t buf[4096];
    size_t n = hex_decode(TLS12_HEX, buf);
    cloak_clienthello_parsed_t out;
    ASSERT_EQ_INT(cloak_clienthello_parse(buf, n, &out), -1);
}

static void test_empty(void) {
    cloak_clienthello_parsed_t out;
    ASSERT_EQ_INT(cloak_clienthello_parse(NULL, 0, &out), -1);
}

/* The critical safety property: truncate the good ClientHello at every
 * possible length from 0 to full, and confirm the parser never crashes and
 * never reads outside the buffer (this whole test binary is also run under
 * ASan+UBSan in Step 6 below). Every truncation must return -1 except the
 * one at full length. */
static void test_truncation_sweep(void) {
    uint8_t full[4096];
    size_t full_len = hex_decode(GOOD_HEX, full);
    for (size_t n = 0; n <= full_len; n++) {
        cloak_clienthello_parsed_t out;
        int rc = cloak_clienthello_parse(full, n, &out);
        if (n < full_len) {
            ASSERT_TRUE(rc == -1);
        } else {
            ASSERT_EQ_INT(rc, 0);
        }
    }
}

/* Same sweep but flipping every single bit of every byte of the good
 * ClientHello one at a time and confirming no crash -- broader adversarial
 * coverage than truncation alone (catches bugs where an inflated
 * *interior* length field causes an OOB read while len(data) itself is
 * untouched). Not a correctness check (many single-bit mutations of a
 * valid ClientHello are still structurally well-formed, e.g. mutating a
 * byte inside `random` or the SNI hostname), so this only needs to run to
 * completion without ASan/UBSan reporting anything. */
static void test_byte_flip_sweep(void) {
    uint8_t full[4096];
    size_t full_len = hex_decode(GOOD_HEX, full);
    for (size_t i = 0; i < full_len; i++) {
        uint8_t saved = full[i];
        for (int bit = 0; bit < 8; bit++) {
            full[i] = (uint8_t)(saved ^ (1u << bit));
            cloak_clienthello_parsed_t out;
            cloak_clienthello_parse(full, full_len, &out); /* must not crash */
        }
        full[i] = saved;
    }
    ASSERT_TRUE(1); /* reaching here without an ASan/UBSan abort is the test */
}

static void store_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

/* Round-trip against this repository's own client-side ClientHello
 * builder: build a real ClientHello (record layer prepended), parse it
 * back, and confirm every field this parser extracts matches exactly what
 * was spliced in during building. Proves the client and server halves of
 * this project agree on wire format -- this is the only place this test
 * file (or the library) touches libcloak-common. */
static void round_trip_one(const cloak_clienthello_template_t *tmpl, const char *sni) {
    uint8_t random[32], session_id[32], keyshare[32];
    cloak_random_bytes(random, 32);
    cloak_random_bytes(session_id, 32);
    cloak_random_bytes(keyshare, 32);

    uint8_t built[CLOAK_CLIENTHELLO_MAX_BYTES + 5];
    long n = cloak_clienthello_build(tmpl, random, session_id, keyshare, sni,
                                      built + 5, sizeof(built) - 5);
    ASSERT_TRUE(n > 0);
    if (n <= 0) {
        return;
    }
    built[0] = 0x16;
    built[1] = 0x03;
    built[2] = 0x01;
    store_be16(built + 3, (uint16_t)n);

    cloak_clienthello_parsed_t out;
    int rc = cloak_clienthello_parse(built, (size_t)n + 5, &out);
    ASSERT_EQ_INT(rc, 0);
    if (rc != 0) {
        return;
    }
    ASSERT_TRUE(out.random != NULL);
    ASSERT_MEM_EQ(out.random, random, 32);
    ASSERT_TRUE(out.session_id != NULL);
    ASSERT_EQ_INT(out.session_id_len, 32);
    ASSERT_MEM_EQ(out.session_id, session_id, 32);
    ASSERT_TRUE(out.x25519_key_share != NULL);
    ASSERT_MEM_EQ(out.x25519_key_share, keyshare, 32);
    ASSERT_TRUE(out.sni != NULL);
    ASSERT_EQ_INT(out.sni_len, strlen(sni));
    ASSERT_MEM_EQ(out.sni, sni, strlen(sni));
}

static void test_round_trip_against_client_builder(void) {
    char long_sni[254];
    memset(long_sni, 'a', 253);
    long_sni[253] = '\0';

    const char *sni_cases[5];
    sni_cases[0] = "a.co";
    sni_cases[1] = "www.example.com";
    sni_cases[2] = "a-considerably-longer-hostname.example.com";
    sni_cases[3] = "x";
    sni_cases[4] = long_sni;

    for (size_t i = 0; i < 5; i++) {
        round_trip_one(&cloak_clienthello_chrome, sni_cases[i]);
        round_trip_one(&cloak_clienthello_firefox, sni_cases[i]);
        round_trip_one(&cloak_clienthello_safari, sni_cases[i]);
    }
}

TEST_MAIN_BEGIN()
    test_good();
    test_corrupted_random_rejected();
    test_not_handshake();
    test_wrong_record_version();
    test_tls12();
    test_empty();
    test_truncation_sweep();
    test_byte_flip_sweep();
    test_round_trip_against_client_builder();
TEST_MAIN_END()
```

- [ ] **Step 5: Write the test's CMakeLists.txt**

Create `libcloak-server/tests/CMakeLists.txt`:

```cmake
add_executable(test_clienthello_parse test_clienthello_parse.c)
target_include_directories(test_clienthello_parse PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_clienthello_parse PRIVATE cloak-server cloak-common)
add_test(NAME test_clienthello_parse COMMAND test_clienthello_parse)
```

(`cloak-common` is linked here -- and only here, not by the `cloak-server` library itself -- purely for the round-trip test's use of `cloak_clienthello_build`/`cloak_random_bytes`. `${CMAKE_SOURCE_DIR}/libcloak-common/tests` is added the same way `libcloak-mux/tests/CMakeLists.txt` already does it, to reach the shared `test_framework.h`.)

- [ ] **Step 6: Wire the new library into the root build**

Modify `CMakeLists.txt` (repo root) -- add one line after the existing `add_subdirectory(libcloak-mux)`:

```cmake
add_subdirectory(libcloak-common)
add_subdirectory(libcloak-mux)
add_subdirectory(libcloak-server)
```

- [ ] **Step 7: Build and run the full suite in Docker**

```bash
docker build -q -f Dockerfile.dev -t cloak-c-dev .
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "rm -rf build && cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure"
```

Expected: all tests pass, including the new `test_clienthello_parse`, with zero compiler warnings in the build log.

- [ ] **Step 8: Build and run under ASan+UBSan in Docker**

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "cmake -S . -B build-asan -DCMAKE_C_FLAGS='-fsanitize=address,undefined -g' -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined' && cmake --build build-asan && ctest --test-dir build-asan --output-on-failure"
```

Expected: all tests pass, zero sanitizer diagnostics. This is the step that actually exercises the truncation sweep (518 cases) and byte-flip sweep (4136 cases) under memory-safety instrumentation -- the property this whole module exists to guarantee.

- [ ] **Step 9: Commit**

```bash
git add libcloak-server CMakeLists.txt
git commit -m "Add libcloak-server ClientHello parser"
```

---

## What comes after this plan

Not started here, deliberately out of scope:

- **Server dispatcher / redirect-on-fail** (design spec section 7): a per-connection state machine that sniffs the first byte to distinguish TLS (`0x16`) from WebSocket (`0x47 GET`) traffic, buffers incrementally, and redirects non-Cloak traffic elsewhere on parse/auth failure -- this is the module that will actually call `cloak_clienthello_parse` on live connections.
- **Full server auth handshake**: decrypting the UID/proxy-method/encryption-method/timestamp/session-ID payload carried across `session_id` and the X25519 `key_share` (ECDH with the server's static private key + AEAD decrypt), the timestamp-window check, the replay cache keyed by `random`, and composing the `ServerHello`/`ChangeCipherSpec`/`ApplicationData` reply -- mirrors `internal/server/TLS.go`'s `unmarshalClientHello`/`makeResponder` and `internal/server/auth.go`. This is a separate, larger plan; this module only extracts the raw fields those functions will need.

## Self-Review

**Spec coverage:** The spec's ask ("Server-side: a minimal ClientHello parser (not a TLS stack) that extracts random, session_id, SNI, and the X25519 key_share -- mirrors internal/server/TLSAux.go") is fully covered by Task 1: all four fields are extracted, the parser is explicitly not a TLS stack (no semantic/cryptographic validation), and its logic is verified equivalent to `TLSAux.go`'s `parseClientHello`/`parseExtensions`/`parseKeyShare` behavior via Go's own test vectors.

**Placeholder scan:** No TBD/TODO/"add error handling"-style steps -- every step has complete, already-verified code.

**Type consistency:** `cloak_clienthello_parsed_t` and `cloak_clienthello_parse`'s signature are defined once (Step 1) and used identically in the implementation (Step 2) and tests (Step 4); no other task references them.
