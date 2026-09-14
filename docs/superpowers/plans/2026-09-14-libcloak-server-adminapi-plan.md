# libcloak-server: The Admin API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator manage users over the Cloak tunnel itself. A client authenticating with the admin UID and session id 0 gets an HTTP/1.1 REST API served over its session's streams — list users, read one, create or modify one, delete one — instead of a proxy.

**Architecture:** Four pieces, each independently testable. A URL-safe base64 decoder, because the API addresses users by a base64url UID in the path while the same UID is base64 **standard** inside the JSON body. An incremental HTTP/1.1 request parser that reads off a `cloak_stream_t` without blocking and without trusting any length it is given. A JSON codec for `cloak_user_info_t` matching what Go's `json.Marshal` emits for its `UserInfo` struct. And `cloak_adminapi_t`, which supplies a session's `on_new_stream`/`on_stream_data`/`on_writable` — the same seam `cloak_proxy_t` uses — treating each accepted stream as one HTTP connection.

The routing decision lives where Go puts it: in the dispatcher, **before** the proxy-method check.

**Tech Stack:** C11, CMake, CTest with the project's assert-based framework, cJSON (already vendored).

**Spec:** `docs/superpowers/specs/2026-09-07-cloak-c-port-design.md` §8, second half — "the admin API is **not** a separate HTTP port … a small hand-rolled HTTP/1.1 request parser + router reading directly off the muxed stream's byte queue".

**Reference:** `/Users/sam/Cloak/internal/server/usermanager/api_router.go` and `api.yaml`; `/Users/sam/Cloak/internal/server/dispatcher.go:202-217` for the admin branch; `/Users/sam/Cloak/cmd/ck-client/ck-client.go:159-167` for what the client actually sends.

## Global Constraints

- C11, `-Wall -Wextra` clean, zero warnings in project code.
- Linux only. `#define _POSIX_C_SOURCE 200809L` as the **first line** of any `.c` needing POSIX APIs.
- Public symbols prefixed `cloak_`; headers with `CLOAK_<NAME>_H` guards; doc comments stating the contract and **why**.
- Every constructor fully initializes its struct **before** validating its other arguments. Every destroy is idempotent and safe on a zeroed struct.
- **Nothing may block the reactor.** Responses are written through the same non-blocking, pause-and-resume discipline everything else in this project uses.
- Append to every `CMakeLists.txt`; never rewrite one. `libcloak-server/tests/CMakeLists.txt` lines 46-126 carry a load-bearing ASan/LD_PRELOAD block that must stay byte-identical.
- Test registration: copy an existing entry, always `TIMEOUT 60`.
- Every test wait is bounded; **a bound whose comment names a duration must assert it reached that duration**.
- Build and test (note the `-w` path — `-w /src` silently builds the main checkout):
  ```bash
  docker run --rm -v /Users/sam/Cloak-c:/src -w /src/.worktrees/libcloak-adminapi cloak-c-dev bash -c \
    'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j8 && ctest --test-dir build --output-on-failure'
  ```
- ASan/UBSan, mandatory from Task 4 on:
  ```bash
  docker run --rm -v /Users/sam/Cloak-c:/src -w /src/.worktrees/libcloak-adminapi cloak-c-dev bash -c \
    'cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
       -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
       -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
       -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined" && \
     cmake --build build-asan -j8 && ctest --test-dir build-asan --output-on-failure'
  ```
- Test counts: **45 before**. Task 1 adds no test binary (it extends an existing one), so the count is still 45 after it; then 46 after Task 2, 47 after Task 3, 48 after Task 4, 49 after Task 5, 50 after Task 6.

## The threat model this module changes

Every other module in this server treats its input as attacker-controlled but *unauthenticated* — the answer to anything malformed is to look like a web server. This one is different: its input is attacker-controlled **and authenticated as the operator**. That changes what the failure modes cost. A parser bug here is not a fingerprint, it is remote code execution against the machine that holds every user's credentials, reached by anyone who obtains the admin UID.

Two consequences bind every task below:

- **Nothing is trusted because it authenticated.** Every length, every header, every JSON number arrives from the wire. The admin UID is a 16-byte shared secret in a config file; treat its holder as a competent attacker who has it, because that is the realistic compromise.
- **Bounds before allocation, always.** The request parser sees a `Content-Length` before it sees a body. It must refuse an implausible one rather than allocate it. Pick the caps, state them, and make exceeding them a clean 413/431 rather than a failed `malloc`.

## Decisions taken before execution

**D1 — the admin branch goes before the proxy-method check, matching Go.** `dispatcher.go:202` takes the admin path before `sta.ProxyBook[ci.ProxyMethod]` is consulted at :217. This is not incidental: `ck-client` in admin mode leaves `ProxyMethod` at whatever the config says (defaulting to `"shadowsocks"`), so an operator whose client config names a method this server does not offer would otherwise be locked out of administering it. Our `dispatcher_authenticate` checks the proxy method at step 7; the admin decision must be made before it, and an admin session must skip it entirely.

**D2 — one stream is one HTTP connection, and `Content-Length` is the only framing.** Go gets `Transfer-Encoding: chunked` free from `net/http`; a hand-rolled parser does not, and the only client is ours. Reject a request carrying `Transfer-Encoding` with `501 Not Implemented` rather than ignoring the header — ignoring it would let a request smuggle a body the router never sees. Say so in the header.

**D3 — two base64 alphabets, and the asymmetry is a trap.** The UID in the *path* is `base64.URLEncoding` (`api_router.go` decodes it that way). The UID in the JSON *body and responses* is whatever Go's `encoding/json` does with a `[]byte`, which is `StdEncoding`. Same value, two alphabets, in the same request. `cloak/base64.h` today implements only the standard alphabet and explicitly rejects `-`/`_`; Task 1 adds the URL variant alongside it rather than loosening the existing one, because the existing strictness is what the config parser depends on.

**D4 — Go's own handler bugs are NOT ported.** Reading `api_router.go`, four handlers write an error and then continue:
- `getUserInfoHlr` writes "UID cannot be empty" and falls through with no `return`.
- `writeUserInfoHlr` writes "UID mismatch" and **then performs the write anyway** — so a POST to `/admin/users/<A>` carrying a body that says UID `<B>` modifies `<B>`. The path is decorative.
- `writeUserInfoHlr` and `deleteUserHlr` both call `http.Error` and then `w.WriteHeader` again, producing a superfluous-WriteHeader warning and a wrong status.
- `getUserInfoHlr` ignores every error from `GetUserInfo` except `ErrUserNotFound`, then marshals an empty struct as if it were a user.
Port the *intended* behaviour, and record each divergence in the header where a reader comparing the two implementations will find it. The UID-mismatch one is a genuine authorisation bug, not a style defect.

**D7 — cJSON cannot carry an exact `int64`, in either direction, and this is settled here rather than discovered mid-task.** Verified against the vendored `cJSON.c`: numbers are stored as a `double` (`valuedouble`) plus a deprecated `int valueint`, and `print_number` emits `%d` of `valueint` only when the double compares equal to it, falling back to a `%g`-style form otherwise. Two consequences, each with a decision:

- **Encoding must not go through `cJSON_CreateNumber`.** A credit of 10^12 — one terabyte, an ordinary quota — exceeds `INT_MAX`, so cJSON would print it as `1e+12`, and a real Go client's `json.Unmarshal` into an `*int64` field *rejects* that with "cannot unmarshal number 1e+12 into Go value of type int64". Use `cJSON_CreateRaw` with the integer formatted by us, which emits the string verbatim. That also fixes field order and spacing for the byte-exact assertion Task 3 asks for.
- **Decoding cannot recover a magnitude above 2^53.** There is no raw-token access in cJSON's number API; the double is all there is. Decide and document: reject any number that is not an exact integer or whose magnitude exceeds 2^53, with its own error, rather than silently truncating. That bound is ~9 petabytes for a credit and far beyond any real deployment, it is exactly the set a `double` represents without loss, and it has a second benefit worth stating — it means the admin API can no longer feed `INT64_MIN`/`INT64_MAX` into the manager's saturating credit arithmetic, which the user-manager branch found reachable specifically *because* this API would expose `write` over the wire. The saturating arithmetic stays (the config and CLI paths remain), but this surface no longer reaches it.

**D5 — responses may not be written unboundedly.** `cloak_stream_write` never fails on a full queue by design, so a handler that writes a 256-user listing in one call could overrun the session's outbound pool and break every stream on it. A response is composed into a buffer and drained through `on_writable`, the same pause/resume shape `cloak_stream_relay_t` uses. `cloak_usermanager_list` has no cursor (the user-manager module recorded this), so the listing is count-then-allocate-all; cap it and say what happens past the cap.

**D6 — the admin session is not metered and not rate-limited.** Go's admin UID gets `UNLIMITED_VALVE` and is not in the user database. Our step 6 already routes it through `cloak_userpanel_get_bypass_user`, which gives a NULL valve. Nothing to build; stated so no one adds metering to it later thinking it was an oversight.

---

### Task 1: URL-safe base64

**Files:**
- Modify: `libcloak-common/include/cloak/base64.h`, `libcloak-common/src/base64.c`
- Modify: `libcloak-common/tests/test_base64.c` — this file predates the branch, and extending it with new cases is expected; do not alter its existing cases.
- Modify: nothing in CMake — `test_base64` is already registered, so this task adds no test binary and the suite stays at 45.

**What to add**, alongside the existing standard-alphabet functions rather than replacing them:

```c
/* RFC 4648 section 5: '-' and '_' instead of '+' and '/'. This is what
 * Go's base64.URLEncoding produces, and what the admin API's path
 * component uses -- note that the SAME uid travels base64-STANDARD inside
 * the JSON body of the same request, because Go's encoding/json marshals
 * a []byte with StdEncoding. Two alphabets, one request; see this
 * project's admin-API plan, decision D3. */
int cloak_base64url_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap);
int cloak_base64url_decode(const char *in, uint8_t *out, size_t out_cap, size_t *out_len);
```

**Padding is the decision to make and justify.** Go's `base64.URLEncoding` requires padding; `RawURLEncoding` omits it. `api_router.go` uses the padded one, so a padded decoder matches — but a URL-safe encoding is very often written unpadded by hand, and an operator pasting a UID without `=` getting a confusing 400 is a real cost. Decide: strict (match Go exactly) or lenient (accept both). State the reason, and note that the decoder is reached by attacker-controlled input, so "lenient" must mean "accepts a well-defined larger set", never "guesses".

- [ ] **Step 1: Write the failing tests** — add cases to `test_base64.c`:
```
1. Round-trip every byte value through the URL alphabet.
2. A vector whose standard encoding contains '+' and '/' encodes to '-'
   and '_' -- pick input bytes that force both characters, and assert the
   exact expected string as a literal. This is the case that fails if
   someone implements the URL variant by calling the standard one.
3. The URL decoder REJECTS '+' and '/', and the standard decoder still
   rejects '-' and '_'. Both directions, because a shared table edited
   carelessly breaks one of them silently.
4. Whatever you decided about padding, asserted both ways.
5. out_cap exactly large enough, and one byte too small.
```
- [ ] **Step 2: Run to verify they fail**
- [ ] **Step 3: Implement.** If you share a table between the two alphabets, the test in case 3 is what stops that sharing from leaking. Say in a comment which parts are shared and why that is safe.
- [ ] **Step 4: Full suite (45 tests), Debug and ASan**
- [ ] **Step 5: Commit** — `git commit -m "Add URL-safe base64 alongside the standard alphabet"`

---

### Task 2: The HTTP/1.1 request parser

**Files:**
- Create: `libcloak-server/include/cloak/http.h`, `libcloak-server/src/http.c`
- Create: `libcloak-server/tests/test_http_parse.c`
- Modify: `libcloak-server/CMakeLists.txt`, `libcloak-server/tests/CMakeLists.txt`

**Interfaces:**
- Consumes: nothing but the C library. Deliberately standalone and testable without a session, a reactor or a socket.
- Produces: the parser below. Task 4 is its only consumer.

**The shape.** Incremental, fed whatever bytes have arrived, never blocking, never allocating a body it has not bounded:

```c
typedef enum {
    CLOAK_HTTP_INCOMPLETE = 0,  /* need more bytes; feed again */
    CLOAK_HTTP_DONE,            /* a complete request is available */
    CLOAK_HTTP_ERROR,           /* malformed or over a cap; see status */
} cloak_http_state_t;

typedef struct {
    cloak_http_method_t method;      /* GET / POST / DELETE / OPTIONS / OTHER */
    char path[CLOAK_HTTP_MAX_PATH];  /* NUL-terminated, as received */
    size_t content_length;
    int have_content_length;
    /* The body, once state is DONE. Points into the parser's own storage. */
    const uint8_t *body;
    size_t body_len;
    int status;                      /* the HTTP status to reply with on ERROR */
} cloak_http_request_t;
```

**Caps, each named and justified in the header**: the request line, one header line, the total header block, the number of headers, and the body. A `Content-Length` above the body cap is `413`; a header block over its cap is `431`; a malformed request line is `400`. Refuse *before* allocating, never after.

**What to parse and what to refuse:**
- Request line `METHOD SP path SP HTTP/1.1 CRLF`. Accept `HTTP/1.0` and `HTTP/1.1`; anything else is 400. A method that is not one of the four is not an error for the parser — report it and let the router answer 405.
- Headers, case-insensitive names, values trimmed of leading/trailing spaces. Only two matter: `Content-Length` and `Transfer-Encoding`.
- A `Transfer-Encoding` header of any value is `501` (D2). Do not ignore it.
- A `Content-Length` that is not a plain non-negative decimal integer, or that appears twice with different values, is `400`. Both are classic request-smuggling vectors and both must be explicit, not incidental.
- Bare `LF` line endings: decide whether to accept them and say why. Being strict is defensible; being lenient is defensible; being *accidentally* lenient is not.

- [ ] **Step 1: Write the failing test.** `test_http_parse.c`, table-driven where it can be:
```
 1. A minimal GET parses: method, path, no body.
 2. A POST with a body parses, and the body bytes are exactly right.
 3. Byte-at-a-time feeding of every case above reaches the same result as
    feeding it in one call. This is the property that catches most
    incremental-parser bugs, and it should be a loop over the other cases
    rather than a hand-written duplicate.
 4. A split in the middle of CRLF, and a split in the middle of a header
    name, both recover.
 5. Caps: a path one byte over, a header line one byte over, a header
    block one byte over, a Content-Length one over the body cap -- each
    yields the right status, and nothing allocates the oversized thing.
 6. Content-Length: absent on GET; "abc"; "-1"; "+1"; leading zeros;
    two conflicting headers; two identical headers. State which are
    accepted and assert each.
 7. Transfer-Encoding present -> 501.
 8. An unknown method reaches the router rather than erroring.
 9. A body shorter than Content-Length stays INCOMPLETE forever rather
    than returning a short body -- and the caller's own deadline is what
    ends it. Assert INCOMPLETE, not DONE.
10. A body LONGER than Content-Length: the extra bytes are not consumed
    (one stream is one request here, but a parser that silently eats
    trailing bytes hides a smuggling bug).
11. A fuzz-ish smoke case: feed several thousand pseudo-random byte
    strings with a fixed seed; assert no crash, no hang, and that the
    state is always one of the three legal values.
```
- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (46 tests), Debug and ASan. Run case 11 under ASan specifically.**
- [ ] **Step 5: Commit** — `git commit -m "Add an incremental HTTP/1.1 request parser"`

---

### Task 3: The JSON codec for `cloak_user_info_t`

**Files:**
- Create: `libcloak-server/include/cloak/user_json.h`, `libcloak-server/src/user_json.c`
- Create: `libcloak-server/tests/test_user_json.c`
- Modify: both CMakeLists

**The contract is Go's `encoding/json` applied to its `UserInfo` struct, and it must be matched exactly** because a real `ck-client -a` talks to this. The struct carries no JSON tags, so Go uses the field names verbatim, and its `Maybe*` fields are pointers, so an unset field marshals as `null`:

```json
{"UID":"EBESExQVFhcYGRobHB0eHw==","SessionsCap":10,"UpRate":0,"DownRate":0,
 "UpCredit":1000000,"DownCredit":1000000,"ExpiryTime":1789000000}
```

- `UID` is base64 **standard** with padding (Go marshals `[]byte` that way — D3).
- The six numeric fields are JSON numbers, or `null` when unset.
- Decoding must produce both a `cloak_user_info_t` and the field mask `cloak_usermanager_write` takes: a field present and non-null sets its bit; a field absent or `null` does not. That mapping is the whole reason the mask exists.

**Validation is not optional here.** This decoder is the module's attack surface. A JSON number that does not fit `int64`, a `UID` that is not exactly 16 bytes after decoding, a string where a number belongs, a nested object, a 10 MB array — each must be a clean rejection with a distinguishable reason, never a silent truncation. cJSON parses doubles for numbers; decide and document how you get an exact `int64` out of that, because `1e300` and `9223372036854775807` both arrive as doubles and only one of them is representable.

- [ ] **Step 1: Write the failing test**
```
1. Encode a fully-populated user and assert the exact JSON string, with
   the field ORDER Go produces -- a client comparing output byte for byte
   is a real consumer.
2. Round-trip encode->decode->encode is stable.
3. Decode with each field absent in turn: the mask bit is clear and the
   value is untouched.
4. Decode with each field explicitly null: same as absent.
5. A UID that is not 16 bytes after base64 decoding is rejected.
6. A UID that is not valid base64 is rejected.
7. Numbers, per D7: 2^53 and -2^53 round-trip exactly and 2^53+1 is
   REJECTED with its own error -- assert the boundary from both sides,
   since a test that only checks a rejected value far outside the range
   would pass with the bound set anywhere. 1e300, 1.5, "123" and true are
   each rejected too.
8. A credit of 10^12 encodes as the literal `1000000000000` and NOT as
   `1e+12`. This is the case that fails if cJSON_CreateNumber is used
   instead of cJSON_CreateRaw, and a real Go client rejects the
   scientific form outright.
9. Malformed JSON, an empty document, a bare array, and a deeply nested
   object are each rejected without crashing.
10. Decoding leaves no allocation behind on every failure path (ASan).
```
- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (47 tests), Debug and ASan**
- [ ] **Step 5: Commit** — `git commit -m "Add the admin API's user JSON codec"`

---

### Task 4: `cloak_adminapi_t` — the router over streams

**Files:**
- Create: `libcloak-server/include/cloak/adminapi.h`, `libcloak-server/src/adminapi.c`
- Create: `libcloak-server/tests/test_adminapi.c`
- Modify: both CMakeLists

**Interfaces:**
- Consumes: `cloak/http.h` (Task 2), `cloak/user_json.h` (Task 3), `cloak/base64.h` (Task 1), `cloak/usermanager.h`, `cloak/session.h`.
- Produces: `cloak_adminapi_t`, its config, and the three session callbacks it installs. Task 5 wires it.

**The shape** mirrors `cloak_proxy_t`, which is the working precedent for "an object that owns a session's stream callbacks": one context per session, one per stream, an intrusive list, and a teardown that runs from the registry's broken path. **Read `proxy.c` before designing this** — its ownership rules, its `next`-before-callback iteration, and its teardown ordering were established over two review rounds and this module should not rediscover them.

Per stream: a `cloak_http_request_t`, a response buffer, a write offset, and a deadline. Per session: the list, and a pointer to the manager.

**The routes**, matching `api_router.go`:
| Method | Path | Handler |
|---|---|---|
| GET | `/admin/users` | list all |
| GET | `/admin/users/{b64url-uid}` | get one |
| POST | `/admin/users/{b64url-uid}` | create or modify |
| DELETE | `/admin/users/{b64url-uid}` | delete |
| OPTIONS | anything | `Access-Control-Allow-Methods: GET,POST,DELETE,OPTIONS` |

Every response carries `Access-Control-Allow-Origin: *`, as Go's middleware does. It is vestigial over a tunnel with no browser origin — port it for fidelity and say in a comment that it is vestigial, so nobody later takes it for a security control.

**Status codes**: 200 on a successful GET/DELETE, 201 on a successful POST, 400 for a bad UID or body, 404 for an unknown user, 405 for a known path with the wrong method, 413/431 from the parser's caps, 500 for a manager error, 501 for `Transfer-Encoding`. **Fix Go's bugs (D4)**: an empty UID, a UID mismatch between path and body, and a manager error must each `return` after writing their response, and a UID mismatch must refuse the write.

**A deadline per stream is required**, for the same reason the dispatcher has one on its first packet: a client that opens a stream and sends half a request pins its buffers indefinitely. Pick a value, justify it against the dispatcher's own 15-second handshake deadline.

- [ ] **Step 1: Write the failing test.** Drive real streams through a real session pair — `test_proxy_stream.c`'s fixture and `client_harness.h` are the models.
```
1. GET /admin/users on an empty database returns 200 and "[]".
2. POST creates a user; a following GET returns exactly what was written.
3. POST with a partial field set modifies only those fields.
4. POST where the path UID and the body UID disagree is REFUSED with 400
   and the database is UNCHANGED. This is Go's authorisation bug; assert
   the database, not just the status.
5. DELETE removes; the following GET is 404.
6. GET of an unknown user is 404; of a malformed base64url UID, 400.
7. Wrong method on a known path is 405.
8. OPTIONS returns the allow header.
9. A request split across many small writes is handled (the parser's
   incremental path, exercised through a real stream).
10. A response larger than the session's outbound room is delivered
    completely -- fill the database with enough users that the listing
    exceeds one write, and assert the client receives every byte. This is
    D5, and it is the case that breaks the whole session if wrong.
11. A stream opened and abandoned mid-request is closed by its deadline
    and its context freed.
12. The session breaking mid-response frees everything, under ASan.
```
- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (48 tests), Debug and ASan, plus the new test 50x**
- [ ] **Step 5: Mutation-verify cases 4, 10 and 12** — the authorisation refusal, the backpressure delivery, and the teardown. Report any that is not caught.
- [ ] **Step 6: Commit** — `git commit -m "Add cloak_adminapi_t: the admin REST API over a session"`

---

### Task 5: Route admin sessions in the dispatcher

**Files:**
- Modify: `libcloak-server/src/dispatcher.c`, `libcloak-server/include/cloak/dispatcher.h`
- Create: `libcloak-server/tests/test_dispatcher_admin.c`
- Modify: `libcloak-server/tests/CMakeLists.txt`

**What changes.** `dispatcher_authenticate`'s step 7 currently rejects an unknown proxy method for every connection. Per D1, an admin session — `cloak_server_is_admin(srv, info.uid)` **and** `info.session_id == 0` — must be decided before that check and must skip it. Everything else about the handshake is unchanged: the same reply, the same hand-off, the same registry.

The owner then needs to install a different set of session callbacks for that session. `cloak_dispatch_prepare_session_cb` already receives the full `cloak_server_clientinfo_t`, so an owner holding both a `cloak_proxy_t` and a `cloak_adminapi_t` can branch inside its own callback with no dispatcher change. **Decide which way to do it and say why**: a flag on the `info` the dispatcher passes, or the owner re-deriving the admin test itself. The owner re-deriving means two places can disagree about what "admin" means; the dispatcher telling them means one.

- [ ] **Step 1: Write the failing test**
```
1. The admin UID with session id 0 and a proxy method the server does
   NOT have in its ProxyBook still authenticates. This is D1 and it is
   the case that fails today.
2. The admin UID with a NON-zero session id is an ordinary session: it
   takes the proxy path and is subject to the proxy-method check.
3. A non-admin UID with session id 0 is ordinary.
4. With no admin UID configured, nothing takes the admin path.
5. The admin session is not metered: traffic through it leaves the
   database untouched (D6).
```
- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (49 tests), Debug and ASan. Every pre-existing test must pass UNMODIFIED.**
- [ ] **Step 5: Commit** — `git commit -m "Route admin sessions before the proxy-method check"`

---

### Task 6: End to end

**Files:**
- Create: `libcloak-server/tests/test_admin_e2e.c`
- Modify: `libcloak-server/tests/CMakeLists.txt`

One test that drives the whole stack as a binary would: a listener, a dispatcher, a registry, a server from parsed JSON config, a user manager, a panel, a proxy **and** an admin API side by side.

```
1. A real admin client creates a user through the API; a real proxy
   client then authenticates as that user and passes bytes. The two
   halves of this server meeting is the thing this test exists for.
2. The admin deletes that user; the user's existing session keeps
   working until the next upload cycle, then stops. That is the
   documented behaviour the user-manager module recorded -- assert it
   rather than discovering it later.
3. An admin session and a proxy session run concurrently on one server.
4. The admin API is the second SQLite writer: hold a write transaction
   from the panel's upload and confirm an admin request in that window
   degrades cleanly rather than corrupting or hanging.
5. Clean shutdown with an admin request in flight, under ASan.
```

- [ ] **Step 1: Write the test**
- [ ] **Step 2: Run it; fix what it finds, or report it if it is a finding rather than a fix**
- [ ] **Step 3: Full suite (50 tests), Debug and ASan, the new test 50x**
- [ ] **Step 4: Commit** — `git commit -m "Add an end-to-end admin API test"`

---

## What this module inherits

Recorded by the user-manager branch at its merge, and each one lands here:

- **`cloak_usermanager_t` is ready for wire input** — unknown mask bits refused, every parameter bound, saturating credit arithmetic, and `typeof(uid) = 'blob' AND length(uid) = 16` in both the schema CHECK and the open-time scan. Task 3's decoder is the new surface, not the manager.
- **`list` has no offset or cursor**, so the listing is count-then-allocate-all. D5 caps it.
- **`delete`, or zeroing a credit, does not evict an active user** until the next upload cycle — up to one interval of free service. Task 6 case 2 asserts this rather than leaving it to be discovered.
- **This module is the second SQLite writer**, which is what makes `SQLITE_BUSY` on `COMMIT` live and is the reason `usermanager.c` keeps its annotated ROLLBACK and self-heal branches. `busy_timeout` is 0 by design: a second writer costs one drain of metering, never an authorisation outage and never a reactor stall. Task 6 case 4 exercises it.

## What the previous two branches learned

Eleven test-coverage defects, every one found by measuring or mutating, none by reading. Three were the same shape — a test whose green comes from a path other than the one it names — and that shape survived a dedicated reviewer's first pass twice. Two disciplines follow, and both apply here:

1. **Mutate the call sites, not the helper.** Twice, a mutation of a helper's body was killed by one covered site while five others were uncovered, and in each case the report claimed the whole mechanism verified.
2. **Treat an intermittent failure in a timing-sensitive test as a bug until proven otherwise, and soak rather than re-run.** The last branch's final defect was a permanent production stall that appeared as a 1-in-200 flake; no mutation could have found it, because it lived in a guard that was present and wrong.

And the newest: **a false invariant can propagate into a test.** Correcting one contract last branch required inverting an existing assertion that had encoded the false guarantee as fact.

## Self-review notes

- **Spec coverage:** §8's second half is Tasks 2-5; Task 1 is the prerequisite §8 does not mention but `api_router.go` requires; Task 6 is the integration the spec's §11 asks for.
- **Placeholder scan:** every task names its files, its exact interfaces and its test cases. D1-D6 are settled here. Three decisions are delegated *with* a stated requirement to justify them: base64url padding strictness, bare-LF acceptance, and how the dispatcher tells the owner a session is an admin session.
- **Type consistency:** `cloak_http_request_t` is defined in Task 2 and consumed in Task 4; `cloak_user_info_t` and its field mask come from the merged user-manager module; `cloak_adminapi_t` is produced in Task 4 and wired in Tasks 5 and 6. Test counts chain 45 → 45 → 46 → 47 → 48 → 49 → 50; Task 1 extends an existing test binary rather than adding one, which is why the first two entries are equal.
- **D7 was found by reading the vendored `cJSON.c` while writing this plan**, not by an implementer hitting it mid-task. It changes both directions of Task 3 and would otherwise have surfaced as either a silently truncated credit or a client that rejects our JSON at the one-terabyte mark.
- **The riskiest thing here** is Task 2. It is the only hand-rolled parser in this project that reads attacker-controlled input *after* authentication, so a bug in it is worth more to an attacker than anything else in this module.
- **The most consequential thing here** is D4's second bullet. Go's `writeUserInfoHlr` performs the write after detecting a UID mismatch, which means its path component does not constrain which user is modified. Reproducing that faithfully would be porting a bug into a security boundary.
