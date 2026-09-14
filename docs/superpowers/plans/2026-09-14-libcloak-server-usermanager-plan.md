# libcloak-server: User Manager and Accounting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `cloak_server_is_bypass` as the server's entire authorisation policy. After this plan a UID is authorised against a persistent user database — it must exist, have upload and download credit left, not have expired, and not already hold its allowance of sessions — and the traffic it moves is metered back against that credit, with a user whose credit runs out during a session terminated rather than served to exhaustion.

**Architecture:** Three layers, mirroring Go's, with one deliberate structural divergence. `cloak_usermanager_t` owns persistence: a vendored SQLite database and the seven operations Go's `UserManager` interface declares, plus a void mode for a server configured without a database. `cloak_valve_t` lives in `libcloak-mux` and meters one user's bytes across every session that user holds — the switchboard's send path and the connection read path are the two places bytes are counted. `cloak_userpanel_t` sits between them: it tracks which users are active, holds each one's valve, drains their counters onto a queue on a timer, commits that queue to the manager in one transaction, and terminates whoever the manager says has run out.

The divergence: Go's `ActiveUser` keeps its own `map[uint32]*mux.Session`. This port does **not** — `cloak_server_registry_t` already stores sessions keyed by (uid, session_id), and a second table would be a second source of truth for the one question that matters here, "how many sessions does this user have". The registry grows two by-UID accessors instead.

**Tech Stack:** C11, CMake, CTest with the project's existing assert-based framework, SQLite 3.50.4 (vendored amalgamation).

**Spec:** `docs/superpowers/specs/2026-09-07-cloak-c-port-design.md` §8 (first half — the admin API is the next module) and §12's "User DB | SQLite" decision.

**Reference:** `/Users/sam/Cloak/internal/server/usermanager/{usermanager.go,localmanager.go,voidmanager.go}`, `/Users/sam/Cloak/internal/server/{userpanel.go,activeuser.go}`, `/Users/sam/Cloak/internal/multiplex/qos.go`.

## Global Constraints

- C11, `-Wall -Wextra` clean, zero warnings in project code. The vendored SQLite target is built with `-w`, exactly as `third_party/cjson` already is.
- Linux only. `#define _POSIX_C_SOURCE 200809L` as the **first line** of any `.c` needing POSIX APIs.
- Public symbols prefixed `cloak_`; headers under `<module>/include/cloak/` with `CLOAK_<NAME>_H` guards; doc comments in the established style — state the contract and **why**, not what the code does.
- Every constructor fully initializes its struct **before** validating its other arguments. Every destroy is idempotent and safe on a zeroed struct.
- **Nothing may block the reactor.** This is the constraint that shapes the whole module; see Decision D3 and D4 below.
- Append to every `CMakeLists.txt`; never rewrite one. `libcloak-server/tests/CMakeLists.txt` lines 46-126 carry a load-bearing ASan/LD_PRELOAD block that must stay byte-identical.
- Test registration convention — copy an existing entry, always with `TIMEOUT 60`:
  ```cmake
  add_executable(test_X test_X.c)
  target_include_directories(test_X PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
  target_link_libraries(test_X PRIVATE cloak-server)
  add_test(NAME test_X COMMAND test_X)
  set_tests_properties(test_X PROPERTIES TIMEOUT 60)
  ```
- Every test wait is bounded via the `pump_until` idiom; every peer socket is non-blocking. **A bound whose comment names a duration must assert it reached that duration** — see "What the previous branch learned".
- Build and test (note `-w`: `-w /src` silently builds the main checkout):
  ```bash
  docker run --rm -v /Users/sam/Cloak-c:/src -w /src/.worktrees/libcloak-usermanager cloak-c-dev bash -c \
    'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j8 && ctest --test-dir build --output-on-failure'
  ```
- ASan/UBSan, required for Tasks 3, 4 and 5:
  ```bash
  docker run --rm -v /Users/sam/Cloak-c:/src -w /src/.worktrees/libcloak-usermanager cloak-c-dev bash -c \
    'cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
       -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
       -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
       -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined" && \
     cmake --build build-asan -j8 && ctest --test-dir build-asan --output-on-failure'
  ```
- Test counts: **39 before**, 40 after Task 1, 41 after Task 2, 42 after Task 3, 43 after Task 4, 44 after Task 5, 45 after Task 6.

## Decisions taken before execution

**D1 — Follow Go's actual fields, not the spec's schema sketch.** §8 sketches `uid BLOB PRIMARY KEY, bypass INTEGER, rx INTEGER, tx INTEGER, rx_limit INTEGER, tx_limit INTEGER, expiry INTEGER`. Go's `UserInfo` is `UID, SessionsCap, UpRate, DownRate, UpCredit, DownCredit, ExpiryTime`, and the same sentence of the spec says the schema mirrors "the fields `usermanager` tracks in Go's bbolt store". The sketch is an approximation, the stated intent is fidelity, so fidelity wins. `bypass` is not a column: bypass UIDs come from the config file, exactly as they do in Go.

**D2 — Terminology is fixed and easy to get backwards.** Go's `qos.go` carries a warning comment worth repeating here: `rx`/`tx` are from the **server's** perspective (rx = client→server), while `UpCredit`/`UpRate`/`UpUsage` in the user manager are from the **user's**. A user's *upload* is the server's *rx*. Getting this backwards silently meters the wrong direction against the wrong limit, and every test that uses equal values in both directions would pass. Every conversion between the two vocabularies happens in exactly one place — the panel's queue drain — and that place must say so in a comment.

**D3 — SQLite is built `SQLITE_THREADSAFE=0`, and its blocking I/O is accepted with mitigations.** The reactor is single-threaded, so SQLite's mutexes are pure overhead; compiling them out is correct rather than merely faster. The real issue is that SQLite's file I/O blocks: an `fsync` on a slow disk stalls every session on the server, not just the one being authorised. Mitigations, all of which belong in Task 1's build flags or Task 2's open path: WAL journalling with `synchronous = NORMAL` (a crash can lose the last commits' worth of *metering*, never the user table itself, which is the right thing to trade); prepared statements cached for the lifetime of the manager so the authorisation path never re-parses SQL; and every periodic upload committed as ONE transaction for all users, exactly as Go commits one bolt `Update` for the whole batch. The residual — a genuinely slow or failing disk stalls the reactor — is accepted and must be stated in `usermanager.h`. Go has the same shape and hides it behind goroutines; a single-threaded port cannot, and pretending otherwise in the header would be worse than naming it.

**D4 — Rate limiting cannot wait, so it does not.** Go's `Valve.rxWait/txWait` call `ratelimit.Bucket.Wait`, which sleeps the goroutine. Nothing in this reactor may sleep. The port is a non-blocking token bucket the data path *consults*: it asks how many bytes it may move now, moves at most that many, and when the answer is zero the caller pauses its read interest and arms a timer for when the next token is due — the same pause/resume shape `cloak_stream_relay_t` already uses for pool backpressure, and the reason Task 6 can reuse that machinery rather than invent any. Task 6 owns this; Tasks 1-5 build the counting half of the valve, which is what credits and termination actually need, so the module delivers working accounting before rate limiting is attempted.

**D5 — Time is injectable.** Go threads a `common.WorldState` through the manager so expiry and credit tests do not depend on the wall clock. `cloak_usermanager_t` takes a `now_fn` (and userdata) that defaults to `time(NULL)`. Without it, every expiry test either manipulates the real clock or writes timestamps relative to it and hopes — and this project has already shipped one test whose stated bound was not the bound that bound.

**D6 — The registry is the only session store.** Go's `ActiveUser.sessions` is not ported. `cloak_server_registry_t` gains `cloak_server_registry_count_for_uid` and `cloak_server_registry_close_all_for_uid` (both linear scans over at most `CLOAK_REGISTRY_MAX_SESSIONS` entries — the same reasoning, and the same required comment, as `cloak_proxy_t`'s own linear scans). A second per-user session table would have to be kept in step with the registry through every teardown path this project has already spent a branch getting right, and the two would disagree exactly when it mattered.

---

### Task 1: Vendor SQLite

**Files:**
- Create: `third_party/sqlite/sqlite3.c`, `third_party/sqlite/sqlite3.h`, `third_party/sqlite/CMakeLists.txt`, `third_party/sqlite/VENDORING.md`
- Create: `libcloak-common/tests/test_sqlite_link.c`
- Modify: `CMakeLists.txt` (root — add the subdirectory beside `third_party/cjson`), `libcloak-common/tests/CMakeLists.txt`
- Read first: `third_party/cjson/CMakeLists.txt` and `third_party/cjson/VENDORING.md` — this task follows that pattern exactly, and `libcloak-common/tests/test_cjson_link.c` is the model for the smoke test.

**Exact provenance, already verified — do not substitute a different version:**

- Source: `https://sqlite.org/2025/sqlite-amalgamation-3500400.zip`, SQLite **3.50.4**.
- Vendor **only** `sqlite3.c` and `sqlite3.h`. The zip also contains `shell.c` (the CLI, which this project does not build) and `sqlite3ext.h` (the loadable-extension interface, which the build below disables); vendoring either would be dead weight a reader has to rule out.
- SHA-256 of the two files as fetched:
  ```
  e3f5d6901e7492af4a1fc8c4d745cae84c264942524c3fbfc02b82a5ca8818c8  sqlite3.c
  abd1514e0351f79393d1be882830afdb40a8099e8257f311f0bfdf8486f11bea  sqlite3.h
  ```
  **Verify these after downloading.** A mismatch means you fetched something else; stop and report it rather than proceeding.
- License: SQLite is public domain, so unlike cJSON there is no `LICENSE` file to copy. `VENDORING.md` must say that explicitly, with a link to `https://sqlite.org/copyright.html` — an absent licence file otherwise reads as an omission.

**Build flags** (in `third_party/sqlite/CMakeLists.txt`, as `target_compile_definitions` on a static `sqlite3` target built with `-w`):

```
SQLITE_THREADSAFE=0            /* D3: single-threaded reactor; the mutexes are pure overhead */
SQLITE_OMIT_LOAD_EXTENSION     /* nothing loads extensions; removes a file-system attack surface */
SQLITE_OMIT_DEPRECATED
SQLITE_OMIT_SHARED_CACHE
SQLITE_DQS=0                   /* reject double-quoted string literals -- they mask typo'd identifiers */
SQLITE_DEFAULT_MEMSTATUS=0
SQLITE_DEFAULT_FOREIGN_KEYS=1
SQLITE_LIKE_DOESNT_MATCH_BLOBS
SQLITE_MAX_EXPR_DEPTH=0
```

Give each a one-line reason in the CMakeLists, the way this project comments its other build decisions. `SQLITE_THREADSAFE=0` in particular is a correctness-relevant choice, not a tuning one, and the next reader must not "fix" it.

- [ ] **Step 1: Write the smoke test first**

`libcloak-common/tests/test_sqlite_link.c`, modelled on `test_cjson_link.c`: open `:memory:`, create a table, insert two rows with a BLOB key, read them back with a prepared statement, assert the values, finalize and close. Also assert `sqlite3_libversion_number()` matches the vendored version, and assert `sqlite3_threadsafe() == 0` — that is the one build flag whose silent regression would cost correctness rather than speed, and this is the only place it can be checked.

- [ ] **Step 2: Run it and watch it fail** — there is no `sqlite3` target yet.

- [ ] **Step 3: Vendor the files, write the CMakeLists and VENDORING.md, wire the root CMakeLists**

- [ ] **Step 4: Build and run the full suite (40 tests), Debug**

Report the build time delta: `sqlite3.c` is ~9 MB of C and this is the first time this project compiles anything of that size. If it is large enough to hurt the edit-test loop, say so — that is a finding the remaining five tasks and every future branch will pay for.

- [ ] **Step 5: Commit** — `git commit -m "Vendor SQLite 3.50.4 (amalgamation)"`

---

### Task 2: `cloak_usermanager_t` — persistence

**Files:**
- Create: `libcloak-server/include/cloak/usermanager.h`, `libcloak-server/src/usermanager.c`
- Create: `libcloak-server/tests/test_usermanager.c`
- Modify: `libcloak-server/CMakeLists.txt` (append `src/usermanager.c`, link `sqlite3`), `libcloak-server/tests/CMakeLists.txt`

**Interfaces:**
- Consumes: `sqlite3` (Task 1), `cloak/config.h` (`CLOAK_UID_LEN`), `cloak/log.h`.
- Produces: everything below. Tasks 4, 5 and the next module (the admin API) are its consumers.

**The schema**, created with `CREATE TABLE IF NOT EXISTS` on open so an existing database is opened unchanged:

```sql
CREATE TABLE IF NOT EXISTS users (
    uid          BLOB PRIMARY KEY NOT NULL,  /* exactly CLOAK_UID_LEN bytes */
    sessions_cap INTEGER NOT NULL,
    up_rate      INTEGER NOT NULL,           /* bytes/sec, 0 = unlimited */
    down_rate    INTEGER NOT NULL,
    up_credit    INTEGER NOT NULL,           /* bytes remaining */
    down_credit  INTEGER NOT NULL,
    expiry_time  INTEGER NOT NULL            /* unix seconds */
) WITHOUT ROWID;
```

`WITHOUT ROWID` because the table is keyed by a 16-byte blob and never scanned by rowid; it removes an index. Say so in a comment — an unexplained `WITHOUT ROWID` reads as cargo cult.

**The API**, mirroring Go's `UserManager` interface one for one:

```c
typedef struct {
    uint8_t uid[CLOAK_UID_LEN];
    int32_t sessions_cap;
    int64_t up_rate, down_rate;
    int64_t up_credit, down_credit;
    int64_t expiry_time;
} cloak_user_info_t;

/* Which fields of a cloak_user_info_t a write should actually apply.
 * Go expresses this with nil-able pointers (MaybeInt32/MaybeInt64) so a
 * partial update leaves untouched fields alone; C has no such thing, so
 * the caller says explicitly. A write with no bits set creates a row with
 * defaults and changes nothing else. */
typedef enum {
    CLOAK_USER_FIELD_SESSIONS_CAP = 1u << 0,
    CLOAK_USER_FIELD_UP_RATE      = 1u << 1,
    CLOAK_USER_FIELD_DOWN_RATE    = 1u << 2,
    CLOAK_USER_FIELD_UP_CREDIT    = 1u << 3,
    CLOAK_USER_FIELD_DOWN_CREDIT  = 1u << 4,
    CLOAK_USER_FIELD_EXPIRY_TIME  = 1u << 5,
} cloak_user_field_t;

/* One user's metered traffic since the last upload, as the panel drains it. */
typedef struct {
    uint8_t uid[CLOAK_UID_LEN];
    int64_t up_usage, down_usage;   /* USER's perspective -- see D2 */
    int     num_session;
    int     active;
    int64_t timestamp;
} cloak_user_status_t;

/* What the manager tells the panel to do about a user after an upload.
 * Go models this as a slice of StatusResponse with an action enum; only
 * TERMINATE exists, and a user needing no action gets no entry at all. */
typedef struct {
    uint8_t     uid[CLOAK_UID_LEN];
    const char *reason;   /* static string; never freed by the caller */
} cloak_user_terminate_t;

typedef int64_t (*cloak_now_fn)(void *userdata);   /* D5 */

typedef struct cloak_usermanager cloak_usermanager_t;

/* db_path == NULL opens a VOID manager: every authorisation fails with
 * CLOAK_USER_ERR_VOID and every CRUD call fails the same way, matching
 * Go's Voidmanager. This is not a degraded mode to work around -- a
 * server configured with no DatabasePath serves its bypass UIDs and
 * nobody else, which is a legitimate and common deployment. */
int cloak_usermanager_open(cloak_usermanager_t **out, const char *db_path,
                           cloak_now_fn now_fn, void *now_userdata,
                           char *err, size_t err_cap);
void cloak_usermanager_close(cloak_usermanager_t *m);

/* The seven operations. Each returns 0 or a negative CLOAK_USER_ERR_*. */
int cloak_usermanager_authenticate(cloak_usermanager_t *m, const uint8_t uid[CLOAK_UID_LEN],
                                   int64_t *out_up_rate, int64_t *out_down_rate);
int cloak_usermanager_authorise_new_session(cloak_usermanager_t *m,
                                            const uint8_t uid[CLOAK_UID_LEN],
                                            int num_existing_sessions);
int cloak_usermanager_upload_status(cloak_usermanager_t *m, const cloak_user_status_t *updates,
                                    size_t n_updates, cloak_user_terminate_t *out_terminate,
                                    size_t out_cap, size_t *out_n);
int cloak_usermanager_list(cloak_usermanager_t *m, cloak_user_info_t *out, size_t out_cap,
                           size_t *out_n);
int cloak_usermanager_get(cloak_usermanager_t *m, const uint8_t uid[CLOAK_UID_LEN],
                          cloak_user_info_t *out);
int cloak_usermanager_write(cloak_usermanager_t *m, const cloak_user_info_t *info,
                            uint32_t fields);
int cloak_usermanager_delete(cloak_usermanager_t *m, const uint8_t uid[CLOAK_UID_LEN]);
```

Error codes, one per Go error, because the dispatcher and the admin API need to tell them apart: `CLOAK_USER_ERR_NOT_FOUND`, `_NO_UP_CREDIT`, `_NO_DOWN_CREDIT`, `_EXPIRED`, `_SESSIONS_CAP`, `_VOID`, `_DB`.

**Semantics to port exactly — read `localmanager.go` rather than inferring them:**

- `authenticate` checks, in this order: the user exists; `up_credit > 0`; `down_credit > 0`; `expiry_time >= now`. Note Go's comparison is `expiryTime < now` → expired, so a user expiring exactly now is still valid.
- `authorise_new_session` repeats all of those and then checks `num_existing_sessions >= sessions_cap` → `_SESSIONS_CAP`.
- `upload_status` runs in ONE transaction over all updates. For each: a missing user yields a terminate with "user no longer exists" and no write; otherwise subtract usage from each credit, **write the new value back even when it goes non-positive** (Go does, and it matters — the debt is what stops a user reconnecting), and emit a terminate when either new credit `<= 0` or the user has expired. A user can match more than one terminate condition; Go overwrites its local `resp` and appends per condition, ending with at most one entry per user carrying the last reason. **Match Go's observable result (at most one terminate per user), and state in a comment which reason wins.**
- `write` is an upsert: it creates the row if absent, and applies only the fields the mask names. A created row's unnamed fields take documented defaults — choose them and say why; a new user whose `sessions_cap` defaults to 0 can never connect, which may be the correct conservative default but must be a decision rather than an accident.
- `list` and `get` return every field.

**On out-parameter sizing:** `upload_status` and `list` take a caller buffer and a cap rather than allocating. Report how many rows exist even when `out_cap` is smaller, so a caller can retry with a bigger buffer; say in the header what happens when it is too small. The admin API next module will page through `list`.

- [ ] **Step 1: Write the failing test** — `libcloak-server/tests/test_usermanager.c`, with a fake `now_fn` the test controls (D5):

```
 1. Open a temp-file DB, close, reopen: the schema survives and so do rows.
    Use a unique temp path per test and unlink it at the end.
 2. Void manager (db_path NULL): every operation returns _VOID, nothing crashes.
 3. write creates; get reads back every field; list sees exactly one user.
 4. write with a partial field mask changes only the named fields.
 5. authenticate: success returns the rates; unknown UID -> _NOT_FOUND;
    zero and negative up_credit -> _NO_UP_CREDIT; same for down;
    expiry in the past -> _EXPIRED; expiry exactly == now -> SUCCESS
    (the boundary Go's `<` puts on the valid side).
 6. authorise_new_session: below the cap succeeds, at the cap fails with
    _SESSIONS_CAP, and it still enforces every authenticate condition.
 7. upload_status: subtracts usage; drives a credit to zero and gets a
    terminate; the debt is PERSISTED (re-read shows the non-positive
    value, so the user cannot reconnect).
 8. upload_status for a deleted user yields "no longer exists" and does
    not create a row.
 9. upload_status with several users in one call, where only some
    terminate -- assert the terminate list holds exactly the right UIDs.
10. delete removes; get then returns _NOT_FOUND.
11. list with out_cap smaller than the row count reports the true total
    and fills what it can.
12. A UID that is not CLOAK_UID_LEN bytes is rejected rather than stored
    (the admin API will hand this function attacker-influenced input).
```

- [ ] **Step 2: Run it to verify it fails**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (41 tests) Debug and ASan**
- [ ] **Step 5: Commit** — `git commit -m "Add cloak_usermanager_t: the persistent user database"`

---

### Task 3: `cloak_valve_t` — metering the bytes

**Files:**
- Create: `libcloak-mux/include/cloak/valve.h`, `libcloak-mux/src/valve.c`
- Create: `libcloak-mux/tests/test_valve.c`
- Modify: `libcloak-mux/src/switchboard.c`, `libcloak-mux/src/conn.c` (or wherever the read path lands the byte count — find it, do not assume), `libcloak-mux/include/cloak/session.h` (a `valve` field on `cloak_session_config_t`), `libcloak-mux/CMakeLists.txt`, `libcloak-mux/tests/CMakeLists.txt`

**This task builds the counting half only.** Rate limiting is Task 6 (D4). Build `cloak_valve_t` so Task 6 adds token buckets to the same object without changing its call sites.

```c
/* Meters one USER's traffic across every session that user holds -- the
 * object is shared by reference between sessions, which is exactly why it
 * lives here rather than inside cloak_session_t.
 *
 * rx and tx are from the SERVER's perspective: rx is client->server, tx is
 * server->client. The user manager's up/down are from the USER's. A user's
 * upload is the server's rx. See this project's D2 and Go's own warning
 * comment in internal/multiplex/qos.go; the conversion happens in exactly
 * one place and it is not here. */
typedef struct {
    int64_t rx, tx;
} cloak_valve_t;

void cloak_valve_add_rx(cloak_valve_t *v, int64_t n);   /* NULL-tolerant: an unmetered session */
void cloak_valve_add_tx(cloak_valve_t *v, int64_t n);
int64_t cloak_valve_rx(const cloak_valve_t *v);
int64_t cloak_valve_tx(const cloak_valve_t *v);
/* Reads both counters and zeroes them in one step -- Go's Nullify. The
 * caller gets the bytes moved since the last drain; nothing is lost
 * between the read and the reset, which is why this is one call. */
void cloak_valve_nullify(cloak_valve_t *v, int64_t *out_rx, int64_t *out_tx);
```

**A NULL valve means "not metered"** and every entry point tolerates it. That is how bypass users and every existing test keep working without touching a line: `cloak_session_config_t.valve` defaults to NULL, which is what a zeroed config already gives. This replaces Go's `UnlimitedValve` with something that costs no allocation and no branch the compiler cannot predict.

**Where to count** — match Go's `switchboard.go` exactly, and **read that file rather than guessing**: `AddTx(n)` after a successful write of n bytes on the send path, `AddRx(n)` after a successful read of n bytes on the receive path. Count **wire bytes**, the same quantity Go counts, not payload bytes: a user pays for the frame overhead they cause. Say that in the header, because "why does my usage exceed what I transferred" is the first question an operator asks.

- [ ] **Step 1: Write the failing test** — `libcloak-mux/tests/test_valve.c`:

```
1. add/read/nullify arithmetic, including that nullify returns the
   accumulated values AND zeroes them.
2. Every entry point on a NULL valve is a no-op and does not crash.
3. A session configured with a valve counts real traffic: drive bytes
   through a live session in both directions and assert rx and tx both
   move. This is the only test that proves the wiring, so assert the
   DIRECTION -- send only one way and assert the other counter stays 0.
   A test that sends both ways would pass with rx and tx swapped, which
   is precisely D2's failure mode.
4. Two sessions sharing one valve accumulate into it together.
5. A session configured with no valve still passes traffic.
```

- [ ] **Step 2: Run it to verify it fails**
- [ ] **Step 3: Implement and wire**
- [ ] **Step 4: Full suite (42 tests) Debug and ASan**
- [ ] **Step 5: Mutation-verify the direction.** Swap `add_rx` and `add_tx` at their call sites and confirm test 3 fails. If it does not, test 3 is not testing direction and must be rewritten before this task is done.
- [ ] **Step 6: Commit** — `git commit -m "Add cloak_valve_t: per-user byte metering"`

---

### Task 4: `cloak_userpanel_t` — active users, the usage queue, and termination

**Files:**
- Create: `libcloak-server/include/cloak/userpanel.h`, `libcloak-server/src/userpanel.c`
- Create: `libcloak-server/tests/test_userpanel.c`
- Modify: `libcloak-server/include/cloak/registry.h`, `libcloak-server/src/registry.c` (D6's two accessors), `libcloak-server/CMakeLists.txt`, `libcloak-server/tests/CMakeLists.txt`

**What to build:**

1. **The two registry accessors (D6).** `cloak_server_registry_count_for_uid(reg, uid)` counts live entries for a UID; `cloak_server_registry_close_all_for_uid(reg, uid)` closes every one. Both are linear scans over at most `CLOAK_REGISTRY_MAX_SESSIONS` entries — comment that, with the same reasoning `cloak_proxy_t`'s scans carry. `close_all_for_uid` must obey everything `cloak_server_registry_close`'s own doc comment already says about when on_broken does and does not fire, and about being called from inside a broken callback; read it before writing.

2. **`cloak_userpanel_t`.** An active-user table keyed by UID, each entry owning one `cloak_valve_t`, a `bypass` flag, and nothing else — the sessions live in the registry. Operations mirroring Go's:
   - `get_user(uid)` — returns the active user, creating it via `cloak_usermanager_authenticate` if absent. The rates it returns are stored for Task 6.
   - `get_bypass_user(uid)` — creates unconditionally, no manager call, valve NULL (a bypass user is not metered; Go's `updateUsageQueue` skips them and `GetBypassUser` gives them `UNLIMITED_VALVE`).
   - `terminate(user, reason)` — drains that user's usage onto the queue, closes all its sessions through the registry, removes it from the table.
   - `notify_session_closed(uid)` — when a user's last session goes, the user stops being active. Go does this from `ActiveUser.CloseSession`; here the trigger is the registry's broken/close path, so the panel needs to be told. **Name the caller in the header**, because a user that never deactivates is a slow leak and the symptom is only visible as a growing table.
   - The periodic upload: a reactor timer at `upload_interval_ms` (default 60000, Go's `defaultUploadInterval`) that drains every non-bypass active user's valve into the queue, then commits the queue to the manager in one `upload_status` call, then terminates whoever came back.

3. **The queue** accumulates per UID between uploads and survives a user going inactive — Go keeps a `usageUpdateQueue` separate from `activeUsers` for exactly that reason, and its `commitUpdate` reports `Active: false` for a user who left. Port that: usage accrued by a user who disconnects before the next upload must still be billed.

**The ordering hazard, stated once:** `terminate` closes sessions, which runs the registry's broken path, which can call back into the panel (`notify_session_closed`). Decide and document whether `terminate` is re-entrant or guards against it. This project has produced two bugs of exactly this shape already (a registry destroy from inside its own callback; a session unwind destroying a session another connection had joined), so treat re-entrancy as the default assumption, not the edge case.

- [ ] **Step 1: Write the failing test** — `libcloak-server/tests/test_userpanel.c`, with a controllable `now_fn` and an explicit short `upload_interval_ms`:

```
1. get_user on a valid UID makes it active and returns its rates;
   an unknown UID fails and creates nothing.
2. get_bypass_user creates without touching the manager -- assert by
   opening the panel over a VOID manager and having it still work.
3. Usage flows: metered traffic on a session reaches the queue on the
   timer and reaches the database. Assert the DB value, not just the
   queue -- the queue is an implementation detail, the billing is not.
4. A user whose credit runs out mid-session is terminated: its sessions
   are closed and it leaves the active table.
5. Usage accrued by a user who disconnects BEFORE the next upload is
   still billed. This is the case the separate queue exists for.
6. The two registry accessors: count_for_uid and close_all_for_uid over
   several users with several sessions each, including a UID with none.
7. Re-entrancy: terminate while the registry's broken path calls back
   into the panel does not double-free or lose the user. Run under ASan;
   this is the case the ordering hazard above exists for.
8. Bypass users are never metered and never uploaded.
```

- [ ] **Step 2: Run it to verify it fails**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (43 tests) Debug and ASan, plus the new test 50x**
- [ ] **Step 5: Mutation-verify tests 4, 5 and 7** — break the termination, break the queue's survival of a user going inactive, break the re-entrancy guard; confirm each is caught. Report any that is not.
- [ ] **Step 6: Commit** — `git commit -m "Add cloak_userpanel_t: active users, usage accounting and termination"`

---

### Task 5: Wire it into the dispatcher

**Files:**
- Modify: `libcloak-server/src/dispatcher.c`, `libcloak-server/include/cloak/dispatcher.h`
- Create: `libcloak-server/tests/test_dispatcher_users.c`
- Modify: `libcloak-server/tests/CMakeLists.txt`

**What changes.** `dispatcher_authenticate`'s step 6 currently reads:

```c
    /* 6. Authorise the UID. */
    if (!cloak_server_is_bypass(srv, info.uid)) {
        return -1;
    }
```

and its own header comment says "cloak_server_is_bypass is the whole authorisation policy until a user manager exists". It now exists. Step 6 becomes: a bypass UID takes `get_bypass_user`; any other UID takes `get_user`, and a failure there redirects exactly as today — **a prober must learn nothing from which of the two paths refused it**, so both must reach the same `conn_start_redirect` with no branch that differs in bytes or in anything an attacker can time. Step 8's create path additionally calls `authorise_new_session` with `cloak_server_registry_count_for_uid`, and a refusal there redirects too.

`cloak_dispatcher_config_t` gains a `cloak_userpanel_t *panel`, which may be NULL — with no panel, the policy is exactly today's bypass-only check, so every existing dispatcher test keeps passing unmodified. **That is a requirement, not a hope**: if any existing test needs changing, stop and report it.

**The unwind question this task must answer.** Step 8 can now fail *after* `get_user` made a user active. Does that leave a user active with no sessions, and does anything ever reap it? Trace it, decide, and document. This is the same shape as the orphaned-context leak the previous branch found on three separate dispatcher paths, and the previous branch's `session_aborted` callback may be exactly the hook this needs — check before adding a new one.

- [ ] **Step 1: Write the failing test** — `libcloak-server/tests/test_dispatcher_users.c`, built on `client_harness.h`:

```
1. A UID in the database authenticates and gets a session.
2. A UID not in the database is REDIRECTED -- byte-for-byte the same
   cover response an unauthenticated connection gets. Compare against the
   redirect an ordinary garbage connection produces, not against a
   hand-written expectation.
3. An expired user, a user with no credit, and a user at its sessions
   cap are each redirected the same way.
4. A bypass UID still works with no database at all (void manager).
5. With no panel configured, the bypass-only policy is unchanged.
6. A user at its cap with one session closing: the next handshake
   succeeds, proving the cap reads live registry state rather than a
   stale count.
```

- [ ] **Step 2: Run it to verify it fails**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (44 tests) Debug and ASan. Every pre-existing test must pass UNMODIFIED.**
- [ ] **Step 5: Commit** — `git commit -m "Authorise handshakes against the user manager"`

---

### Task 6: Rate limiting

**Files:**
- Modify: `libcloak-mux/include/cloak/valve.h`, `libcloak-mux/src/valve.c`, `libcloak-mux/src/switchboard.c` and the read path, `libcloak-server/src/userpanel.c` (hand the authenticated rates to the valve)
- Create: `libcloak-mux/tests/test_valve_rate.c`
- Modify: `libcloak-mux/tests/CMakeLists.txt`

**D4 is the design.** Add a token bucket per direction to `cloak_valve_t`: a rate in bytes/sec, a capacity, a token count and a last-refill timestamp. The data path asks `cloak_valve_take_rx(v, want)` / `_take_tx` for permission to move up to `want` bytes and is told how many it may actually move — possibly zero. Zero means the caller pauses its read interest and arms a timer for when the next whole token is due; `cloak_stream_relay_t`'s existing pause/resume is the shape to copy, not to reinvent. A rate of 0 means unlimited and must take the same code path as a NULL valve: no timer, no pause, no arithmetic.

**The failure this task must not produce is a stall.** A paused direction that is never resumed is indistinguishable from a hung session, and this project has already shipped one relay whose budget could reach zero with nothing left to ever wake it. Every pause must arm a timer before it returns, and a test must prove a paused direction resumes on its own with no further input from the peer.

- [ ] **Step 1: Write the failing test** — `libcloak-mux/tests/test_valve_rate.c`, with injectable time so the test does not sleep:

```
1. Token arithmetic: refill over elapsed time, the cap, and that a
   request larger than the available tokens is partially granted.
2. rate == 0 is unlimited and allocates no timer.
3. A session limited to a low rate transfers a known number of bytes in
   a known simulated interval, within a stated tolerance. State the
   tolerance and why it is what it is.
4. A direction that hits zero tokens RESUMES on its own -- no peer
   activity, only time passing. This is the stall test and it is the
   reason this task exists at all.
5. Limiting one direction does not throttle the other.
6. Bytes moved under a limit are still counted by the metering half.
```

- [ ] **Step 2: Run it to verify it fails**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Full suite (45 tests) Debug and ASan, plus the new test 50x**
- [ ] **Step 5: Mutation-verify the stall guard** — remove the timer arming on pause and confirm test 4 fails rather than hangs. A test that hangs instead of failing is a worse outcome than no test; if that is what happens, bound it so it fails.
- [ ] **Step 6: Commit** — `git commit -m "Add rate limiting to cloak_valve_t"`

---

## What the previous branch learned

Six test-coverage defects on the proxy-path branch, every one found by measuring or mutating, none by reading. Their shapes recur and this module is full of timers and counters, which is where they live:

1. A wall-clock bound whose iteration cap bound first — a pump whose comment claimed 400 ms measured 84 ms.
2. An assertion that could not fail — a count asserted zero on a path the test never exercised.
3. A precondition asserted before the code under test ran, not at it.
4. A buffer sized for the average case when the protocol pads randomly.
5. A "mid-flight" assertion with nothing in flight.
6. A constant chosen so the mechanism under test and its absence produce the same number.

Two disciplines catch them: before writing an assertion, ask what change to the implementation would make it fail, and if the answer is "none", it is not coverage; and write an expected value as a literal, never recomputed from the implementation's own expression, which would agree with any mutation of it.

## Self-review notes

- **Spec coverage:** §8's first half is Tasks 1-5; §12's SQLite decision is Task 1. The admin API, §8's second half, is deliberately the next module. Rate limiting (Task 6) is not named in the spec but is required by `UpRate`/`DownRate` in the data model the spec says to mirror; it is last so the module delivers accounting even if it proves larger than estimated.
- **Placeholder scan:** every task names its files, its exact interfaces and its test cases. The six decisions D1-D6 are settled here rather than deferred. The two places a decision is genuinely left to the implementer — the defaults a created user row takes, and whether `terminate` is re-entrant or guards — each say explicitly that a decision with a stated reason is required, which is the point.
- **Type consistency:** `cloak_user_info_t`, `cloak_user_status_t`, `cloak_user_terminate_t` and `cloak_valve_t` are defined once and used under those names throughout. Test counts chain 39 → 40 → 41 → 42 → 43 → 44 → 45.
- **The riskiest thing here** is D2, the rx/tx versus up/down inversion. It is silent, it is plausible in both directions, and a test that exercises both directions symmetrically passes either way. Task 3's step 5 mutation exists solely to catch it.
- **The most consequential thing here** is D4. Go's rate limiter blocks a goroutine; this reactor has no thread to block. Every other difference between the Go original and this port in this module is mechanical.
