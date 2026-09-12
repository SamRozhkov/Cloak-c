# libcloak-mux Session + Connection Pool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port Go Cloak's `Session` + `switchboard` (`internal/multiplex/session.go`, `switchboard.go`) to C: a stream table with tombstoning, a connection pool that spreads frames across multiple underlying connections, and the plumbing that wires already-merged `cloak_stream_t` instances to real non-blocking sockets via the reactor.

**Architecture:** Four new files layered strictly bottom-up, each depending only on the one(s) below it: `strmtab.c` (a `uint32_t -> void*` table with a third "tombstone" state, no dependencies beyond libc) → `conn.c` (one non-blocking fd wrapped for the reactor, with a length-prefixed wire envelope so `cloak_frame_deobfuscate` always gets exactly one frame's bytes) → `switchboard.c` (a pool of `conn.c` instances, picks one at random per send) → `session.c` (owns a `strmtab` + a `switchboard` + the shared `cloak_obfuscator_t`, and is the thing that actually creates/destroys `cloak_stream_t` instances and routes frames to them).

**Tech Stack:** C11, raw epoll via the already-merged `cloak_reactor_t` (`libcloak-common/include/cloak/reactor.h`), the already-merged `cloak_bytequeue_t`/`cloak_stream_t`/`cloak_frame_t` (`libcloak-mux`), CMake, Docker (`Dockerfile.dev` / image `cloak-c-dev`) for all building and testing since this is Linux-only code (epoll, `socketpair`).

## Global Constraints

- **Linux-only, Docker-only builds.** Every build/test command in this plan runs inside the `cloak-c-dev` Docker image via `docker run -v "$(pwd)":/src -w /src cloak-c-dev bash -c "..."`. Never attempt to build or run these tests on the host directly (epoll and `socketpair(AF_UNIX, SOCK_STREAM, ...)` targeted here are Linux/POSIX; this whole codebase already assumes Linux per the master design spec's Non-goals).
- **Zero compiler warnings.** The project's root `CMakeLists.txt` sets `-Wall -Wextra` (not `-Werror` — verified directly: `grep -rn Werror CMakeLists.txt libcloak-*/CMakeLists.txt` finds nothing). Every task's default build must be warning-free under that. In addition, per this project's established verification practice (every prior module's final report did this as a separate explicit pass, not by relying on the default build), also rebuild with `-Werror` added on top (`cmake -S . -B build_warncheck -DCMAKE_C_FLAGS='-Werror' && cmake --build build_warncheck`) and confirm that succeeds too, before reporting a task done.
- **`memset` the struct as the very first statement of every `_init` function, before any parameter validation.** This project has twice independently hit and fixed the same bug class (`cloak_replay_cache_init` in `libcloak-server`, then `cloak_stream_init` in this same `libcloak-mux` library): if validation runs first and rejects the call, a caller who then calls the matching `_destroy` on the still-uninitialized struct frees/inspects garbage pointers. Every `_init` function in this plan (`cloak_strmtab_init`, `cloak_conn_init`, `cloak_switchboard_init`, `cloak_session_init`) must `memset(x, 0, sizeof(*x));` first, then validate, so a rejected `_init` always leaves a struct that's safe to pass to `_destroy`.
- **Never silently drop data or silently wedge.** Every buffering structure in this codebase (`cloak_bytequeue_t`, `cloak_stream_t`'s reorder heap) either accepts data or explicitly rejects it with a return value the caller can act on — nothing is ever accepted and then quietly lost, and nothing is ever accepted in a way that can permanently stall delivery of everything behind it. This plan's new structures (`cloak_strmtab_t`, `cloak_conn_t`'s two byte queues) follow the same rule; see each task's own reasoning for the specific invariant that guarantees it.
- **Fault model: any single connection failure tears down the whole session.** This is Go's actual, verified behavior (`switchboard.go`'s `send()` and `deplex()` both call `sb.session.passiveClose()` on ANY read or write error on ANY one connection — not just the failing connection), not a simplification introduced by this port. A session with several underlying connections is not resilient to losing just one of them; losing any one is fatal to the whole session. Do not build per-connection retry/failover logic anywhere in this plan — `cloak_conn_send` returns a plain `0` (accepted) / `-1` (this connection — and therefore this session — is now broken) precisely so it drops into the already-merged, synchronous `cloak_stream_frame_sink_t` contract (`libcloak-mux/include/cloak/stream.h`) with no adaptation needed.
- **Wire format addition: a 2-byte big-endian length prefix precedes every obfuscated frame on the wire, added at the connection layer only.** `cloak_frame_deobfuscate` (`libcloak-mux/src/frame.c`, already merged, not modified by this plan) decrypts its input's header using the *last 8 bytes of its entire input* as the Salsa20 nonce — it can only be called with a buffer containing **exactly** one frame's bytes, no more, no less, decided *before* any decryption happens. Go's implementation gets away without an explicit length prefix because it assumes one `net.Conn.Read()` call returns exactly one frame's bytes — an assumption that does not hold for a non-blocking, edge-triggered epoll reactor (a single readable event can legitimately deliver zero, one, or several frames' worth of bytes, or a partial frame). This plan's `conn.c` (Task 2) prepends/strips a 2-byte big-endian length prefix (`CLOAK_CONN_LEN_PREFIX_LEN`) around every frame, purely as connection-layer framing; `cloak_frame_obfuscate`/`cloak_frame_deobfuscate` themselves are not touched and know nothing about this prefix. This does not change DPI-evasion properties (the prefix is inside the encrypted tunnel, not observable by a passive observer) — it is a correctness fix for the blocking→non-blocking architecture change already decided in the master spec (§3), not a wire-compatibility or fingerprinting decision.
- **`recv_acc`'s capacity must be at least `2 * max_envelope_len`.** This is the invariant that makes the previous point's backpressure-free design safe: as long as every non-blocking `read()` is bounded by `cloak_bytequeue_free_space`, and extraction runs immediately after every successful commit, `recv_acc` can be proven never to reach 0 free space (see Task 2's reasoning) — meaning `cloak_conn_t` never needs to deregister `EPOLLIN`, which in turn means the "one more byte needed to complete a pending frame will never arrive because we stopped listening for it" deadlock class is structurally unreachable. Do not shrink this multiplier without re-deriving the proof in Task 2's comments.
- **A `cloak_strmtab_t` tombstone is permanent for the life of the table** (mirrors Go's `sesh.streams[id] = nil`, which Go's session code never deletes, only ever overwrites at session close). A late frame for a since-closed stream must be recognized as "known dead, drop silently" — not misread as "never seen, must be a new stream" — for as long as the session exists, including across every future table growth/rehash. `cloak_strmtab_insert_active` must never repurpose a *different* key's tombstone slot for a new key (this exact bug was caught and fixed during this plan's design verification — see Task 1).
- **Exactly one pending inactivity timer per session at a time.** `cloak_session_t` must call `cloak_reactor_cancel_timer` on its previously-scheduled inactivity timer (if any) before scheduling a new one, every time it reschedules (Task 4). Go's `time.AfterFunc` calls never get cancelled/replaced this way, which is safe there only because Go's GC keeps the session reachable until a stale timer fires and no-ops against its own idempotent guard; in C, an uncancelled stale timer whose callback fires after `cloak_session_destroy` has freed the session is a use-after-free. This is a deliberate, documented deviation from a literal Go translation, made for C-specific memory safety — not a DPI-relevant or observable-behavior change (the guard condition inside the timer callback is unchanged and still Go-faithful; only the *bookkeeping* of pending timers differs).
- **Never free an object that a callback currently executing on the call stack still holds a live pointer to — a real, recurring hazard in this specific module, not a one-off.** This plan's own design-verification process (extract the plan's literal code, build and test it for real, under ASan/UBSan, before handing it to an implementer — including adversarial scenarios beyond this plan's own written tests, contributed independently by this project's own final-review process, not just the plan's author) caught this exact bug class SEVEN times, in different shapes, all fixed in this plan as written:
  1. **Stream layer, passive close (Task 4):** passively closing a stream (a remote closing frame, or a protocol violation) used to synchronously `free()` the `cloak_stream_t` the moment `cloak_stream_feed_frame` reported it — but the consumer holding that pointer (from `on_new_stream`) might not have read its buffered data yet, especially when the data frame and the closing frame land in the same non-blocking read and get dispatched back-to-back. Fixed by splitting "retire" (stop routing, stop counting — safe to do immediately) from "release" (actually free the memory — only ever done by an explicit `cloak_session_release_stream` call from whoever is holding the pointer). See Task 4's own "Stream memory ownership" note and `test_active_stream_close_propagates_to_peer`'s regression test for the full mechanics.
  2. **New-stream ordering vs. a session-closing `on_new_stream` (Task 4, `session_on_envelope`):** a *brand new* stream's revealing frame was fed to it (`cloak_stream_feed_frame`) only *after* `on_new_stream` was invoked for it. `on_new_stream` is documented as safe to call `cloak_session_close` from — and that close's stream-teardown sweep ran synchronously and unconditionally freed every currently-ACTIVE stream, including the one just created two statements earlier. Fixed by reordering `session_on_envelope`'s new-stream branch: feed the revealing frame (and retire the stream immediately if that one frame already closes it) *before* invoking `on_new_stream`, not after — so nothing in that function touches the stream pointer again once `on_new_stream` returns, regardless of what it does. This also matches Go's actual ordering: `newStream.recvFrame(frame)` always runs synchronously in `recvDataFromRemote`, strictly before any consumer goroutine calling `Accept()` could observe the new stream via the channel send that precedes it.
  3. **Connection layer, whole-session teardown (Task 4, `session_passive_close`/`cloak_session_close`):** tearing down the whole session used to synchronously call `cloak_switchboard_close_all`, which `free()`s every `cloak_conn_t` in the pool — but this can be triggered *reentrantly*, from deep inside one specific `cloak_conn_t`'s own dispatch call chain (a closing-session frame arriving mid-read, or a connection breaking mid-write), freeing the very `cloak_conn_t` whose call frames are still unwinding above that point on the stack. First-pass fix: defer just the `cloak_switchboard_close_all` call (and `on_broken`) to a 0ms reactor timer — the standard "close on next tick" pattern any single-threaded event loop needs for this hazard. **This first-pass fix was itself incomplete — see #4 below.**
  4. **Stream layer, whole-session teardown, found during an independent final review's own adversarial testing (Task 4, `session_close_internal`):** fix #3 deferred the *connection* teardown but left the *stream*-freeing sweep (`cloak_strmtab_for_each_active` over every ACTIVE stream, freeing each one) running synchronously inside `session_close_internal`, called directly from `session_passive_close`/`cloak_session_close`. That sweep is reachable through the exact same reentrant paths as #3 (a connection failure cascading up through `conn_mark_broken` into a full session close) — but ALSO through a path #3's fix never touched: `cloak_stream_write`'s own sink call (`session_stream_sink_adapter` → `cloak_switchboard_send` → `cloak_conn_send` → `conn_mark_broken` on a write failure) can trigger this same synchronous sweep, freeing the very stream `cloak_stream_write` is still executing inside of — a genuine, deterministically-reproducible heap-use-after-free under a completely ordinary condition (the peer has disconnected; the local side calls `cloak_session_close_stream` or writes to the stream). Fixed by moving the entire stream-freeing sweep (not just the connection teardown) into the SAME deferred 0ms callback as #3 — `session_close_internal` now does nothing but set `sesh->closed = 1` and cancel the inactivity timer, touching no stream or connection memory at all, so it is safe to call from literally anywhere, including reentrantly from inside a stream's own write path. This single change closes both #3's original connection-layer hazard and this stream-layer one with one mechanism, and is why `cloak_session_close_stream`/`cloak_session_release_stream` do NOT need their own call to `cloak_stream_send_closing` reordered relative to `session_retire_stream` (an alternative, narrower fix that was also verified to work for this specific pair of functions, but did not address the general case — see `session_schedule_deferred_teardown`'s own comment for why the broader fix was chosen instead). See `test_close_stream_after_peer_disconnect_is_safe` for the regression test (a stream's own connection failing, then the application actively closing that same stream — completely ordinary, not an artificial trigger).
  5. **`session_send_closing_session_frame` missing the padding clamp `cloak_stream_send_closing` already has:** not a use-after-free, but the same root discipline failure (an invariant enforced at one call site, silently skipped at another) — an unclamped `[1,256]`-byte pad plus `cloak_frame_obfuscate`'s own up-to-`CLOAK_FRAME_MAX_EXTRA_LEN` padding could exceed `max_on_wire_size`, causing `cloak_conn_send` to reject the session's own closing notification as oversized and mark the connection broken instead of delivering it — the peer would then never learn the session closed gracefully, only that the connection died. Fixed by applying the identical clamp `cloak_stream_send_closing` already uses, adapted to session-level parameters.
  6. **The deferred-teardown timer from #3/#4 outliving `cloak_session_destroy`:** the first-pass fix for #3 argued (incorrectly) that no timer-id tracking/cancellation was needed for the deferred teardown timer, reasoning that `cloak_session_destroy` never frees `sesh`'s own storage itself. That's true, but irrelevant — the *caller* owns and can free that storage immediately after `cloak_session_destroy` returns, and nothing in the documented contract forbids it. A caller that heap-allocates a session, closes it, destroys it, frees its own storage, and only later runs the reactor again leaves the still-pending deferred-teardown timer pointing at freed memory. Fixed by tracking `sesh->teardown_timer_id` and having `cloak_session_destroy` cancel it, the same discipline already applied to the inactivity timer (see the constraint above this one) — this project's own established pattern, which the first-pass fix for #3 should have applied from the start instead of arguing it away.
  7. **`session_deferred_teardown_cb` itself, found during this plan's own FINAL whole-branch review — introduced by the fix that closed a non-blocking finding from the SAME review's own first pass, without a full re-review of that specific fix.** After #6 landed, a follow-up (still within the same review round) reordered `session_deferred_teardown_cb` to fire `on_broken` *before* the stream sweep and connection teardown (rather than after), specifically so a consumer's `on_broken` handler could safely call `cloak_session_release_stream` on a still-ACTIVE stream without racing the automatic sweep. That follow-up was verified thoroughly (three full Docker rebuilds, 10 consecutive direct ASan runs) but *not* sent through another independent review round, on the reasoning that the finding it closed was explicitly framed as "non-blocking, the plan author's call." The final whole-branch review caught what that verification missed: `cloak_session_broken_cb` is *also* documented as safe to call `cloak_session_destroy` from — including freeing `sesh`'s own heap storage before `on_broken` returns — and the reordered function still had two statements *after* the `on_broken` call (`session_free_all_active_streams(sesh)` and `cloak_switchboard_close_all(&sesh->sb)`) that unconditionally touched `sesh` again. A consumer following the documented pattern exactly (`cloak_session_destroy(sesh); free(sesh);` inside `on_broken`) reproduces a heap-use-after-free deterministically. Fixed by splitting the single deferred callback into two chained 0ms timers: the first fires `on_broken` and, immediately before doing so, schedules the second (which performs the actual stream sweep and connection teardown) as a *new*, separately-tracked `sesh->teardown_timer_id` — so if `on_broken` destroys `sesh`, `cloak_session_destroy`'s existing timer-cancellation (already established for #6) cancels this second timer too, synchronously, before `sesh` is ever freed; if `on_broken` does not destroy `sesh`, the second timer simply fires normally on the reactor's next tick. The first callback, after scheduling the second timer and calling `on_broken`, does nothing else — by construction, nothing runs after `on_broken` in that function that could touch `sesh`. See `session_deferred_teardown_cb`'s own comment and `test_on_broken_destroying_and_freeing_heap_session_is_safe`'s regression test. **The lesson this specific instance adds, beyond the general pattern below: a fix framed as "small enough to skip a review round" is not evidence it's safe — it's evidence nobody re-derived the safety argument for the new code path the fix introduced. This module's history says: it never is.**
  8. **(Not a use-after-free, but the same root cause — memory lifecycle claims that don't match what the code actually does — found by the same final whole-branch review.)** `cloak_session_destroy`, `cloak_session_close`, and `cloak_session_broken_cb`'s doc comments each claimed teardown reclaims "every remaining stream" / "every stream you didn't release yourself." False: every teardown sweep goes through `cloak_strmtab_for_each_active`, which structurally cannot see a stream that was already retired (tombstoned) by ANY means — the peer closing it, a protocol violation, or a prior `cloak_session_close_stream` call, not just the consumer's own `cloak_session_release_stream`. A retired-but-unreleased stream is unreachable from the session at all (its `strmtab` entry's value is cleared to NULL on tombstoning) and leaks unconditionally, confirmed by LeakSanitizer in the most ordinary possible scenario (a stream opened, written to, and normally closed on either side, with no consumer code anywhere calling `cloak_session_release_stream`). Fixed by correcting all three doc comments to state the real, narrower guarantee (only streams still ACTIVE at teardown time are reclaimed automatically) rather than fixing the underlying leak — a genuine architectural choice (should retired streams become session-reclaimable via some other tracking structure?) explicitly left for whoever builds the next module on top of this one to decide with real usage patterns in hand, not guessed at here. A related, separately-flagged issue in the same review (`cloak_session_close` can discard data still queued in a connection's `send_q`, including its own closing-session frame, when the deferred teardown runs before that queue drains) was handled the same way: documented as a known, deliberate limitation rather than solved, since Go's equivalent avoids it only because its blocking-write model has no non-blocking analogue here to trivially borrow.

  The pattern to watch for when reviewing or extending this module: any function that both (a) might be called from within a callback chain rooted in one specific `cloak_conn_t`'s or `cloak_stream_t`'s own dispatch, AND (b) frees memory that object (or something the caller of that callback still references) points to, needs either the retire/release split, the defer-to-next-tick treatment (deferring the FULL set of things that free memory, not just the ones already known to be reentrant — #3/#4 is the cautionary tale here), or a reordering that avoids touching the pointer after the callback — whichever fits the specific ownership shape. Don't assume an eighth instance of this can't happen in a future module built on top of this one; check for it explicitly, and don't trust a claim like "safe to call X from within callback Y" without tracing every statement that runs after Y returns in every caller of Y, including callers reachable only through a *different* object's callback (#4's stream-write path was missed initially precisely because the review that found #1-#3 was reasoning about connection/session callbacks, not stream write calls) — and, per #7, don't skip a real review round for a fix just because the finding it closes was itself labeled non-blocking; the fix's OWN new code path still needs the same scrutiny as everything else in this file.

---

### Task 1: `cloak_strmtab_t` — stream ID table with tombstoning

**Files:**
- Create: `libcloak-mux/include/cloak/strmtab.h`
- Create: `libcloak-mux/src/strmtab.c`
- Create: `libcloak-mux/tests/test_strmtab.c`
- Modify: `libcloak-mux/CMakeLists.txt` (add `src/strmtab.c` to the `cloak-mux` library's sources)
- Modify: `libcloak-mux/tests/CMakeLists.txt` (register `test_strmtab`)

**Interfaces:**
- Produces (used by Task 4): `cloak_strmtab_t`, `cloak_strmtab_state_t` (`CLOAK_STRMTAB_ABSENT`/`CLOAK_STRMTAB_ACTIVE`/`CLOAK_STRMTAB_TOMBSTONE`), `cloak_strmtab_init`, `cloak_strmtab_destroy`, `cloak_strmtab_lookup`, `cloak_strmtab_insert_active`, `cloak_strmtab_tombstone`, `cloak_strmtab_for_each_active` — exact signatures below.

This is a `uint32_t stream_id -> void* stream_pointer` open-addressing hash table (linear probing, power-of-two capacity, grows at a 0.7 load factor) with **three** states per key, not two: a key can be `ABSENT` (never seen), `ACTIVE` (a live pointer), or `TOMBSTONE` (was active, has since been closed — remembered forever, not deleted). This mirrors Go's `Session.streams map[uint32]*Stream`, where a closed stream's entry is set to `nil` rather than deleted (`session.go`'s `closeStream`: *"We set it as nil to signify that the stream id had existed before... it will not be able to tell if the frame it received was from a new stream or a dying stream whose frame arrived late"*).

- [ ] **Step 1: Write the failing test**

Create `libcloak-mux/tests/test_strmtab.c`:

```c
#include "cloak/strmtab.h"

#include <stdlib.h>
#include <string.h>

#include "test_framework.h"

static void test_absent_key_reports_absent(void) {
    cloak_strmtab_t t;
    ASSERT_EQ_INT(cloak_strmtab_init(&t, 4), 0);

    cloak_strmtab_state_t state;
    void *value;
    ASSERT_EQ_INT(cloak_strmtab_lookup(&t, 42, &state, &value), 0);

    cloak_strmtab_destroy(&t);
}

static void test_insert_lookup_tombstone_reinsert(void) {
    cloak_strmtab_t t;
    ASSERT_EQ_INT(cloak_strmtab_init(&t, 4), 0);

    int dummy1 = 111;
    ASSERT_EQ_INT(cloak_strmtab_insert_active(&t, 42, &dummy1), 0);

    cloak_strmtab_state_t state;
    void *value;
    ASSERT_EQ_INT(cloak_strmtab_lookup(&t, 42, &state, &value), 1);
    ASSERT_EQ_INT(state, CLOAK_STRMTAB_ACTIVE);
    ASSERT_TRUE(value == &dummy1);

    /* Duplicate insert of a still-active key must fail. */
    ASSERT_EQ_INT(cloak_strmtab_insert_active(&t, 42, &dummy1), -1);

    /* Tombstone it -- lookup must report TOMBSTONE, not ABSENT. This is
     * the distinction Go's nil-but-present map entry exists to capture: a
     * late frame for id 42 must be recognized as "known dead", not
     * mistaken for a brand new stream. */
    ASSERT_EQ_INT(cloak_strmtab_tombstone(&t, 42), 0);
    ASSERT_EQ_INT(cloak_strmtab_lookup(&t, 42, &state, &value), 1);
    ASSERT_EQ_INT(state, CLOAK_STRMTAB_TOMBSTONE);

    /* Tombstoning an already-tombstoned (or never-active) key fails. */
    ASSERT_EQ_INT(cloak_strmtab_tombstone(&t, 42), -1);
    ASSERT_EQ_INT(cloak_strmtab_tombstone(&t, 999), -1);

    /* Reinserting the SAME key over its own tombstone must succeed (no
     * information is lost -- it's the same key). */
    int dummy2 = 222;
    ASSERT_EQ_INT(cloak_strmtab_insert_active(&t, 42, &dummy2), 0);
    ASSERT_EQ_INT(cloak_strmtab_lookup(&t, 42, &state, &value), 1);
    ASSERT_EQ_INT(state, CLOAK_STRMTAB_ACTIVE);
    ASSERT_TRUE(value == &dummy2);

    cloak_strmtab_destroy(&t);
}

typedef struct {
    uint32_t keys[16];
    void *values[16];
    size_t count;
} iter_capture_t;

static void capture_iter_cb(uint32_t key, void *value, void *userdata) {
    iter_capture_t *cap = (iter_capture_t *)userdata;
    ASSERT_TRUE(cap->count < 16);
    cap->keys[cap->count] = key;
    cap->values[cap->count] = value;
    cap->count++;
}

static void test_for_each_active_visits_only_active(void) {
    cloak_strmtab_t t;
    ASSERT_EQ_INT(cloak_strmtab_init(&t, 4), 0);

    int a = 1, b = 2, c = 3;
    ASSERT_EQ_INT(cloak_strmtab_insert_active(&t, 1, &a), 0);
    ASSERT_EQ_INT(cloak_strmtab_insert_active(&t, 2, &b), 0);
    ASSERT_EQ_INT(cloak_strmtab_insert_active(&t, 3, &c), 0);
    ASSERT_EQ_INT(cloak_strmtab_tombstone(&t, 2), 0);

    iter_capture_t cap;
    cap.count = 0;
    cloak_strmtab_for_each_active(&t, capture_iter_cb, &cap);

    ASSERT_EQ_INT(cap.count, 2);
    int saw_1 = 0, saw_3 = 0;
    for (size_t i = 0; i < cap.count; i++) {
        if (cap.keys[i] == 1) { ASSERT_TRUE(cap.values[i] == &a); saw_1 = 1; }
        if (cap.keys[i] == 3) { ASSERT_TRUE(cap.values[i] == &c); saw_3 = 1; }
        ASSERT_TRUE(cap.keys[i] != 2); /* tombstoned -- must not be visited */
    }
    ASSERT_TRUE(saw_1 && saw_3);

    cloak_strmtab_destroy(&t);
}

/* Regression test for a real bug caught during this table's design
 * verification: an earlier version of insert_active reused the FIRST
 * tombstone slot seen along the probe chain for ANY new key, which
 * silently destroyed the overwritten key's tombstone. A late frame for
 * that now-clobbered id would then be misread as ABSENT (a brand new
 * stream) instead of TOMBSTONE (drop silently) -- exactly the bug
 * tombstoning exists to prevent. This test inserts and tombstones 5000
 * sequential ids (a third of them, interspersed), verifying after EVERY
 * single insertion that every previously-tombstoned id is still
 * correctly reported as TOMBSTONE and every still-active id still maps
 * to its correct pointer -- including across every table growth the 5000
 * insertions trigger. */
static void test_5000_key_growth_with_interspersed_tombstones(void) {
    cloak_strmtab_t t;
    ASSERT_EQ_INT(cloak_strmtab_init(&t, 4), 0);

    enum { N = 5000 };
    void **ptrs = (void **)malloc(N * sizeof(void *));
    int *alive = (int *)calloc(N, sizeof(int));
    ASSERT_TRUE(ptrs != NULL && alive != NULL);

    for (int i = 0; i < N; i++) {
        ptrs[i] = malloc(1);
        ASSERT_EQ_INT(cloak_strmtab_insert_active(&t, (uint32_t)i, ptrs[i]), 0);
        alive[i] = 1;
        if (i % 3 == 0) {
            ASSERT_EQ_INT(cloak_strmtab_tombstone(&t, (uint32_t)i), 0);
            alive[i] = 0;
        }
        for (int j = 0; j <= i; j++) {
            cloak_strmtab_state_t state;
            void *value;
            ASSERT_EQ_INT(cloak_strmtab_lookup(&t, (uint32_t)j, &state, &value), 1);
            if (alive[j]) {
                ASSERT_EQ_INT(state, CLOAK_STRMTAB_ACTIVE);
                ASSERT_TRUE(value == ptrs[j]);
            } else {
                ASSERT_EQ_INT(state, CLOAK_STRMTAB_TOMBSTONE);
            }
        }
    }

    cloak_strmtab_state_t state;
    void *value;
    ASSERT_EQ_INT(cloak_strmtab_lookup(&t, (uint32_t)(N + 1000), &state, &value), 0);

    for (int i = 0; i < N; i++) free(ptrs[i]);
    free(ptrs);
    free(alive);
    cloak_strmtab_destroy(&t);
}

static void test_destroy_after_failed_init_is_safe(void) {
    cloak_strmtab_t t;
    /* initial_cap_hint == 0 is rejected (see Step 3) -- destroy on the
     * resulting zeroed struct must not crash. */
    ASSERT_EQ_INT(cloak_strmtab_init(&t, 0), -1);
    cloak_strmtab_destroy(&t);
}

TEST_MAIN_BEGIN()
    test_absent_key_reports_absent();
    test_insert_lookup_tombstone_reinsert();
    test_for_each_active_visits_only_active();
    test_5000_key_growth_with_interspersed_tombstones();
    test_destroy_after_failed_init_is_safe();
TEST_MAIN_END()
```

- [ ] **Step 2: Run test to verify it fails**

Run (from the worktree root):
```bash
docker build -q -f Dockerfile.dev -t cloak-c-dev .
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "cmake -S . -B build 2>&1 | tail -5"
```
Expected: CMake configure fails or the build fails, because `cloak/strmtab.h` doesn't exist yet and `test_strmtab` isn't registered.

- [ ] **Step 3: Write the header**

Create `libcloak-mux/include/cloak/strmtab.h`:

```c
#ifndef CLOAK_STRMTAB_H
#define CLOAK_STRMTAB_H

#include <stddef.h>
#include <stdint.h>

/* A uint32_t stream_id -> void* table with three states per key (not the
 * usual two): CLOAK_STRMTAB_ABSENT (never seen), CLOAK_STRMTAB_ACTIVE (a
 * live pointer), or CLOAK_STRMTAB_TOMBSTONE (was active, has since been
 * closed -- remembered forever, not deleted). This mirrors Go Cloak's
 * Session.streams map, where a closed stream's entry is set to nil rather
 * than deleted, specifically so a late-arriving frame for a since-closed
 * stream is recognized as "known dead, drop silently" instead of being
 * mistaken for a brand new stream. Open addressing, linear probing,
 * power-of-two capacity, grows (rehashes) at a 0.7 load factor. Not
 * thread-safe (matches this whole project's single-threaded-reactor
 * design -- see the master spec). */
typedef enum {
    CLOAK_STRMTAB_ABSENT = 0,
    CLOAK_STRMTAB_ACTIVE = 1,
    CLOAK_STRMTAB_TOMBSTONE = 2
} cloak_strmtab_state_t;

typedef struct {
    uint32_t key;
    cloak_strmtab_state_t state;
    void *value; /* only meaningful when state == CLOAK_STRMTAB_ACTIVE */
} cloak_strmtab_slot_t;

typedef struct {
    cloak_strmtab_slot_t *slots;
    size_t cap;   /* always a power of two */
    size_t count; /* ACTIVE + TOMBSTONE entries -- both occupy a probe slot permanently */
} cloak_strmtab_t;

/* Allocates a backing array sized to the next power of two >=
 * initial_cap_hint (minimum 8). Returns 0 on success, -1 on allocation
 * failure or initial_cap_hint == 0. */
int cloak_strmtab_init(cloak_strmtab_t *t, size_t initial_cap_hint);

void cloak_strmtab_destroy(cloak_strmtab_t *t);

/* Returns 1 and sets out_state/out_value if key has an entry (ACTIVE or
 * TOMBSTONE); returns 0 (out_state/out_value untouched) if key was never
 * seen (ABSENT). Either output pointer may be NULL if not needed. */
int cloak_strmtab_lookup(const cloak_strmtab_t *t, uint32_t key,
                          cloak_strmtab_state_t *out_state, void **out_value);

/* Inserts key as ACTIVE with value. Fails (-1) if key is already ACTIVE,
 * or on allocation failure during a triggered grow. Succeeds (0) for a
 * brand new key, or for a key that's currently TOMBSTONE (reactivating it
 * in place -- safe, since it's the same key, no information is lost).
 *
 * Deliberately never reuses a DIFFERENT key's tombstone slot for a new
 * key -- see this file's own strmtab.c comment on cloak_strmtab_insert_active
 * for why that specific optimization is unsafe here. */
int cloak_strmtab_insert_active(cloak_strmtab_t *t, uint32_t key, void *value);

/* Marks key's entry as TOMBSTONE (must currently be ACTIVE). Returns 0 on
 * success, -1 if key is not currently ACTIVE (absent or already a
 * tombstone). Never grows/reallocates -- safe to call from within a
 * cloak_strmtab_for_each_active callback. */
int cloak_strmtab_tombstone(cloak_strmtab_t *t, uint32_t key);

typedef void (*cloak_strmtab_iter_cb)(uint32_t key, void *value, void *userdata);

/* Calls cb once for every currently-ACTIVE entry (TOMBSTONE and ABSENT
 * slots are skipped). It is safe for cb to call cloak_strmtab_tombstone
 * on the key it was just given (tombstoning never grows/reallocates the
 * table), but not to call cloak_strmtab_insert_active (which can grow the
 * table mid-iteration). */
void cloak_strmtab_for_each_active(const cloak_strmtab_t *t, cloak_strmtab_iter_cb cb, void *userdata);

#endif
```

- [ ] **Step 4: Write the implementation**

Create `libcloak-mux/src/strmtab.c`:

```c
#include "cloak/strmtab.h"

#include <stdlib.h>
#include <string.h>

static uint32_t hash_u32(uint32_t x) {
    /* murmur3 finalizer -- fast, good enough avalanche for a probe-order
     * hash; no adversarial-input concerns here since stream_id space is
     * either locally monotonic (OpenStream) or bounded by the remote
     * peer's own monotonic counter, not attacker-chosen against this
     * specific hash. */
    x ^= x >> 16;
    x *= 0x85ebca6bu;
    x ^= x >> 13;
    x *= 0xc2b2ae35u;
    x ^= x >> 16;
    return x;
}

static size_t next_pow2(size_t n) {
    size_t p = 8;
    while (p < n) p *= 2;
    return p;
}

int cloak_strmtab_init(cloak_strmtab_t *t, size_t initial_cap_hint) {
    memset(t, 0, sizeof(*t));
    if (initial_cap_hint == 0) {
        return -1;
    }
    size_t cap = next_pow2(initial_cap_hint);
    t->slots = (cloak_strmtab_slot_t *)calloc(cap, sizeof(cloak_strmtab_slot_t));
    if (t->slots == NULL) {
        return -1;
    }
    t->cap = cap;
    t->count = 0;
    return 0;
}

void cloak_strmtab_destroy(cloak_strmtab_t *t) {
    free(t->slots);
    memset(t, 0, sizeof(*t));
}

int cloak_strmtab_lookup(const cloak_strmtab_t *t, uint32_t key,
                          cloak_strmtab_state_t *out_state, void **out_value) {
    size_t mask = t->cap - 1;
    size_t i = hash_u32(key) & mask;
    for (size_t probes = 0; probes < t->cap; probes++) {
        const cloak_strmtab_slot_t *s = &t->slots[i];
        if (s->state == CLOAK_STRMTAB_ABSENT) {
            return 0;
        }
        if (s->key == key) {
            if (out_state) *out_state = s->state;
            if (out_value) *out_value = s->value;
            return 1;
        }
        i = (i + 1) & mask;
    }
    return 0;
}

static int strmtab_grow(cloak_strmtab_t *t) {
    size_t old_cap = t->cap;
    cloak_strmtab_slot_t *old_slots = t->slots;
    size_t new_cap = old_cap * 2;
    cloak_strmtab_slot_t *new_slots = (cloak_strmtab_slot_t *)calloc(new_cap, sizeof(cloak_strmtab_slot_t));
    if (new_slots == NULL) {
        return -1;
    }
    t->slots = new_slots;
    t->cap = new_cap;
    t->count = 0;
    size_t mask = new_cap - 1;
    for (size_t i = 0; i < old_cap; i++) {
        if (old_slots[i].state == CLOAK_STRMTAB_ABSENT) {
            continue;
        }
        /* Both ACTIVE and TOMBSTONE entries must survive a grow: a
         * tombstone's entire purpose is to be remembered for the whole
         * session's lifetime (matching Go's sesh.streams[id] = nil,
         * which is never deleted, only ever overwritten by session
         * close) so a late frame for a since-closed stream is recognized
         * as "known dead, drop silently" rather than mistaken for a
         * brand new stream. Dropping tombstones on grow would reopen
         * exactly the bug tombstoning exists to prevent, just gated on
         * when a resize happens to occur. */
        size_t j = hash_u32(old_slots[i].key) & mask;
        while (t->slots[j].state != CLOAK_STRMTAB_ABSENT) {
            j = (j + 1) & mask;
        }
        t->slots[j] = old_slots[i];
        t->count++;
    }
    free(old_slots);
    return 0;
}

/* Deliberately does NOT reuse a *different* key's tombstone slot: a
 * tombstone must remain permanently findable (see strmtab_grow's comment
 * above) for the life of the table, so a new, unrelated key is only ever
 * placed in a genuinely ABSENT slot. The one safe exception is
 * reinserting the SAME key that was tombstoned in this exact slot -- no
 * information is lost, since it's the same key. An earlier version of
 * this function reused the first tombstone seen along the probe chain
 * for ANY new key, which silently destroyed the overwritten key's
 * tombstone -- a late frame for that now-clobbered id would then be
 * misread as ABSENT (a brand new stream) instead of TOMBSTONE (drop
 * silently), exactly the bug tombstoning exists to prevent. Caught by
 * this module's own 5000-key growth test during design verification (a
 * lookup for a previously-tombstoned id started returning "not found"
 * once enough further insertions had cycled through its slot). */
int cloak_strmtab_insert_active(cloak_strmtab_t *t, uint32_t key, void *value) {
    if (t->count * 10 >= t->cap * 7) { /* load factor 0.7 */
        if (strmtab_grow(t) != 0) {
            return -1;
        }
    }
    size_t mask = t->cap - 1;
    size_t i = hash_u32(key) & mask;
    for (size_t probes = 0; probes < t->cap; probes++) {
        cloak_strmtab_slot_t *s = &t->slots[i];
        if (s->state == CLOAK_STRMTAB_ABSENT) {
            s->key = key;
            s->state = CLOAK_STRMTAB_ACTIVE;
            s->value = value;
            t->count++;
            return 0;
        }
        if (s->key == key) {
            if (s->state == CLOAK_STRMTAB_ACTIVE) {
                return -1;
            }
            /* s->state == CLOAK_STRMTAB_TOMBSTONE for this exact key. */
            s->state = CLOAK_STRMTAB_ACTIVE;
            s->value = value;
            return 0; /* slot was already counted as occupied */
        }
        i = (i + 1) & mask;
    }
    return -1; /* table full -- shouldn't happen given load-factor growth */
}

int cloak_strmtab_tombstone(cloak_strmtab_t *t, uint32_t key) {
    size_t mask = t->cap - 1;
    size_t i = hash_u32(key) & mask;
    for (size_t probes = 0; probes < t->cap; probes++) {
        cloak_strmtab_slot_t *s = &t->slots[i];
        if (s->state == CLOAK_STRMTAB_ABSENT) {
            return -1;
        }
        if (s->state == CLOAK_STRMTAB_ACTIVE && s->key == key) {
            s->state = CLOAK_STRMTAB_TOMBSTONE;
            s->value = NULL;
            return 0;
        }
        i = (i + 1) & mask;
    }
    return -1;
}

void cloak_strmtab_for_each_active(const cloak_strmtab_t *t, cloak_strmtab_iter_cb cb, void *userdata) {
    for (size_t i = 0; i < t->cap; i++) {
        if (t->slots[i].state == CLOAK_STRMTAB_ACTIVE) {
            cb(t->slots[i].key, t->slots[i].value, userdata);
        }
    }
}
```

- [ ] **Step 5: Wire into CMake**

In `libcloak-mux/CMakeLists.txt`, find the `add_library(cloak-mux STATIC ...)` block and add `src/strmtab.c` to its source list (alongside the existing `src/frame.c`, `src/bytequeue.c`, `src/stream.c`).

In `libcloak-mux/tests/CMakeLists.txt`, append:
```cmake
add_executable(test_strmtab test_strmtab.c)
target_include_directories(test_strmtab PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_strmtab PRIVATE cloak-mux)
add_test(NAME test_strmtab COMMAND test_strmtab)
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "rm -rf build && cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure"
```
Expected: all tests pass, including the new `test_strmtab`, with zero compiler warnings.

Also run under ASan/UBSan:
```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "cmake -S . -B build-asan -DCMAKE_C_FLAGS='-fsanitize=address,undefined -g' -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined' && cmake --build build-asan && ctest --test-dir build-asan --output-on-failure"
```
Expected: clean, no leaks, no UB.

- [ ] **Step 7: Commit**

```bash
git add libcloak-mux/include/cloak/strmtab.h libcloak-mux/src/strmtab.c libcloak-mux/tests/test_strmtab.c libcloak-mux/CMakeLists.txt libcloak-mux/tests/CMakeLists.txt
git commit -m "Add strmtab: stream ID table with permanent tombstoning"
```

---

### Task 2: `cloak_bytequeue_peek` + `cloak_conn_t` — non-blocking framed connection

**Files:**
- Modify: `libcloak-mux/include/cloak/bytequeue.h` (add `cloak_bytequeue_peek`)
- Modify: `libcloak-mux/src/bytequeue.c` (add `cloak_bytequeue_peek`)
- Create: `libcloak-mux/include/cloak/conn.h`
- Create: `libcloak-mux/src/conn.c`
- Create: `libcloak-mux/tests/test_conn.c`
- Modify: `libcloak-mux/CMakeLists.txt` (add `src/conn.c`)
- Modify: `libcloak-mux/tests/CMakeLists.txt` (register `test_conn`, link `cloak-common` for the reactor)

**Interfaces:**
- Consumes: `cloak_bytequeue_t` and its existing functions (`libcloak-mux/include/cloak/bytequeue.h`); `cloak_reactor_t`, `CLOAK_REACTOR_READABLE`, `CLOAK_REACTOR_WRITABLE`, `cloak_reactor_fd_cb`, `cloak_reactor_create`, `cloak_reactor_add_fd`, `cloak_reactor_mod_fd`, `cloak_reactor_remove_fd`, `cloak_reactor_run`, `cloak_reactor_stop` (`libcloak-common/include/cloak/reactor.h`, already merged).
- Produces (used by Task 3): `cloak_conn_t`, `cloak_conn_envelope_cb`, `cloak_conn_closed_cb`, `cloak_conn_init`, `cloak_conn_destroy`, `cloak_conn_send` — exact signatures below.

**Step 1a — add the peek function first (bytequeue.h/.c already merged, small additive change):**

- [ ] **Step 1: Write the failing test for peek**

Add to `libcloak-mux/tests/test_bytequeue.c` (append a new test function and register it in `TEST_MAIN_BEGIN()`/`TEST_MAIN_END()` alongside the existing tests):

```c
static void test_peek_does_not_consume(void) {
    cloak_bytequeue_t q;
    ASSERT_EQ_INT(cloak_bytequeue_init(&q, 16), 0);

    uint8_t in[5] = {1, 2, 3, 4, 5};
    ASSERT_EQ_INT(cloak_bytequeue_write(&q, in, 5), 5);

    uint8_t peeked[3];
    ASSERT_EQ_INT(cloak_bytequeue_peek(&q, peeked, 3), 3);
    ASSERT_MEM_EQ(peeked, in, 3);
    ASSERT_EQ_INT(cloak_bytequeue_len(&q), 5); /* unchanged -- not consumed */

    /* A subsequent read returns the SAME bytes peek already saw. */
    uint8_t out[5];
    ASSERT_EQ_INT(cloak_bytequeue_read(&q, out, 5), 5);
    ASSERT_MEM_EQ(out, in, 5);

    /* Peeking more than available returns only what's available. */
    ASSERT_EQ_INT(cloak_bytequeue_write(&q, in, 2), 2);
    uint8_t peeked2[10];
    ASSERT_EQ_INT(cloak_bytequeue_peek(&q, peeked2, 10), 2);

    /* Peek correctly wraps around the ring buffer's internal boundary,
     * same as read does. */
    cloak_bytequeue_t q2;
    ASSERT_EQ_INT(cloak_bytequeue_init(&q2, 4), 0);
    uint8_t four[4] = {10, 20, 30, 40};
    ASSERT_EQ_INT(cloak_bytequeue_write(&q2, four, 4), 4);
    uint8_t tmp[2];
    ASSERT_EQ_INT(cloak_bytequeue_read(&q2, tmp, 2), 2); /* consume 10,20 -- head now at index 2 */
    uint8_t more[2] = {50, 60};
    ASSERT_EQ_INT(cloak_bytequeue_write(&q2, more, 2), 2); /* wraps: 50,60 land at indices 0,1 */
    uint8_t wrapped_peek[4];
    ASSERT_EQ_INT(cloak_bytequeue_peek(&q2, wrapped_peek, 4), 4);
    uint8_t expected[4] = {30, 40, 50, 60};
    ASSERT_MEM_EQ(wrapped_peek, expected, 4);
    ASSERT_EQ_INT(cloak_bytequeue_len(&q2), 4); /* still unconsumed */

    cloak_bytequeue_destroy(&q);
    cloak_bytequeue_destroy(&q2);
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "cmake -S . -B build 2>&1 | tail -20"
```
Expected: compile failure, `cloak_bytequeue_peek` is not declared.

- [ ] **Step 3: Add the declaration**

In `libcloak-mux/include/cloak/bytequeue.h`, add immediately after the existing `cloak_bytequeue_read` declaration:

```c
/* Copies up to len bytes starting at the current head into out, WITHOUT
 * consuming them -- a subsequent cloak_bytequeue_read (or another peek)
 * returns the same bytes. Returns bytes copied (may be fewer than len if
 * that's all that's currently available). */
size_t cloak_bytequeue_peek(const cloak_bytequeue_t *q, uint8_t *out, size_t len);
```

- [ ] **Step 4: Add the implementation**

In `libcloak-mux/src/bytequeue.c`, add immediately before the existing `cloak_bytequeue_close` function:

```c
size_t cloak_bytequeue_peek(const cloak_bytequeue_t *q, uint8_t *out, size_t len) {
    size_t n = len < q->len ? len : q->len;
    if (n == 0) {
        return 0;
    }
    size_t first_chunk = q->cap - q->head;
    if (first_chunk >= n) {
        memcpy(out, q->data + q->head, n);
    } else {
        memcpy(out, q->data + q->head, first_chunk);
        memcpy(out + first_chunk, q->data, n - first_chunk);
    }
    return n;
}
```

- [ ] **Step 5: Run test to verify it passes, then commit**

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "rm -rf build && cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure -R test_bytequeue"
```
Expected: PASS.

```bash
git add libcloak-mux/include/cloak/bytequeue.h libcloak-mux/src/bytequeue.c libcloak-mux/tests/test_bytequeue.c
git commit -m "Add cloak_bytequeue_peek: non-consuming read"
```

**Step 1b — `cloak_conn_t`:**

The core design: `cloak_conn_t` wraps exactly one non-blocking fd registered with the reactor. Every frame handed to `cloak_conn_send` is prefixed with its own 2-byte big-endian length before being queued/written, and every complete `[len][frame bytes]` envelope read back off the wire is extracted and handed to a callback with the prefix already stripped (see this task's own file header comment for the full framing rationale, restated from this plan's Global Constraints).

Two byte queues, sized very differently on purpose:
- `recv_acc` (capacity `2 * max_envelope_len`): accumulates raw incoming bytes. Every `read()` is bounded by `cloak_bytequeue_free_space(&c->recv_acc)`, and the extraction loop runs immediately after every successful write into it -- together these guarantee `recv_acc` can never actually fill up (see this plan's Global Constraints for the short proof), so `cloak_conn_t` never needs to deregister `EPOLLIN` for backpressure reasons; it is registered once at `cloak_conn_init` and never turned off.
- `send_q` (capacity `send_queue_cap`, a construction parameter -- a generous fixed size, not meant to be tightly tuned): buffers outgoing envelopes not yet fully written to the kernel. Unlike `recv_acc`, this genuinely can fill up under real backpressure (a slow/stalled peer) -- and per this plan's Global Constraints, hitting that limit is treated exactly like a connection failure (not a "try again" signal), matching Go's own fault model where a stuck connection just blocks forever, which is effectively fatal to that connection's usefulness anyway.

- [ ] **Step 1: Write the failing test**

Create `libcloak-mux/tests/test_conn.c`:

```c
#include "cloak/conn.h"

#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cloak/reactor.h"
#include "test_framework.h"

#define MAX_FRAME_LEN 300u
#define SEND_QUEUE_CAP 4096u

typedef struct {
    uint8_t received[16][512];
    size_t received_len[16];
    int received_count;
    int closed_count;
} conn_harness_t;

static void on_envelope(cloak_conn_t *c, const uint8_t *bytes, size_t len, void *userdata) {
    (void)c;
    conn_harness_t *h = (conn_harness_t *)userdata;
    ASSERT_TRUE(h->received_count < 16);
    memcpy(h->received[h->received_count], bytes, len);
    h->received_len[h->received_count] = len;
    h->received_count++;
}

static void on_closed(cloak_conn_t *c, void *userdata) {
    (void)c;
    conn_harness_t *h = (conn_harness_t *)userdata;
    h->closed_count++;
}

static int make_nonblocking_socketpair(int fds[2]) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return -1;
    if (fcntl(fds[0], F_SETFL, O_NONBLOCK) != 0) return -1;
    if (fcntl(fds[1], F_SETFL, O_NONBLOCK) != 0) return -1;
    return 0;
}

static void stop_reactor_timer_cb(cloak_reactor_t *r, void *userdata) {
    (void)userdata;
    cloak_reactor_stop(r);
}

/* Runs the reactor's dispatch loop just long enough to process whatever
 * is currently ready, without blocking indefinitely -- schedules a short
 * timer that stops the reactor, so cloak_reactor_run returns promptly
 * once the current batch of ready fds has been dispatched. */
static void pump_reactor_once(cloak_reactor_t *r) {
    cloak_reactor_add_timer(r, 20, stop_reactor_timer_cb, r);
    cloak_reactor_run(r);
}

static void test_single_envelope_round_trip(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    conn_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(cloak_conn_init(&c, fds[0], r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                   on_envelope, &h, on_closed, &h), 0);

    uint8_t payload[10];
    for (int i = 0; i < 10; i++) payload[i] = (uint8_t)('A' + i);
    ASSERT_EQ_INT(cloak_conn_send(&c, payload, sizeof(payload)), 0);

    /* Read what conn_send just wrote directly off the raw peer fd,
     * confirming the on-wire envelope is exactly [00 0A][payload]. */
    uint8_t wire[64];
    ssize_t n = read(fds[1], wire, sizeof(wire));
    ASSERT_EQ_INT(n, 12);
    ASSERT_EQ_INT(wire[0], 0);
    ASSERT_EQ_INT(wire[1], 10);
    ASSERT_MEM_EQ(wire + 2, payload, 10);

    /* Now the reverse direction: peer writes a raw envelope, conn must
     * parse and dispatch it. */
    uint8_t reply_wire[2 + 5] = {0, 5, 'h', 'e', 'l', 'l', 'o'};
    ASSERT_EQ_INT(write(fds[1], reply_wire, sizeof(reply_wire)), (ssize_t)sizeof(reply_wire));
    pump_reactor_once(r);

    ASSERT_EQ_INT(h.received_count, 1);
    ASSERT_EQ_INT(h.received_len[0], 5);
    ASSERT_MEM_EQ(h.received[0], "hello", 5);

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

static void test_multiple_envelopes_in_one_read(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    conn_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(cloak_conn_init(&c, fds[0], r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                   on_envelope, &h, on_closed, &h), 0);

    uint8_t wire[] = {
        0, 3, 'f', 'o', 'o',
        0, 3, 'b', 'a', 'r',
        0, 4, 'q', 'u', 'u', 'x',
    };
    ASSERT_EQ_INT(write(fds[1], wire, sizeof(wire)), (ssize_t)sizeof(wire));
    pump_reactor_once(r);

    ASSERT_EQ_INT(h.received_count, 3);
    ASSERT_MEM_EQ(h.received[0], "foo", 3);
    ASSERT_MEM_EQ(h.received[1], "bar", 3);
    ASSERT_MEM_EQ(h.received[2], "quux", 4);

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

static void test_envelope_split_across_many_small_writes(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    conn_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(cloak_conn_init(&c, fds[0], r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                   on_envelope, &h, on_closed, &h), 0);

    uint8_t payload[200];
    for (int i = 0; i < 200; i++) payload[i] = (uint8_t)(i & 0xff);
    uint8_t wire[2 + 200];
    wire[0] = 0;
    wire[1] = 200;
    memcpy(wire + 2, payload, 200);

    size_t off = 0;
    while (off < sizeof(wire)) {
        size_t chunk = 3;
        if (chunk > sizeof(wire) - off) chunk = sizeof(wire) - off;
        ASSERT_EQ_INT(write(fds[1], wire + off, chunk), (ssize_t)chunk);
        off += chunk;
        pump_reactor_once(r);
    }

    ASSERT_EQ_INT(h.received_count, 1);
    ASSERT_EQ_INT(h.received_len[0], 200);
    ASSERT_MEM_EQ(h.received[0], payload, 200);

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

static void test_send_drains_across_epollout_when_kernel_buffer_is_small(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    /* Force a tiny kernel socket buffer on the sending side so a large
     * payload cannot be written in one non-blocking write() call,
     * exercising the EPOLLOUT-driven drain path. */
    int small_buf = 256;
    ASSERT_EQ_INT(setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &small_buf, sizeof(small_buf)), 0);

    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    conn_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(cloak_conn_init(&c, fds[0], r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                   on_envelope, &h, on_closed, &h), 0);

    uint8_t big_payload[290];
    for (int i = 0; i < 290; i++) big_payload[i] = (uint8_t)(i & 0xff);
    ASSERT_EQ_INT(cloak_conn_send(&c, big_payload, sizeof(big_payload)), 0);

    /* Drain the peer's read side in a loop, pumping the reactor between
     * reads so cloak_conn_t's EPOLLOUT-driven drain keeps making
     * progress as kernel buffer space frees up. */
    uint8_t assembled[2 + 290];
    size_t assembled_len = 0;
    for (int iter = 0; iter < 50 && assembled_len < sizeof(assembled); iter++) {
        pump_reactor_once(r);
        uint8_t tmp[128];
        ssize_t n;
        while ((n = read(fds[1], tmp, sizeof(tmp))) > 0) {
            ASSERT_TRUE(assembled_len + (size_t)n <= sizeof(assembled));
            memcpy(assembled + assembled_len, tmp, (size_t)n);
            assembled_len += (size_t)n;
        }
    }

    ASSERT_EQ_INT(assembled_len, sizeof(assembled));
    ASSERT_EQ_INT(assembled[0], 1); /* 290 >> 8 */
    ASSERT_EQ_INT(assembled[1], (uint8_t)290);
    ASSERT_MEM_EQ(assembled + 2, big_payload, 290);

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

static void test_peer_eof_reports_closed(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    conn_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(cloak_conn_init(&c, fds[0], r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                   on_envelope, &h, on_closed, &h), 0);

    close(fds[1]); /* peer hangs up */
    pump_reactor_once(r);

    ASSERT_EQ_INT(h.closed_count, 1);

    /* A send after the conn is marked broken must fail, not crash. */
    uint8_t payload[3] = {1, 2, 3};
    ASSERT_EQ_INT(cloak_conn_send(&c, payload, sizeof(payload)), -1);

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
}

static void test_oversized_frame_len_is_rejected_not_wedged(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    conn_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_conn_t c;
    ASSERT_EQ_INT(cloak_conn_init(&c, fds[0], r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                   on_envelope, &h, on_closed, &h), 0);

    /* Declares a frame_len far larger than MAX_FRAME_LEN -- a protocol
     * violation that must mark the connection broken (not silently wait
     * forever for bytes that were never going to arrive validly). */
    uint8_t wire[2] = {0xff, 0xff};
    ASSERT_EQ_INT(write(fds[1], wire, sizeof(wire)), 2);
    pump_reactor_once(r);

    ASSERT_EQ_INT(h.closed_count, 1);
    ASSERT_EQ_INT(h.received_count, 0);

    cloak_conn_destroy(&c);
    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

static void test_destroy_after_failed_init_is_safe(void) {
    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    cloak_conn_t c;
    /* max_frame_len == 0 is rejected. */
    ASSERT_EQ_INT(cloak_conn_init(&c, fds[0], r, 0, SEND_QUEUE_CAP, on_envelope, NULL, on_closed, NULL), -1);
    cloak_conn_destroy(&c);

    cloak_reactor_destroy(r);
    close(fds[0]);
    close(fds[1]);
}

TEST_MAIN_BEGIN()
    test_single_envelope_round_trip();
    test_multiple_envelopes_in_one_read();
    test_envelope_split_across_many_small_writes();
    test_send_drains_across_epollout_when_kernel_buffer_is_small();
    test_peer_eof_reports_closed();
    test_oversized_frame_len_is_rejected_not_wedged();
    test_destroy_after_failed_init_is_safe();
TEST_MAIN_END()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "cmake -S . -B build 2>&1 | tail -20"
```
Expected: compile failure, `cloak/conn.h` doesn't exist yet.

- [ ] **Step 3: Write the header**

Create `libcloak-mux/include/cloak/conn.h`:

```c
#ifndef CLOAK_CONN_H
#define CLOAK_CONN_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/bytequeue.h"
#include "cloak/reactor.h"

/* Number of bytes in the length prefix this module adds around every
 * frame on the wire -- see this project's plan/design notes on why: in
 * short, cloak_frame_deobfuscate needs to know a frame's exact byte
 * length before it can decrypt anything (its header-decryption nonce is
 * the trailing bytes of the WHOLE frame), which a raw TCP byte stream
 * does not provide on its own. Big-endian u16, so max_frame_len must fit
 * in 16 bits (see cloak_conn_init). */
#define CLOAK_CONN_LEN_PREFIX_LEN 2

typedef struct cloak_conn cloak_conn_t;

/* bytes points at CLOAK_CONN_LEN_PREFIX_LEN-stripped frame data, valid
 * only for the duration of this call (it points into conn's own reused
 * scratch buffer) -- copy or fully consume before returning. */
typedef void (*cloak_conn_envelope_cb)(cloak_conn_t *conn, const uint8_t *bytes, size_t len, void *userdata);

/* Called exactly once, the moment conn becomes unusable (peer EOF, a
 * hard read/write error, a declared frame length that violates
 * max_frame_len, or the outbound send queue's hard capacity being
 * exceeded). conn's fd is already deregistered from the reactor by the
 * time this fires, but conn's own memory is NOT yet freed -- the owner
 * must still call cloak_conn_destroy (and separately close() the fd,
 * which conn never owns) once it's done reacting. */
typedef void (*cloak_conn_closed_cb)(cloak_conn_t *conn, void *userdata);

struct cloak_conn {
    int fd;
    cloak_reactor_t *reactor;

    cloak_bytequeue_t recv_acc;
    cloak_bytequeue_t send_q;
    uint8_t *recv_scratch; /* owned, max_envelope_len bytes, reused per extracted envelope */

    size_t max_frame_len;
    size_t max_envelope_len; /* CLOAK_CONN_LEN_PREFIX_LEN + max_frame_len */

    cloak_conn_envelope_cb on_envelope;
    void *on_envelope_userdata;
    cloak_conn_closed_cb on_closed;
    void *on_closed_userdata;

    int broken;
    int want_writable; /* whether EPOLLWRITABLE is currently part of our registered interest */
};

/* max_frame_len is the largest single frame's on-wire byte length this
 * connection will ever send or accept (must be 1..65535, since the
 * length prefix is a big-endian u16); a peer declaring a larger length
 * is treated as a protocol violation (connection marked broken).
 * send_queue_cap is a generous, fixed hard cap on buffered-but-not-yet-
 * written outbound bytes; exceeding it is treated exactly like a
 * connection failure (see this project's plan-level fault-model
 * documentation -- this port intentionally does not retry a different
 * path the way it might for a pool of independent connections, because
 * a single conn's own backlog filling up means that link is stuck, same
 * as Go's blocking Write() would be).
 *
 * Registers fd with reactor for CLOAK_REACTOR_READABLE immediately (and
 * keeps it registered for the connection's whole life -- see this
 * project's plan-level notes on why recv-side backpressure is never
 * needed here). fd must already be an open, non-blocking-capable socket;
 * this function does not create or configure fd itself, matching
 * cloak_reactor_add_fd's own convention of forcing O_NONBLOCK itself
 * without the caller having to.
 *
 * Returns 0 on success, -1 on invalid parameters (max_frame_len == 0,
 * max_frame_len > 65535, or send_queue_cap == 0) or allocation/reactor
 * registration failure. */
int cloak_conn_init(cloak_conn_t *c, int fd, cloak_reactor_t *reactor,
                     size_t max_frame_len, size_t send_queue_cap,
                     cloak_conn_envelope_cb on_envelope, void *on_envelope_userdata,
                     cloak_conn_closed_cb on_closed, void *on_closed_userdata);

/* Deregisters fd from the reactor (safe even if already deregistered,
 * e.g. because on_closed already fired) and frees c's own buffers. Does
 * NOT close(fd) -- matching cloak_reactor_destroy's own documented
 * convention, the caller owns fd's lifecycle. */
void cloak_conn_destroy(cloak_conn_t *c);

/* Frames frame_bytes[0, frame_len) with its length prefix and enqueues
 * it for transmission, attempting an immediate non-blocking write.
 * Returns 0 on success (accepted -- may still be partially buffered,
 * draining asynchronously via EPOLLWRITABLE), or -1 if c is already
 * broken, frame_len + CLOAK_CONN_LEN_PREFIX_LEN exceeds max_envelope_len,
 * or the send queue's hard capacity would be exceeded (in the last two
 * cases, on_closed fires synchronously, before this call returns). Must
 * not block. */
int cloak_conn_send(cloak_conn_t *c, const uint8_t *frame_bytes, size_t frame_len);

#endif
```

- [ ] **Step 4: Write the implementation**

Create `libcloak-mux/src/conn.c`:

```c
#include "cloak/conn.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void conn_set_want_writable(cloak_conn_t *c, int want) {
    if (c->want_writable == want) {
        return;
    }
    c->want_writable = want;
    uint32_t events = CLOAK_REACTOR_READABLE | (want ? CLOAK_REACTOR_WRITABLE : 0);
    cloak_reactor_mod_fd(c->reactor, c->fd, events);
}

static void conn_mark_broken(cloak_conn_t *c) {
    if (c->broken) {
        return; /* idempotent -- already reported */
    }
    c->broken = 1;
    cloak_reactor_remove_fd(c->reactor, c->fd);
    if (c->on_closed) {
        c->on_closed(c, c->on_closed_userdata);
    }
}

/* Attempts to write everything currently buffered in send_q to the fd,
 * non-blocking, looping until either send_q is empty or the kernel
 * reports EAGAIN. Peeks a chunk (never consuming ahead of what the
 * kernel actually accepted), writes it, then discards exactly the number
 * of bytes the kernel took -- so a partial write never loses buffered
 * data, and a full write of one peeked chunk continues the loop to see
 * if more remains. */
static void conn_try_drain_send(cloak_conn_t *c) {
    uint8_t drain_buf[4096];
    for (;;) {
        size_t avail = cloak_bytequeue_len(&c->send_q);
        if (avail == 0) {
            conn_set_want_writable(c, 0);
            return;
        }
        size_t want = avail < sizeof(drain_buf) ? avail : sizeof(drain_buf);
        size_t peeked = cloak_bytequeue_peek(&c->send_q, drain_buf, want);
        /* send() with MSG_NOSIGNAL, not write() -- writing to a socket
         * whose peer has already closed raises SIGPIPE, which by default
         * terminates the whole process. A proxy server must survive an
         * individual client disconnecting; MSG_NOSIGNAL makes this an
         * ordinary EPIPE error instead (handled below, same as any other
         * write error -- conn_mark_broken). Found during this plan's own
         * design verification while constructing a peer-disconnect
         * regression test for an unrelated bug (see this plan's Global
         * Constraints) -- not a hypothetical. */
        ssize_t n = send(c->fd, drain_buf, peeked, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                conn_set_want_writable(c, 1);
                return;
            }
            conn_mark_broken(c);
            return;
        }
        cloak_bytequeue_read(&c->send_q, drain_buf, (size_t)n); /* discard exactly what the kernel took */
        if ((size_t)n < peeked) {
            /* Kernel's send buffer is now full -- stop for now, resume
             * on the next EPOLLWRITABLE. */
            conn_set_want_writable(c, 1);
            return;
        }
        /* Fully wrote this chunk -- loop to see if more remains. */
    }
}

static void conn_extract_and_dispatch(cloak_conn_t *c) {
    uint8_t prefix[CLOAK_CONN_LEN_PREFIX_LEN];
    for (;;) {
        size_t peeked = cloak_bytequeue_peek(&c->recv_acc, prefix, CLOAK_CONN_LEN_PREFIX_LEN);
        if (peeked < CLOAK_CONN_LEN_PREFIX_LEN) {
            return; /* not even the length prefix has fully arrived yet */
        }
        uint16_t frame_len = (uint16_t)(((uint16_t)prefix[0] << 8) | (uint16_t)prefix[1]);
        if ((size_t)frame_len > c->max_frame_len) {
            conn_mark_broken(c); /* protocol violation -- declared length too large for this conn */
            return;
        }
        size_t envelope_len = (size_t)CLOAK_CONN_LEN_PREFIX_LEN + frame_len;
        if (cloak_bytequeue_len(&c->recv_acc) < envelope_len) {
            return; /* full envelope hasn't arrived yet */
        }
        cloak_bytequeue_read(&c->recv_acc, c->recv_scratch, envelope_len);
        if (c->on_envelope) {
            c->on_envelope(c, c->recv_scratch + CLOAK_CONN_LEN_PREFIX_LEN, frame_len, c->on_envelope_userdata);
        }
        if (c->broken) {
            return; /* the callback may have torn c down re-entrantly */
        }
    }
}

static void conn_handle_readable(cloak_conn_t *c) {
    for (;;) {
        size_t room = cloak_bytequeue_free_space(&c->recv_acc);
        if (room == 0) {
            return; /* structurally unreachable given recv_acc's capacity invariant; defensive only */
        }
        uint8_t tmp[4096];
        size_t want = room < sizeof(tmp) ? room : sizeof(tmp);
        ssize_t n = read(c->fd, tmp, want);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            conn_mark_broken(c);
            return;
        }
        if (n == 0) {
            conn_mark_broken(c); /* peer EOF */
            return;
        }
        cloak_bytequeue_write(&c->recv_acc, tmp, (size_t)n); /* always fits: n <= room */
        conn_extract_and_dispatch(c);
        if (c->broken) {
            return;
        }
    }
}

static void conn_reactor_cb(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)fd;
    cloak_conn_t *c = (cloak_conn_t *)userdata;
    if (c->broken) {
        return;
    }
    if (events & CLOAK_REACTOR_READABLE) {
        conn_handle_readable(c);
        if (c->broken) {
            return;
        }
    }
    if (events & CLOAK_REACTOR_WRITABLE) {
        conn_try_drain_send(c);
    }
}

int cloak_conn_init(cloak_conn_t *c, int fd, cloak_reactor_t *reactor,
                     size_t max_frame_len, size_t send_queue_cap,
                     cloak_conn_envelope_cb on_envelope, void *on_envelope_userdata,
                     cloak_conn_closed_cb on_closed, void *on_closed_userdata) {
    memset(c, 0, sizeof(*c));
    if (max_frame_len == 0 || max_frame_len > 65535 || send_queue_cap == 0) {
        return -1;
    }
    c->fd = fd;
    c->reactor = reactor;
    c->max_frame_len = max_frame_len;
    c->max_envelope_len = (size_t)CLOAK_CONN_LEN_PREFIX_LEN + max_frame_len;
    c->on_envelope = on_envelope;
    c->on_envelope_userdata = on_envelope_userdata;
    c->on_closed = on_closed;
    c->on_closed_userdata = on_closed_userdata;

    if (cloak_bytequeue_init(&c->recv_acc, 2 * c->max_envelope_len) != 0) {
        return -1;
    }
    if (cloak_bytequeue_init(&c->send_q, send_queue_cap) != 0) {
        cloak_bytequeue_destroy(&c->recv_acc);
        return -1;
    }
    c->recv_scratch = (uint8_t *)malloc(c->max_envelope_len);
    if (c->recv_scratch == NULL) {
        cloak_bytequeue_destroy(&c->recv_acc);
        cloak_bytequeue_destroy(&c->send_q);
        return -1;
    }
    if (cloak_reactor_add_fd(reactor, fd, CLOAK_REACTOR_READABLE, conn_reactor_cb, c) != 0) {
        free(c->recv_scratch);
        cloak_bytequeue_destroy(&c->recv_acc);
        cloak_bytequeue_destroy(&c->send_q);
        return -1;
    }
    return 0;
}

void cloak_conn_destroy(cloak_conn_t *c) {
    if (c->reactor != NULL) {
        cloak_reactor_remove_fd(c->reactor, c->fd); /* no-op-with-error-return if already removed */
    }
    free(c->recv_scratch);
    if (c->recv_acc.data != NULL) {
        cloak_bytequeue_destroy(&c->recv_acc);
    }
    if (c->send_q.data != NULL) {
        cloak_bytequeue_destroy(&c->send_q);
    }
    memset(c, 0, sizeof(*c));
}

int cloak_conn_send(cloak_conn_t *c, const uint8_t *frame_bytes, size_t frame_len) {
    if (c->broken) {
        return -1;
    }
    /* Checked directly against max_frame_len first, before the addition
     * below -- frame_len is always this module's own bounded chunking in
     * practice (never network-derived), but a caller bug passing a
     * frame_len near SIZE_MAX would otherwise wrap CLOAK_CONN_LEN_PREFIX_LEN
     * + frame_len back into range and silently bypass the size check
     * entirely. Flagged as an open Minor by an earlier task review and
     * triaged (fixed, not deferred) during this plan's final
     * whole-branch review, since it's free and removes the reasoning
     * burden for every future caller of this function. */
    if (frame_len > c->max_frame_len) {
        conn_mark_broken(c); /* caller/config bug: frame too large for this conn */
        return -1;
    }
    size_t total = (size_t)CLOAK_CONN_LEN_PREFIX_LEN + frame_len;
    if (total > c->max_envelope_len) {
        conn_mark_broken(c); /* caller/config bug: frame too large for this conn */
        return -1;
    }
    if (cloak_bytequeue_free_space(&c->send_q) < total) {
        conn_mark_broken(c); /* send queue's hard cap exceeded -- treated as a connection failure */
        return -1;
    }
    uint8_t prefix[CLOAK_CONN_LEN_PREFIX_LEN];
    prefix[0] = (uint8_t)((frame_len >> 8) & 0xff);
    prefix[1] = (uint8_t)(frame_len & 0xff);
    cloak_bytequeue_write(&c->send_q, prefix, CLOAK_CONN_LEN_PREFIX_LEN);
    cloak_bytequeue_write(&c->send_q, frame_bytes, frame_len);
    conn_try_drain_send(c);
    /* conn_try_drain_send may have discovered a hard write failure (e.g.
     * the peer disconnected) and called conn_mark_broken during THIS
     * call -- in which case the bytes just enqueued above are sitting in
     * a send_q that's about to be destroyed, never actually delivered.
     * Reporting success (0) here would silently drop them, violating
     * this plan's Global Constraints ("never silently drop data"). Found
     * during this plan's own design verification, via a regression test
     * for an unrelated bug (a stream write surviving its own connection
     * dying mid-call -- see the Global Constraints entry on this
     * project's recurring UAF class) that happened to also exercise this
     * return-value path for the first time. */
    return c->broken ? -1 : 0;
}
```

Note on `cloak_conn_destroy`'s `c->reactor != NULL` / `c->recv_acc.data != NULL` guards: these make it safe to call on a struct left zeroed by a rejected `cloak_conn_init` (per this plan's Global Constraints memset-first rule) -- `cloak_bytequeue_destroy` itself is safe on an already-zeroed queue (its own `free(NULL)` is a no-op), but `cloak_reactor_remove_fd` with `reactor == NULL` would crash, hence the explicit guard there.

- [ ] **Step 5: Wire into CMake**

In `libcloak-mux/CMakeLists.txt`, add `src/conn.c` to the `cloak-mux` library's sources.

In `libcloak-mux/tests/CMakeLists.txt`, append:
```cmake
add_executable(test_conn test_conn.c)
target_include_directories(test_conn PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_conn PRIVATE cloak-mux)
add_test(NAME test_conn COMMAND test_conn)
```
(`cloak-mux` already publicly links `cloak-common`, which provides `cloak/reactor.h` and its implementation -- no separate link needed.)

- [ ] **Step 6: Run tests to verify they pass**

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "rm -rf build && cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure"
```

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "cmake -S . -B build-asan -DCMAKE_C_FLAGS='-fsanitize=address,undefined -g' -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined' && cmake --build build-asan && ctest --test-dir build-asan --output-on-failure"
```
Expected: all tests pass under both, zero warnings, clean under ASan/UBSan.

- [ ] **Step 7: Commit**

```bash
git add libcloak-mux/include/cloak/conn.h libcloak-mux/src/conn.c libcloak-mux/tests/test_conn.c libcloak-mux/CMakeLists.txt libcloak-mux/tests/CMakeLists.txt
git commit -m "Add conn: non-blocking length-prefixed connection framing"
```

---

### Task 3: `cloak_switchboard_t` — connection pool

**Files:**
- Create: `libcloak-mux/include/cloak/switchboard.h`
- Create: `libcloak-mux/src/switchboard.c`
- Create: `libcloak-mux/tests/test_switchboard.c`
- Modify: `libcloak-mux/CMakeLists.txt` (add `src/switchboard.c`)
- Modify: `libcloak-mux/tests/CMakeLists.txt` (register `test_switchboard`)

**Interfaces:**
- Consumes: `cloak_conn_t`, `cloak_conn_envelope_cb`, `cloak_conn_closed_cb`, `cloak_conn_init`, `cloak_conn_destroy`, `cloak_conn_send` (Task 2); `cloak_reactor_t` (already merged).
- Produces (used by Task 4): `cloak_switchboard_t`, `cloak_switchboard_envelope_cb`, `cloak_switchboard_broken_cb`, `cloak_switchboard_init`, `cloak_switchboard_destroy`, `cloak_switchboard_add_conn`, `cloak_switchboard_send`, `cloak_switchboard_close_all`, `cloak_switchboard_conn_count` — exact signatures below.

Holds a growable array of owned `cloak_conn_t*` (the same realloc-doubling growth style already used and reviewed in this library's `cloak_stream_t` reorder heap). `cloak_switchboard_send` picks one uniformly at random (Go's `uniformSpread` strategy) and calls `cloak_conn_send` on it -- no retry among connections on failure (see this plan's Global Constraints: any one connection's failure is fatal to the whole switchboard, matching Go exactly). The PRNG is a single `xorshift32` state seeded once from `cloak_random_bytes` at construction -- no per-call CSPRNG syscall needed (this project already established, in the already-merged `cloak_stream_t`'s closing-frame padding, that `cloak_random_bytes` is available via `libcloak-common/include/cloak/common.h`; `xorshift32` here is deliberately NOT cryptographic -- connection selection for load distribution has no security requirement, only a seed to avoid a fixed, predictable pick order).

- [ ] **Step 1: Write the failing test**

Create `libcloak-mux/tests/test_switchboard.c`:

```c
#include "cloak/switchboard.h"

#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "test_framework.h"

#define MAX_FRAME_LEN 300u
#define SEND_QUEUE_CAP 4096u

typedef struct {
    uint8_t received[16][512];
    size_t received_len[16];
    int received_count;
    int broken_count;
} sb_harness_t;

static void on_envelope(cloak_switchboard_t *sb, const uint8_t *bytes, size_t len, void *userdata) {
    (void)sb;
    sb_harness_t *h = (sb_harness_t *)userdata;
    ASSERT_TRUE(h->received_count < 16);
    memcpy(h->received[h->received_count], bytes, len);
    h->received_len[h->received_count] = len;
    h->received_count++;
}

static void on_broken(cloak_switchboard_t *sb, void *userdata) {
    (void)sb;
    sb_harness_t *h = (sb_harness_t *)userdata;
    h->broken_count++;
}

static int make_nonblocking_socketpair(int fds[2]) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return -1;
    if (fcntl(fds[0], F_SETFL, O_NONBLOCK) != 0) return -1;
    if (fcntl(fds[1], F_SETFL, O_NONBLOCK) != 0) return -1;
    return 0;
}

static void stop_reactor_timer_cb(cloak_reactor_t *r, void *userdata) {
    (void)userdata;
    cloak_reactor_stop(r);
}

static void pump_reactor_once(cloak_reactor_t *r) {
    cloak_reactor_add_timer(r, 20, stop_reactor_timer_cb, r);
    cloak_reactor_run(r);
}

static void test_send_reaches_one_of_the_pool_and_receives_back(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);

    sb_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_switchboard_t sb;
    ASSERT_EQ_INT(cloak_switchboard_init(&sb, r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                          on_envelope, &h, on_broken, &h), 0);

    int fds_a[2], fds_b[2], fds_c[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds_a), 0);
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds_b), 0);
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds_c), 0);
    ASSERT_EQ_INT(cloak_switchboard_add_conn(&sb, fds_a[0]), 0);
    ASSERT_EQ_INT(cloak_switchboard_add_conn(&sb, fds_b[0]), 0);
    ASSERT_EQ_INT(cloak_switchboard_add_conn(&sb, fds_c[0]), 0);
    ASSERT_EQ_INT(cloak_switchboard_conn_count(&sb), 3);

    uint8_t payload[5] = {1, 2, 3, 4, 5};
    ASSERT_EQ_INT(cloak_switchboard_send(&sb, payload, sizeof(payload)), 0);

    /* Exactly one of the three raw peer fds received the envelope. */
    int hits = 0;
    int peer_fds[3] = {fds_a[1], fds_b[1], fds_c[1]};
    for (int i = 0; i < 3; i++) {
        uint8_t wire[64];
        ssize_t n = read(peer_fds[i], wire, sizeof(wire));
        if (n > 0) {
            hits++;
            ASSERT_EQ_INT(n, 7);
            ASSERT_EQ_INT(wire[0], 0);
            ASSERT_EQ_INT(wire[1], 5);
            ASSERT_MEM_EQ(wire + 2, payload, 5);
        }
    }
    ASSERT_EQ_INT(hits, 1);

    /* Any peer can send back, and it's routed to the switchboard's
     * on_envelope callback regardless of which underlying conn it
     * arrived on. */
    uint8_t reply_wire[2 + 3] = {0, 3, 'h', 'i', '!'};
    ASSERT_EQ_INT(write(fds_b[1], reply_wire, sizeof(reply_wire)), (ssize_t)sizeof(reply_wire));
    pump_reactor_once(r);
    ASSERT_EQ_INT(h.received_count, 1);
    ASSERT_MEM_EQ(h.received[0], "hi!", 3);

    cloak_switchboard_destroy(&sb);
    cloak_reactor_destroy(r);
    close(fds_a[0]); close(fds_a[1]);
    close(fds_b[0]); close(fds_b[1]);
    close(fds_c[0]); close(fds_c[1]);
}

static void test_distribution_hits_every_connection_over_many_sends(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    sb_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_switchboard_t sb;
    ASSERT_EQ_INT(cloak_switchboard_init(&sb, r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                          on_envelope, &h, on_broken, &h), 0);

    enum { NCONN = 4 };
    int fds[NCONN][2];
    for (int i = 0; i < NCONN; i++) {
        ASSERT_EQ_INT(make_nonblocking_socketpair(fds[i]), 0);
        ASSERT_EQ_INT(cloak_switchboard_add_conn(&sb, fds[i][0]), 0);
    }

    int hit_count[NCONN];
    memset(hit_count, 0, sizeof(hit_count));
    uint8_t payload[1] = {0xAB};
    for (int iter = 0; iter < 200; iter++) {
        ASSERT_EQ_INT(cloak_switchboard_send(&sb, payload, sizeof(payload)), 0);
        for (int i = 0; i < NCONN; i++) {
            uint8_t wire[8];
            ssize_t n = read(fds[i][1], wire, sizeof(wire));
            if (n > 0) hit_count[i]++;
        }
    }
    /* Statistical, not exact: with 200 uniformly random picks across 4
     * connections, every connection should be hit at least once (the
     * probability any one is hit zero times is (3/4)^200, astronomically
     * small) -- this is enough to catch a broken distribution (e.g.
     * always picking index 0) without being a flaky exact-count check. */
    for (int i = 0; i < NCONN; i++) {
        ASSERT_TRUE(hit_count[i] > 0);
    }

    cloak_switchboard_destroy(&sb);
    cloak_reactor_destroy(r);
    for (int i = 0; i < NCONN; i++) {
        close(fds[i][0]);
        close(fds[i][1]);
    }
}

static void test_any_connection_failure_breaks_whole_switchboard(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    sb_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_switchboard_t sb;
    ASSERT_EQ_INT(cloak_switchboard_init(&sb, r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                          on_envelope, &h, on_broken, &h), 0);

    int fds_a[2], fds_b[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds_a), 0);
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds_b), 0);
    ASSERT_EQ_INT(cloak_switchboard_add_conn(&sb, fds_a[0]), 0);
    ASSERT_EQ_INT(cloak_switchboard_add_conn(&sb, fds_b[0]), 0);

    close(fds_a[1]); /* peer of conn A hangs up */
    close(fds_b[1]);
    pump_reactor_once(r);

    ASSERT_EQ_INT(h.broken_count, 1);

    /* A send after the switchboard is broken must fail, not crash, and
     * must not fall back to trying a still-technically-open conn. */
    uint8_t payload[2] = {9, 9};
    ASSERT_EQ_INT(cloak_switchboard_send(&sb, payload, sizeof(payload)), -1);

    cloak_switchboard_destroy(&sb);
    cloak_reactor_destroy(r);
    close(fds_a[0]);
    close(fds_b[0]);
}

static void test_send_with_zero_connections_fails_cleanly(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    sb_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_switchboard_t sb;
    ASSERT_EQ_INT(cloak_switchboard_init(&sb, r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                          on_envelope, &h, on_broken, &h), 0);

    uint8_t payload[1] = {1};
    ASSERT_EQ_INT(cloak_switchboard_send(&sb, payload, sizeof(payload)), -1);

    cloak_switchboard_destroy(&sb);
    cloak_reactor_destroy(r);
}

static void test_close_all_closes_every_fd_and_empties_pool(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    sb_harness_t h;
    memset(&h, 0, sizeof(h));
    cloak_switchboard_t sb;
    ASSERT_EQ_INT(cloak_switchboard_init(&sb, r, MAX_FRAME_LEN, SEND_QUEUE_CAP,
                                          on_envelope, &h, on_broken, &h), 0);

    int fds_a[2], fds_b[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds_a), 0);
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds_b), 0);
    ASSERT_EQ_INT(cloak_switchboard_add_conn(&sb, fds_a[0]), 0);
    ASSERT_EQ_INT(cloak_switchboard_add_conn(&sb, fds_b[0]), 0);

    cloak_switchboard_close_all(&sb);
    ASSERT_EQ_INT(cloak_switchboard_conn_count(&sb), 0);

    /* fds_a[0]/fds_b[0] were closed BY close_all -- confirm each is no
     * longer a valid fd (a write on a closed fd fails with EBADF). */
    ssize_t rc = write(fds_a[0], "x", 1);
    ASSERT_TRUE(rc < 0);

    cloak_switchboard_destroy(&sb);
    cloak_reactor_destroy(r);
    close(fds_a[1]);
    close(fds_b[1]);
}

TEST_MAIN_BEGIN()
    test_send_reaches_one_of_the_pool_and_receives_back();
    test_distribution_hits_every_connection_over_many_sends();
    test_any_connection_failure_breaks_whole_switchboard();
    test_send_with_zero_connections_fails_cleanly();
    test_close_all_closes_every_fd_and_empties_pool();
TEST_MAIN_END()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "cmake -S . -B build 2>&1 | tail -20"
```
Expected: compile failure, `cloak/switchboard.h` doesn't exist yet.

- [ ] **Step 3: Write the header**

Create `libcloak-mux/include/cloak/switchboard.h`:

```c
#ifndef CLOAK_SWITCHBOARD_H
#define CLOAK_SWITCHBOARD_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/reactor.h"

typedef struct cloak_switchboard cloak_switchboard_t;
typedef struct cloak_conn cloak_conn_t;

/* frame_bytes/len: an already length-prefix-stripped, still-obfuscated
 * frame's bytes, valid only for the duration of this call (points into
 * the originating cloak_conn_t's reused scratch buffer). */
typedef void (*cloak_switchboard_envelope_cb)(cloak_switchboard_t *sb, const uint8_t *frame_bytes, size_t frame_len, void *userdata);

/* Called exactly once, the moment ANY connection in the pool becomes
 * broken (matches Go's switchboard: a single connection's failure is
 * fatal to the whole pool, not just that connection -- see this
 * project's plan-level fault-model documentation). sb is NOT
 * automatically torn down when this fires -- the owner must still call
 * cloak_switchboard_close_all and/or cloak_switchboard_destroy once it's
 * done reacting (this lets the owner, e.g. a session, do its own
 * higher-layer cleanup first, matching Go's Session.closeSession()
 * running before switchboard.closeAll()). */
typedef void (*cloak_switchboard_broken_cb)(cloak_switchboard_t *sb, void *userdata);

struct cloak_switchboard {
    cloak_reactor_t *reactor;
    cloak_conn_t **conns; /* owned array of owned heap-allocated cloak_conn_t */
    size_t conns_len;
    size_t conns_cap;

    size_t max_frame_len;
    size_t conn_send_queue_cap;

    uint32_t rng_state; /* xorshift32, seeded once at init -- NOT cryptographic, see this file's header comment */

    int broken;
    cloak_switchboard_envelope_cb on_envelope;
    void *on_envelope_userdata;
    cloak_switchboard_broken_cb on_broken;
    void *on_broken_userdata;
};

/* max_frame_len/conn_send_queue_cap are forwarded unchanged to every
 * cloak_conn_t this switchboard creates (see cloak_conn_init's own
 * documentation for their meaning).
 *
 * Returns 0 on success, -1 on invalid parameters (same validation as
 * cloak_conn_init) or allocation failure. */
int cloak_switchboard_init(cloak_switchboard_t *sb, cloak_reactor_t *reactor,
                            size_t max_frame_len, size_t conn_send_queue_cap,
                            cloak_switchboard_envelope_cb on_envelope, void *on_envelope_userdata,
                            cloak_switchboard_broken_cb on_broken, void *on_broken_userdata);

/* Calls cloak_switchboard_close_all, then frees sb's own array. */
void cloak_switchboard_destroy(cloak_switchboard_t *sb);

/* Wraps fd in a new cloak_conn_t and adds it to the pool. fd must already
 * be an open, non-blocking-capable socket -- ownership of fd passes to
 * the switchboard (it will be close()d by cloak_switchboard_close_all).
 * Returns 0 on success, -1 if sb is already broken or on allocation/
 * cloak_conn_init failure. */
int cloak_switchboard_add_conn(cloak_switchboard_t *sb, int fd);

/* Picks one connection uniformly at random from the pool and sends
 * frame_bytes/frame_len through it (length-prefixed by that connection,
 * see cloak_conn_send). Returns 0 on success, -1 if sb is broken, the
 * pool is empty, or the picked connection's send fails (in the last
 * case, on_broken fires synchronously before this call returns -- see
 * this project's plan-level fault-model documentation: no retry among
 * other connections). Must not block. */
int cloak_switchboard_send(cloak_switchboard_t *sb, const uint8_t *frame_bytes, size_t frame_len);

/* Destroys and close()s every connection in the pool and empties it.
 * Idempotent (a second call is a harmless no-op). Does not fire
 * on_broken (that callback signals "something failed", not "cleanup
 * happened" -- a normal, expected close_all from the owner's own active
 * teardown is not a failure). */
void cloak_switchboard_close_all(cloak_switchboard_t *sb);

size_t cloak_switchboard_conn_count(const cloak_switchboard_t *sb);

#endif
```

- [ ] **Step 4: Write the implementation**

Create `libcloak-mux/src/switchboard.c`:

```c
#include "cloak/switchboard.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cloak/common.h"
#include "cloak/conn.h"

static uint32_t xorshift32(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static void switchboard_conn_envelope_adapter(cloak_conn_t *conn, const uint8_t *bytes, size_t len, void *userdata) {
    (void)conn;
    cloak_switchboard_t *sb = (cloak_switchboard_t *)userdata;
    if (sb->on_envelope) {
        sb->on_envelope(sb, bytes, len, sb->on_envelope_userdata);
    }
}

static void switchboard_conn_closed_adapter(cloak_conn_t *conn, void *userdata) {
    (void)conn;
    cloak_switchboard_t *sb = (cloak_switchboard_t *)userdata;
    if (sb->broken) {
        return; /* idempotent -- another conn in this same dispatch batch may have already reported */
    }
    sb->broken = 1;
    if (sb->on_broken) {
        sb->on_broken(sb, sb->on_broken_userdata);
    }
}

int cloak_switchboard_init(cloak_switchboard_t *sb, cloak_reactor_t *reactor,
                            size_t max_frame_len, size_t conn_send_queue_cap,
                            cloak_switchboard_envelope_cb on_envelope, void *on_envelope_userdata,
                            cloak_switchboard_broken_cb on_broken, void *on_broken_userdata) {
    memset(sb, 0, sizeof(*sb));
    if (max_frame_len == 0 || max_frame_len > 65535 || conn_send_queue_cap == 0) {
        return -1;
    }
    sb->reactor = reactor;
    sb->max_frame_len = max_frame_len;
    sb->conn_send_queue_cap = conn_send_queue_cap;
    sb->on_envelope = on_envelope;
    sb->on_envelope_userdata = on_envelope_userdata;
    sb->on_broken = on_broken;
    sb->on_broken_userdata = on_broken_userdata;

    uint8_t seed[4];
    cloak_random_bytes(seed, sizeof(seed));
    sb->rng_state = ((uint32_t)seed[0] << 24) | ((uint32_t)seed[1] << 16) |
                     ((uint32_t)seed[2] << 8) | (uint32_t)seed[3];
    if (sb->rng_state == 0) {
        sb->rng_state = 1; /* xorshift32 is fixed at 0 forever -- avoid that one degenerate seed */
    }
    return 0;
}

void cloak_switchboard_destroy(cloak_switchboard_t *sb) {
    cloak_switchboard_close_all(sb);
    free(sb->conns);
    memset(sb, 0, sizeof(*sb));
}

int cloak_switchboard_add_conn(cloak_switchboard_t *sb, int fd) {
    if (sb->broken) {
        return -1;
    }
    if (sb->conns_len == sb->conns_cap) {
        size_t new_cap = sb->conns_cap == 0 ? 4 : sb->conns_cap * 2;
        cloak_conn_t **new_conns = (cloak_conn_t **)realloc(sb->conns, new_cap * sizeof(cloak_conn_t *));
        if (new_conns == NULL) {
            return -1;
        }
        sb->conns = new_conns;
        sb->conns_cap = new_cap;
    }
    cloak_conn_t *c = (cloak_conn_t *)malloc(sizeof(cloak_conn_t));
    if (c == NULL) {
        return -1;
    }
    if (cloak_conn_init(c, fd, sb->reactor, sb->max_frame_len, sb->conn_send_queue_cap,
                         switchboard_conn_envelope_adapter, sb,
                         switchboard_conn_closed_adapter, sb) != 0) {
        free(c);
        return -1;
    }
    sb->conns[sb->conns_len++] = c;
    return 0;
}

int cloak_switchboard_send(cloak_switchboard_t *sb, const uint8_t *frame_bytes, size_t frame_len) {
    if (sb->broken || sb->conns_len == 0) {
        return -1;
    }
    size_t idx = xorshift32(&sb->rng_state) % sb->conns_len;
    return cloak_conn_send(sb->conns[idx], frame_bytes, frame_len);
}

void cloak_switchboard_close_all(cloak_switchboard_t *sb) {
    for (size_t i = 0; i < sb->conns_len; i++) {
        int fd = sb->conns[i]->fd;
        cloak_conn_destroy(sb->conns[i]);
        close(fd);
        free(sb->conns[i]);
    }
    sb->conns_len = 0;
}

size_t cloak_switchboard_conn_count(const cloak_switchboard_t *sb) {
    return sb->conns_len;
}
```

Note: `cloak_switchboard_close_all` reads `sb->conns[i]->fd` *before* calling `cloak_conn_destroy` (which does not clear `->fd` itself in a way that matters here, but the read happens first regardless, so the order is safe either way -- `cloak_conn_destroy` only deregisters from the reactor and frees `recv_scratch`/the two byte queues, it does not zero `->fd` until its own final `memset`, but reading it beforehand avoids depending on that internal detail at all).

- [ ] **Step 5: Wire into CMake**

In `libcloak-mux/CMakeLists.txt`, add `src/switchboard.c` to the `cloak-mux` library's sources.

In `libcloak-mux/tests/CMakeLists.txt`, append:
```cmake
add_executable(test_switchboard test_switchboard.c)
target_include_directories(test_switchboard PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_switchboard PRIVATE cloak-mux)
add_test(NAME test_switchboard COMMAND test_switchboard)
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "rm -rf build && cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure"
```

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "cmake -S . -B build-asan -DCMAKE_C_FLAGS='-fsanitize=address,undefined -g' -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined' && cmake --build build-asan && ctest --test-dir build-asan --output-on-failure"
```
Expected: all pass, zero warnings, clean under ASan/UBSan.

- [ ] **Step 7: Commit**

```bash
git add libcloak-mux/include/cloak/switchboard.h libcloak-mux/src/switchboard.c libcloak-mux/tests/test_switchboard.c libcloak-mux/CMakeLists.txt libcloak-mux/tests/CMakeLists.txt
git commit -m "Add switchboard: connection pool with uniform-random distribution"
```

---

### Task 4: `cloak_session_t` — stream lifecycle, frame routing, inactivity timeout, and end-to-end integration test

**Files:**
- Create: `libcloak-mux/include/cloak/session.h`
- Create: `libcloak-mux/src/session.c`
- Create: `libcloak-mux/tests/test_session.c`
- Modify: `libcloak-mux/CMakeLists.txt` (add `src/session.c`)
- Modify: `libcloak-mux/tests/CMakeLists.txt` (register `test_session`)

**Interfaces:**
- Consumes: `cloak_strmtab_t` and its functions (Task 1); `cloak_switchboard_t` and its functions (Task 3); `cloak_stream_t`, `cloak_stream_init`, `cloak_stream_destroy`, `cloak_stream_write`, `cloak_stream_send_closing`, `cloak_stream_feed_frame`, `cloak_stream_read`, `cloak_stream_recv_available`, `cloak_stream_frame_sink_t` (`libcloak-mux/include/cloak/stream.h`, already merged); `cloak_frame_t`, `cloak_obfuscator_t`, `cloak_frame_obfuscate`, `cloak_frame_deobfuscate`, `CLOAK_FRAME_HEADER_LEN`, `CLOAK_FRAME_MAX_EXTRA_LEN`, `CLOAK_FRAME_CLOSING_NOTHING`, `CLOAK_FRAME_CLOSING_STREAM`, `CLOAK_FRAME_CLOSING_SESSION` (`libcloak-mux/include/cloak/frame.h`, already merged); `cloak_reactor_t`, `cloak_reactor_add_timer`, `cloak_reactor_cancel_timer`, `CLOAK_TIMER_INVALID` (already merged); `cloak_random_bytes` (already merged).
- Produces: `cloak_session_t`, `cloak_session_config_t`, `cloak_session_new_stream_cb`, `cloak_session_broken_cb`, `cloak_session_init`, `cloak_session_destroy`, `cloak_session_add_conn`, `cloak_session_open_stream`, `cloak_session_close_stream`, `cloak_session_close`, `cloak_session_is_closed` — exact signatures below. This is the last task in this plan; nothing later depends on it.

Owns a `cloak_strmtab_t`, a `cloak_switchboard_t`, and a `cloak_obfuscator_t` **by value** (not a borrowed pointer) -- every `cloak_stream_t` this session creates holds a borrowed, not-owned pointer to `&sesh->obfuscator` per `cloak_stream_init`'s existing documented contract ("not owned -- must outlive the stream"), and storing the obfuscator by value inside the session guarantees that pointer stays valid for as long as any stream the session created does, without relying on the caller to separately keep one alive.

**Stream memory ownership (this is subtler than it first looks -- read before implementing):** a `cloak_stream_t` this session hands out (via `on_new_stream` or `cloak_session_open_stream`'s return value) can become "closed" for a reason the *holder* of that pointer didn't initiate and doesn't yet know about -- specifically, the remote peer's closing frame can arrive and be fully processed by `session_on_envelope` (including, in an earlier draft of this design, immediately tearing down its memory) *before* the holder ever gets a chance to call `cloak_stream_read` on it. If closing a stream synchronously freed its memory right then, the holder's pointer would already be dangling the next time they touch it -- a real, deterministic (not flaky) heap-use-after-free this plan's own integration test caught during design verification: `test_active_stream_close_propagates_to_peer` triggers it because the data frame and the closing frame both land in the same non-blocking read and get dispatched back-to-back, inside `session_on_envelope`, before the test ever calls `cloak_stream_read`.

Go doesn't have this problem because nothing is ever explicitly freed -- a closed `*Stream` just stops being reachable from `sesh.streams` (replaced with `nil`) while the GC keeps the underlying object alive for as long as any other reference (e.g. one the consumer is holding) still exists. C has no GC, so this port needs an explicit split between two distinct events that Go collapses into one:
1. **"Retire"** -- the stream stops being routable (its `strmtab` entry is tombstoned) and stops counting toward `active_stream_count`. This can happen at any time, for reasons outside the pointer-holder's control (a passive close) or because the holder itself asked for it (`cloak_session_close_stream`).
2. **"Release"** -- the stream's memory is actually freed. This must only ever happen once the pointer-holder is truly done with it -- so it is a *separate*, explicit call (`cloak_session_release_stream`) the holder makes themselves, typically right after observing `cloak_stream_read` return `-1` (end of stream) or after deciding they no longer care about it.

`cloak_session_close_stream` performs step 1 only (plus sending the closing frame, for the active-close case) -- it does **not** free `stream`. `cloak_session_release_stream` performs step 2 (freeing), and is safe to call whether step 1 already happened (passively, or via a prior `cloak_session_close_stream` call) or not (in which case it performs step 1 itself first, treating "release without a prior close" as an implicit active close). Internally, every `cloak_stream_t` this session creates is actually the first member of a private `cloak_session_stream_entry_t` wrapper (defined only in `session.c`, never exposed) that carries the one extra bit of bookkeeping ("has step 1 already happened for this stream") needed to make `cloak_session_release_stream` idempotent-safe; because `stream` is that wrapper's first member, a `cloak_stream_t*` the caller holds is always also validly convertible back to the wrapper pointer internally (a guarantee C itself makes about a pointer to a struct and a pointer to its first member), so the public API surface still only ever hands callers a plain `cloak_stream_t*`.

- [ ] **Step 1: Write the failing test**

Create `libcloak-mux/tests/test_session.c`. This is the plan's end-to-end integration test: two real `cloak_session_t` instances, each with its own `cloak_reactor_t`, connected by real (non-blocking) `socketpair` fds standing in for underlying TCP connections, driven by pumping both reactors in alternation (no `sleep`-based polling anywhere -- the inactivity-timeout test uses a real, short configured timeout and the reactor's own timer heap to detect it).

```c
#include "cloak/session.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cloak/common.h"
#include "test_framework.h"

#define MAX_ON_WIRE 2048u
#define STREAM_RECV_CAP 65536u
#define STREAM_MAX_PENDING 64u
#define CONN_SEND_QUEUE_CAP 65536u

static int make_nonblocking_socketpair(int fds[2]) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return -1;
    if (fcntl(fds[0], F_SETFL, O_NONBLOCK) != 0) return -1;
    if (fcntl(fds[1], F_SETFL, O_NONBLOCK) != 0) return -1;
    return 0;
}

static void stop_reactor_timer_cb(cloak_reactor_t *r, void *userdata) {
    (void)userdata;
    cloak_reactor_stop(r);
}

/* Runs both reactors' dispatch loops in short alternating bursts until
 * either done_flag becomes true or max_rounds is exhausted -- the
 * standard pattern this integration test uses instead of sleep-polling:
 * each round schedules a short stop-timer on BOTH reactors so each
 * cloak_reactor_run call returns promptly, giving control back to check
 * done_flag. */
static void pump_until(cloak_reactor_t *r1, cloak_reactor_t *r2, const int *done_flag, int max_rounds) {
    for (int i = 0; i < max_rounds && !*done_flag; i++) {
        cloak_reactor_add_timer(r1, 5, stop_reactor_timer_cb, r1);
        cloak_reactor_run(r1);
        cloak_reactor_add_timer(r2, 5, stop_reactor_timer_cb, r2);
        cloak_reactor_run(r2);
    }
}

typedef struct {
    cloak_stream_t *last_new_stream;
    int new_stream_count;
    int broken_count;
} sesh_harness_t;

static void on_new_stream(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    sesh_harness_t *h = (sesh_harness_t *)userdata;
    h->last_new_stream = stream;
    h->new_stream_count++;
}

static void on_broken(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    sesh_harness_t *h = (sesh_harness_t *)userdata;
    h->broken_count++;
}

static void make_obfuscator(cloak_obfuscator_t *o) {
    o->method = CLOAK_AEAD_AES_256_GCM;
    cloak_random_bytes(o->session_key, sizeof(o->session_key));
}

static void init_session_pair(cloak_session_t *client, sesh_harness_t *client_h, cloak_reactor_t *client_r,
                               cloak_session_t *server, sesh_harness_t *server_h, cloak_reactor_t *server_r,
                               const cloak_obfuscator_t *shared_obfuscator, int nconns) {
    memset(client_h, 0, sizeof(*client_h));
    memset(server_h, 0, sizeof(*server_h));

    cloak_session_config_t client_cfg;
    memset(&client_cfg, 0, sizeof(client_cfg));
    client_cfg.obfuscator = *shared_obfuscator;
    client_cfg.max_on_wire_size = MAX_ON_WIRE;
    client_cfg.stream_recv_capacity = STREAM_RECV_CAP;
    client_cfg.stream_max_pending_frames = STREAM_MAX_PENDING;
    client_cfg.conn_send_queue_cap = CONN_SEND_QUEUE_CAP;
    client_cfg.inactivity_timeout_ms = 60000;
    client_cfg.on_new_stream = on_new_stream;
    client_cfg.on_new_stream_userdata = client_h;
    client_cfg.on_broken = on_broken;
    client_cfg.on_broken_userdata = client_h;
    ASSERT_EQ_INT(cloak_session_init(client, 1, client_r, &client_cfg), 0);

    cloak_session_config_t server_cfg = client_cfg;
    server_cfg.on_new_stream_userdata = server_h;
    server_cfg.on_broken_userdata = server_h;
    ASSERT_EQ_INT(cloak_session_init(server, 2, server_r, &server_cfg), 0);

    for (int i = 0; i < nconns; i++) {
        int fds[2];
        ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
        ASSERT_EQ_INT(cloak_session_add_conn(client, fds[0]), 0);
        ASSERT_EQ_INT(cloak_session_add_conn(server, fds[1]), 0);
    }
}

static void test_single_stream_single_conn_round_trip(void) {
    cloak_reactor_t *client_r = cloak_reactor_create();
    cloak_reactor_t *server_r = cloak_reactor_create();
    ASSERT_TRUE(client_r != NULL && server_r != NULL);

    cloak_obfuscator_t obfuscator;
    make_obfuscator(&obfuscator);

    cloak_session_t client, server;
    sesh_harness_t client_h, server_h;
    init_session_pair(&client, &client_h, client_r, &server, &server_h, server_r, &obfuscator, 1);

    uint32_t stream_id;
    cloak_stream_t *client_stream = cloak_session_open_stream(&client, &stream_id);
    ASSERT_TRUE(client_stream != NULL);

    const char *msg = "hello from the client";
    ASSERT_EQ_INT(cloak_stream_write(client_stream, (const uint8_t *)msg, strlen(msg)), (long)strlen(msg));

    int always_false = 0;
    pump_until(client_r, server_r, &always_false, 5);

    ASSERT_EQ_INT(server_h.new_stream_count, 1);
    cloak_stream_t *server_stream = server_h.last_new_stream;
    ASSERT_TRUE(server_stream != NULL);

    uint8_t out[128];
    long got = cloak_stream_read(server_stream, out, sizeof(out));
    ASSERT_EQ_INT(got, (long)strlen(msg));
    ASSERT_MEM_EQ(out, msg, (size_t)got);

    /* Neither stream was ever closed above -- release both explicitly
     * (see cloak_session_release_stream's contract: it performs an
     * implicit active close first when needed) before tearing the
     * sessions down, so this test doesn't leak either allocation. */
    cloak_session_release_stream(&client, client_stream);
    cloak_session_release_stream(&server, server_stream);

    cloak_session_destroy(&client);
    cloak_session_destroy(&server);
    cloak_reactor_destroy(client_r);
    cloak_reactor_destroy(server_r);
}

typedef struct {
    cloak_stream_t *streams[16];
    int count;
} multi_new_stream_capture_t;

static void on_new_stream_capture_all(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)sesh;
    multi_new_stream_capture_t *cap = (multi_new_stream_capture_t *)userdata;
    ASSERT_TRUE(cap->count < 16);
    cap->streams[cap->count++] = stream;
}

static void test_multiple_streams_multiple_conns_byte_exact(void) {
    cloak_reactor_t *client_r = cloak_reactor_create();
    cloak_reactor_t *server_r = cloak_reactor_create();
    ASSERT_TRUE(client_r != NULL && server_r != NULL);

    cloak_obfuscator_t obfuscator;
    make_obfuscator(&obfuscator);

    cloak_session_config_t client_cfg;
    memset(&client_cfg, 0, sizeof(client_cfg));
    client_cfg.obfuscator = obfuscator;
    client_cfg.max_on_wire_size = MAX_ON_WIRE;
    client_cfg.stream_recv_capacity = STREAM_RECV_CAP;
    client_cfg.stream_max_pending_frames = STREAM_MAX_PENDING;
    client_cfg.conn_send_queue_cap = CONN_SEND_QUEUE_CAP;
    client_cfg.inactivity_timeout_ms = 60000;

    cloak_session_t client, server;
    ASSERT_EQ_INT(cloak_session_init(&client, 1, client_r, &client_cfg), 0);

    multi_new_stream_capture_t cap;
    memset(&cap, 0, sizeof(cap));
    cloak_session_config_t server_cfg = client_cfg;
    server_cfg.on_new_stream = on_new_stream_capture_all;
    server_cfg.on_new_stream_userdata = &cap;
    ASSERT_EQ_INT(cloak_session_init(&server, 2, server_r, &server_cfg), 0);

    enum { NCONN = 4, NSTREAMS = 6 };
    for (int i = 0; i < NCONN; i++) {
        int fds[2];
        ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
        ASSERT_EQ_INT(cloak_session_add_conn(&client, fds[0]), 0);
        ASSERT_EQ_INT(cloak_session_add_conn(&server, fds[1]), 0);
    }

    cloak_stream_t *client_streams[NSTREAMS];
    char messages[NSTREAMS][64];
    size_t message_lens[NSTREAMS];
    for (int i = 0; i < NSTREAMS; i++) {
        uint32_t id;
        client_streams[i] = cloak_session_open_stream(&client, &id);
        ASSERT_TRUE(client_streams[i] != NULL);
        int len = snprintf(messages[i], sizeof(messages[i]), "stream-%d-payload-abcdef", i);
        message_lens[i] = (size_t)len;
        ASSERT_EQ_INT(cloak_stream_write(client_streams[i], (const uint8_t *)messages[i], (size_t)len),
                      (long)len);
    }

    int always_false = 0;
    pump_until(client_r, server_r, &always_false, 10);

    ASSERT_EQ_INT(cap.count, NSTREAMS);
    for (int i = 0; i < NSTREAMS; i++) {
        uint8_t out[128];
        long got = cloak_stream_read(cap.streams[i], out, sizeof(out));
        ASSERT_TRUE(got > 0);
        int matched = 0;
        for (int j = 0; j < NSTREAMS; j++) {
            if ((size_t)got == message_lens[j] && memcmp(out, messages[j], (size_t)got) == 0) {
                matched = 1;
                break;
            }
        }
        ASSERT_TRUE(matched);
        cloak_session_release_stream(&server, cap.streams[i]);
    }
    for (int i = 0; i < NSTREAMS; i++) {
        cloak_session_release_stream(&client, client_streams[i]);
    }

    cloak_session_destroy(&client);
    cloak_session_destroy(&server);
    cloak_reactor_destroy(client_r);
    cloak_reactor_destroy(server_r);
}

static void test_active_stream_close_propagates_to_peer(void) {
    cloak_reactor_t *client_r = cloak_reactor_create();
    cloak_reactor_t *server_r = cloak_reactor_create();
    ASSERT_TRUE(client_r != NULL && server_r != NULL);
    cloak_obfuscator_t obfuscator;
    make_obfuscator(&obfuscator);
    cloak_session_t client, server;
    sesh_harness_t client_h, server_h;
    init_session_pair(&client, &client_h, client_r, &server, &server_h, server_r, &obfuscator, 1);

    uint32_t id;
    cloak_stream_t *client_stream = cloak_session_open_stream(&client, &id);
    ASSERT_TRUE(client_stream != NULL);
    ASSERT_EQ_INT(cloak_stream_write(client_stream, (const uint8_t *)"x", 1), 1);

    int always_false = 0;
    pump_until(client_r, server_r, &always_false, 5);
    ASSERT_EQ_INT(server_h.new_stream_count, 1);
    cloak_stream_t *server_stream = server_h.last_new_stream;

    /* Regression test for a real heap-use-after-free caught during this
     * plan's own design verification: the client closes its stream
     * (sends a closing frame) immediately after writing one byte, with
     * NO gap for the test to read anything in between. On the server
     * side, both the data frame and the closing frame can land in the
     * same non-blocking read() and get dispatched back-to-back inside
     * session_on_envelope -- so by the time pump_until returns control
     * here, cloak_stream_feed_frame has already reported the closing
     * frame (return value 1) to session_on_envelope, which retires (but,
     * per this module's design, does NOT free) server_stream. If
     * session.c ever again frees a stream's memory at the moment it's
     * retired (rather than only in cloak_session_release_stream), the
     * cloak_stream_read call below reads freed memory -- this exact
     * scenario is what an earlier draft of this plan's session.c got
     * wrong, caught by this test under ASan (heap-use-after-free in
     * cloak_bytequeue_read, freed by session_close_stream_internal). */
    ASSERT_EQ_INT(cloak_session_close_stream(&client, client_stream), 0);
    pump_until(client_r, server_r, &always_false, 5);

    /* The server side's stream must still be safely readable here,
     * reporting end-of-stream only once its buffered byte and the close
     * are both delivered -- not a moment before, and definitely not via
     * a dangling pointer. */
    uint8_t out[8];
    long got = cloak_stream_read(server_stream, out, sizeof(out));
    ASSERT_EQ_INT(got, 1);
    ASSERT_MEM_EQ(out, "x", 1);
    ASSERT_EQ_INT(cloak_stream_read(server_stream, out, sizeof(out)), -1);

    cloak_session_release_stream(&client, client_stream);
    cloak_session_release_stream(&server, server_stream);

    cloak_session_destroy(&client);
    cloak_session_destroy(&server);
    cloak_reactor_destroy(client_r);
    cloak_reactor_destroy(server_r);
}

static void test_active_session_close_notifies_peer(void) {
    cloak_reactor_t *client_r = cloak_reactor_create();
    cloak_reactor_t *server_r = cloak_reactor_create();
    ASSERT_TRUE(client_r != NULL && server_r != NULL);
    cloak_obfuscator_t obfuscator;
    make_obfuscator(&obfuscator);
    cloak_session_t client, server;
    sesh_harness_t client_h, server_h;
    init_session_pair(&client, &client_h, client_r, &server, &server_h, server_r, &obfuscator, 1);

    ASSERT_EQ_INT(cloak_session_close(&client), 0);

    int always_false = 0;
    pump_until(client_r, server_r, &always_false, 5);

    ASSERT_EQ_INT(server_h.broken_count, 1);
    ASSERT_EQ_INT(cloak_session_is_closed(&server), 1);

    /* cloak_session_close (called above on client) already destroyed
     * every stream client owned (there were none opened here), and
     * server's whole-session teardown will do the same for server's (also
     * none) -- nothing to release in this test. */
    cloak_session_destroy(&client);
    cloak_session_destroy(&server);
    cloak_reactor_destroy(client_r);
    cloak_reactor_destroy(server_r);
}

static void test_inactivity_timeout_closes_session(void) {
    cloak_reactor_t *client_r = cloak_reactor_create();
    cloak_reactor_t *server_r = cloak_reactor_create();
    ASSERT_TRUE(client_r != NULL && server_r != NULL);
    cloak_obfuscator_t obfuscator;
    make_obfuscator(&obfuscator);

    cloak_session_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.obfuscator = obfuscator;
    cfg.max_on_wire_size = MAX_ON_WIRE;
    cfg.stream_recv_capacity = STREAM_RECV_CAP;
    cfg.stream_max_pending_frames = STREAM_MAX_PENDING;
    cfg.conn_send_queue_cap = CONN_SEND_QUEUE_CAP;
    cfg.inactivity_timeout_ms = 30; /* short, real timeout -- no streams are ever opened */

    sesh_harness_t h;
    memset(&h, 0, sizeof(h));
    cfg.on_broken = on_broken;
    cfg.on_broken_userdata = &h;

    cloak_session_t sesh;
    ASSERT_EQ_INT(cloak_session_init(&sesh, 1, client_r, &cfg), 0);

    ASSERT_EQ_INT(cloak_session_is_closed(&sesh), 0);

    /* Pump ONLY this session's own reactor (no peer needed -- this
     * exercises the timer firing, not the network path) until on_broken
     * actually fires or a generous round budget is exhausted. Waits on
     * h.broken_count, not cloak_session_is_closed: is_closed() flips
     * synchronously inside session_check_timeout (before the deferred
     * teardown that fires on_broken even gets scheduled), so a loop that
     * stopped as soon as is_closed() became true could exit one round
     * too early, on the rare occasion this test's own stop_reactor_timer_cb
     * (used to bound each cloak_reactor_run call) is itself due in the
     * very same batch as the freshly-scheduled 0ms deferred-teardown
     * timer and happens to run first, setting the reactor's own stopped
     * flag before that timer gets a chance to fire. Found as a real,
     * reproducible ~5% flake during this plan's own design verification
     * after the deferred-teardown redesign (see this plan's Global
     * Constraints) separated is_closed() from on_broken() in time where
     * they used to be simultaneous. */
    for (int i = 0; i < 50 && h.broken_count == 0; i++) {
        cloak_reactor_add_timer(client_r, 10, stop_reactor_timer_cb, client_r);
        cloak_reactor_run(client_r);
    }

    ASSERT_EQ_INT(cloak_session_is_closed(&sesh), 1);
    ASSERT_EQ_INT(h.broken_count, 1);

    cloak_session_destroy(&sesh);
    cloak_reactor_destroy(client_r);
    cloak_reactor_destroy(server_r);
}

static cloak_session_t *g_on_new_stream_closes_target = NULL;

static void on_new_stream_closes_whole_session(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    (void)stream;
    (void)userdata;
    /* A legitimate consumer policy: reject an unexpected new stream by
     * tearing down the whole session on the spot, synchronously, from
     * within this very callback. cloak_session_close's doc comment
     * promises this is safe. */
    ASSERT_EQ_INT(cloak_session_close(sesh), 0);
    g_on_new_stream_closes_target = sesh;
}

/* Regression test for a real heap-use-after-free caught during this
 * plan's own design verification (found by an adversarial probe beyond
 * this file's own originally-written tests, then folded in here): if
 * session_on_envelope invoked on_new_stream BEFORE feeding the revealing
 * frame to the brand new stream, and on_new_stream synchronously called
 * cloak_session_close (a documented-safe, realistic thing to do), that
 * close's synchronous stream-teardown sweep would free the stream that
 * session_on_envelope was still about to call cloak_stream_feed_frame
 * on. This test exercises exactly that sequence under ASan. */
static void test_on_new_stream_closing_session_is_safe(void) {
    cloak_reactor_t *client_r = cloak_reactor_create();
    cloak_reactor_t *server_r = cloak_reactor_create();
    ASSERT_TRUE(client_r != NULL && server_r != NULL);
    cloak_obfuscator_t obfuscator;
    make_obfuscator(&obfuscator);

    cloak_session_config_t client_cfg;
    memset(&client_cfg, 0, sizeof(client_cfg));
    client_cfg.obfuscator = obfuscator;
    client_cfg.max_on_wire_size = MAX_ON_WIRE;
    client_cfg.stream_recv_capacity = STREAM_RECV_CAP;
    client_cfg.stream_max_pending_frames = STREAM_MAX_PENDING;
    client_cfg.conn_send_queue_cap = CONN_SEND_QUEUE_CAP;
    client_cfg.inactivity_timeout_ms = 60000;

    cloak_session_t client, server;
    ASSERT_EQ_INT(cloak_session_init(&client, 1, client_r, &client_cfg), 0);

    cloak_session_config_t server_cfg = client_cfg;
    server_cfg.on_new_stream = on_new_stream_closes_whole_session;
    ASSERT_EQ_INT(cloak_session_init(&server, 2, server_r, &server_cfg), 0);

    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    ASSERT_EQ_INT(cloak_session_add_conn(&client, fds[0]), 0);
    ASSERT_EQ_INT(cloak_session_add_conn(&server, fds[1]), 0);

    uint32_t id;
    cloak_stream_t *client_stream = cloak_session_open_stream(&client, &id);
    ASSERT_TRUE(client_stream != NULL);
    ASSERT_EQ_INT(cloak_stream_write(client_stream, (const uint8_t *)"hi", 2), 2);

    g_on_new_stream_closes_target = NULL;
    int always_false = 0;
    pump_until(client_r, server_r, &always_false, 5);

    /* If session_on_envelope's ordering is correct, this whole sequence
     * (new stream created, fed, retired, THEN on_new_stream closes the
     * session) completes without any use-after-free, and the server
     * session ends up closed. */
    ASSERT_TRUE(g_on_new_stream_closes_target == &server);
    ASSERT_EQ_INT(cloak_session_is_closed(&server), 1);

    /* server's active close (triggered from within on_new_stream above)
     * sends a session-closing frame to client -- which client processes
     * within this same pump_until call, passively closing ITS session
     * too (matching Go: an active Close() on one side always notifies
     * the remote, which tears itself down symmetrically) and, as part of
     * that, freeing every stream it owned via
     * session_destroy_stream_iter_cb, including client_stream. Do NOT
     * call cloak_session_release_stream on client_stream here -- its
     * memory is already gone by this point, and doing so would itself be
     * a use-after-free (caught by this plan's own verification process
     * against an earlier draft of this exact test). Assert the symmetric
     * teardown happened instead. */
    ASSERT_EQ_INT(cloak_session_is_closed(&client), 1);

    cloak_session_destroy(&client);
    cloak_session_destroy(&server);
    cloak_reactor_destroy(client_r);
    cloak_reactor_destroy(server_r);
}

/* Regression test for findings 3/4 in this plan's Global Constraints
 * (the fifth/sixth instances of this project's recurring UAF class):
 * closing a stream whose underlying connection has already died must
 * not free that same stream out from under cloak_session_close_stream's
 * own call chain. Completely ordinary trigger -- a peer disconnecting is
 * the single most common event a proxy server has to handle -- not an
 * artificial configuration (no tiny queue caps, no forced small buffers). */
static void test_close_stream_after_peer_disconnect_is_safe(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    cloak_obfuscator_t obfuscator;
    make_obfuscator(&obfuscator);

    cloak_session_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.obfuscator = obfuscator;
    cfg.max_on_wire_size = MAX_ON_WIRE;
    cfg.stream_recv_capacity = STREAM_RECV_CAP;
    cfg.stream_max_pending_frames = STREAM_MAX_PENDING;
    cfg.conn_send_queue_cap = CONN_SEND_QUEUE_CAP;
    cfg.inactivity_timeout_ms = 60000;

    cloak_session_t sesh;
    ASSERT_EQ_INT(cloak_session_init(&sesh, 1, r, &cfg), 0);

    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    ASSERT_EQ_INT(cloak_session_add_conn(&sesh, fds[0]), 0);

    uint32_t id;
    cloak_stream_t *stream = cloak_session_open_stream(&sesh, &id);
    ASSERT_TRUE(stream != NULL);

    close(fds[1]); /* peer disconnects */

    /* Actively closing this stream now triggers, inside
     * cloak_stream_send_closing's own sink call, a write failure that
     * cascades all the way up into a full session teardown -- reentrant
     * to this very call. Must not crash. */
    (void)cloak_session_close_stream(&sesh, stream);
    ASSERT_EQ_INT(cloak_session_is_closed(&sesh), 1);

    /* cloak_session_close_stream only retires stream -- it does not free
     * it (see cloak_session_release_stream's own contract). Release it
     * explicitly so this test doesn't leak (cloak_session_destroy's own
     * deferred/synchronous sweep only reaches still-ACTIVE streams;
     * stream is already retired by this point, so it would otherwise
     * never be freed by anything). */
    cloak_session_release_stream(&sesh, stream);

    cloak_session_destroy(&sesh);
    cloak_reactor_destroy(r);
}

/* Sibling regression test: the same reentrant-teardown hazard, but
 * triggered from cloak_stream_write's own sink call instead of an
 * explicit close -- the specific path that reordering
 * cloak_session_close_stream/cloak_session_release_stream alone would
 * NOT have closed (see this plan's Global Constraints, finding 4) and
 * which is why the fix defers the whole stream-freeing sweep instead. */
static void test_stream_write_after_peer_disconnect_is_safe(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    cloak_obfuscator_t obfuscator;
    make_obfuscator(&obfuscator);

    cloak_session_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.obfuscator = obfuscator;
    cfg.max_on_wire_size = MAX_ON_WIRE;
    cfg.stream_recv_capacity = STREAM_RECV_CAP;
    cfg.stream_max_pending_frames = STREAM_MAX_PENDING;
    cfg.conn_send_queue_cap = CONN_SEND_QUEUE_CAP;
    cfg.inactivity_timeout_ms = 60000;

    cloak_session_t sesh;
    ASSERT_EQ_INT(cloak_session_init(&sesh, 1, r, &cfg), 0);

    int fds[2];
    ASSERT_EQ_INT(make_nonblocking_socketpair(fds), 0);
    ASSERT_EQ_INT(cloak_session_add_conn(&sesh, fds[0]), 0);

    uint32_t id;
    cloak_stream_t *stream = cloak_session_open_stream(&sesh, &id);
    ASSERT_TRUE(stream != NULL);

    close(fds[1]); /* peer disconnects */

    /* This write's own sink call fails (peer gone), cascading into a
     * full session teardown reentrant to this very call -- must not
     * crash, and cloak_stream_write itself must survive touching
     * `stream` again (s->write_closed = 1) after its sink call returns. */
    long got = cloak_stream_write(stream, (const uint8_t *)"x", 1);
    ASSERT_EQ_INT(got, -1);
    ASSERT_EQ_INT(cloak_session_is_closed(&sesh), 1);

    cloak_session_destroy(&sesh);
    cloak_reactor_destroy(r);
}

static cloak_session_t *g_heap_alloc_destroy_target = NULL;

static void on_broken_destroys_and_frees_heap_session(cloak_session_t *sesh, void *userdata) {
    (void)userdata;
    /* Exactly the documented-safe pattern: destroy AND free the
     * session's own heap storage from within on_broken. Regression test
     * for the seventh instance of this module's recurring UAF class
     * (see this plan's Global Constraints, finding 7): the deferred
     * teardown must survive this without ever touching `sesh` again
     * once this callback returns -- including the second, sweep-only
     * timer that was scheduled just before this callback was invoked. */
    cloak_session_destroy(sesh);
    free(sesh);
    g_heap_alloc_destroy_target = NULL; /* sentinel: reached this line without crashing */
}

static void test_on_broken_destroying_and_freeing_heap_session_is_safe(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    cloak_obfuscator_t obfuscator;
    make_obfuscator(&obfuscator);

    cloak_session_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.obfuscator = obfuscator;
    cfg.max_on_wire_size = MAX_ON_WIRE;
    cfg.stream_recv_capacity = STREAM_RECV_CAP;
    cfg.stream_max_pending_frames = STREAM_MAX_PENDING;
    cfg.conn_send_queue_cap = CONN_SEND_QUEUE_CAP;
    cfg.inactivity_timeout_ms = 30; /* short, real timeout -- fires on its own, no streams ever opened */
    cfg.on_broken = on_broken_destroys_and_frees_heap_session;

    cloak_session_t *sesh = (cloak_session_t *)malloc(sizeof(cloak_session_t));
    ASSERT_TRUE(sesh != NULL);
    ASSERT_EQ_INT(cloak_session_init(sesh, 1, r, &cfg), 0);
    g_heap_alloc_destroy_target = sesh;

    for (int i = 0; i < 50 && g_heap_alloc_destroy_target != NULL; i++) {
        cloak_reactor_add_timer(r, 10, stop_reactor_timer_cb, r);
        cloak_reactor_run(r);
    }
    ASSERT_TRUE(g_heap_alloc_destroy_target == NULL); /* on_broken ran, destroyed+freed sesh, no crash */

    /* Pump a few more rounds to make sure nothing was left dangling --
     * in particular, the sweep timer session_deferred_teardown_cb
     * schedules just before calling on_broken must have been cancelled
     * by cloak_session_destroy above, or it would fire here against
     * already-freed memory. */
    for (int i = 0; i < 5; i++) {
        cloak_reactor_add_timer(r, 10, stop_reactor_timer_cb, r);
        cloak_reactor_run(r);
    }

    cloak_reactor_destroy(r);
}

static void test_destroy_after_failed_init_is_safe(void) {
    cloak_reactor_t *r = cloak_reactor_create();
    ASSERT_TRUE(r != NULL);
    cloak_obfuscator_t obfuscator;
    make_obfuscator(&obfuscator);

    cloak_session_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.obfuscator = obfuscator;
    cfg.max_on_wire_size = 0; /* invalid -- too small to fit a header */
    cfg.stream_recv_capacity = STREAM_RECV_CAP;
    cfg.stream_max_pending_frames = STREAM_MAX_PENDING;
    cfg.conn_send_queue_cap = CONN_SEND_QUEUE_CAP;
    cfg.inactivity_timeout_ms = 1000;

    cloak_session_t sesh;
    ASSERT_EQ_INT(cloak_session_init(&sesh, 1, r, &cfg), -1);
    cloak_session_destroy(&sesh);

    cloak_reactor_destroy(r);
}

TEST_MAIN_BEGIN()
    test_single_stream_single_conn_round_trip();
    test_multiple_streams_multiple_conns_byte_exact();
    test_active_stream_close_propagates_to_peer();
    test_active_session_close_notifies_peer();
    test_inactivity_timeout_closes_session();
    test_on_new_stream_closing_session_is_safe();
    test_close_stream_after_peer_disconnect_is_safe();
    test_stream_write_after_peer_disconnect_is_safe();
    test_on_broken_destroying_and_freeing_heap_session_is_safe();
    test_destroy_after_failed_init_is_safe();
TEST_MAIN_END()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "cmake -S . -B build 2>&1 | tail -20"
```
Expected: compile failure, `cloak/session.h` doesn't exist yet.

- [ ] **Step 3: Write the header**

Create `libcloak-mux/include/cloak/session.h`:

```c
#ifndef CLOAK_SESSION_H
#define CLOAK_SESSION_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/frame.h"
#include "cloak/reactor.h"
#include "cloak/strmtab.h"
#include "cloak/stream.h"
#include "cloak/switchboard.h"

typedef struct cloak_session cloak_session_t;

/* Fired the moment a frame arrives for a stream_id this session has never
 * seen before (mirrors Go's Session.acceptCh -- a push callback instead
 * of a blocking-channel receive, consistent with this whole project's
 * reactor-callback translation of Go's blocking idioms). stream is
 * already fully initialized and already fed the frame that revealed it;
 * it may already have data available via cloak_stream_read by the time
 * this fires.
 *
 * stream remains valid (safe to call cloak_stream_read/cloak_stream_write
 * on) even after the peer closes it or this session tears it down for
 * any other reason -- its memory is freed ONLY by an explicit
 * cloak_session_release_stream call, never automatically. The recipient
 * of this callback owns that responsibility: call
 * cloak_session_release_stream once done with stream (typically after
 * observing cloak_stream_read return -1), or its memory leaks for the
 * remaining lifetime of the process. See this file's own top-of-task
 * "Stream memory ownership" note for the full reasoning. */
typedef void (*cloak_session_new_stream_cb)(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata);

/* Fired exactly once, the moment sesh becomes closed for ANY reason
 * (active cloak_session_close, a received closing-session frame, any
 * underlying connection failing, or the inactivity timeout).
 *
 * Any stream that is still ACTIVE (never retired, by any means, at the
 * moment this fires) is NOT yet destroyed when this callback runs -- this
 * is deliberately your last chance to call cloak_session_release_stream
 * on any such stream you're still holding a reference to (safe to do so
 * from within this callback). Immediately after this callback returns,
 * every stream that is STILL active (i.e. that neither you nor anything
 * else retired) is automatically destroyed and freed, and every
 * underlying connection is closed.
 *
 * IMPORTANT, and easy to get wrong: this automatic cleanup only ever
 * reaches streams that are still ACTIVE at teardown time. A stream that
 * was retired EARLIER for any reason other than your own explicit
 * cloak_session_release_stream call -- the peer closing it, a protocol
 * violation, or your own prior cloak_session_close_stream call -- is
 * untouched by this sweep (it's no longer reachable through this
 * session's internal routing table at all once retired) and its memory
 * leaks unless you call cloak_session_release_stream on it yourself, at
 * any point up to and including from within this very callback. In
 * short: nothing here reclaims a stream you haven't released UNLESS it
 * was still active and unretired the whole time. See
 * cloak_session_release_stream's own doc comment and this plan's Global
 * Constraints (finding 8) for the full reasoning -- an earlier version
 * of this comment overclaimed that everything gets reclaimed
 * automatically, which is not true and was caught by this plan's own
 * final whole-branch review, reproduced as a real LeakSanitizer-detected
 * leak in the most ordinary possible scenario (a stream opened, used,
 * and normally closed, on either side, without an explicit release).
 *
 * Guaranteed to fire OUTSIDE of any cloak_session_t/cloak_conn_t
 * callback's own call stack (deferred internally to the reactor's next
 * dispatch loop iteration even when the close was triggered from within
 * one) -- so it is always safe to call cloak_session_release_stream
 * synchronously from within this callback. Calling cloak_session_destroy
 * from within this callback is ALSO safe, including freeing sesh's own
 * storage before this callback returns -- but if you do, do not also
 * expect the leak-avoidance advice above to still apply afterward: once
 * sesh is destroyed, any stream pointer you didn't already release is
 * gone regardless, exactly like calling cloak_session_destroy from
 * ordinary application code. */
typedef void (*cloak_session_broken_cb)(cloak_session_t *sesh, void *userdata);

typedef struct {
    cloak_obfuscator_t obfuscator;   /* copied by value into the session -- see this task's own file header comment for why */
    size_t max_on_wire_size;         /* forwarded to every cloak_stream_init and cloak_conn_init this session performs */
    size_t stream_recv_capacity;     /* forwarded to every cloak_stream_init this session performs */
    size_t stream_max_pending_frames;/* forwarded to every cloak_stream_init this session performs */
    size_t conn_send_queue_cap;      /* forwarded to every cloak_conn_init this session performs, via its switchboard */
    uint64_t inactivity_timeout_ms;  /* how long with zero active streams before the session auto-closes */
    cloak_session_new_stream_cb on_new_stream;
    void *on_new_stream_userdata;
    cloak_session_broken_cb on_broken;
    void *on_broken_userdata;
} cloak_session_config_t;

struct cloak_session {
    uint32_t id;
    cloak_reactor_t *reactor;
    cloak_obfuscator_t obfuscator;

    cloak_strmtab_t streams;
    cloak_switchboard_t sb;

    uint32_t next_stream_id;
    size_t active_stream_count;

    size_t max_on_wire_size;
    size_t stream_recv_capacity;
    size_t stream_max_pending_frames;
    uint64_t inactivity_timeout_ms;
    cloak_timer_id_t inactivity_timer_id;
    cloak_timer_id_t teardown_timer_id;

    int closed;

    cloak_session_new_stream_cb on_new_stream;
    void *on_new_stream_userdata;
    cloak_session_broken_cb on_broken;
    void *on_broken_userdata;
};

/* Returns 0 on success, -1 on invalid parameters (same validation
 * cloak_stream_init and cloak_conn_init/cloak_switchboard_init already
 * apply to max_on_wire_size/stream_recv_capacity/conn_send_queue_cap,
 * checked eagerly here as far as is possible without a stream/conn to
 * actually construct) or allocation failure. Schedules the initial
 * inactivity timer as part of construction (matching Go's MakeSession,
 * which does the same immediately after setting up the session). */
int cloak_session_init(cloak_session_t *sesh, uint32_t id, cloak_reactor_t *reactor,
                        const cloak_session_config_t *config);

/* If not already closed, marks the session closed WITHOUT sending a
 * closing-session frame first (there is likely nothing left to send it
 * through, and the caller is discarding this session outright, not
 * notifying a peer). Then, synchronously and unconditionally (whether or
 * not a deferred teardown was already pending -- see cloak_session_close's
 * own doc comment): cancels any pending deferred-teardown timer, destroys
 * and frees every still-ACTIVE stream (see cloak_session_broken_cb's own
 * doc comment for why "still-ACTIVE" is not the same as "every stream" --
 * a stream retired earlier by any means and never released leaks even
 * here, since it's no longer reachable through this session at all once
 * retired), closes every underlying connection, and frees sesh's own
 * resources. Does NOT fire on_broken (this is the caller's own explicit
 * teardown, not a failure notification) -- so this is also NOT your last
 * chance to release a still-ACTIVE stream via cloak_session_release_stream
 * the way on_broken is; release anything you still hold BEFORE calling
 * this, not after.
 *
 * Must NOT be called from within on_new_stream, or from within any
 * cloak_conn_t/cloak_switchboard_t callback -- only from ordinary
 * application code, or from within on_broken (on_broken is documented as
 * always firing outside of any such callback's call stack, which is what
 * makes calling this from there safe). Safe to call on a session left
 * zeroed by a rejected cloak_session_init. */
void cloak_session_destroy(cloak_session_t *sesh);

/* Wraps fd (an open, non-blocking-capable socket) in a new underlying
 * connection and adds it to the session's pool. Returns 0 on success, -1
 * if sesh is closed or on failure adding to the switchboard. */
int cloak_session_add_conn(cloak_session_t *sesh, int fd);

/* Opens a new locally-initiated stream (Go's Session.OpenStream).
 * Returns the new stream and, if out_id is non-NULL, its id. Returns NULL
 * if sesh is closed or on allocation failure. See this file's own
 * top-of-task "Stream memory ownership" note: the returned pointer stays
 * valid (never automatically freed) until an explicit
 * cloak_session_release_stream call. */
cloak_stream_t *cloak_session_open_stream(cloak_session_t *sesh, uint32_t *out_id);

/* Actively closes stream: sends a closing-stream frame to the peer, stops
 * it from receiving any more routed frames, and stops it counting toward
 * the session's active-stream count. Does NOT free stream's memory --
 * see cloak_session_release_stream, and this file's own top-of-task
 * "Stream memory ownership" note. Returns 0 on success, -1 if stream was
 * already closed this way (matches Go's errRepeatStreamClosing) or if
 * sesh is already closed. stream remains valid to read from (and must
 * still be released) after this call. */
int cloak_session_close_stream(cloak_session_t *sesh, cloak_stream_t *stream);

/* Frees stream's memory. Safe to call whether stream was already closed
 * (actively via cloak_session_close_stream, or passively because the
 * peer closed it, or because of a protocol violation) or not -- if not,
 * this performs an implicit active close first (same effect as calling
 * cloak_session_close_stream immediately before this). After this call,
 * stream must never be used again by the caller for any purpose
 * (including passing it to any cloak_session_* or cloak_stream_* function
 * again) -- exactly like calling free() on any other heap pointer. */
void cloak_session_release_stream(cloak_session_t *sesh, cloak_stream_t *stream);

/* Actively closes the whole session (Go's Session.Close): marks the
 * session closed and ENQUEUES one session-level closing frame to be sent
 * to the peer, synchronously, before this call returns -- but "enqueued"
 * is as far as this call guarantees: it does not wait for that frame, or
 * any data queued by an earlier cloak_stream_write, to actually reach the
 * kernel. Destroying every still-ACTIVE stream's memory (see
 * cloak_session_broken_cb's own doc comment for what "still-ACTIVE" does
 * and doesn't cover) and closing every underlying connection are BOTH
 * deferred to the reactor's next dispatch loop iteration, and that
 * deferred step unconditionally discards anything still sitting in a
 * connection's outbound queue at that point -- including the
 * closing-session frame this call just enqueued, if the queue was
 * already backed up. This is a known, deliberate limitation (Go's own
 * Session.Close() avoids it because its send() is a blocking write, so
 * everything queued has genuinely reached the kernel before closeAll()
 * runs -- this port's non-blocking connections have no equivalent
 * built-in guarantee). The peer still learns the session ended either
 * way, just via the connection dying (EOF) instead of the intended
 * graceful notification, in the rare case a substantial amount of data
 * was still queued at the exact moment of this call. If you need every
 * byte to actually go out first, drain each stream's own backpressure
 * signal (there is currently no session-level equivalent) before calling
 * this. Every stream this session ever handed out stays valid (though no
 * longer routable -- no more frames will ever reach it) until the
 * deferred sweep runs; call cloak_session_release_stream on any you
 * still hold if you need deterministic, immediate cleanup of a specific
 * one rather than waiting for that sweep, which (per
 * cloak_session_broken_cb's doc) only reclaims streams that are still
 * ACTIVE when it runs.
 *
 * Returns 0 on success, -1 if already closed (matches Go's
 * errRepeatSessionClosing). Safe to call from within any of this
 * session's own callbacks (on_new_stream, on_broken, etc.), not just from
 * ordinary application code. */
int cloak_session_close(cloak_session_t *sesh);

int cloak_session_is_closed(const cloak_session_t *sesh);

#endif
```

- [ ] **Step 4: Write the implementation**

Create `libcloak-mux/src/session.c`:

```c
#include "cloak/session.h"

#include <stdlib.h>
#include <string.h>

#include "cloak/common.h"

/* Every cloak_stream_t this session creates is actually the first member
 * of this wrapper -- see session.h's "Stream memory ownership" note for
 * why an extra bit of per-stream bookkeeping is needed. Because `stream`
 * is the first member, a plain cloak_stream_t* (what callers receive) is
 * always safely convertible back to cloak_session_stream_entry_t* here --
 * a guarantee C itself makes about a pointer to a struct and a pointer to
 * its first member. */
typedef struct {
    cloak_stream_t stream;
    int retired; /* 1 once tombstoned (actively or passively) -- see session_retire_stream */
} cloak_session_stream_entry_t;

static void session_check_timeout(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_session_t *sesh = (cloak_session_t *)userdata;
    if (sesh->active_stream_count == 0 && !sesh->closed) {
        cloak_session_close(sesh);
    }
}

/* At most one pending inactivity timer at a time -- see this plan's
 * Global Constraints for why an uncancelled predecessor would be a
 * use-after-free once cloak_session_destroy has freed sesh. */
static void session_reschedule_inactivity_timer(cloak_session_t *sesh) {
    cloak_reactor_cancel_timer(sesh->reactor, sesh->inactivity_timer_id);
    sesh->inactivity_timer_id = cloak_reactor_add_timer(sesh->reactor, sesh->inactivity_timeout_ms,
                                                         session_check_timeout, sesh);
}

static int session_stream_sink_adapter(void *userdata, const uint8_t *bytes, size_t len) {
    cloak_session_t *sesh = (cloak_session_t *)userdata;
    return cloak_switchboard_send(&sesh->sb, bytes, len);
}

/* Stops stream from receiving any more routed frames (tombstones its
 * strmtab entry) and stops it counting toward active_stream_count. Does
 * NOT free stream's memory -- see cloak_session_release_stream and this
 * task's own "Stream memory ownership" note (a consumer holding this
 * stream's pointer, e.g. from on_new_stream, may not have read its
 * buffered data yet; freeing here would be a use-after-free the moment
 * they call cloak_stream_read -- this was caught by this plan's own
 * integration test during design verification). Safe to call on an
 * already-retired stream (no-op). */
static void session_retire_stream(cloak_session_t *sesh, cloak_stream_t *stream) {
    cloak_session_stream_entry_t *entry = (cloak_session_stream_entry_t *)stream;
    if (entry->retired) {
        return;
    }
    entry->retired = 1;
    cloak_strmtab_tombstone(&sesh->streams, stream->id);
    sesh->active_stream_count--;
    if (sesh->active_stream_count == 0 && !sesh->closed) {
        session_reschedule_inactivity_timer(sesh);
    }
}

/* Destroys and frees a single stream entry: used both by
 * session_free_all_active_streams (below) and directly (see its own
 * comment for why timing differs between the two call sites). */
static void session_destroy_stream_iter_cb(uint32_t key, void *value, void *userdata) {
    cloak_session_t *sesh = (cloak_session_t *)userdata;
    cloak_stream_t *stream = (cloak_stream_t *)value;
    cloak_session_stream_entry_t *entry = (cloak_session_stream_entry_t *)stream;
    cloak_stream_destroy(stream);
    free(entry);
    cloak_strmtab_tombstone(&sesh->streams, key); /* never grows/reallocates -- safe mid-iteration */
    sesh->active_stream_count--;
}

/* Frees every still-ACTIVE stream's memory. Called from two places with
 * two different timing guarantees -- see each call site's own comment:
 * session_deferred_teardown_cb (always safe -- runs outside any nested
 * call stack) and cloak_session_destroy (safe by that function's own
 * documented calling contract, not by anything here). Never call this
 * synchronously from session_close_internal or from anywhere reachable
 * from a cloak_conn_t/cloak_stream_t callback -- see this plan's Global
 * Constraints for why (this is exactly the fifth and sixth instances of
 * this project's recurring "freed object still has a live pointer above
 * it on the call stack" bug class, both caused by an earlier draft of
 * this exact function running synchronously from session_close_internal). */
static void session_free_all_active_streams(cloak_session_t *sesh) {
    cloak_strmtab_for_each_active(&sesh->streams, session_destroy_stream_iter_cb, sesh);
}

/* Marks the session closed and cancels the inactivity timer. Deliberately
 * does NOT touch any stream's or connection's memory -- see
 * session_schedule_deferred_teardown's own comment for why freeing
 * either must never happen synchronously here. Safe to call from
 * anywhere, including reentrantly from deep inside a cloak_conn_t's or
 * cloak_stream_t's own dispatch/write call chain, for exactly that
 * reason. Returns 1 if this call actually did the work (first call), 0
 * if sesh was already closed (matches Go's errRepeatSessionClosing being
 * surfaced by the caller as appropriate). */
static int session_close_internal(cloak_session_t *sesh) {
    if (sesh->closed) {
        return 0;
    }
    sesh->closed = 1;
    cloak_reactor_cancel_timer(sesh->reactor, sesh->inactivity_timer_id);
    return 1;
}

static void session_send_closing_session_frame(cloak_session_t *sesh) {
    uint8_t len_byte;
    cloak_random_bytes(&len_byte, 1);
    size_t pad_len = (size_t)len_byte + 1;
    /* Clamp so the fully obfuscated frame (header + payload + padding +
     * AEAD tag, bounded by CLOAK_FRAME_MAX_EXTRA_LEN) never exceeds
     * max_on_wire_size -- without this, cloak_conn_send would reject an
     * oversized closing-session frame as a protocol violation and mark
     * the connection broken, meaning the peer would never receive this
     * notification and would only learn of the close from the connection
     * dying instead. Same clamp cloak_stream_send_closing already
     * applies, for the same reason (stream.c, already merged) -- missing
     * here until caught during this plan's own design verification.
     * cloak_session_init already validates max_on_wire_size >
     * CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN, so this
     * subtraction cannot underflow. */
    size_t max_payload = sesh->max_on_wire_size - CLOAK_FRAME_HEADER_LEN - CLOAK_FRAME_MAX_EXTRA_LEN;
    size_t max_pad = max_payload < 256 ? max_payload : 256;
    if (pad_len > max_pad) {
        pad_len = max_pad;
    }
    uint8_t pad[256];
    cloak_random_bytes(pad, pad_len);

    cloak_frame_t frame;
    frame.stream_id = 0xffffffffu; /* matches Go's session-closing sentinel StreamID */
    frame.seq = 0;
    frame.closing = CLOAK_FRAME_CLOSING_SESSION;
    frame.payload = pad;
    frame.payload_len = pad_len;

    uint8_t buf[CLOAK_FRAME_HEADER_LEN + 256 + CLOAK_FRAME_MAX_EXTRA_LEN];
    long written = cloak_frame_obfuscate(&sesh->obfuscator, &frame, buf, sizeof(buf), 0);
    if (written < 0) {
        return; /* best-effort -- local state is already torn down regardless, matching Go */
    }
    cloak_switchboard_send(&sesh->sb, buf, (size_t)written);
}

/* Fired by the SECOND of two chained 0ms timers -- see
 * session_deferred_teardown_cb's own comment for why the actual sweep is
 * split into its own timer instead of running inline after on_broken. */
static void session_teardown_sweep_cb(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_session_t *sesh = (cloak_session_t *)userdata;
    sesh->teardown_timer_id = CLOAK_TIMER_INVALID; /* this timer has now fired -- nothing left to cancel */
    session_free_all_active_streams(sesh);
    cloak_switchboard_close_all(&sesh->sb);
}

/* Fired by a 0ms reactor timer scheduled by session_passive_close/
 * cloak_session_close -- see session_schedule_deferred_teardown's own
 * comment for why every bit of actual teardown work lives here (across
 * this function and session_teardown_sweep_cb) instead of running
 * synchronously in session_close_internal.
 *
 * Schedules the actual sweep as a SEPARATE, second deferred timer
 * (session_teardown_sweep_cb) BEFORE calling on_broken below -- does not
 * do the sweep inline here. This is required, not stylistic:
 * cloak_session_broken_cb's own doc comment says it is safe to call
 * cloak_session_destroy synchronously from within on_broken, including
 * destroying AND freeing sesh's own storage before on_broken returns. If
 * that happens and this function still had code AFTER the on_broken call
 * that touched `sesh` (which an earlier version of this function did --
 * see this plan's Global Constraints, finding 7, the SEVENTH instance of
 * this module's recurring "freed object still has a live pointer above
 * it on the call stack" bug class, found during this plan's own final
 * whole-branch review, introduced by the very fix that closed finding 6),
 * that code would read/write freed memory the instant on_broken returns.
 *
 * Scheduling the sweep as its own timer FIRST closes this: if on_broken
 * destroys (and possibly frees) sesh, cloak_session_destroy's own
 * cloak_reactor_cancel_timer(sesh->reactor, sesh->teardown_timer_id) call
 * cancels THIS freshly-scheduled sweep timer -- synchronously, from
 * within on_broken, before sesh is ever freed and before this function's
 * own single remaining statement (calling on_broken) even returns. If
 * on_broken does NOT destroy sesh, the sweep timer simply fires normally
 * on the reactor's next tick, exactly as session_deferred_teardown_cb
 * used to do inline. Either way, nothing below the on_broken call in
 * THIS function may ever touch `sesh` again -- there is deliberately
 * nothing there. */
static void session_deferred_teardown_cb(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_session_t *sesh = (cloak_session_t *)userdata;
    sesh->teardown_timer_id = cloak_reactor_add_timer(sesh->reactor, 0, session_teardown_sweep_cb, sesh);
    if (sesh->on_broken) {
        sesh->on_broken(sesh, sesh->on_broken_userdata);
    }
    /* Do not add any code here -- see this function's own comment above
     * for why `sesh` must not be touched again past this point. */
}

/* Schedules the actual teardown -- freeing every stream's memory,
 * closing the connection pool, and firing on_broken -- for the reactor's
 * NEXT dispatch loop iteration, rather than performing any of it here.
 *
 * This is required, not just cautious: session_passive_close and
 * cloak_session_close can both be invoked REENTRANTLY, from deep inside
 * either a specific cloak_conn_t's own dispatch call chain (a
 * closing-session frame arriving mid-read, or a connection breaking
 * mid-write -- conn_reactor_cb -> ... -> session_on_envelope or
 * conn_mark_broken -> ... -> session_on_switchboard_broken -> here) OR a
 * specific cloak_stream_t's own write call chain (cloak_stream_write's
 * sink call cascading into a connection failure -- session's own
 * session_stream_sink_adapter -> cloak_switchboard_send -> cloak_conn_send
 * -> conn_mark_broken -> ... -> here -- while cloak_stream_write is still
 * on the stack above it, about to touch that same stream's fields again
 * once the sink call returns) OR from within cloak_session_close_stream/
 * cloak_session_release_stream's own call to cloak_stream_send_closing
 * (identical hazard, one frame later).
 *
 * If EITHER freeing every stream OR closing every connection ran
 * synchronously from any of those call chains, it would free memory a
 * live stack frame above this point still points into -- a
 * heap-use-after-free. This project has hit this exact class of bug six
 * times across this one module (see this plan's Global Constraints for
 * the full list); the first four were each patched at their own call
 * site, but the fifth and sixth (found during this plan's own design
 * verification, after this file's first draft had already "fixed" the
 * first four) are what led to deferring the ENTIRE teardown -- streams
 * included, not just connections -- as a single mechanism, rather than
 * chasing further call sites one at a time. Deferring to a 0ms timer is
 * the standard "close on next tick" pattern any single-threaded event
 * loop needs for this hazard: by the time session_deferred_teardown_cb
 * runs, every nested call from the triggering event has fully unwound
 * back to the reactor's own dispatch loop, so nothing is still holding a
 * live stack frame into anything this call is about to free. As a
 * consequence, on_broken is now ALSO guaranteed to fire outside of any
 * cloak_session_t/cloak_conn_t/cloak_stream_t callback's call stack --
 * safe for a consumer to call cloak_session_destroy synchronously from
 * within it.
 *
 * Because session_close_internal no longer touches any stream, a
 * consumer calling cloak_session_release_stream on a specific stream
 * during the (usually sub-millisecond) window between this call and the
 * deferred callback firing works correctly: that call tombstones and
 * frees just that one stream immediately, and the later deferred sweep's
 * cloak_strmtab_for_each_active simply no longer sees it (tombstoned
 * entries aren't ACTIVE), so it isn't touched twice.
 *
 * sesh->teardown_timer_id IS tracked and must be cancelled by
 * cloak_session_destroy (unlike this reasoning's own first draft, which
 * argued no cancellation was needed here -- that argument was wrong: it
 * assumed cloak_session_destroy always outlives this timer or the
 * reactor is destroyed first, but nothing enforces either. A caller that
 * heap-allocates a cloak_session_t, calls cloak_session_close, then
 * cloak_session_destroy, then frees its own storage -- all before ever
 * running the reactor again -- leaves this timer pointing at freed
 * memory once the reactor finally runs. This was the sixth instance of
 * this same bug class, also found during this plan's own design
 * verification.) */
static void session_schedule_deferred_teardown(cloak_session_t *sesh) {
    sesh->teardown_timer_id = cloak_reactor_add_timer(sesh->reactor, 0, session_deferred_teardown_cb, sesh);
}

static void session_passive_close(cloak_session_t *sesh) {
    if (!session_close_internal(sesh)) {
        return;
    }
    session_schedule_deferred_teardown(sesh);
}

static void session_on_switchboard_broken(cloak_switchboard_t *sb, void *userdata) {
    (void)sb;
    session_passive_close((cloak_session_t *)userdata);
}

static void session_on_envelope(cloak_switchboard_t *sb, const uint8_t *frame_bytes, size_t frame_len, void *userdata) {
    (void)sb;
    cloak_session_t *sesh = (cloak_session_t *)userdata;
    if (sesh->closed) {
        return;
    }

    cloak_frame_t frame;
    /* cloak_frame_deobfuscate decrypts in place -- frame_bytes points
     * into the originating cloak_conn_t's reused recv_scratch buffer,
     * valid only for this call, which is exactly the lifetime we need
     * here (we're done with it by the time this function returns). */
    if (cloak_frame_deobfuscate(&sesh->obfuscator, &frame, (uint8_t *)frame_bytes, frame_len) != 0) {
        return; /* corrupt/garbled frame -- Go just logs and continues (switchboard.deplex), not fatal */
    }

    if (frame.closing == CLOAK_FRAME_CLOSING_SESSION) {
        session_passive_close(sesh);
        return;
    }

    cloak_strmtab_state_t state;
    void *value;
    int found = cloak_strmtab_lookup(&sesh->streams, frame.stream_id, &state, &value);
    if (found && state == CLOAK_STRMTAB_TOMBSTONE) {
        return; /* late frame for an already-closed stream -- drop silently, matching Go */
    }

    if (found && state == CLOAK_STRMTAB_ACTIVE) {
        cloak_stream_t *stream = (cloak_stream_t *)value;
        int rc = cloak_stream_feed_frame(stream, &frame);
        if (rc == 1 || rc == -1) {
            /* rc == 1: closing frame drained into order -- passive
             * close. rc == -1: protocol violation on this one stream --
             * tear it down rather than leave it permanently stuck; does
             * not affect the rest of the session. Go has no equivalent
             * detection to react to here (its ordered-mode ring buffer
             * has no error return path for a bad seq at all) -- this is
             * a deliberate, documented improvement over a literal Go
             * translation, not a behavior Go itself exhibits.
             *
             * Either way: only RETIRE it here (stop routing, stop
             * counting) -- never free it from this call path. See
             * session_retire_stream and this task's own "Stream memory
             * ownership" note. */
            session_retire_stream(sesh, stream);
        }
        return;
    }

    /* Brand new stream_id -- nothing in strmtab yet. */
    cloak_session_stream_entry_t *entry =
        (cloak_session_stream_entry_t *)malloc(sizeof(cloak_session_stream_entry_t));
    if (entry == NULL) {
        return; /* allocation failure -- drop this frame */
    }
    entry->retired = 0;
    cloak_stream_t *stream = &entry->stream;
    if (cloak_stream_init(stream, frame.stream_id, &sesh->obfuscator,
                           sesh->max_on_wire_size, sesh->stream_recv_capacity,
                           sesh->stream_max_pending_frames,
                           session_stream_sink_adapter, sesh) != 0) {
        free(entry);
        return;
    }
    if (cloak_strmtab_insert_active(&sesh->streams, frame.stream_id, stream) != 0) {
        cloak_stream_destroy(stream);
        free(entry);
        return;
    }
    sesh->active_stream_count++;

    /* Feed the revealing frame (and retire this stream immediately if
     * that single frame already closes it or violates the protocol)
     * BEFORE invoking on_new_stream below -- not after. This order is
     * required, not stylistic: on_new_stream may reasonably call
     * cloak_session_release_stream on `stream` synchronously (it's
     * documented as safe to do so), which DOES free its memory right
     * then and there -- so this function must not touch `stream` again
     * once on_new_stream returns. (An earlier version of this comment
     * justified the same ordering by pointing at session_close_internal's
     * stream-freeing sweep, reasoning that on_new_stream might
     * synchronously call cloak_session_close and that sweep ran
     * synchronously too -- that sweep is now deferred (see this plan's
     * Global Constraints, finding 4), so that specific path is no longer
     * the live hazard, but this ordering is still required for the
     * cloak_session_release_stream reason above. Don't let this comment
     * go stale a second time: if you ever change what on_new_stream is
     * allowed to do, re-derive this reasoning from scratch rather than
     * assuming the sweep being deferred makes the ordering unnecessary.)
     * This also still matches Go's own actual ordering, where
     * newStream.recvFrame(frame) always runs (synchronously, in
     * recvDataFromRemote) before any consumer goroutine calling Accept()
     * could possibly observe the new stream via the channel send that
     * precedes it. */
    int rc = cloak_stream_feed_frame(stream, &frame);
    if (rc == 1 || rc == -1) {
        session_retire_stream(sesh, stream);
    }

    if (sesh->on_new_stream) {
        sesh->on_new_stream(sesh, stream, sesh->on_new_stream_userdata);
    }
}

int cloak_session_init(cloak_session_t *sesh, uint32_t id, cloak_reactor_t *reactor,
                        const cloak_session_config_t *config) {
    memset(sesh, 0, sizeof(*sesh));
    if (config->max_on_wire_size <= CLOAK_FRAME_HEADER_LEN + CLOAK_FRAME_MAX_EXTRA_LEN ||
        config->stream_recv_capacity == 0 ||
        config->stream_recv_capacity < config->max_on_wire_size - CLOAK_FRAME_HEADER_LEN ||
        config->conn_send_queue_cap == 0 ||
        config->max_on_wire_size > 65535) {
        return -1;
    }

    sesh->id = id;
    sesh->reactor = reactor;
    sesh->obfuscator = config->obfuscator;
    sesh->next_stream_id = 1; /* matches Go's MakeSession: nextStreamID starts at 1 */
    sesh->max_on_wire_size = config->max_on_wire_size;
    sesh->stream_recv_capacity = config->stream_recv_capacity;
    sesh->stream_max_pending_frames = config->stream_max_pending_frames;
    sesh->inactivity_timeout_ms = config->inactivity_timeout_ms;
    sesh->on_new_stream = config->on_new_stream;
    sesh->on_new_stream_userdata = config->on_new_stream_userdata;
    sesh->on_broken = config->on_broken;
    sesh->on_broken_userdata = config->on_broken_userdata;

    if (cloak_strmtab_init(&sesh->streams, 16) != 0) {
        return -1;
    }
    if (cloak_switchboard_init(&sesh->sb, reactor, config->max_on_wire_size, config->conn_send_queue_cap,
                                session_on_envelope, sesh, session_on_switchboard_broken, sesh) != 0) {
        cloak_strmtab_destroy(&sesh->streams);
        return -1;
    }

    session_reschedule_inactivity_timer(sesh);
    return 0;
}

void cloak_session_destroy(cloak_session_t *sesh) {
    session_close_internal(sesh); /* idempotent; no-op if already closed or never successfully initialized */
    /* Cancel any still-pending deferred teardown BEFORE freeing anything
     * below -- otherwise, if the reactor runs again later (after this
     * call returns but before it's destroyed), session_deferred_teardown_cb
     * would fire against memory this function is about to free/zero. See
     * session_schedule_deferred_teardown's own comment for the full
     * reasoning (this is what closes the sixth instance of this
     * project's recurring UAF class). */
    cloak_reactor_cancel_timer(sesh->reactor, sesh->teardown_timer_id);
    /* Synchronously free every remaining stream here -- safe only
     * because of this function's own documented calling contract (never
     * from within on_new_stream or any cloak_conn_t/cloak_stream_t
     * callback; only from ordinary code or from within on_broken, which
     * itself always runs outside any such callback's call stack). This
     * is the one place in this file allowed to call
     * session_free_all_active_streams synchronously. */
    session_free_all_active_streams(sesh);
    cloak_switchboard_destroy(&sesh->sb);
    cloak_strmtab_destroy(&sesh->streams);
    memset(sesh, 0, sizeof(*sesh));
}

int cloak_session_add_conn(cloak_session_t *sesh, int fd) {
    if (sesh->closed) {
        return -1;
    }
    return cloak_switchboard_add_conn(&sesh->sb, fd);
}

cloak_stream_t *cloak_session_open_stream(cloak_session_t *sesh, uint32_t *out_id) {
    if (sesh->closed) {
        return NULL;
    }
    uint32_t id = sesh->next_stream_id++;
    cloak_session_stream_entry_t *entry =
        (cloak_session_stream_entry_t *)malloc(sizeof(cloak_session_stream_entry_t));
    if (entry == NULL) {
        return NULL;
    }
    entry->retired = 0;
    cloak_stream_t *stream = &entry->stream;
    if (cloak_stream_init(stream, id, &sesh->obfuscator, sesh->max_on_wire_size,
                           sesh->stream_recv_capacity, sesh->stream_max_pending_frames,
                           session_stream_sink_adapter, sesh) != 0) {
        free(entry);
        return NULL;
    }
    if (cloak_strmtab_insert_active(&sesh->streams, id, stream) != 0) {
        cloak_stream_destroy(stream);
        free(entry);
        return NULL;
    }
    sesh->active_stream_count++;
    if (out_id) {
        *out_id = id;
    }
    return stream;
}

/* Sends the closing frame BEFORE retiring, matching Go's own order
 * (notify the peer, then clean up locally) -- this is safe, including
 * when cloak_stream_send_closing's sink call reentrantly triggers a full
 * session teardown (e.g. the connection it would have gone out on is
 * already dead), specifically BECAUSE session_close_internal no longer
 * touches any stream's memory (see session_schedule_deferred_teardown's
 * own comment) -- such a reentrant teardown only sets sesh->closed and
 * schedules a deferred callback; it cannot free `stream` out from under
 * this function. session_retire_stream below therefore always still
 * operates on valid memory, regardless of what cloak_stream_send_closing
 * triggered. (This was NOT true of an earlier draft of this file, before
 * session_close_internal's stream-freeing sweep was moved into the
 * deferred callback -- see this plan's Global Constraints for the full
 * incident.) */
int cloak_session_close_stream(cloak_session_t *sesh, cloak_stream_t *stream) {
    if (sesh->closed) {
        return -1;
    }
    cloak_session_stream_entry_t *entry = (cloak_session_stream_entry_t *)stream;
    if (entry->retired) {
        return -1; /* matches Go's errRepeatStreamClosing */
    }
    cloak_stream_send_closing(stream, CLOAK_FRAME_CLOSING_STREAM); /* best-effort -- proceed regardless, matching Go */
    session_retire_stream(sesh, stream);
    return 0;
}

void cloak_session_release_stream(cloak_session_t *sesh, cloak_stream_t *stream) {
    cloak_session_stream_entry_t *entry = (cloak_session_stream_entry_t *)stream;
    if (!entry->retired) {
        /* Releasing a still-open stream -- perform an implicit active
         * close first (send the closing frame, retire it), matching this
         * function's documented contract. Safe in the same way
         * cloak_session_close_stream's own comment explains above. */
        cloak_stream_send_closing(stream, CLOAK_FRAME_CLOSING_STREAM);
        session_retire_stream(sesh, stream);
    }
    cloak_stream_destroy(stream);
    free(entry);
}

int cloak_session_close(cloak_session_t *sesh) {
    if (!session_close_internal(sesh)) {
        return -1;
    }
    session_send_closing_session_frame(sesh);
    /* Deferred, not immediate -- see session_schedule_deferred_teardown's
     * own comment. cloak_session_close is documented as callable by
     * ordinary application code, but nothing stops a caller from also
     * calling it from within one of this session's own callbacks (e.g.
     * on_new_stream, reacting to an unwanted stream by closing the whole
     * session on the spot) -- which is exactly the same reentrant-free()
     * hazard passive close already has to guard against, so both paths
     * share the same fix. */
    session_schedule_deferred_teardown(sesh);
    return 0;
}

int cloak_session_is_closed(const cloak_session_t *sesh) {
    return sesh->closed;
}
```

Note on `cloak_session_close_stream`'s `sesh->closed` guard vs `entry->retired` guard: once the whole session is marked closed, its deferred teardown callback (`session_deferred_teardown_cb`) may or may not have fired yet -- and by the time it has, every still-ACTIVE stream's memory has been freed by `session_free_all_active_streams`. `cloak_session_close_stream` cannot tell these two cases apart without touching `stream`, which might already be freed in the second one -- so the `sesh->closed` check comes *first* and returns immediately whenever the session is closed at all, never dereferencing `stream` in that case regardless of whether the deferred sweep has actually run yet. `cloak_session_release_stream` has no equivalent guard by design -- see its own doc comment: it's meant to be safe to call on a stream whose session has since closed, which works because `entry->retired` was already set (by whichever teardown path retired it) before this session-level free could ever reach it, making the `cloak_strmtab_for_each_active`-driven sweep skip it entirely (tombstoned entries aren't ACTIVE) -- `stream`'s memory is therefore never touched by anything except this one `cloak_session_release_stream` call itself.

- [ ] **Step 5: Wire into CMake**

In `libcloak-mux/CMakeLists.txt`, add `src/session.c` to the `cloak-mux` library's sources.

In `libcloak-mux/tests/CMakeLists.txt`, append:
```cmake
add_executable(test_session test_session.c)
target_include_directories(test_session PRIVATE ${CMAKE_SOURCE_DIR}/libcloak-common/tests)
target_link_libraries(test_session PRIVATE cloak-mux)
add_test(NAME test_session COMMAND test_session)
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "rm -rf build && cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure"
```

```bash
docker run --rm -v "$(pwd)":/src -w /src cloak-c-dev bash -c "cmake -S . -B build-asan -DCMAKE_C_FLAGS='-fsanitize=address,undefined -g' -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined' && cmake --build build-asan && ctest --test-dir build-asan --output-on-failure"
```
Expected: all tests pass (including every prior task's tests, unaffected), zero warnings, clean under ASan/UBSan. This is the plan's full integration point -- if `test_session` passes clean under ASan/UBSan, the whole chain (strmtab → conn → switchboard → session, wired to real non-blocking sockets and a real reactor) is verified end-to-end.

- [ ] **Step 7: Commit**

```bash
git add libcloak-mux/include/cloak/session.h libcloak-mux/src/session.c libcloak-mux/tests/test_session.c libcloak-mux/CMakeLists.txt libcloak-mux/tests/CMakeLists.txt
git commit -m "Add session: stream lifecycle, frame routing, inactivity timeout"
```

---

## What comes after this plan

Per the master design spec (§7), the next module is the **server dispatcher and redirect-on-fail** (`dispatch_conn()`: sniff the first byte, run the auth handshake already merged in `libcloak-server`, attach the resulting connection to a `cloak_session_t` — new or existing, keyed by UID+session ID — or `goWeb()` to `RedirAddr` on failure). That module is what will finally give `cloak_session_t`/`cloak_switchboard_t` their real caller (currently only exercised by this plan's own tests) and is a separate future plan, not started by this one.

Also explicitly out of scope for this plan (per the master spec, deferred to their own future work): unordered/datagram mode (`datagramBufferedPipe` equivalent — `cloak_session_t` here only supports ordered-mode streams, matching this whole library's `cloak_stream_t` so far), rate limiting/QoS (`qos.go`'s `Valve` equivalent — this plan's `cloak_switchboard_send`/`cloak_conn_send` have no rate-limiting hook), and `Singleplex` mode (Go's single-stream-auto-closes-session option — not plumbed through `cloak_session_config_t` here; YAGNI until a caller needs it).

## Self-review notes

- **Spec coverage:** §6's four bullet points are covered: stream table + accept (Task 1 + Task 4's `on_new_stream`), switchboard/`uniformSpread` (Task 3), ordered-mode stream buffering (already merged `cloak_stream_t`, wired in Task 4), and the event-driven-splicing backpressure model (Task 2's `recv_acc`/`send_q` design, `EPOLLIN`/`EPOLLOUT` toggling). Unordered/datagram mode is explicitly out of scope per "What comes after this plan" above (§6 itself scopes it to when UDP-backed client sockets exist, which they don't yet).
- **Placeholder scan:** no TBD/TODO/"add error handling"-style steps; every step above contains complete, literal code.
- **Type consistency:** `cloak_conn_envelope_cb`/`cloak_conn_closed_cb` (Task 2) → `cloak_switchboard_envelope_cb`/`cloak_switchboard_broken_cb` (Task 3, distinct types, adapted via the two static adapter functions in `switchboard.c`) → `cloak_session_new_stream_cb`/`cloak_session_broken_cb` (Task 4) form a consistent three-layer callback chain, each layer's adapter functions shown in full in that layer's own task. `cloak_conn_send`/`cloak_switchboard_send` both return `int` (`0`/`-1`), matching `cloak_stream_frame_sink_t`'s existing `int` contract exactly (`session_stream_sink_adapter` in Task 4 forwards `cloak_switchboard_send`'s result unchanged, no translation needed). `uint32_t stream_id`/`frame->stream_id`/`cloak_strmtab` keys are `uint32_t` throughout, matching `cloak_frame_t.stream_id` and `cloak_stream_t.id` (already merged).
