#define _POSIX_C_SOURCE 200809L
#include "cloak/dispatcher.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "cloak/clienthello_parse.h"
#include "cloak/common.h"
#include "cloak/crypto.h"
#include "cloak/log.h"
#include "cloak/ws_frame.h"
#include "cloak/ws_handshake.h"

/* Forward-declared: armed both at accept (the first-packet read deadline)
 * and again in conn_on_firstpacket_done (the reply-write/hand-off
 * deadline), but its own natural home -- alongside on_readable, the other
 * reactor callback registered against a connection's fd -- is well after
 * both of those call sites. See its own doc comment, below. */
static void on_deadline(cloak_reactor_t *r, void *userdata);

/* ---- connection lifecycle helpers -------------------------------------- */

/* Fires cloak_dispatcher_config_t::session_aborted for (uid, session_id).
 *
 * THE prepare_session != NULL GUARD IS THE CONTRACT, not defensiveness:
 * cloak_dispatch_session_aborted_cb promises the owner that this fires
 * only for a session its own prepare_session actually prepared, so a
 * dispatcher configured without one must never fire it. At the two
 * authentication-path sites the "prepare_session returned 0" half of that
 * promise is guaranteed by position and by the `created` flag (a
 * prepare_session that returns -1 makes dispatcher_authenticate return
 * before anything can be created); at conn_teardown's site it is
 * guaranteed by auth_created, which is that same flag carried forward. */
static void conn_fire_session_aborted(cloak_dispatcher_t *d, const uint8_t uid[CLOAK_UID_LEN],
                                      uint32_t session_id) {
    if (d->cfg.session_aborted == NULL || d->cfg.prepare_session == NULL) {
        return;
    }
    d->cfg.session_aborted(d, uid, session_id, d->cfg.session_aborted_userdata);
}

/* Tells the panel that a user this connection made active (step 6's
 * cloak_userpanel_get_user / _get_bypass_user) did not, after all, end up
 * holding the session it was made active for.
 *
 * WHY THIS IS NOT cloak_dispatch_session_aborted_cb. That callback is the
 * OWNER's, the dispatcher has exactly one of it, and cloak_proxy_t already
 * holds it -- so it cannot also carry the panel's bookkeeping, and the
 * panel does not expose a function of that shape anyway. The dispatcher
 * holds the panel directly, so it tells it directly. The two notifications
 * are complementary, not alternatives: session_aborted reclaims the
 * owner's per-SESSION context, this reclaims the panel's per-USER entry,
 * and the sites that need both fire both.
 *
 * WHY IT IS A NO-OP MOST OF THE TIME, and why that is the point rather
 * than a weakness: cloak_userpanel_notify_session_closed deactivates a
 * user only when the registry says it now holds ZERO sessions. So a
 * connection that failed while its user still has other live sessions
 * (including the common "an additional connection to an existing session
 * failed") changes nothing, and only the case this function exists for --
 * a user made active moments ago whose one and only session never came to
 * be -- actually deactivates.
 *
 * WITHOUT IT the panel's own upload-cycle reaper (cloak/userpanel.h step
 * 4) still collects such an entry, so this is promptness, not
 * correctness: it closes the window from "up to one upload interval" (one
 * minute by default, during which a remote attacker can hold one active
 * table slot per distinct UID it can authenticate as) to "immediately".
 * Safe on a NULL panel, which is what every dispatcher configured without
 * one has. */
static void dispatcher_release_user(cloak_dispatcher_t *d, const uint8_t uid[CLOAK_UID_LEN]) {
    cloak_userpanel_notify_session_closed(d->cfg.panel, uid);
}

static void conn_unlink(cloak_dispatch_conn_t *c) {
    cloak_dispatcher_t *d = c->d;
    if (c->prev != NULL) {
        c->prev->next = c->next;
    } else {
        d->conns = c->next;
    }
    if (c->next != NULL) {
        c->next->prev = c->prev;
    }
    d->conn_count--;
    /* pending is cleared here for every path that removes a connection
     * from the list while it is still "pending" (mid first-packet,
     * mid-dial, mid-reply-write) -- peer-gone, a dial that never started,
     * a redirect/auth failure, a hand-off failure, or a successful
     * hand-off (conn_handoff's own success path unlinks immediately, so
     * this is also where THAT decrement happens). A connection that
     * already transitioned to relaying (see conn_start_redirect's own
     * comment on on_dial_done) already cleared pending there, so this is
     * a no-op for it -- guarded, not unconditional, specifically so this
     * can never double-decrement. */
    if (c->pending) {
        c->pending = 0;
        d->pending_count--;
    }
}

/* Cancels whatever this connection still has live (its deadline, an
 * in-progress dial, an in-progress relay) and closes whatever fd(s) it
 * still owns. Used both by the ordinary per-connection teardown paths
 * (conn_drop) and by cloak_dispatcher_destroy, which calls this on every
 * entry in its list before freeing it. Does NOT unlink c from the list or
 * free it -- callers that need that do it themselves, since
 * cloak_dispatcher_destroy walks (and discards) the whole list at once
 * rather than unlinking one node at a time. */
static void conn_teardown(cloak_dispatch_conn_t *c) {
    cloak_reactor_t *r = c->d->cfg.reactor;

    if (c->deadline != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(r, c->deadline);
        c->deadline = CLOAK_TIMER_INVALID;
    }

    /* If dispatcher_authenticate got as far as creating a brand-new
     * session for this connection (auth_created) but the connection
     * itself never completed hand-off to it -- a step-10 write failure,
     * a step-11 cloak_session_add_conn failure, the reply-write deadline
     * firing, or the whole dispatcher tearing down while this connection
     * was mid-reply-write -- that session would otherwise sit in the
     * registry forever with zero connections and nobody left who could
     * ever add one. Every one of those paths funnels through conn_drop
     * (hence here) rather than through conn_handoff's success branch,
     * which never calls this function at all (see on_relay_done's
     * sibling pattern) -- so this check never fires for a connection
     * that actually made it onto its session. auth_created is 0 for an
     * additional connection to an ALREADY-existing session, so this never
     * tears one of those down over one bad late-stage failure on its own
     * -- but auth_created == 1 alone is NOT enough: the session THIS
     * connection created is addressable by (uid, session_id) from the
     * moment cloak_server_registry_get_or_create returns, which is well
     * before this connection ever reaches hand-off, so another
     * connection with the same (uid, session_id) can find it and attach
     * (cloak_session_add_conn) while this one is still stuck in
     * writing_reply. Closing unconditionally on auth_created would then
     * take that other, already-attached connection down with it over
     * THIS connection's own unrelated late failure -- Go does not do
     * this (it only closes a session it just created, never one another
     * connection has since joined). So re-resolve by (uid, session_id)
     * -- never trust auth_sesh, a raw pointer that can already be
     * pointing at freed memory by the time this runs (see conn_handoff's
     * own comment for why) -- and require BOTH that the session is still
     * live AND that it is still empty (sesh->sb.conns_len == 0) before
     * closing it. If cloak_server_registry_find returns NULL the session
     * is already gone by some other path (e.g. its own inactivity timer
     * raced this one), so there is nothing left to close. Guarded so this
     * runs at most once even if conn_teardown is ever called twice on the
     * same c. */
    if (c->auth_created) {
        cloak_session_t *sesh =
            cloak_server_registry_find(c->d->cfg.registry, c->auth_uid, c->auth_session_id);
        if (sesh != NULL && sesh->sb.conns_len == 0) {
            /* SITE C of cloak_dispatch_session_aborted_cb. Fired BEFORE
             * the close, and only in the same branch as the close: the
             * owner's prepare_session built per-session state for this
             * (uid, session_id) and this is the last notification it will
             * ever get about it, since cloak_server_registry_close does
             * not fire on_broken (cloak/registry.h: it is the owner's own
             * action, not a failure). Before rather than after, so that
             * anything the owner still needs the session alive for --
             * releasing a stream, stopping a relay -- happens while it
             * is. The other two arms of this branch deliberately do not
             * fire it: a session another connection has since joined is
             * still live and still the owner's to keep, and one already
             * gone by another path has already had its on_broken. */
            conn_fire_session_aborted(c->d, c->auth_uid, c->auth_session_id);
            cloak_server_registry_close(c->d->cfg.registry, c->auth_uid, c->auth_session_id);
            /* The panel's half of the same unwind, and AFTER the close
             * for the reason dispatcher_authenticate's step-9 site gives:
             * the panel deactivates only when the registry reports zero
             * sessions. Inside this branch rather than under
             * auth_created alone, so that a session another connection
             * has since joined (the branch just above) does not
             * deactivate its own user out from under it. */
            dispatcher_release_user(c->d, c->auth_uid);
        }
        c->auth_created = 0;
    }

    if (c->relaying) {
        /* The relay owns both fds by now; stopping it closes both and
         * fires no completion callback (this is a teardown, not the
         * relay finishing on its own). c->fd must not be touched again. */
        cloak_relay_stop(&c->relay);
        c->relaying = 0;
        c->fd = -1;
    } else {
        if (c->dialing) {
            /* Guarantees the dial callback will NOT fire; c->fd (the
             * client fd, deregistered from the reactor before the dial
             * started -- see conn_start_redirect) is still ours and is
             * closed below. */
            cloak_dial_cancel(&c->dial);
            c->dialing = 0;
        }
        /* Covers the writing_reply case too: a connection mid-reply-write
         * has no dial or relay live, just an fd registered
         * CLOAK_REACTOR_WRITABLE, which this removes and closes exactly
         * like any other still-owned fd. */
        c->writing_reply = 0;
        if (c->fd >= 0) {
            /* A no-op (returns -1) if fd is not currently registered,
             * e.g. because we are mid-dial and already removed it --
             * safe either way, see cloak_reactor_remove_fd's own doc
             * comment. */
            cloak_reactor_remove_fd(r, c->fd);
            close(c->fd);
            c->fd = -1;
        }
    }
}

/* Tears c down, unlinks it, and frees it. The one function every
 * "something ended, and it is not a successful hand-off" path funnels
 * through. */
static void conn_drop(cloak_dispatch_conn_t *c) {
    conn_teardown(c);
    conn_unlink(c);
    free(c);
}

/* ---- authentication ------------------------------------------------------
 *
 * The maximum length cloak_server_auth_cert_lens can ever contain (see
 * cloak/server_auth.h's own CLOAK_SERVER_AUTH_REPLY_MAX_BYTES comment,
 * which derives the same number: 68). A stack buffer this size can hold
 * any cert length that constant offers, chosen uniformly per connection
 * below. */
#define DISPATCHER_MAX_FAKE_CERT_LEN 68

/* Steps 1-9 of the task-2 brief's authenticated path, in order, with the
 * reason each is where it is:
 *
 *  1. THE TRANSPORT BRANCH, and -- on the CDN path -- THE WHOLE UPGRADE
 *     VALIDATED IN ONE PASS BEFORE ANYTHING ELSE HAPPENS.
 *
 *     CLOAK_FIRSTPACKET_TRANSPORT_TLS takes step 2 below.
 *     CLOAK_FIRSTPACKET_TRANSPORT_WEBSOCKET takes cloak_ws_handshake_parse
 *     instead, which extracts the auth material from the `Hidden` header
 *     AND checks the method, `Connection`, `Upgrade`,
 *     `Sec-WebSocket-Version` and `Sec-WebSocket-Key` -- all of it, here,
 *     before step 6 authorises a UID or the panel is touched. Anything
 *     else redirects, exactly as an unrecognised protocol does.
 *
 *     THE ORDER IS THE POINT, AND IT DIVERGES FROM GO DELIBERATELY. Go
 *     splits the same work in two and runs it in the opposite order:
 *     processFirstPacket (internal/server/websocket.go:22-41) reads
 *     `hidden` and NOTHING else, dispatchConnection then authorises the
 *     UID, makes the user active and calls finishHandshake -- and only
 *     inside that does gorilla's Upgrader.Upgrade finally check
 *     `Connection`, `Sec-WebSocket-Key` and `Origin`. When that last
 *     check fails, websocketAux.go:129-138 returns WITHOUT sending on the
 *     unbuffered `finished` channel that websocket.go:47-50 is already
 *     blocked on, so the goroutine, the socket and the ActiveUser
 *     bookkeeping leak PERMANENTLY. Three reachable triggers were
 *     reproduced (module 8 scouting report, section 6.5): a CDN that
 *     rewrites `Connection`, one that regenerates a malformed
 *     `Sec-WebSocket-Key`, and one that injects an `Origin` header --
 *     each of which wedges every connection through that CDN.
 *
 *     Validating here makes a malformed upgrade an ordinary redirect,
 *     which is both the fix for that leak and the better mimicry: the
 *     origin must look identically like a web server whether the GET
 *     carried a bad `Hidden` or a bad `Upgrade`. Nothing below this point
 *     may branch on WHICH check refused -- see step 6's own paragraph on
 *     why every refusal on this path is one indistinguishable outcome.
 *  2. cloak_clienthello_parse over the already-framed record. TLS PATH
 *     ONLY; the CDN path has no ClientHello and gets the same three
 *     32-byte quantities out of the decoded `Hidden` payload instead
 *     (randPubKey || ciphertextWithTag, split 32/32/32 -- Go's own
 *     unmarshalHidden, internal/server/websocket.go:76-99, feeding the
 *     SAME decryption the TLS path uses at auth.go:37).
 *  3. cloak_server_check_replay against the RAW, not-yet-authenticated
 *     ch.random -- BEFORE any decryption, so a replayed handshake is
 *     rejected without the server doing any asymmetric work (both
 *     cloak/server.h and cloak/server_auth.h state this ordering; Go does
 *     the same).
 *  4. cloak_server_auth_decrypt. Everything in info is attacker-chosen
 *     until step 6 authorises info.uid.
 *  5. cloak_aead_method_is_valid on info.encryption_method BEFORE it is
 *     used for anything -- cloak/crypto.h requires this of any
 *     wire-sourced method byte. cloak_aead_overhead/cloak_aead_key_len
 *     are switch/default, not array indexing, so an unvalidated byte
 *     does not read out of bounds -- it silently degrades to whatever
 *     the default case returns (CLOAK_AEAD_TAG_LEN's zero-overhead
 *     branch aside, effectively AES-256-GCM's own sizes) instead of
 *     being rejected as the invalid method it is. That is still wrong
 *     enough on its own to check for explicitly: an attacker-chosen
 *     out-of-range byte would silently pick a real cipher's parameters
 *     for a session whose obfuscator.method field itself stores the
 *     invalid value, later reaching cloak_frame_obfuscate/deobfuscate
 *     with a method cloak_aead_seal/open were never validated against.
 *  6. AUTHORISE THE UID. With no panel (cfg.panel == NULL) this is
 *     cloak_server_is_bypass and nothing else -- the policy this module
 *     had before a user manager existed, and a legitimate deployment
 *     rather than a degraded one (see cloak_dispatcher_config_t::panel).
 *     With a panel it is Go's dispatchConnection, ported: a bypass UID
 *     takes cloak_userpanel_get_bypass_user (which never consults the
 *     database -- a bypass UID comes from the config file and may have no
 *     row at all), every other UID takes cloak_userpanel_get_user (which
 *     does: existence, up credit, down credit, expiry, in that order).
 *
 *     EVERY REFUSAL HERE IS THE SAME REFUSAL, and that is a security
 *     property, not tidiness. Unknown UID, expired, out of credit, and
 *     the active-user table being full all return -1 from exactly this
 *     one place, which sends the connection to conn_start_redirect on
 *     exactly the path an unrecognised protocol takes. No logging, no
 *     early close, no distinct branch: a prober holding no valid
 *     credentials must not be able to tell "no such user" from "not a
 *     Cloak server".
 *
 *     THE ONE DIFFERENCE THAT REMAINS IS A TIMING ONE, AND IT IS
 *     MEASURED RATHER THAN HAND-WAVED. A refusal HERE runs an X25519
 *     shared secret, an AES-GCM open and a SQLite lookup that a refusal
 *     at step 1 (an unparseable first packet, a rewritten `Connection`
 *     header) never reaches. On an idle host the two groups separate
 *     cleanly: step-1 refusals cluster at 175-205 us with a 3-9 us
 *     spread between them, while a step-6 refusal sits at 300-340 us --
 *     a ~130 us gap against a ~6 us intra-group spread. Under load they
 *     overlap entirely. libcloak-server/tests/test_dispatcher_ws.c
 *     prints both figures on every run.
 *
 *     IT IS INHERENT, and Go pays the same cost on the same path: any
 *     server with a user database does work for a plausible UID that it
 *     does not do for a malformed request. What bounds it is not the
 *     code but WHO CAN SEE IT. This transport's only leg is behind a
 *     CDN, so a remote prober's measurement passes through the CDN's own
 *     queuing, connection reuse and TLS variance -- orders of magnitude
 *     above 130 us, and not something more samples average away, because
 *     the noise is not independent of the probe. An attacker positioned
 *     to time the ORIGIN directly has already found the origin, which is
 *     the thing this transport exists to hide; at that point the side
 *     channel is not the exposure.
 *
 *     THE OBVIOUS CLOSURE IS A TRADE, NOT AN IMPROVEMENT, and is
 *     deliberately not taken: a jittered floor on conn_start_redirect's
 *     dial (say uniform 0-2 ms) would submerge the signal for a timer
 *     and no work, and unlike the other obvious idea -- running the
 *     database lookup on every refusal -- it hands an attacker no free
 *     query per junk byte. But it would also stop the origin's latency
 *     distribution looking like the web server it is pretending to be,
 *     which may be a worse fingerprint than the one it fixes. Nobody
 *     should add it without first measuring what the cover site's own
 *     distribution looks like.
 *
 *     WHAT STEP 6 OWES THE PANEL: cloak_userpanel_get_user makes the
 *     user ACTIVE, and cloak/userpanel.h requires that user to acquire
 *     its first session in the SAME reactor turn -- the upload cycle's
 *     reaper cannot distinguish an entry that has not got its session
 *     yet from one whose session went away silently. Steps 6 through 8
 *     are straight-line synchronous with no return to the reactor
 *     between them, which is what satisfies that; nothing may be
 *     inserted here that yields. The failures that CAN still happen in
 *     between (steps 7, 8 and 9) each call dispatcher_release_user,
 *     which tells the panel immediately rather than waiting for the
 *     reaper -- see that function's own comment.
 *
 *     6a. IS THIS AN ADMIN SESSION? A sub-step of 6 rather than a number
 *         of its own because it is the second half of the same question
 *         ("what is this UID getting?") and because renumbering 7-9 would
 *         make every cross-reference in this file and in cloak/
 *         dispatcher.h wrong. It is cloak_server_is_admin(srv, info.uid)
 *         AND info.session_id == 0 -- BOTH halves, because the admin UID
 *         with a non-zero session id is an ordinary session and Go says
 *         so in as many words (internal/server/dispatcher.go:200-202:
 *         "the distinction between going into the admin mode and normal
 *         proxy mode is that sessionID needs == 0 for admin mode").
 *
 *         ITS POSITION IS THE WHOLE POINT, and it is Go's: Go takes the
 *         admin branch at dispatcher.go:202, BEFORE consulting
 *         sta.ProxyBook[ci.ProxyMethod] at :217, and an admin session
 *         therefore never faces that lookup. That is not incidental.
 *         ck-client in admin mode (cmd/ck-client/ck-client.go:159-167)
 *         leaves ProxyMethod at whatever its config file says --
 *         "shadowsocks" by default -- so an operator whose client config
 *         names a method THIS server does not offer would otherwise be
 *         locked out of administering it, with a redirect to the cover
 *         site as the only diagnostic. Hence: decided here, before step
 *         7, and step 7 skipped for it.
 *
 *         It does NOT change authorisation. The admin UID is already in
 *         the bypass set (cloak_server_init folds it in), so step 6 has
 *         just routed it through cloak_userpanel_get_bypass_user and it
 *         carries a NULL valve -- Go's "unlimited QoS credits", and this
 *         port's D6: an admin session is not metered, not rate-limited,
 *         and has no row in the user database.
 *
 *         The verdict is published in info.is_admin (cloak/server_auth.h)
 *         and is the ONLY definition of "admin session" in this project:
 *         the owner's cloak_dispatch_prepare_session_cb reads it to
 *         choose between cloak_adminapi_t and cloak_proxy_t rather than
 *         re-deriving it, so the two cannot drift apart.
 *  7. cloak_server_lookup_proxy(info.proxy_method) must resolve -- FOR
 *     EVERY SESSION BUT AN ADMIN ONE, which skips this check entirely for
 *     the reason 6a gives. This task only checks existence; the address
 *     itself is a later task's concern.
 *
 *     WHAT THAT MEANS FOR AN OWNER WITH NO ADMIN API: a connection that
 *     skipped this check reaches prepare_session with a proxy method this
 *     server does not offer, and an owner that hands every session to
 *     cloak_proxy_prepare_session gets a -1 from it (proxy.c refuses an
 *     upstream it cannot resolve) and the same redirect this step would
 *     have produced. The refusal moves; it does not disappear.
 *  8. cloak_server_registry_find FIRST. If found, this is an additional
 *     connection to a session that already exists: THE LIVE-KEY RULE --
 *     compose the reply with sesh->obfuscator.session_key, never a fresh
 *     one (cloak/registry.h's own get_or_create doc comment explains why
 *     composing with fresh material here silently breaks every frame on
 *     this connection with no error at the handshake).
 *
 *     BUT NOT THE ORDERING MODE, WHICH IS CHECKED RATHER THAN INHERITED.
 *     info.unordered is decrypted and parsed like every other field of
 *     this connection's own auth record, and here it is COMPARED against
 *     the live session's mode: a disagreement is REFUSED (the ordinary
 *     redirect, plus cloak_dispatcher_t::ordering_mismatch_refusals and a
 *     log line), not spliced. Until module 9 this branch discarded the
 *     flag -- first connection wins, exactly as for the key -- which was
 *     harmless only while nothing read sesh->ordering. Once the two modes
 *     frame differently, a spliced connection's frames are interpreted
 *     under the SESSION's mode rather than its own, with no error at
 *     either end. A deliberate divergence from Go, which splices
 *     silently; no legitimate client can produce the disagreement, since
 *     all NumConn connections of one session carry the same flag. The
 *     check itself carries the full reasoning, and
 *     test_dispatcher_auth.c's
 *     test_second_connection_with_the_opposite_ordering_is_refused and
 *     test_second_connection_with_the_same_ordering_joins are the two
 *     halves that pin it.
 *     If not found:
 *
 *     8a. THE PER-USER SESSIONS CAP, asked only on this path and only of
 *         a metered user. Go asks it in exactly the same place
 *         (ActiveUser.GetSession calls AuthoriseNewSession only when it
 *         is about to make a session, and skips it entirely for a bypass
 *         user), and the position is load-bearing in both: an ADDITIONAL
 *         connection to an existing session is not a new session, so a
 *         user at its cap must still be able to open a second connection
 *         to a session it already holds -- checking the cap before the
 *         find would refuse that. The count comes from
 *         cloak_server_registry_count_for_uid, i.e. from the registry,
 *         which is the only record of what is actually alive (D6 in
 *         cloak/userpanel.h): a count kept anywhere else would disagree
 *         with it exactly during a teardown, which is when it matters.
 *         A refusal redirects like every other, via step 6's rule.
 *     8b. Generate a fresh key, build the session config from
 *         cfg.session_config_template plus the decrypted encryption
 *         method AND the authorised user's own valve (NULL for a bypass
 *         user and for a dispatcher with no panel, which cloak/valve.h
 *         defines as "not metered"). THE VALVE IS WHAT MAKES METERING
 *         EXIST AT ALL: without this line every session on the server is
 *         unmetered, every user's credit stays where it was, and nothing
 *         anywhere reports it.
 *     8c. Run the owner's prepare_session callback (if any), then
 *         cloak_server_registry_get_or_create.
 *  9. THE REPLY, whose SHAPE is the other thing the transport decides.
 *
 *     TLS: cloak_server_auth_compose_reply with a fresh nonce, a fresh
 *     pad4, and a cert length chosen uniformly from
 *     cloak_server_auth_cert_lens (a DPI-plausibility measure -- a fixed
 *     length would itself be a fingerprint). "Uniformly" is accurate as
 *     of the cloak_random_below fix and was not before it: the pick was a
 *     random byte modulo 7, skewed 1.028x, while the word said otherwise
 *     in two places in this file. The distribution is pinned by
 *     libcloak-common/tests/test_random.c. The 60 bytes that actually
 *     matter are SCATTERED across a fake ServerHello and followed by two
 *     more records.
 *
 *     CDN: the 101 response (cloak_ws_handshake_compose_101, over the
 *     accept computed from the key this request carried) immediately
 *     followed by ONE unmasked binary WebSocket frame carrying
 *     cloak_server_auth_compose_ws_reply's flat 60 bytes -- 129 + 2 + 60
 *     = 191 bytes in ONE c->reply buffer. That coalescing is deliberate
 *     and it is safe for a measured reason, not a hopeful one: a gorilla
 *     client handles a single write carrying both, because
 *     http.ReadResponse reads the 101 from the same buffered reader the
 *     frame reader then continues from. Step 10 does not care either way
 *     -- it is a send() loop over an opaque byte buffer -- so the CDN
 *     path needs no new write machinery, only different bytes.
 *
 *     But coalescing is an OPTIMISATION, not a correctness requirement,
 *     and that distinction was measured rather than assumed: a gorilla
 *     client also accepts the same bytes split 129|62 with a 5 ms gap,
 *     split every 40 bytes with 5 ms gaps, and split 129|62 with a
 *     100 ms gap. Only REVERSING the order fails, which is the control
 *     that gives those passes meaning. So a future change that splits
 *     this write -- a partial send(), a different buffer strategy -- is
 *     not a protocol break. Do not read the paragraph above as a reason
 *     the two pieces must travel together; they must only travel in
 *     order.
 *
 * On success, fills c->reply/reply_len and c->auth_* (consumed by
 * conn_continue_reply_write and conn_handoff, steps 10-11) and returns 0.
 * On any failure this function returns -1 having left the connection
 * exactly as it found it (redirectable) EXCEPT for two things. First, if
 * step 8 created a brand-new session and a LATER step in this same
 * function (only step 9 can fail after that point) then fails, that
 * session is torn down here, via cloak_server_registry_close, before
 * returning -- matching cloak/registry.h's "created == 1 is the only
 * correct discriminator" guidance. A failure at or before step 8's create
 * never has a session to unwind. Second, every failure AFTER step 6 has
 * made a user active calls dispatcher_release_user, so the panel does not
 * carry an active user that never got a session until its reaper notices;
 * that call is a no-op whenever the user still holds sessions, so it is
 * unconditional at each site rather than guarded by a flag that would
 * have to be kept in step with five returns. */
static int dispatcher_authenticate(cloak_dispatch_conn_t *c) {
    cloak_dispatcher_t *d = c->d;
    cloak_server_t *srv = d->cfg.srv;

    /* 1+2. The transport branch, and with it everything the wire format
     * decides. Both arms end with the same three 32-byte quantities --
     * the value the replay cache registers and the two halves of the
     * 64-byte ciphertext+tag -- so steps 3 through 8 below are literally
     * the same code for both transports, which is the point of arranging
     * it this way rather than forking the whole function. */
    cloak_clienthello_parsed_t ch;
    cloak_ws_hs_t hs;
    const uint8_t *auth_random;
    const uint8_t *auth_session_id_field;
    size_t auth_session_id_field_len;
    const uint8_t *auth_key_share_field;

    /* Zeroed, not left indeterminate: hs.accept is read at step 9 only
     * on the CDN arm, and a reader should not have to re-derive that to
     * know this is safe. It costs 125 bytes of memset per handshake. */
    memset(&hs, 0, sizeof(hs));

    if (c->fp.transport == CLOAK_FIRSTPACKET_TRANSPORT_TLS) {
        if (cloak_clienthello_parse(cloak_firstpacket_data(&c->fp), cloak_firstpacket_len(&c->fp),
                                    &ch) != 0) {
            return -1;
        }
        auth_random = ch.random;
        auth_session_id_field = ch.session_id;
        auth_session_id_field_len = ch.session_id_len;
        auth_key_share_field = ch.x25519_key_share;
    } else if (c->fp.transport == CLOAK_FIRSTPACKET_TRANSPORT_WEBSOCKET) {
        /* THE WHOLE UPGRADE, HERE, BEFORE ANY UID IS AUTHORISED -- see
         * this function's own step-1 comment for the Go leak this
         * ordering exists to avoid.
         *
         * EVERY NON-OK CODE IS THE SAME OUTCOME, and that is a
         * REQUIREMENT this comparison exists to satisfy, not a
         * convenience. Do not turn it into a switch, a log line, a
         * counter or an early close, however tempting a diagnosis
         * becomes. cloak_ws_handshake_parse is deliberately STRICTER
         * than Go in exactly one place -- it refuses bare-LF line
         * endings that Go's net/http accepts and answers 101 to
         * (measured; see test_ws_handshake.c's
         * test_bare_lf_line_endings_are_refused) -- and that divergence
         * was waived on the sole condition that nothing downstream can
         * tell CLOAK_WS_HS_ERR_MALFORMED from CLOAK_WS_HS_ERR_BAD_HIDDEN.
         * Bare LF is the one input class that separates them. The moment
         * this branch distinguishes them, a prober can identify a Cloak
         * origin by sending a bare-LF upgrade and comparing the answer
         * to a plain web server's, and a harmless strictness becomes a
         * live fingerprint. test_dispatcher_ws.c's
         * test_three_refusals_are_indistinguishable carries a bare-LF
         * arm for precisely this, and asserts its bytes and its timing
         * against the others. */
        if (cloak_ws_handshake_parse(cloak_firstpacket_data(&c->fp), cloak_firstpacket_len(&c->fp),
                                     &hs) != CLOAK_WS_HS_OK) {
            return -1;
        }
        /* Go's unmarshalHidden split (internal/server/websocket.go:76-99):
         * hidden[0:32) is randPubKey -- both the ECDH input and the value
         * the replay cache registers -- and hidden[32:96) is the 64-byte
         * ciphertext+tag, which the TLS path happens to carry as two
         * separate ClientHello fields. Passing it as the same two halves
         * is what lets the SAME cloak_server_auth_decrypt serve both. */
        auth_random = hs.hidden;
        auth_session_id_field = hs.hidden + 32;
        auth_session_id_field_len = 32;
        auth_key_share_field = hs.hidden + 64;
    } else {
        /* CLOAK_FIRSTPACKET_TRANSPORT_UNKNOWN. Not reachable from
         * cloak_firstpacket_t, which reports ERROR rather than DONE for
         * an unrecognised first byte and never reaches this function --
         * kept because "the enum grew a third real transport and this
         * defaulted into one of the other two" is a strictly worse
         * failure than a redirect. */
        return -1;
    }

    int64_t now = (int64_t)time(NULL);

    /* 3. Replay, against the raw random, before decrypting. */
    if (cloak_server_check_replay(srv, auth_random, now)) {
        return -1;
    }

    /* 4. Decrypt. */
    cloak_server_clientinfo_t info;
    uint8_t shared_secret[CLOAK_AEAD_KEY_LEN];
    if (cloak_server_auth_decrypt(auth_random, auth_session_id_field, auth_session_id_field_len,
                                  auth_key_share_field, srv->cfg->private_key, now, &info,
                                  shared_secret) != 0) {
        return -1;
    }

    /* 5. Validate the wire-sourced method byte before it is used for
     * anything at all. */
    if (!cloak_aead_method_is_valid((cloak_aead_method_t)info.encryption_method)) {
        return -1;
    }

    /* 6. Authorise the UID. Every arm that refuses returns -1 from here
     * and does nothing else -- see this function's own step-6 comment
     * for why all four refusal reasons must be one indistinguishable
     * outcome. */
    cloak_userpanel_user_t *user = NULL;
    int is_bypass = cloak_server_is_bypass(srv, info.uid);
    if (d->cfg.panel == NULL) {
        if (!is_bypass) {
            return -1;
        }
    } else if (is_bypass) {
        if (cloak_userpanel_get_bypass_user(d->cfg.panel, info.uid, &user) != 0) {
            return -1;
        }
    } else {
        if (cloak_userpanel_get_user(d->cfg.panel, info.uid, &user) != 0) {
            return -1;
        }
    }

    /* 6a. THE ADMIN DECISION, made here and nowhere else -- see this
     * function's own step-6a comment for why it sits BEFORE step 7 and
     * why both halves of the test are required. */
    info.is_admin = cloak_server_is_admin(srv, info.uid) && info.session_id == 0;

    /* 7. Proxy method must be known -- except for an admin session, which
     * never had one to offer: it skips this check exactly as Go's admin
     * branch skips its ProxyBook lookup. The resolved address itself is a
     * later task's concern. */
    if (!info.is_admin && cloak_server_lookup_proxy(srv, info.proxy_method) == NULL) {
        dispatcher_release_user(d, info.uid);
        return -1;
    }

    /* 8. Find, then (only if not found) create. */
    int created = 0;
    uint8_t session_key[CLOAK_AEAD_KEY_LEN];
    cloak_session_t *sesh = cloak_server_registry_find(d->cfg.registry, info.uid, info.session_id);
    if (sesh != NULL) {
        /* THE LIVE-KEY RULE: an existing session's config (obfuscator
         * included) was fixed at whatever creation first used -- read
         * ITS key back out rather than generating a fresh one. See
         * cloak/registry.h's own get_or_create doc comment.
         *
         * AND THE ORDERING MODE IS NOT FIXED THE SAME WAY: it is CHECKED,
         * and a disagreement is REFUSED. Until this module that was the
         * live-key rule's exact analogue -- info.unordered was decrypted,
         * parsed, and discarded, so the first connection's mode won for
         * every later one. For the KEY that is right: a session has one
         * obfuscator and a joining connection must use it. For the MODE
         * it is not, and the difference is that the key is something the
         * connection can be made to agree with, while the mode is
         * something it has already committed to. A connection that framed
         * datagrams joining a session that reassembles byte streams (or
         * the mirror) has every one of its frames interpreted under the
         * SESSION's mode, with no error at either end and corruption as
         * the first symptom.
         *
         * A LEGITIMATE PEER CANNOT REACH THIS. All NumConn connections of
         * one Cloak session carry the same flag, because it comes from
         * one client's one config -- so refusing costs nothing against an
         * honest peer and turns a silent misinterpretation into an
         * immediate failure against a broken or hostile one. This is a
         * DELIBERATE DIVERGENCE from Go, whose ActiveUser.GetSession
         * returns the existing session and drops the joining connection's
         * own SessionConfig on the floor.
         *
         * THE REFUSAL IS THE ORDINARY REDIRECT, indistinguishable from
         * the one a bad UID gets -- see step 6's comment for why every
         * refusal this function makes must look alike from outside. The
         * diagnosis is therefore operator-side only: the counter below
         * and, at DEBUG, the line beside it. Asserted by
         * test_dispatcher_auth.c's
         * test_second_connection_with_the_opposite_ordering_is_refused,
         * with test_second_connection_with_the_same_ordering_joins
         * bounding it on the other side so it cannot decay into "refuse
         * every additional connection".
         *
         * AND THE LOG IS AT DEBUG BECAUSE A WARN HERE WAS A TIMING
         * ORACLE -- measured, not feared. This line shipped at
         * CLOAK_LOGW for one round, and a review timed 150 refusals per
         * arm through this very function: an ordering mismatch came back
         * 13-18 microseconds slower at p10 than an unauthorised UID, 3
         * runs out of 3, and suppressing the line alone made the two
         * distributions coincide to within half a microsecond. The cause
         * is not the registry lookup, it is the write: cloak_log_write is
         * an fprintf to unbuffered stderr, i.e. a blocking write(2) from
         * inside a reactor callback, and behind a slow consumer it is
         * much worse than 18 us. It was also the ONLY log on any refusal
         * path in this file -- every other refusal here (bad UID, replay,
         * stale timestamp, unknown method, the caps) says nothing -- and
         * it was unthrottled, one line per probe.
         *
         * So the whole argument for making this refusal look like every
         * other one rested on a line that made it measurably different.
         * At DEBUG nothing is emitted at the shipping level, and a
         * deployment that turns DEBUG on is noisy enough everywhere else
         * that a comparison between two refusal paths means nothing.
         * test_second_connection_with_the_opposite_ordering_is_refused
         * captures the log stream across the refusal and asserts it stays
         * EMPTY, so a future line added here fails a test rather than
         * quietly reintroducing the oracle. */
        cloak_session_ordering_t asked = info.unordered ? CLOAK_SESSION_ORDERING_UNORDERED
                                                        : CLOAK_SESSION_ORDERING_ORDERED;
        if (sesh->ordering != asked) {
            d->ordering_mismatch_refusals++;
            CLOAK_LOGD("dispatcher: refusing a connection to session %u -- it asked for %s while "
                       "the live session is %s; no legitimate client varies this flag between the "
                       "connections of one session",
                       info.session_id, asked == CLOAK_SESSION_ORDERING_UNORDERED ? "unordered"
                                                                                  : "ordered",
                       sesh->ordering == CLOAK_SESSION_ORDERING_UNORDERED ? "unordered"
                                                                          : "ordered");
            /* Step 6 may have made this user active for a session this
             * connection is not going to get; the panel is still owed the
             * news, exactly as on step 7's refusal. */
            dispatcher_release_user(d, info.uid);
            return -1;
        }
        memcpy(session_key, sesh->obfuscator.session_key, CLOAK_AEAD_KEY_LEN);
    } else {
        /* 8a. The per-user sessions cap. `user` is NULL for a dispatcher
         * with no panel (no policy to ask) and user->bypass is set for a
         * bypass UID (no row to ask about, and Go skips the question for
         * the same reason) -- in both cases there is nothing to check and
         * the manager is never touched. Note that user->bypass, not
         * is_bypass, is what governs: cloak_userpanel_get_bypass_user
         * returns an ALREADY-ACTIVE non-bypass user unchanged rather than
         * silently un-metering it mid-flight, and such a user is still
         * subject to its own cap. */
        if (user != NULL && !user->bypass) {
            size_t existing = cloak_server_registry_count_for_uid(d->cfg.registry, info.uid);
            if (cloak_usermanager_authorise_new_session(cloak_userpanel_manager(d->cfg.panel),
                                                        info.uid, (int)existing) != 0) {
                dispatcher_release_user(d, info.uid);
                return -1;
            }
        }

        /* 8b. */
        cloak_random_bytes(session_key, sizeof(session_key));

        cloak_session_config_t session_cfg = d->cfg.session_config_template;
        session_cfg.obfuscator.method = (cloak_aead_method_t)info.encryption_method;
        memcpy(session_cfg.obfuscator.session_key, session_key, CLOAK_AEAD_KEY_LEN);
        /* THE ORDERING MODE. Per-SESSION and declared by the CLIENT, in
         * the flag byte of the auth record step 5 just decrypted, so --
         * exactly like the obfuscator and the valve around it -- it can
         * never come from the template: one server serves ordered and
         * unordered clients at the same time. Deriving it here is what
         * makes a session's mode structurally equal to the mode its peer
         * asked for rather than equal by coincidence.
         *
         * THIS FIELD IS NOW READ ALL THE WAY DOWN, which it was not when
         * this comment was first written: cloak_stream_t frames one
         * datagram per write and reassembles nothing, the proxy splices
         * an unordered stream to a datagram upstream with
         * cloak_dgram_relay_t, and nothing anywhere refuses an unordered
         * client for being one -- cloak_proxy_prepare_session's old
         * obligation 5, which used to redirect them at step 8c below, is
         * gone (see cloak/proxy.h for what replaced it). An admin session
         * that set the flag is still built UNORDERED here, which is the
         * honest record of what the client asked for and is now carried
         * through by cloak_adminapi_t rather than being inert. The one
         * refusal that exists is at step 8's OTHER branch, for a
         * connection joining a session in the opposite mode. See
         * cloak/ordering.h. */
        session_cfg.ordering = info.unordered ? CLOAK_SESSION_ORDERING_UNORDERED
                                              : CLOAK_SESSION_ORDERING_ORDERED;
        /* THE METER. Per-USER (it is the panel's, shared by every session
         * that user holds) installed into a per-SESSION config, which is
         * why it is set here and can never come from the template. NULL
         * -- a bypass user, or no panel at all -- is cloak/valve.h's
         * "not metered" and costs one predicted branch per transfer. */
        session_cfg.valve = cloak_userpanel_user_valve(user);

        /* 8c. */
        if (d->cfg.prepare_session != NULL &&
            d->cfg.prepare_session(d, &info, &session_cfg, d->cfg.prepare_session_userdata) != 0) {
            /* No session was created -- but step 6 may have made a user
             * active for one, so the panel is still owed the news. */
            dispatcher_release_user(d, info.uid);
            return -1;
        }

        sesh = cloak_server_registry_get_or_create(d->cfg.registry, info.uid, info.session_id,
                                                    &session_cfg, &created);
        if (sesh == NULL) {
            /* Resource limit or cloak_session_init/allocation failure --
             * cloak/registry.h documents *out_created as untouched here,
             * and indeed nothing was created either way.
             *
             * SITE A of cloak_dispatch_session_aborted_cb, and the one
             * place where "prepare_session already ran and returned 0" is
             * guaranteed purely by position: the call is three lines up,
             * and its -1 path returned. Nothing here will ever be in the
             * registry, so no on_broken can ever fire for it -- without
             * this, whatever prepare_session allocated is orphaned, once
             * per handshake, for as long as the registry stays full. */
            conn_fire_session_aborted(d, info.uid, info.session_id);
            dispatcher_release_user(d, info.uid);
            return -1;
        }
    }

    /* 9. Compose the reply, in whichever of the two shapes this
     * transport wants -- see this function's own step-9 comment. */
    long n;
    if (c->fp.transport == CLOAK_FIRSTPACKET_TRANSPORT_WEBSOCKET) {
        /* ONE BUFFER, TWO PIECES: the 101, then a single unmasked binary
         * frame. Composed head-first so that a short c->reply (which
         * cannot happen -- 191 against
         * CLOAK_SERVER_AUTH_REPLY_MAX_BYTES' 256 -- but is still checked
         * by each writer) refuses before anything is sealed. */
        ssize_t r101 =
            cloak_ws_handshake_compose_101(c->reply, sizeof(c->reply), hs.accept);
        uint8_t ws_payload[CLOAK_SERVER_AUTH_WS_REPLY_LEN];
        ssize_t hdr = -1;
        if (r101 > 0 &&
            cloak_server_auth_compose_ws_reply(ws_payload, session_key, shared_secret) == 0) {
            /* The codec writes it, rather than this file spelling out
             * 0x82 0x3C: one place decides what a Cloak WebSocket frame
             * header looks like, and libcloak-mux/tests/test_ws_frame.c
             * is where that decision is pinned against the RFC. NULL
             * mask key -- RFC 6455 section 5.1 forbids a server masking,
             * and gorilla hangs up on one that does. */
            hdr = cloak_ws_frame_write_header(c->reply + r101, sizeof(c->reply) - (size_t)r101,
                                              CLOAK_WS_OP_BINARY, 1, NULL,
                                              CLOAK_SERVER_AUTH_WS_REPLY_LEN);
        }
        if (r101 > 0 && hdr > 0 &&
            (size_t)r101 + (size_t)hdr + CLOAK_SERVER_AUTH_WS_REPLY_LEN <= sizeof(c->reply)) {
            memcpy(c->reply + r101 + hdr, ws_payload, CLOAK_SERVER_AUTH_WS_REPLY_LEN);
            n = (long)((size_t)r101 + (size_t)hdr + CLOAK_SERVER_AUTH_WS_REPLY_LEN);
        } else {
            n = -1;
        }
    } else {
        uint8_t reply_nonce[CLOAK_AEAD_NONCE_LEN];
        uint8_t pad4[4];
        cloak_random_bytes(reply_nonce, sizeof(reply_nonce));
        cloak_random_bytes(pad4, sizeof(pad4));

        /* cloak_random_below, not `one_random_byte % 7`. Go picks with
         * possibleCertLengths[common.RandInt(len(possibleCertLengths))]
         * (internal/server/TLS.go:48), which is uniform; 256 = 7*36 + 4,
         * so the byte-modulo this line used to be drew four of the seven
         * lengths 37/256 = 14.453 % of the time and the other three
         * 36/256 = 14.063 %. A 1.028x ratio -- visible only to a prober
         * willing to collect tens of thousands of cover-site replies, and
         * fixed here anyway because it is the same defect as
         * libcloak-mux/src/frame.c's padding length (2.009x, and that one
         * mattered) and the word "uniformly" appears twice in this file's
         * own prose above. See cloak/common.h. */
        size_t cert_len =
            cloak_server_auth_cert_lens[cloak_random_below(CLOAK_SERVER_AUTH_CERT_LEN_COUNT)];
        uint8_t fake_cert[DISPATCHER_MAX_FAKE_CERT_LEN];
        cloak_random_bytes(fake_cert, cert_len);

        n = cloak_server_auth_compose_reply(shared_secret, session_key, reply_nonce, ch.session_id,
                                            pad4, fake_cert, cert_len, c->reply,
                                            sizeof(c->reply));
    }
    if (n <= 0) {
        /* Unwind: this is the one failure in this function that can
         * happen AFTER step 8 created a session. created == 1 is the
         * only correct discriminator -- see this function's own
         * top-of-task comment and cloak/registry.h. */
        if (created) {
            /* SITE B of cloak_dispatch_session_aborted_cb, fired before
             * the close for the same reason site C's is: this close does
             * not fire on_broken, so this is the owner's only
             * notification, and it wants the session still alive while it
             * runs. `created` is what proves prepare_session ran and
             * returned 0 -- the existing-session path never calls it. */
            conn_fire_session_aborted(d, info.uid, info.session_id);
            cloak_server_registry_close(d->cfg.registry, info.uid, info.session_id);
        }
        /* AFTER the close above, never before: the panel deactivates a
         * user only once the registry reports zero sessions for it, so a
         * notification sent while the session this function just closed
         * was still in the table would be a silent no-op. Outside the
         * `created` guard, because the existing-session path can also
         * reach here and a release there is correctly a no-op (that
         * session is still live). */
        dispatcher_release_user(d, info.uid);
        return -1;
    }

    c->reply_len = (size_t)n;
    c->reply_sent = 0;
    /* WHAT STEP 11 MUST WRAP THIS SOCKET IN, decided here, where the
     * transport is already in hand, rather than re-derived from
     * c->fp.transport at the hand-off. Two reasons, and the second is
     * the load-bearing one: there is then exactly one place in this file
     * that maps a transport onto a framing mode, and the WRONG mapping
     * is invisible to every round-trip test, because both ends agree
     * whichever one they pick (cloak/conn.h's cloak_conn_framing_t says
     * so at length). A TLS_RECORD conn on a WebSocket connection emits
     * 0x17 0x03 0x03 <len> INSIDE a binary frame -- wire-incompatible
     * with Go, and a perfect Cloak signature to anyone who can read
     * inside the CDN's TLS. */
    c->auth_framing = c->fp.transport == CLOAK_FIRSTPACKET_TRANSPORT_WEBSOCKET
                          ? CLOAK_CONN_FRAMING_WS_SERVER
                          : CLOAK_CONN_FRAMING_TLS_RECORD;
    c->auth_created = created;
    c->auth_info = info;
    memcpy(c->auth_uid, info.uid, CLOAK_UID_LEN);
    c->auth_session_id = info.session_id;
    return 0;
}

/* ---- redirect path ------------------------------------------------------ */

static void on_relay_done(cloak_relay_t *rl, void *userdata) {
    (void)rl;
    cloak_dispatch_conn_t *c = userdata;
    /* The relay already closed both fds; it does not touch c->fd, which
     * this connection stopped owning the moment it handed both
     * descriptors to cloak_relay_start (see on_dial_done). */
    c->relaying = 0;
    conn_unlink(c);
    free(c);
}

static void on_dial_done(cloak_dial_t *dial, int fd, void *userdata) {
    (void)dial;
    cloak_dispatch_conn_t *c = userdata;
    c->dialing = 0;

    if (fd < 0) {
        /* Nothing to forward to: close, matching the property this whole
         * module protects everywhere else it can (redirect) except here,
         * where redirecting is exactly what just failed. */
        conn_drop(c);
        return;
    }

    int client_fd = c->fd;
    /* Ownership of the client fd passes to the relay now, unconditionally
     * -- set the sentinel before the call that might fail, so that if it
     * does fail, the explicit close() below is the only thing that will
     * ever touch this fd again. */
    c->fd = -1;

    if (cloak_relay_start(&c->relay, c->d->cfg.reactor, client_fd, fd,
                          cloak_firstpacket_data(&c->fp), cloak_firstpacket_len(&c->fp),
                          c->d->cfg.relay_buf_cap, on_relay_done, c) != 0) {
        /* cloak_relay_start's own contract: on failure neither descriptor
         * is closed and neither is left registered with the reactor --
         * we still own both and must close them ourselves rather than
         * leave the client hanging. */
        close(client_fd);
        close(fd);
        conn_unlink(c);
        free(c);
        return;
    }
    c->relaying = 1;
    /* THE CAP'S OTHER HALF: this connection now has a live relay, and a
     * live relay is bounded the same way a real web server's own
     * connections are -- two descriptors and the relay's own buffers,
     * against the process's descriptor limit -- not by max_pending_conns.
     * It stops counting against the cap HERE, while it stays linked in
     * d->conns (for teardown -- see cloak/dispatcher.h's own OWNERSHIP
     * comment) for as long as the relay runs. See
     * CLOAK_DISPATCHER_DEFAULT_MAX_PENDING_CONNS's own comment in
     * cloak/dispatcher.h for why counting relaying connections against
     * this cap would itself be a remotely triggerable denial of service:
     * an attacker who gets max_pending_conns connections redirected and
     * then holds every one of them open (trivial: control the peer that
     * receives the relay) would otherwise permanently starve every
     * legitimate client of a slot, which is a strictly worse failure than
     * the memory exhaustion this cap exists to prevent. */
    if (c->pending) {
        c->pending = 0;
        c->d->pending_count--;
    }
}

/* MUST NEVER be reached with c->auth_created set. Every failure path in
 * this function (redir-addr lookup, cloak_dial_start) frees c via
 * conn_unlink+free (through conn_drop) WITHOUT going through
 * conn_teardown's auth_created check -- unlike conn_drop's OTHER callers,
 * which all route through conn_teardown first. This is safe today only
 * because nothing that has already created a session (auth_created == 1
 * is set exclusively by dispatcher_authenticate, step 8, deep inside the
 * authenticated path) can also reach this function: dispatcher_authenticate
 * either succeeds and this connection proceeds to reply-write/hand-off, or
 * it fails before step 8 ever creates anything, or it fails after step 8
 * and unwinds the session itself before returning -1 (see its own
 * top-of-function comment). If a future change ever calls this function
 * for a connection with auth_created == 1, the session it created leaks
 * silently: it stays in the registry forever, with zero connections and
 * nobody left who could ever add one, and this function's own callers
 * would never notice. */
static void conn_start_redirect(cloak_dispatch_conn_t *c) {
    cloak_dispatcher_t *d = c->d;

    /* Cancel the deadline first: from this point on the connection is no
     * longer "reading its first packet", regardless of what happens
     * next, and nothing past here should be raced by that timer firing. */
    if (c->deadline != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(d->cfg.reactor, c->deadline);
        c->deadline = CLOAK_TIMER_INVALID;
    }

    cloak_addr_t addr;
    if (cloak_server_redir_addr(d->cfg.srv, c->local_port, &addr) != 0) {
        /* Only reachable if srv or addr were NULL, neither of which is
         * possible here (cloak_dispatcher_init requires a non-NULL srv,
         * and addr is a local). Handled anyway: there is nowhere to
         * forward to, so close rather than hang. */
        conn_drop(c);
        return;
    }

    /* Deregister the client fd; the relay (on dial success) re-registers
     * it itself. Bytes already sitting in the kernel's receive buffer for
     * it are not lost -- EPOLL_CTL_ADD on an already-ready fd still
     * enqueues a fresh event even under edge-triggered mode. */
    cloak_reactor_remove_fd(d->cfg.reactor, c->fd);

    if (cloak_dial_start(&c->dial, d->cfg.reactor, &addr, d->cfg.redirect_dial_timeout_ms,
                         on_dial_done, c, NULL, 0) != 0) {
        /* Could not even start the dial: nothing to forward to. */
        conn_drop(c);
        return;
    }
    c->dialing = 1;
}

/* ---- post-authentication: reply write and hand-off ---------------------- */

/* Step 11. Only ever called once c->reply has been written in full.
 * c->fd is still ours; this is the one place that either hands it, still
 * open, to cloak_session_add_conn, or closes it itself. */
static void conn_handoff(cloak_dispatch_conn_t *c) {
    cloak_dispatcher_t *d = c->d;
    int fd = c->fd;
    int created = c->auth_created;
    cloak_server_clientinfo_t info = c->auth_info;

    /* c->fd was registered CLOAK_REACTOR_WRITABLE (or never re-registered
     * at all, if step 10's write completed synchronously on the first
     * attempt) for the reply write; either way it must come off the
     * reactor before cloak_session_add_conn wraps it in a cloak_conn_t of
     * its own, exactly like the redirect path's own dial hand-off. */
    cloak_reactor_remove_fd(d->cfg.reactor, fd);

    /* Re-resolve the session by (uid, session_id) rather than trusting a
     * raw pointer captured back in dispatcher_authenticate: writing_reply
     * spans reactor turns by design, and the registry can free that exact
     * memory on an intervening turn -- a session another connection broke
     * arms a zero-delay sweep timer that runs before this turn ends, or
     * (when THIS connection is the one that created the session,
     * auth_created == 1) the session's own inactivity timer can fire and
     * free it first if inactivity_timeout_ms is shorter than
     * handshake_timeout_ms. Either way, a stored cloak_session_t* can be
     * dangling by the time this function runs -- see cloak/dispatcher.h's
     * OWNERSHIP comment and this module's C1 finding for the full
     * sequence. conn_teardown already addresses this way for exactly the
     * same reason; this is the one other place that used to trust the raw
     * pointer instead. auth_uid/auth_session_id are plain byte/integer
     * fields captured by value, so they are never stale the way a pointer
     * would be. */
    cloak_session_t *sesh =
        cloak_server_registry_find(d->cfg.registry, c->auth_uid, c->auth_session_id);
    if (sesh == NULL) {
        /* The session is gone. The client already has a ServerHello (the
         * reply this connection just finished writing), so the cover
         * story is blown regardless of what happens now -- close, not
         * redirect, the same reasoning conn_reply_write_failed documents
         * for a step-10 write error. There is no session left to unwind
         * via conn_teardown's auth_created check either: whatever
         * destroyed it already did so. */
        close(fd);
        c->fd = -1;
        conn_drop(c);
        return;
    }

    /* _framed, never cloak_session_add_conn: this connection's framing
     * was decided at the end of dispatcher_authenticate (see the comment
     * on c->auth_framing there), and the plain entry point would silently
     * mean TLS records on a WebSocket socket. It is also the call whose
     * zero value FAILS rather than defaulting, which is the one
     * mechanical defence here that does not depend on anybody
     * remembering anything -- see cloak/conn.h's cloak_conn_framing_t. */
    if (cloak_session_add_conn_framed(sesh, fd, c->auth_framing) != 0) {
        /* The dispatcher still owns fd on failure (cloak_session_add_conn's
         * own contract). The client has already received a ServerHello by
         * this point -- the reply this connection just finished writing
         * -- so the cover story is blown regardless of what happens now;
         * close rather than redirect, the same reasoning
         * conn_reply_write_failed documents for a step-10 write error.
         * conn_drop's call into conn_teardown is what unwinds a
         * brand-new session here, if this connection was the one that
         * created it (auth_created is still set on c at this point). */
        close(fd);
        c->fd = -1;
        conn_drop(c);
        return;
    }

    c->fd = -1;
    /* The one exit from the reply-write/hand-off state that does NOT go
     * through conn_teardown (see on_relay_done's sibling pattern) --
     * conn_teardown is what cancels the deadline armed for this state on
     * every other exit, so this success path must do it explicitly
     * itself, exactly once, here. */
    if (c->deadline != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(d->cfg.reactor, c->deadline);
        c->deadline = CLOAK_TIMER_INVALID;
    }
    if (d->cfg.attached != NULL) {
        d->cfg.attached(d, sesh, &info, created, d->cfg.attached_userdata);
    }
    conn_unlink(c);
    free(c);
}

/* Step 10's failure path. A write error here is the ONE place in this
 * whole module that closes instead of redirecting: by the time this can
 * fire, the client has already received a ServerHello (composed in
 * dispatcher_authenticate, step 9), so the cover story is already blown
 * -- forwarding to the cover site now would be visibly incoherent (a real
 * web server never follows a ServerHello with a second, unrelated
 * handshake attempt). Do NOT "fix" this into a redirect. conn_drop's call
 * into conn_teardown is what unwinds a brand-new session here, if this
 * connection was the one that created it. */
static void conn_reply_write_failed(cloak_dispatch_conn_t *c) {
    conn_drop(c);
}

/* Step 10. Writes c->reply[c->reply_sent, c->reply_len) to c->fd,
 * non-blocking: what the socket takes is taken, and on a short write or
 * EAGAIN this registers c->fd for writable and returns, to be called
 * again from on_readable (see its own comment) once the reactor says the
 * fd is writable. Only once the last byte is out does the connection
 * proceed to hand-off (step 11) -- this is the one non-blocking
 * write-then-handover primitive the project did not already have. */
static void conn_continue_reply_write(cloak_dispatch_conn_t *c) {
    while (c->reply_sent < c->reply_len) {
        size_t remaining = c->reply_len - c->reply_sent;
        /* send() with MSG_NOSIGNAL, not write(): c->fd is a socket whose
         * peer is an unauthenticated stranger who may have gone away
         * between the two writes of a reply that did not fit in one, and
         * writing to a socket whose peer has closed raises SIGPIPE --
         * which at default disposition kills the whole server. The rule is
         * cloak/relay.c's and this was the one socket write in the tree
         * that broke it. Both mains additionally ignore SIGPIPE (which is
         * what Go's runtime does for every non-stdio descriptor), so this
         * is the belt to that pair of braces; it is also what makes
         * conn_reply_write_failed reachable for EPIPE at all, instead of
         * the signal arriving before errno is ever inspected. */
        ssize_t n = send(c->fd, c->reply + c->reply_sent, remaining, MSG_NOSIGNAL);
        if (n > 0) {
            c->reply_sent += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!c->writing_reply) {
                c->writing_reply = 1;
                /* Switches this fd's registration from whatever it was
                 * (READABLE, during first-packet reading) to WRITABLE;
                 * on_readable (registered once, at accept) is what
                 * dispatches the resulting event back into this
                 * function -- see its own comment for why the same
                 * callback handles both phases. */
                if (cloak_reactor_mod_fd(c->d->cfg.reactor, c->fd, CLOAK_REACTOR_WRITABLE) != 0) {
                    /* An unlikely failure (this fd is definitely still
                     * registered, from either cloak_dispatcher_accept's
                     * original add_fd or an earlier mod_fd call), but
                     * leaving writing_reply == 1 against a mask that
                     * never actually changed to WRITABLE would silently
                     * stall this connection with no further event ever
                     * arriving for it. This is an ENOMEM-only failure
                     * (cloak_reactor_mod_fd fails only if epoll_ctl
                     * itself fails, which for a MOD on an fd already
                     * known-registered means the kernel is out of
                     * resources) -- i.e. class (c) in cloak/dispatcher.h's
                     * top-of-file enumeration (resources already
                     * exhausted), NOT class (b) (cover story already
                     * spent): reply_sent can still be 0 here (the very
                     * first write() attempt is what returned EAGAIN), so
                     * the client may not have received any part of the
                     * ServerHello yet. Closing anyway, rather than
                     * redirecting, is still correct even then: this
                     * connection may already have created a session
                     * (auth_created), and conn_start_redirect's own
                     * failure paths do not run conn_teardown -- routing
                     * an authenticated connection into them would leak
                     * that session rather than unwind it (see
                     * conn_start_redirect's own top-of-function comment,
                     * M2). conn_reply_write_failed (close via conn_drop,
                     * which does run conn_teardown) is what actually
                     * unwinds it. */
                    conn_reply_write_failed(c);
                }
            }
            return;
        }
        /* A real write error: the peer is gone or the socket is broken. */
        conn_reply_write_failed(c);
        return;
    }

    /* Fully drained. */
    c->writing_reply = 0;
    conn_handoff(c);
}

/* ---- reading the first packet -------------------------------------------- */

static void conn_on_firstpacket_error(cloak_dispatch_conn_t *c) {
    /* cloak/firstpacket.h's own contract: every error it can report is a
     * redirectable one. cloak_firstpacket_redirect_on_error would agree
     * for every case this parser actually produces, but the contract
     * itself -- not a per-case check of it -- is what this branch relies
     * on, matching the task's own instruction to send every ERROR
     * straight to redirect. */
    conn_start_redirect(c);
}

static void conn_on_firstpacket_done(cloak_dispatch_conn_t *c) {
    /* Past this point the connection is no longer "reading its first
     * packet" regardless of what happens next -- authentication success,
     * authentication failure (redirect), or a step-10 write failure
     * (close) -- so the deadline is cancelled here, once, on every path
     * out of this state. conn_start_redirect's own cancellation below is
     * then a documented no-op (CLOAK_TIMER_INVALID guard). */
    if (c->deadline != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(c->d->cfg.reactor, c->deadline);
        c->deadline = CLOAK_TIMER_INVALID;
    }

    if (dispatcher_authenticate(c) != 0) {
        conn_start_redirect(c);
        return;
    }

    /* Entering the reply-write/hand-off state: arm a deadline covering
     * it. This module's own stated philosophy (see the redirect-dial
     * timeout's comment, and the first-packet deadline this one just
     * replaces) is that no state here is unbounded -- a step-10 write
     * that never drains because the client never reads is exactly the
     * same failure shape as a first-packet read that never completes,
     * and deserves the same treatment rather than being allowed to pin
     * this connection's heap state (including, potentially, a
     * freshly-created session sitting in the registry) forever.
     * handshake_timeout_ms is reused rather than given its own knob:
     * this phase is a single bounded write of at most
     * CLOAK_SERVER_AUTH_REPLY_MAX_BYTES followed by one
     * cloak_session_add_conn call, no less bounded than the first-packet
     * read it follows, so the same timeout is an equally reasonable
     * bound and it is not worth a second configuration surface for it.
     * Cancelled on every exit from this state: conn_handoff's success
     * path cancels it explicitly (see its own comment, since success is
     * the one exit that does not go through conn_teardown), and every
     * other exit (redirect is not reachable from here; a step-10 write
     * failure or a step-11 hand-off failure both route through
     * conn_drop) cancels it via conn_teardown's own unconditional check
     * at its top. */
    c->deadline =
        cloak_reactor_add_timer(c->d->cfg.reactor, c->d->cfg.handshake_timeout_ms, on_deadline, c);
    if (c->deadline == CLOAK_TIMER_INVALID) {
        /* Cannot honor a deadline for this state either -- the same
         * allocation failure growing the reactor's timer heap that
         * cloak_dispatcher_accept's own arm-failure handling documents,
         * with the same conclusion: refusing to enter an unbounded state
         * is not an option, so this connection is dropped rather than
         * left to write its reply with nothing to bound it. This is
         * class (c) in cloak/dispatcher.h's top-of-file enumeration
         * (resources already exhausted), NOT class (b) (cover story
         * already spent) -- conn_continue_reply_write has not even been
         * called yet at this point, so literally none of the reply has
         * reached the client. Routed through conn_reply_write_failed
         * (close via conn_drop, which runs conn_teardown) rather than
         * conn_start_redirect anyway: this connection may already have
         * created a session (auth_created), and conn_start_redirect's
         * own failure paths do not run conn_teardown, so redirecting an
         * authenticated connection through them would leak that session
         * instead of unwinding it (see conn_start_redirect's own
         * top-of-function comment, M2). */
        conn_reply_write_failed(c);
        return;
    }

    conn_continue_reply_write(c);
}

static void conn_drop_peer_gone(cloak_dispatch_conn_t *c) {
    /* read() returned 0 or a real error: the peer is already gone, so
     * there is nobody to redirect to -- this is the one first-packet
     * outcome that is not itself a CLOAK_FIRSTPACKET_ERROR and still does
     * not redirect. */
    conn_drop(c);
}

/* The single callback registered (once, at accept) for a connection's own
 * fd, for the whole time this module owns that fd. It serves two,
 * mutually exclusive, phases of that fd's life: reading the first packet
 * (registered CLOAK_REACTOR_READABLE) and, after a successful
 * authentication, draining the non-blocking reply write (registered
 * CLOAK_REACTOR_WRITABLE via cloak_reactor_mod_fd in
 * conn_continue_reply_write) -- cloak_reactor_mod_fd changes the event
 * mask of an existing registration, not its callback, so this same
 * function is what the reactor calls for both; c->writing_reply is what
 * tells it which phase it is in. */
static void on_readable(cloak_reactor_t *r, int fd, uint32_t events, void *userdata) {
    (void)r;
    (void)events;
    cloak_dispatch_conn_t *c = userdata;

    if (c->writing_reply) {
        conn_continue_reply_write(c);
        return;
    }

    /* Edge-triggered: this loop must keep reading until want() reaches 0
     * or read() returns EAGAIN, or data that arrived within this same
     * edge is never reported again. */
    for (;;) {
        size_t want = cloak_firstpacket_want(&c->fp);
        if (want == 0) {
            /* Should not happen while still registered readable -- every
             * path that reaches DONE/ERROR returns immediately below --
             * but stop rather than loop forever if it ever does. */
            return;
        }

        uint8_t buf[CLOAK_FIRSTPACKET_MAX];
        ssize_t n = read(fd, buf, want);
        if (n > 0) {
            cloak_firstpacket_status_t st = cloak_firstpacket_feed(&c->fp, buf, (size_t)n);
            if (st == CLOAK_FIRSTPACKET_DONE) {
                conn_on_firstpacket_done(c);
                return;
            }
            if (st == CLOAK_FIRSTPACKET_ERROR) {
                conn_on_firstpacket_error(c);
                return;
            }
            continue; /* NEED_MORE: want() may have changed, loop again */
        }
        if (n == 0) {
            conn_drop_peer_gone(c);
            return;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return; /* wait for the next readiness edge */
        }
        /* Any other read() error: the peer is effectively gone too. */
        conn_drop_peer_gone(c);
        return;
    }
}

/* Fires for BOTH deadlines this module ever arms against c->deadline: the
 * first-packet read deadline (armed in cloak_dispatcher_accept) and the
 * reply-write/hand-off deadline (armed in conn_on_firstpacket_done) --
 * never both at once, since the second is armed only after the first has
 * already been cancelled. Either way, conn_drop is the right response: a
 * client that never finishes sending its first packet and a client that
 * never drains this connection's write buffer fail the same way, by
 * pinning this connection's state forever, and both are handled by
 * simply dropping the connection. */
static void on_deadline(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_dispatch_conn_t *c = userdata;
    /* The timer already fired (this callback is that firing); mark it
     * consumed before conn_drop's own cancel-timer call, which would
     * otherwise be cancelling a timer that no longer exists. */
    c->deadline = CLOAK_TIMER_INVALID;
    conn_drop(c);
}

/* ---- public API ---------------------------------------------------------- */

int cloak_dispatcher_init(cloak_dispatcher_t *d, const cloak_dispatcher_config_t *cfg) {
    if (d == NULL) {
        return -1;
    }
    /* Initialize before validating anything else, so that ANY failure
     * return below still leaves d in a state cloak_dispatcher_destroy can
     * safely be called against -- four earlier constructors on this
     * project got this ordering backwards and it was a crash every time. */
    memset(d, 0, sizeof(*d));

    if (cfg == NULL || cfg->reactor == NULL || cfg->srv == NULL) {
        return -1;
    }
    /* A non-zero relay_buf_cap smaller than CLOAK_FIRSTPACKET_MAX would
     * make cloak_relay_start fail (preload_len > buf_cap) on every single
     * redirect -- silently turning "every failure redirects" into "every
     * connection closes" from nothing worse than a config typo. Reject it
     * here, loudly, rather than let it surface later as connections that
     * merely fail to redirect. */
    if (cfg->relay_buf_cap != 0 && cfg->relay_buf_cap < CLOAK_FIRSTPACKET_MAX) {
        return -1;
    }

    d->cfg = *cfg;
    if (d->cfg.handshake_timeout_ms == 0) {
        d->cfg.handshake_timeout_ms = CLOAK_DISPATCHER_DEFAULT_HANDSHAKE_TIMEOUT_MS;
    }
    if (d->cfg.redirect_dial_timeout_ms == 0) {
        d->cfg.redirect_dial_timeout_ms = CLOAK_DISPATCHER_DEFAULT_REDIRECT_DIAL_TIMEOUT_MS;
    }
    if (d->cfg.relay_buf_cap == 0) {
        d->cfg.relay_buf_cap = CLOAK_DISPATCHER_DEFAULT_RELAY_BUF_CAP;
    }
    if (d->cfg.max_pending_conns == 0) {
        d->cfg.max_pending_conns = CLOAK_DISPATCHER_DEFAULT_MAX_PENDING_CONNS;
    }

    d->conns = NULL;
    d->conn_count = 0;
    d->pending_count = 0;
    return 0;
}

void cloak_dispatcher_destroy(cloak_dispatcher_t *d) {
    if (d == NULL) {
        return;
    }
    cloak_dispatch_conn_t *c = d->conns;
    while (c != NULL) {
        cloak_dispatch_conn_t *next = c->next;
        conn_teardown(c);
        free(c);
        c = next;
    }
    d->conns = NULL;
    d->conn_count = 0;
    /* Reset directly, exactly like conn_count above, rather than via
     * conn_unlink: this loop frees every connection in one pass without
     * unlinking them one at a time (see this function's own doc comment),
     * so nothing else clears pending_count for connections still pending
     * at destroy time. Correct regardless of each connection's own
     * pending state -- destroying the dispatcher ends everything. */
    d->pending_count = 0;
}

void cloak_dispatcher_accept(cloak_listener_t *l, int fd, void *userdata) {
    cloak_dispatcher_t *d = userdata;
    if (d == NULL) {
        close(fd);
        return;
    }

    /* THE CAP, checked before any allocation happens for this fd -- see
     * CLOAK_DISPATCHER_DEFAULT_MAX_PENDING_CONNS's and this function's own
     * doc comments in cloak/dispatcher.h for the full reasoning. Short
     * version: this is a C server allocating ~3KB of heap per
     * unauthenticated connection, Go has no equivalent cap because it has
     * no equivalent allocation, and CLOSING (not redirecting) is the
     * correct response at the cap -- redirecting would spend a second fd
     * and, on a successful dial, a live relay's buffers, which is exactly
     * backwards when the reason we are here is that resources are already
     * exhausted. Every other close-instead-of-redirect path in this
     * module fires because there is nowhere to redirect TO; this is the
     * only one that closes despite somewhere to redirect existing, so a
     * future reader should not "fix" this into a redirect.
     *
     * pending_count, NOT conn_count: a relaying connection's own
     * lifetime is controlled by whoever it is relaying to, not by this
     * module, so counting it against this cap would let an attacker who
     * simply holds max_pending_conns redirected connections open starve
     * every legitimate client permanently -- see on_dial_done's own
     * comment at the point a connection stops being pending. */
    if (d->pending_count >= d->cfg.max_pending_conns) {
        close(fd);
        return;
    }

    cloak_dispatch_conn_t *c = calloc(1, sizeof(*c));
    if (c == NULL) {
        close(fd);
        return;
    }

    c->d = d;
    c->fd = fd;
    /* Exactly the local_port cloak_server_redir_addr wants, straight from
     * the listener this connection arrived on -- no getsockname needed
     * (see docs/superpowers/plans/2026-09-13-libcloak-server-state-plan.md,
     * "What a paper walk of that loop already established"). */
    c->local_port = (uint16_t)cloak_listener_port(l);
    cloak_firstpacket_init(&c->fp);
    c->deadline = CLOAK_TIMER_INVALID;
    c->dialing = 0;
    c->relaying = 0;
    c->pending = 1;
    c->prev = NULL;
    c->next = NULL;

    /* Link in before arming anything, so any failure path below can use
     * conn_drop (which unlinks) uniformly rather than needing a separate
     * "not linked yet" teardown. */
    c->next = d->conns;
    if (d->conns != NULL) {
        d->conns->prev = c;
    }
    d->conns = c;
    d->conn_count++;
    d->pending_count++;

    c->deadline =
        cloak_reactor_add_timer(d->cfg.reactor, d->cfg.handshake_timeout_ms, on_deadline, c);
    if (c->deadline == CLOAK_TIMER_INVALID) {
        /* Cannot honor the handshake deadline (allocation failure growing
         * the reactor's timer heap) -- refusing to read from this fd
         * without any deadline at all would risk pinning it forever, the
         * exact failure mode the deadline exists to prevent, so drop the
         * connection instead. */
        conn_drop(c);
        return;
    }

    if (cloak_reactor_add_fd(d->cfg.reactor, fd, CLOAK_REACTOR_READABLE, on_readable, c) != 0) {
        /* Cannot register this fd with the reactor at all (e.g. the
         * reactor's own watcher table failed to grow) -- there is no way
         * to ever read a first packet from it, so this connection can
         * never do anything but sit here forever; drop it instead. */
        conn_drop(c);
        return;
    }
}

size_t cloak_dispatcher_conn_count(const cloak_dispatcher_t *d) {
    return d == NULL ? 0 : d->conn_count;
}

size_t cloak_dispatcher_pending_count(const cloak_dispatcher_t *d) {
    return d == NULL ? 0 : d->pending_count;
}
