#define _POSIX_C_SOURCE 200809L
#include "cloak/adminapi.h"

#include "cloak/base64.h"
#include "cloak/conn.h" /* CLOAK_CONN_RECORD_HEADER_LEN: a fixed wire-format
                         * constant needed to compute the true on-wire
                         * cost of one frame, exactly as
                         * libcloak-mux/src/stream_relay.c uses it -- not
                         * a reach into any per-connection state. */
#include "cloak/frame.h"
#include "cloak/log.h"
#include "cloak/user_json.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* How many bytes are pulled off a stream per cloak_stream_read call while
 * a request is being read. On an ORDERED stream nothing is bounded by
 * this -- the parser's own caps bound the request -- so it would be
 * purely how much stack the read loop uses per turn.
 *
 * ON AN UNORDERED (DATAGRAM) STREAM IT IS A HARD FLOOR, WHICH IS WHY IT
 * IS NO LONGER ONE PAGE. cloak_stream_read hands over one WHOLE datagram
 * or none, and answers CLOAK_STREAM_ERR_SHORT_BUFFER for a buffer smaller
 * than the datagram at the head. At 4096 this reader could not read any
 * admin request that arrived as a single datagram above that size -- and
 * it treated the refusal as end-of-stream and tore the stream down, so
 * the client got no answer and nothing distinguishing it from a peer that
 * hung up. That is Go's bug 6 (internal/client/piper.go's 8192-byte
 * reader against datagrams of up to 16132) in this port's own admin
 * reader. It is reachable, and MORE reachable since module 9 task 6 than
 * when this was written: an admin session that sets the flag has always
 * been built UNORDERED, and the proxy path -- which used to redirect
 * every unordered client -- now carries them too, so nothing anywhere
 * refuses one.
 *
 * 16384 is chosen to exceed the largest datagram a session at the
 * shipping max_on_wire_size of 16401 can ever deliver: Go's
 * maxStreamUnitWrite, 16401 - 14 (frame header) - 255 (padding/AEAD) =
 * 16132. It is the same constant, for the same reason, as
 * stream_relay.c's STREAM_RELAY_CHUNK. A session configured with a larger
 * max_on_wire_size can still exceed it, which adminapi_drain now handles
 * explicitly rather than by falling into the end-of-stream arm. Pinned by
 * test_adminapi.c's test_unordered_request_larger_than_one_read_chunk. */
#define ADMINAPI_READ_CHUNK 16384

/* The routes, in one place so the 405 Allow headers and the OPTIONS
 * Access-Control-Allow-Methods cannot drift away from what is actually
 * implemented. */
#define ADMINAPI_ALLOW_COLLECTION "GET,OPTIONS"
#define ADMINAPI_ALLOW_ITEM       "GET,POST,DELETE,OPTIONS"
#define ADMINAPI_CORS_METHODS     "GET,POST,DELETE,OPTIONS"

static const char ADMINAPI_USERS_PATH[] = "/admin/users";
#define ADMINAPI_USERS_PATH_LEN (sizeof(ADMINAPI_USERS_PATH) - 1)

/* ---- intrusive list bookkeeping ----------------------------------------- */

static void adminapi_session_link(cloak_adminapi_t *a, cloak_adminapi_session_t *as) {
    as->prev = NULL;
    as->next = a->sessions;
    if (a->sessions != NULL) {
        a->sessions->prev = as;
    }
    a->sessions = as;
    a->session_count++;
}

static void adminapi_session_unlink(cloak_adminapi_t *a, cloak_adminapi_session_t *as) {
    if (as->prev != NULL) {
        as->prev->next = as->next;
    } else {
        a->sessions = as->next;
    }
    if (as->next != NULL) {
        as->next->prev = as->prev;
    }
    as->prev = NULL;
    as->next = NULL;
    a->session_count--;
}

static void adminapi_stream_link(cloak_adminapi_session_t *as, cloak_adminapi_stream_t *ast) {
    ast->prev = NULL;
    ast->next = as->streams;
    if (as->streams != NULL) {
        as->streams->prev = ast;
    }
    as->streams = ast;
    as->stream_count++;
    as->a->stream_count++;
}

static void adminapi_stream_unlink(cloak_adminapi_session_t *as, cloak_adminapi_stream_t *ast) {
    if (ast->prev != NULL) {
        ast->prev->next = ast->next;
    } else {
        as->streams = ast->next;
    }
    if (ast->next != NULL) {
        ast->next->prev = ast->prev;
    }
    ast->prev = NULL;
    ast->next = NULL;
    as->stream_count--;
    as->a->stream_count--;
}

/* ---- teardown ------------------------------------------------------------
 *
 * THE ONE COPY, for the same reason cloak_proxy_t has one: three public
 * entry points drive exactly this walk (cloak_adminapi_destroy,
 * cloak_adminapi_registry_broken and cloak_adminapi_session_aborted) and
 * differ only in what they do afterwards. */

/* Releases everything one stream context holds, releases the stream back
 * to its session, unlinks the context and FREES IT. ast must not be
 * touched after this returns. */
static void adminapi_stream_teardown(cloak_adminapi_stream_t *ast) {
    cloak_adminapi_session_t *as = ast->as;
    cloak_adminapi_t *a = as->a;

    if (ast->deadline != CLOAK_TIMER_INVALID) {
        cloak_reactor_cancel_timer(a->cfg.reactor, ast->deadline);
        ast->deadline = CLOAK_TIMER_INVALID;
    }
    /* The parser is destroyed HERE and nowhere else. cloak_http_parser_
     * destroy re-initializes rather than poisons, so destroying one that
     * is still being fed would silently start a SECOND request from
     * mid-stream bytes -- the exact smuggling the parser's terminal-state
     * stickiness exists to prevent. Tying the destroy to the free of the
     * context makes "one stream, one request" true by construction. */
    cloak_http_parser_destroy(&ast->parser);

    /* THE RESPONSE IS FREED AND ITS POINTER CLEARED BEFORE THE RELEASE
     * BELOW, AND THAT ORDER IS LOAD-BEARING. cloak_session_release_stream
     * performs an active close, which sends a closing frame; that send
     * can complete a connection's drain inline and so raise this
     * session's on_writable synchronously (cloak/session.h says this
     * callback is NOT guaranteed to run at a reactor turn boundary). This
     * context is STILL LINKED into as->streams at that instant, so the
     * walk in adminapi_on_writable would reach it -- and it skips a
     * context whose resp is NULL. Clearing resp first is therefore what
     * makes that re-entry a no-op instead of a pump against a context
     * that is one statement away from being freed. (as->in_writable
     * covers the same re-entry when the release happens from inside that
     * walk; this ordering covers it when the release happens from
     * anywhere else, which is every other teardown path.) */
    free(ast->resp);
    ast->resp = NULL;

    if (as->sesh != NULL && ast->stream != NULL) {
        /* cloak_session_release_stream performs the active close itself
         * when the stream has not already been closed, so there is no
         * separate cloak_session_close_stream to make here -- and that
         * close is how the client learns the response ended. */
        cloak_session_release_stream(as->sesh, ast->stream);
    }
    ast->stream = NULL;

    adminapi_stream_unlink(as, ast);
    free(ast);
}

/* Tears down every stream context this session holds, then unlinks and
 * frees the session context. as must not be touched after this returns. */
static void adminapi_session_teardown(cloak_adminapi_session_t *as) {
    while (as->streams != NULL) {
        adminapi_stream_teardown(as->streams);
    }

    /* THE INSTANT as->sesh STOPS BEING VALID. It has to happen HERE:
     * after the walk, because adminapi_stream_teardown needs a live
     * session to release streams to (cloak_adminapi_registry_broken runs
     * in the one window where that is still possible), and before
     * anything else, because on the broken path the session is gone the
     * moment the callback that led here returns. */
    as->sesh = NULL;

    adminapi_session_unlink(as->a, as);
    free(as);
}

/* The session context for (uid, session_id), or NULL.
 *
 * KEYED ON (uid, session_id), NOT ON THE cloak_session_t POINTER, for the
 * same reason cloak_proxy_t's is: that pair is recorded by
 * cloak_adminapi_prepare_session, the only place a context is ever
 * created, so it is valid for the whole of a context's life -- including
 * the entire window before as->sesh is ever set, which is exactly the
 * window cloak_adminapi_session_aborted searches in. A linear scan is the
 * right structure: one entry per live admin session, walked once per
 * teardown rather than per frame. */
static cloak_adminapi_session_t *adminapi_find_session(cloak_adminapi_t *a,
                                                       const uint8_t uid[CLOAK_UID_LEN],
                                                       uint32_t session_id) {
    for (cloak_adminapi_session_t *as = a->sessions; as != NULL; as = as->next) {
        if (as->session_id == session_id && memcmp(as->uid, uid, CLOAK_UID_LEN) == 0) {
            return as;
        }
    }
    return NULL;
}

/* ---- response composition ------------------------------------------------ */

static const char *adminapi_reason(int status) {
    switch (status) {
    case 200: return "OK";
    case 201: return "Created";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 413: return "Content Too Large";
    case 414: return "URI Too Long";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    default:  return "Error";
    }
}

/* Composes one whole response into ast->resp.
 *
 * extra may be NULL, or one or more complete CRLF-terminated header
 * lines. body may be NULL only when body_len is 0.
 *
 * ACCESS-CONTROL-ALLOW-ORIGIN IS ON EVERY RESPONSE because Go's
 * corsMiddleware puts it on every response
 * (internal/server/usermanager/api_router.go:25-30, installed for the
 * whole router by ar.Use at :41). IT IS VESTIGIAL HERE: this
 * API is reachable only over an authenticated Cloak session, where there
 * is no browser and no origin, so it grants nothing and protects nothing.
 * It is ported for fidelity with the real admin client's expectations and
 * named as vestigial here so nobody later mistakes it for a security
 * control.
 *
 * CONNECTION: CLOSE is a deliberate divergence from Go, whose http.Server
 * keeps the connection alive for a second request. One stream carries one
 * request here (see cloak_adminapi_stream_t), so announcing the close is
 * the honest description of what this server will do, and it stops a
 * client from pipelining a request that would never be read.
 *
 * Returns 0, or -1 if the response could not be allocated -- in which
 * case the caller must tear the stream down, because there is nothing
 * left to answer with. */
static int adminapi_respond(cloak_adminapi_stream_t *ast, int status, const char *ctype,
                            const char *extra, const char *body, size_t body_len) {
    char head[512];
    int n = snprintf(head, sizeof(head),
                     "HTTP/1.1 %d %s\r\n"
                     "Access-Control-Allow-Origin: *\r\n"
                     "%s"
                     "Content-Type: %s\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     status, adminapi_reason(status), extra == NULL ? "" : extra, ctype, body_len);
    if (n < 0 || (size_t)n >= sizeof(head)) {
        /* Unreachable with the fixed header set above and the bounded
         * `extra` strings this file passes; refusing rather than
         * truncating keeps it that way if either ever grows. */
        return -1;
    }
    size_t hlen = (size_t)n;
    char *buf = malloc(hlen + body_len);
    if (buf == NULL) {
        return -1;
    }
    memcpy(buf, head, hlen);
    if (body_len > 0) {
        memcpy(buf + hlen, body, body_len);
    }
    free(ast->resp);
    ast->resp = buf;
    ast->resp_len = hlen + body_len;
    ast->resp_sent = 0;
    return 0;
}

/* A plain-text error body, the shape Go's http.Error produces. */
static int adminapi_respond_text(cloak_adminapi_stream_t *ast, int status, const char *extra,
                                 const char *text) {
    char body[256];
    int n = snprintf(body, sizeof(body), "%s\n", text);
    if (n < 0) {
        return -1;
    }
    size_t blen = (size_t)n;
    if (blen >= sizeof(body)) {
        blen = sizeof(body) - 1;
    }
    return adminapi_respond(ast, status, "text/plain; charset=utf-8", extra, body, blen);
}

/* ---- the write pump ------------------------------------------------------ */

/* The number of response bytes it is currently safe to hand to
 * cloak_stream_write.
 *
 * THIS IS SIZED IN WHOLE FRAMES, NOT RAW BYTES, and that distinction is
 * the whole point -- it is the same calculation
 * stream_relay_fd_read_budget makes, for the same reason. The on-wire
 * cost of n raw bytes is not n: cloak_stream_write chunks them into
 * ceil(n / max_payload_per_frame) frames and each frame costs a header,
 * up to CLOAK_FRAME_MAX_EXTRA_LEN of padding/AEAD and the connection
 * layer's TLS record header on top of its payload.
 *
 * It budgets off cloak_session_send_min_conn_free -- the MINIMUM free
 * space over every connection in the pool -- and not the aggregate,
 * because cloak_switchboard_send hands each whole frame to ONE connection
 * chosen uniformly at random. The aggregate stays large while one
 * congested connection is about to trip its own cap, and that cap firing
 * breaks the whole pool and therefore every stream on this session.
 *
 * 0 means "pause": the resume is owned by cloak_session_writable_cb,
 * which fires when the pool drains. There is no second kind of zero here
 * -- unlike cloak_stream_relay_t, this module deliberately does NOT
 * consult the session's valve. A valve limits a metered USER's
 * throughput, and an admin session is the operator's own; more to the
 * point, a valve's zero is resumed by nothing but the passage of time and
 * would need a timer of its own, whereas the response this module has to
 * deliver is bounded by the listing cap and is over in one burst. Pacing
 * it would buy a rate limit nobody asked for and cost a second stall
 * path. */
static size_t adminapi_write_budget(const cloak_adminapi_stream_t *ast) {
    const cloak_stream_t *s = ast->stream;
    size_t frame_cost = (size_t)CLOAK_CONN_RECORD_HEADER_LEN + s->max_payload_per_frame +
                        (size_t)CLOAK_FRAME_HEADER_LEN + (size_t)CLOAK_FRAME_MAX_EXTRA_LEN;
    size_t frames = cloak_session_send_min_conn_free(ast->as->sesh) / frame_cost;
    size_t budget = frames * s->max_payload_per_frame;
    /* AND, IN UNORDERED MODE, NEVER MORE THAN ONE FRAME'S PAYLOAD.
     *
     * THIS WAS A LIVE DEFECT, not a precaution. Two frames' room offers a
     * chunk of 2 * max_payload_per_frame; an unordered stream REFUSES any
     * write over max_payload_per_frame outright (cloak/stream.h:
     * CLOAK_STREAM_ERR_SHORT_BUFFER -- splitting a datagram would be
     * silent corruption, because the far end does no reassembly in this
     * mode), and adminapi_pump_write reads every negative return as
     * terminal. So at the ordinary pool size the FIRST chunk of any
     * response over 16132 bytes was refused and the stream was torn down
     * having written nothing: an admin client saw its stream close with
     * no response at all. It is reachable -- dispatcher.c builds an
     * unordered admin session whenever the client's auth record sets the
     * flag -- and pinned by test_adminapi.c's
     * test_unordered_response_larger_than_one_frame, which sees no status
     * line at all without this clamp.
     *
     * THE THIRD AND LAST OF THE THREE PLACES that size a buffer for
     * cloak_stream_write: stream_relay_fd_read_budget carries the same
     * clamp with the same argument, and cloak_client_piper_t's first read
     * is already below one frame by construction. A response delivered as
     * several datagrams is what an unordered stream can carry; it is not
     * a byte stream and never was.
     *
     * THE ORDERED PATH IS UNTOUCHED, deliberately: it chunks freely, so
     * clamping there would cost an extra frame's worth of loop iterations
     * for nothing and would change what every existing case in that file
     * measures. */
    if (s->ordering == CLOAK_SESSION_ORDERING_UNORDERED && budget > s->max_payload_per_frame) {
        budget = s->max_payload_per_frame;
    }
    return budget;
}

/* Drains as much of the composed response as certainly fits, and tears
 * the stream down once it is fully written (or once writing it became
 * impossible). ast may be freed by the time this returns. */
static void adminapi_pump_write(cloak_adminapi_stream_t *ast) {
    if (ast->resp == NULL || ast->as->sesh == NULL || ast->stream == NULL) {
        return;
    }
    if (ast->pumping) {
        /* RE-ENTERED FROM INSIDE OUR OWN cloak_stream_write.
         * cloak_session_writable_cb is explicitly permitted to fire
         * synchronously from underneath a write (cloak/session.h), so
         * this function can be reached from within itself. Returning
         * loses nothing: the outer loop re-reads resp_sent and the budget
         * on every turn, so whatever room this nested call would have
         * used is used by the very next iteration of the outer one. */
        return;
    }
    ast->pumping = 1;

    int finished = 0;
    while (ast->resp_sent < ast->resp_len) {
        size_t budget = adminapi_write_budget(ast);
        if (budget == 0) {
            break; /* pool-bound; on_writable owns this resume */
        }
        size_t remaining = ast->resp_len - ast->resp_sent;
        size_t chunk = budget < remaining ? budget : remaining;
        if (cloak_stream_write(ast->stream, (const uint8_t *)ast->resp + ast->resp_sent, chunk) <
            0) {
            /* The stream's write side is closed (the peer went away) or a
             * frame could not be built. Either way there is no response
             * to finish. */
            finished = 1;
            break;
        }
        ast->resp_sent += chunk;
    }
    if (ast->resp_sent >= ast->resp_len) {
        finished = 1;
    }

    ast->pumping = 0;
    if (finished) {
        /* ONE STREAM, ONE REQUEST: the answer is written, so the stream
         * is closed rather than the parser reset. */
        adminapi_stream_teardown(ast);
    }
}

/* ---- the handlers -------------------------------------------------------- */

/* GET /admin/users.
 *
 * cloak_usermanager_list has no cursor, so this is count-then-allocate-
 * all and the cap is what keeps that bounded. Past the cap the request is
 * REFUSED with 500 naming both numbers rather than truncated: an operator
 * handed a silently short list would act on a database that does not
 * exist. See CLOAK_ADMINAPI_DEFAULT_MAX_LIST_USERS. */
static int adminapi_handle_list(cloak_adminapi_stream_t *ast) {
    cloak_adminapi_t *a = ast->as->a;
    size_t n = 0;
    int rc = cloak_usermanager_list(a->cfg.manager, NULL, 0, &n);
    if (rc != 0) {
        return adminapi_respond_text(ast, 500, NULL, "user database error");
    }
    if (n > a->cfg.max_list_users) {
        char msg[192];
        snprintf(msg, sizeof(msg),
                 "too many users to list in one response: %zu stored, cap is %zu", n,
                 a->cfg.max_list_users);
        CLOAK_LOGW("adminapi: refusing a listing of %zu users (cap %zu)", n, a->cfg.max_list_users);
        return adminapi_respond_text(ast, 500, NULL, msg);
    }
    if (n == 0) {
        return adminapi_respond(ast, 200, "application/json", NULL, "[]", 2);
    }

    cloak_user_info_t *infos = calloc(n, sizeof(*infos));
    if (infos == NULL) {
        return adminapi_respond_text(ast, 500, NULL, "out of memory");
    }
    size_t got = 0;
    rc = cloak_usermanager_list(a->cfg.manager, infos, n, &got);
    if (rc != 0) {
        free(infos);
        return adminapi_respond_text(ast, 500, NULL, "user database error");
    }
    if (got > n) {
        got = n; /* the count cannot grow between two calls on one reactor
                  * turn, but the buffer is what bounds the copy either way */
    }

    /* Worst case per element: one whole CLOAK_USER_JSON_MAX document plus
     * its separating comma. Plus the two brackets and a NUL that
     * cloak_user_json_encode needs room for in the scratch, never in
     * here. */
    size_t cap = 2 + got * (CLOAK_USER_JSON_MAX + 1) + 1;
    char *buf = malloc(cap);
    if (buf == NULL) {
        free(infos);
        return adminapi_respond_text(ast, 500, NULL, "out of memory");
    }
    size_t len = 0;
    buf[len++] = '[';
    for (size_t i = 0; i < got; i++) {
        if (i > 0) {
            buf[len++] = ',';
        }
        char one[CLOAK_USER_JSON_MAX];
        size_t one_len = 0;
        if (cloak_user_json_encode(&infos[i], CLOAK_USER_FIELD_ALL, one, sizeof(one), &one_len) !=
            0) {
            free(buf);
            free(infos);
            return adminapi_respond_text(ast, 500, NULL, "could not encode a stored user");
        }
        memcpy(buf + len, one, one_len);
        len += one_len;
    }
    buf[len++] = ']';

    int r = adminapi_respond(ast, 200, "application/json", NULL, buf, len);
    free(buf);
    free(infos);
    return r;
}

static int adminapi_handle_get_one(cloak_adminapi_stream_t *ast,
                                   const uint8_t uid[CLOAK_UID_LEN]) {
    cloak_user_info_t info;
    memset(&info, 0, sizeof(info));
    int rc = cloak_usermanager_get(ast->as->a->cfg.manager, uid, &info);
    if (rc == CLOAK_USER_ERR_NOT_FOUND) {
        return adminapi_respond_text(ast, 404, NULL, "user not found");
    }
    if (rc != 0) {
        return adminapi_respond_text(ast, 500, NULL, "user database error");
    }
    char json[CLOAK_USER_JSON_MAX];
    size_t json_len = 0;
    if (cloak_user_json_encode(&info, CLOAK_USER_FIELD_ALL, json, sizeof(json), &json_len) != 0) {
        return adminapi_respond_text(ast, 500, NULL, "could not encode the stored user");
    }
    return adminapi_respond(ast, 200, "application/json", NULL, json, json_len);
}

/* POST /admin/users/{uid}.
 *
 * THE PATH UID IS AUTHORITATIVE AND A DISAGREEING BODY UID IS REFUSED
 * WITHOUT A WRITE. Go's writeUserInfoHlr detects the mismatch, writes
 * "UID mismatch" to the response, and then performs the write anyway --
 * with the BODY's UID -- so a POST to /admin/users/<A> carrying a body
 * naming <B> modifies <B> and the path is decorative. That is an
 * authorisation bug, not a cosmetic missing `return`: the resource a
 * request names is the resource it may change. This port refuses it.
 *
 * An ABSENT body UID is fine and is the ordinary case: the field is
 * optional (cloak/user_json.h reports it through out_have_uid precisely
 * because the router takes the UID from the path).
 *
 * io_info is NOT seeded from cloak_usermanager_get first, even though
 * cloak/user_json.h describes that as an option: cloak_usermanager_write
 * already applies exactly the fields named in the mask and leaves every
 * other column of an existing row alone, so a read-then-merge would
 * change nothing about the result and would add a second database
 * round-trip whose value could only ever be stale. */
static int adminapi_handle_post(cloak_adminapi_stream_t *ast, const uint8_t uid[CLOAK_UID_LEN],
                                const cloak_http_request_t *req) {
    cloak_user_info_t info;
    memset(&info, 0, sizeof(info));
    memcpy(info.uid, uid, CLOAK_UID_LEN);

    uint32_t fields = 0;
    int have_uid = 0;
    int rc = cloak_user_json_decode(req->body, req->body_len, &info, &fields, &have_uid);
    if (rc == CLOAK_USER_JSON_ERR_MEMORY) {
        return adminapi_respond_text(ast, 500, NULL, "out of memory");
    }
    if (rc == CLOAK_USER_JSON_ERR_ARG) {
        /* A caller bug, not a wire condition -- unreachable from here, but
         * reporting it as a client error would send an operator hunting
         * for a mistake in their own request. */
        return adminapi_respond_text(ast, 500, NULL, "internal decode error");
    }
    if (rc != 0) {
        return adminapi_respond_text(ast, 400, NULL, "malformed user document");
    }

    if (have_uid && memcmp(info.uid, uid, CLOAK_UID_LEN) != 0) {
        /* RETURN, and no write. See this function's comment. */
        CLOAK_LOGW("adminapi: refusing a POST whose body UID disagrees with its path UID");
        return adminapi_respond_text(ast, 400, NULL, "UID mismatch");
    }
    /* The path wins even when the body agreed, so there is exactly one
     * source of truth for what is being written. */
    memcpy(info.uid, uid, CLOAK_UID_LEN);

    rc = cloak_usermanager_write(ast->as->a->cfg.manager, &info, fields);
    if (rc != 0) {
        /* RETURN. Go writes the error and then answers 201 over the top
         * of it, so a client cannot tell a failed write from a
         * successful one. */
        return adminapi_respond_text(ast, 500, NULL, "user database error");
    }
    return adminapi_respond(ast, 201, "application/json", NULL, NULL, 0);
}

static int adminapi_handle_delete(cloak_adminapi_stream_t *ast,
                                  const uint8_t uid[CLOAK_UID_LEN]) {
    int rc = cloak_usermanager_delete(ast->as->a->cfg.manager, uid);
    if (rc == CLOAK_USER_ERR_NOT_FOUND) {
        return adminapi_respond_text(ast, 404, NULL, "user not found");
    }
    if (rc != 0) {
        /* RETURN, for the same reason the POST path does. */
        return adminapi_respond_text(ast, 500, NULL, "user database error");
    }
    return adminapi_respond(ast, 200, "application/json", NULL, NULL, 0);
}

/* ---- routing ------------------------------------------------------------- */

/* Routes one fully parsed request and composes its response. Returns 0,
 * or -1 if no response could be composed at all (allocation failure), in
 * which case the caller tears the stream down.
 *
 * THE PATH IS MATCHED AS RECEIVED, minus any query string. It is
 * deliberately NOT percent-decoded, even though Go's gorilla/mux matches
 * against the decoded r.URL.Path: base64url's alphabet contains no
 * character that needs escaping, so no legitimate client ever sends one,
 * and a decoder here would be a second place where a path is normalised
 * (cloak/http.h refuses to be the first). A percent-escaped UID simply
 * fails to decode and is answered 400, which is an honest answer rather
 * than a differential. */
static int adminapi_route(cloak_adminapi_stream_t *ast) {
    const cloak_http_request_t *req = cloak_http_parser_request(&ast->parser);

    if (cloak_http_parser_state(&ast->parser) == CLOAK_HTTP_ERROR) {
        /* The parser's own decision is forwarded verbatim; it is the only
         * thing that can distinguish 413 from 414 from 431 from 501, and
         * re-deriving any of that here would be a second parser. */
        return adminapi_respond_text(ast, req->status, NULL, "bad request");
    }

    /* Go registers OPTIONS on the router itself, not per route, so it
     * answers for any path -- including one that would otherwise 404. */
    if (req->method == CLOAK_HTTP_METHOD_OPTIONS) {
        return adminapi_respond(ast, 200, "text/plain; charset=utf-8",
                                "Access-Control-Allow-Methods: " ADMINAPI_CORS_METHODS "\r\n",
                                NULL, 0);
    }

    size_t plen = strcspn(req->path, "?");
    if (plen < ADMINAPI_USERS_PATH_LEN ||
        memcmp(req->path, ADMINAPI_USERS_PATH, ADMINAPI_USERS_PATH_LEN) != 0) {
        return adminapi_respond_text(ast, 404, NULL, "not found");
    }

    if (plen == ADMINAPI_USERS_PATH_LEN) {
        if (req->method != CLOAK_HTTP_METHOD_GET) {
            return adminapi_respond_text(ast, 405, "Allow: " ADMINAPI_ALLOW_COLLECTION "\r\n",
                                         "method not allowed");
        }
        return adminapi_handle_list(ast);
    }
    if (req->path[ADMINAPI_USERS_PATH_LEN] != '/') {
        /* "/admin/usersXYZ" is a different resource entirely, not a
         * malformed UID. */
        return adminapi_respond_text(ast, 404, NULL, "not found");
    }

    const char *b64 = req->path + ADMINAPI_USERS_PATH_LEN + 1;
    size_t b64_len = plen - (ADMINAPI_USERS_PATH_LEN + 1);
    if (b64_len == 0) {
        /* RETURN. Go's handlers write "UID cannot be empty" and two of
         * the four then carry on to decode "" anyway. */
        return adminapi_respond_text(ast, 400, NULL, "UID cannot be empty");
    }
    if (b64_len >= CLOAK_HTTP_MAX_PATH) {
        return adminapi_respond_text(ast, 400, NULL, "UID too long");
    }

    /* A NUL-terminated copy, because cloak_base64url_decode takes a
     * string and the path may carry a query after the UID. The bound
     * above is what makes this copy safe; CLOAK_HTTP_MAX_PATH is the
     * parser's own cap on the whole target. */
    char b64z[CLOAK_HTTP_MAX_PATH];
    memcpy(b64z, b64, b64_len);
    b64z[b64_len] = '\0';

    /* URL-SAFE, NOT STANDARD. The same 16 bytes travel standard-alphabet
     * base64 inside the JSON body of this very request (Go's
     * encoding/json marshals a []byte with StdEncoding) and url-safe in
     * the path (api_router.go decodes it with base64.URLEncoding). Using
     * the wrong decoder here accepts a '+' or '/' where a real client
     * sends '-' or '_', and the mismatch is silent until a UID happens to
     * contain the offending sextet. */
    uint8_t uid[CLOAK_UID_LEN];
    size_t uid_len = 0;
    if (cloak_base64url_decode(b64z, uid, sizeof(uid), &uid_len) != 0 ||
        uid_len != CLOAK_UID_LEN) {
        return adminapi_respond_text(ast, 400, NULL, "malformed UID");
    }

    switch (req->method) {
    case CLOAK_HTTP_METHOD_GET:
        return adminapi_handle_get_one(ast, uid);
    case CLOAK_HTTP_METHOD_POST:
        return adminapi_handle_post(ast, uid, req);
    case CLOAK_HTTP_METHOD_DELETE:
        return adminapi_handle_delete(ast, uid);
    default:
        return adminapi_respond_text(ast, 405, "Allow: " ADMINAPI_ALLOW_ITEM "\r\n",
                                     "method not allowed");
    }
}

/* ---- reading ------------------------------------------------------------- */

/* Pulls whatever has arrived on this stream into the parser, and, the
 * moment the parser reaches a terminal state, routes and starts writing.
 * ast may be freed by the time this returns. */
static void adminapi_drain(cloak_adminapi_stream_t *ast) {
    if (ast->resp != NULL) {
        /* A response already exists, so this stream has stopped reading.
         * Bytes arriving after a complete request are a protocol
         * violation on a connection that carries exactly one request;
         * leaving them unread (rather than feeding them to a parser that
         * would refuse them anyway) is what makes that true rather than
         * merely documented. */
        return;
    }
    for (;;) {
        uint8_t chunk[ADMINAPI_READ_CHUNK];
        long n = cloak_stream_read(ast->stream, chunk, sizeof(chunk));
        if (n == 0) {
            return; /* nothing more right now */
        }
        if (n == CLOAK_STREAM_ERR_SHORT_BUFFER) {
            /* Not an end of stream, and deliberately NOT folded into the
             * arm below. An unordered peer sent one datagram larger than
             * ADMINAPI_READ_CHUNK, which that constant is sized to make
             * impossible for any session at the shipping
             * max_on_wire_size -- so reaching here means a session
             * configured above it, and the datagram is undeliverable to
             * this reader no matter how many times it is re-read (the
             * chunk is a compile-time size; nothing here grows). Tearing
             * down is the only non-wedging answer available, exactly as
             * in stream_relay.c's empty-queue case, but it is reached by
             * its own named branch so the log and the next reader see a
             * request too large to read rather than a client that hung
             * up. */
            adminapi_stream_teardown(ast);
            return;
        }
        if (n < 0) {
            /* End of stream before the request finished: the client
             * closed mid-message and there is nobody to answer. */
            adminapi_stream_teardown(ast);
            return;
        }
        cloak_http_state_t st = cloak_http_parser_feed(&ast->parser, chunk, (size_t)n, NULL);
        if (st == CLOAK_HTTP_INCOMPLETE) {
            continue;
        }
        if (adminapi_route(ast) != 0) {
            /* No response could be composed -- there is nothing to say
             * and nothing to wait for. */
            adminapi_stream_teardown(ast);
            return;
        }
        adminapi_pump_write(ast);
        return; /* ast may already be freed */
    }
}

/* ---- the deadline -------------------------------------------------------- */

/* The obligation cloak/http.h states and cannot meet itself: a parser
 * cannot time anything out, so a request that stops one byte short of its
 * Content-Length stays INCOMPLETE forever. This also covers the WRITE
 * half -- a client that issues a large GET and then stops reading pins
 * the response buffer exactly as a half-sent request pins a parser -- so
 * the whole exchange is bounded by one timer that is armed once and never
 * re-armed. */
static void adminapi_on_deadline(cloak_reactor_t *r, void *userdata) {
    (void)r;
    cloak_adminapi_stream_t *ast = userdata;
    ast->deadline = CLOAK_TIMER_INVALID; /* already fired: nothing to cancel */
    CLOAK_LOGW("adminapi: closing a stream that did not complete its exchange within the "
               "request deadline");
    adminapi_stream_teardown(ast);
}

/* ---- session callbacks --------------------------------------------------- */

static void adminapi_on_new_stream(cloak_session_t *sesh, cloak_stream_t *stream, void *userdata) {
    cloak_adminapi_session_t *as = userdata;
    if (as == NULL || sesh == NULL || stream == NULL) {
        return;
    }
    if (as->sesh == NULL) {
        /* THE ONLY PLACE as->sesh IS EVER SET, and the earliest moment
         * the pointer is of any use: everything in this module that wants
         * it wants it for a stream. */
        as->sesh = sesh;
    }
    cloak_adminapi_t *a = as->a;

    /* THE CAP, checked before anything is allocated or registered with
     * the reactor -- a cap enforced any later would already have spent
     * the resource it exists to protect. Releasing the stream is legal
     * from within this callback (cloak/session.h) and performs the active
     * close itself, so the client learns immediately. */
    if (as->stream_count >= a->cfg.max_streams_per_session) {
        CLOAK_LOGW("adminapi: refusing a stream for session %u -- per-session cap of %zu reached",
                   as->session_id, a->cfg.max_streams_per_session);
        cloak_session_release_stream(sesh, stream);
        return;
    }

    cloak_adminapi_stream_t *ast = calloc(1, sizeof(*ast));
    if (ast == NULL) {
        cloak_session_release_stream(sesh, stream);
        return;
    }
    ast->as = as;
    ast->stream = stream;
    cloak_http_parser_init(&ast->parser);
    ast->deadline = cloak_reactor_add_timer(a->cfg.reactor, a->cfg.request_timeout_ms,
                                            adminapi_on_deadline, ast);
    if (ast->deadline == CLOAK_TIMER_INVALID) {
        /* An unbounded stream is exactly what the deadline exists to
         * prevent, so a stream that cannot have one is refused rather
         * than admitted without it. */
        cloak_http_parser_destroy(&ast->parser);
        free(ast);
        cloak_session_release_stream(sesh, stream);
        return;
    }
    adminapi_stream_link(as, ast);

    /* READ NOW. on_stream_data is deliberately NOT fired for the frame
     * that revealed a stream (cloak/session.h), so a request small enough
     * to arrive in that first frame -- which is every real admin request
     * -- would otherwise sit unread until a second frame that never
     * comes, and then be closed by its own deadline. */
    adminapi_drain(ast);
}

static void adminapi_on_stream_data(cloak_session_t *sesh, cloak_stream_t *stream,
                                    void *userdata) {
    (void)sesh;
    cloak_adminapi_session_t *as = userdata;
    if (as == NULL || stream == NULL) {
        return;
    }
    /* A linear scan over at most max_streams_per_session entries. next is
     * saved before the call that can free the node, matching
     * proxy_on_stream_data's own discipline -- the early return below
     * means this loop would survive without it, and it is written this
     * way anyway so the pattern cannot rot. */
    cloak_adminapi_stream_t *ast = as->streams;
    while (ast != NULL) {
        cloak_adminapi_stream_t *next = ast->next;
        if (ast->stream == stream) {
            adminapi_drain(ast);
            return; /* ast may already be freed */
        }
        ast = next;
    }
}

static void adminapi_on_writable(cloak_session_t *sesh, void *userdata) {
    (void)sesh;
    cloak_adminapi_session_t *as = userdata;
    if (as == NULL) {
        return;
    }
    if (as->in_writable) {
        /* A NESTED WALK, raised by a cloak_stream_write this very walk
         * made (cloak/session.h permits that callback to fire
         * synchronously from underneath a write). Refusing it loses
         * nothing -- the outer walk re-reads every remaining stream's
         * budget -- and it is what keeps the outer walk's saved `next`
         * pointer from being freed by a teardown a nested walk performed.
         */
        return;
    }
    as->in_writable = 1;

    cloak_adminapi_stream_t *ast = as->streams;
    while (ast != NULL) {
        cloak_adminapi_stream_t *next = ast->next;
        if (ast->resp != NULL) {
            adminapi_pump_write(ast); /* may free ast */
        }
        ast = next;
    }

    as->in_writable = 0;
}

/* ---- public entry points -------------------------------------------------- */

int cloak_adminapi_init(cloak_adminapi_t *a, const cloak_adminapi_config_t *cfg) {
    if (a == NULL) {
        return -1;
    }
    /* Fully initialize BEFORE validating anything else, so that every
     * failure return leaves a safe to pass to cloak_adminapi_destroy. */
    memset(a, 0, sizeof(*a));

    if (cfg == NULL || cfg->reactor == NULL || cfg->manager == NULL) {
        return -1;
    }
    a->cfg = *cfg;
    if (a->cfg.request_timeout_ms == 0) {
        a->cfg.request_timeout_ms = CLOAK_ADMINAPI_DEFAULT_REQUEST_TIMEOUT_MS;
    }
    if (a->cfg.max_list_users == 0) {
        a->cfg.max_list_users = CLOAK_ADMINAPI_DEFAULT_MAX_LIST_USERS;
    }
    if (a->cfg.max_streams_per_session == 0) {
        a->cfg.max_streams_per_session = CLOAK_ADMINAPI_DEFAULT_MAX_STREAMS_PER_SESSION;
    }
    return 0;
}

void cloak_adminapi_destroy(cloak_adminapi_t *a) {
    if (a == NULL) {
        return;
    }
    /* Idempotent and safe on a zeroed struct for the same reason: a
     * zeroed (or already-drained) adminapi has no sessions, so this loop
     * does not run and nothing below it touches the borrowed reactor. */
    while (a->sessions != NULL) {
        adminapi_session_teardown(a->sessions);
    }
}

int cloak_adminapi_prepare_session(cloak_adminapi_t *a, const uint8_t uid[CLOAK_UID_LEN],
                                   uint32_t session_id, cloak_session_config_t *config) {
    if (a == NULL || uid == NULL || config == NULL) {
        return -1;
    }
    cloak_adminapi_session_t *as = calloc(1, sizeof(*as));
    if (as == NULL) {
        return -1;
    }
    as->a = a;
    as->sesh = NULL; /* adminapi_on_new_stream records it with the first stream */
    memcpy(as->uid, uid, CLOAK_UID_LEN);
    as->session_id = session_id;
    adminapi_session_link(a, as);

    config->on_new_stream = adminapi_on_new_stream;
    config->on_new_stream_userdata = as;
    config->on_stream_data = adminapi_on_stream_data;
    config->on_stream_data_userdata = as;
    config->on_writable = adminapi_on_writable;
    config->on_writable_userdata = as;
    /* on_broken and on_broken_userdata are deliberately untouched --
     * cloak_server_registry_get_or_create overwrites both regardless. */
    return 0;
}

void cloak_adminapi_registry_broken(cloak_server_registry_t *reg, cloak_session_t *sesh,
                                    const uint8_t uid[CLOAK_UID_LEN], uint32_t session_id,
                                    void *userdata) {
    cloak_adminapi_t *a = userdata;
    if (a == NULL) {
        /* Not this module's callback at all; there is not even a chain to
         * reach from here. */
        return;
    }

    /* THE ONLY WINDOW IN WHICH THIS CAN BE DONE: sesh is still fully
     * usable right now, and every stream still active when this returns
     * is destroyed and freed by the session itself (cloak/session.h). A
     * context left behind leaks, and its deadline timer would fire on a
     * freed cloak_stream_t. */
    if (uid != NULL) {
        cloak_adminapi_session_t *as = adminapi_find_session(a, uid, session_id);
        if (as != NULL) {
            adminapi_session_teardown(as);
        }
        /* No context is not an error: this session belongs to something
         * else (the proxy, most likely). Fall through to the chain. */
    }

    /* AFTER the cleanup, never before. The next link may reach
     * cloak_userpanel_terminate, which closes sessions, and a link after
     * that is permitted to destroy the registry outright. */
    if (a->cfg.chain != NULL) {
        a->cfg.chain(reg, sesh, uid, session_id, a->cfg.chain_userdata);
    }
}

void cloak_adminapi_session_aborted(cloak_adminapi_t *a, const uint8_t uid[CLOAK_UID_LEN],
                                    uint32_t session_id) {
    if (a == NULL || uid == NULL) {
        return;
    }
    /* The same shared walk as every other path, deliberately: at the
     * dispatcher's abort sites this degenerates to an unlink and a free,
     * but a second "simpler" copy of the teardown is exactly how the two
     * would drift apart if a later change ever made one of those sites
     * reachable with a stream in flight. */
    cloak_adminapi_session_t *as = adminapi_find_session(a, uid, session_id);
    if (as != NULL) {
        adminapi_session_teardown(as);
    }
}

size_t cloak_adminapi_session_count(const cloak_adminapi_t *a) {
    return a == NULL ? 0 : a->session_count;
}

size_t cloak_adminapi_stream_count(const cloak_adminapi_t *a) {
    return a == NULL ? 0 : a->stream_count;
}
