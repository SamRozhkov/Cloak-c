#define _POSIX_C_SOURCE 200809L

/* ck-server -- the Cloak server, as a program.
 *
 * The port of Go Cloak's cmd/ck-server/ck-server.go. Everything that file
 * does after parsing its flags -- build the server state, listen, serve --
 * is one call to cloak_server_stack_open here, because libcloak-server
 * owns the nine-object graph and its teardown order (cloak/server_stack.h
 * explains at length why that is not a binary's business). What is left in
 * this file is argument handling, configuration loading, and the plugin
 * mode's environment translation.
 *
 * ---------------------------------------------------------------------
 * EXIT CODES. Go uses log.Fatal for every failure, which is exit 1 for
 * everything: a supervisor cannot tell "this config will never work" from
 * "port 443 was busy this second" from "the database disappeared". This
 * port distinguishes them, deliberately, and the mapping is part of the
 * contract from the commit that introduced it -- an operator's restart
 * policy keys on these, so they do not change later:
 *
 *   0  success: the server ran and shut down cleanly on SIGINT/SIGTERM.
 *   1  usage error: an unknown flag, a flag missing its value, a
 *      -verbosity level that is not a level name, or -d (see below).
 *      Retrying is pointless; the command line is wrong.
 *   2  configuration error: the config could not be read or parsed, a
 *      BindAddr could not be resolved, the plugin environment was
 *      incomplete, or cloak_server_stack_open rejected the configuration
 *      itself (CONFIG / TEMPLATE / RETRY_LADDER / SERVER / DATABASE).
 *      Retrying is pointless until the config or the environment changes.
 *   3  bind failure: cloak_server_stack_open could not open a listening
 *      socket (CLOAK_SERVER_STACK_ERR_LISTEN). THIS IS THE ONE WORTH
 *      RETRYING -- a port in TIME_WAIT from the previous instance, an
 *      interface that has not come up yet -- and it is the reason these
 *      codes exist at all.
 *   4  runtime failure: everything else. Out of memory, no reactor, no
 *      signalfd, a constructor refusing for allocation-class reasons.
 *      Retrying may or may not help; the log line says what broke.
 *
 * ---------------------------------------------------------------------
 * DIVERGENCE FROM GO, D3: -c ACCEPTS INLINE CONTENT, AND GO'S DOES NOT.
 *
 * Go's flag help for the server says "config: path to the configuration
 * file or its content", and the second half of that sentence is false.
 * server.ParseConfig (internal/server/state.go) reads:
 *
 *     content, errPath := ioutil.ReadFile(conf)
 *     if errPath != nil {
 *         errJson := json.Unmarshal(content, &raw)   // <- content, not conf
 *         ...
 *
 * On a read failure it unmarshals `content` -- the empty buffer it just
 * failed to fill -- rather than the string the operator passed, so inline
 * content always fails with "unexpected end of JSON input". The CLIENT's
 * equivalent (client.ParseConfig) does not share the bug: it switches on
 * the string itself. This port implements what the help text promises: -c
 * is tried as a path first, and if it cannot be read, the value itself is
 * parsed as JSON. Both failures are reported together, naming the path, so
 * an operator who mistyped a filename does not get a JSON syntax error.
 *
 * Note the format: the server's inline form is JSON, not the
 * semicolon-separated ssv the client accepts. That is Go's shape too --
 * ParseConfig's comment says "config file or semicolon-separated options"
 * but its body only ever calls json.Unmarshal -- and it is what
 * SS_PLUGIN_OPTIONS carries for the server side (see PLUGIN MODE below).
 *
 * ---------------------------------------------------------------------
 * DIVERGENCE FROM GO, D6: NO -d / pprof.
 *
 * Go's -d starts net/http/pprof on an operator-supplied address. A second
 * listening socket, speaking a trivially fingerprintable protocol, in a
 * program whose entire purpose is not being noticed, is not a debugging
 * convenience worth having. -d is recognised and rejected with that
 * reason rather than silently ignored, so a script carrying it over from
 * Go Cloak fails loudly instead of quietly losing its profiler. (Go's
 * flag.Usage lists -d and usage() below does not, so an operator learns
 * why it is refused by trying it rather than by reading --help.)
 *
 * ---------------------------------------------------------------------
 * FOUR SMALLER THINGS THAT ARE NOT DIVERGENCES BUT LOOK LIKE THEM, and
 * were true of this file for a whole branch without being written down.
 * They are here because a reader comparing the two implementations will
 * reach for this comment block and not for a report.
 *
 * P1. PLUGIN MODE IGNORES -verbosity, AND STANDALONE MODE HONOURS IT --
 *     faithfully, and the opposite way round from ck-client. In Go's
 *     server, log.SetLevel sits INSIDE the standalone `else` branch; in
 *     Go's client it sits outside the if/else and applies to both modes.
 *     Each port follows its own original. The visible consequence is that
 *     `-verbosity error` silences a plugin-mode ck-client and does not
 *     silence a plugin-mode ck-server, while usage() advertises
 *     -verbosity unconditionally.
 *
 * P2. PLUGIN MODE IGNORES EVERY ARGV TOKEN, including a misspelt one --
 *     also Go's ("Go does not look at argv at all in plugin mode"), and
 *     also the opposite of ck-client, which refuses an unknown flag in
 *     plugin mode by name and lists what it does accept. A launcher that
 *     passes ck-server a typo in plugin mode gets no complaint from
 *     either implementation.
 *
 * P3. AN EMPTY SS_REMOTE_HOST IS FATAL HERE AND IS FINE IN GO.
 *     merge_ss_bind_addr refuses the one-sided environment; Go's
 *     parseSSBindAddr takes net.JoinHostPort("", port) -> ":port", which
 *     resolves and listens on the wildcard. Refusing is the better
 *     behaviour -- a half-populated SS environment is a broken launcher
 *     and should say so rather than silently listening somewhere the
 *     launcher did not ask for -- and it is tested
 *     (test_plugin_one_sided_remote_env_is_refused). It is a real
 *     divergence and was simply never declared.
 *
 * P4. -v PRINTS A TRAILING NEWLINE; Go's fmt.Printf("ck-server %s",
 *     version) does not. Cosmetic, deliberate, and recorded so nobody
 *     "fixes" a diff that is not a defect.
 */

#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "cJSON.h"

#include "cloak/common.h"
#include "cloak/config.h"
#include "cloak/keygen.h"
#include "cloak/log.h"
#include "cloak/net.h"
#include "cloak/reactor.h"
#include "cloak/server_stack.h"
#include "cloak/signals.h"

#define CK_EXIT_OK      0
#define CK_EXIT_USAGE   1
#define CK_EXIT_CONFIG  2
#define CK_EXIT_BIND    3
#define CK_EXIT_RUNTIME 4

/* Matches the library's own cap on a config file. */
#define CK_MAX_CONFIG_FILE (1024 * 1024)

#define CK_ERR_LEN 512

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

static int ck_err(char *err, size_t cap, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static int ck_err(char *err, size_t cap, const char *fmt, ...) {
    if (err != NULL && cap > 0) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, cap, fmt, ap);
        va_end(ap);
    }
    return -1;
}

static void usage(FILE *out) {
    fprintf(out, "Usage of ck-server:\n");
    fprintf(out, "  -c string\n");
    fprintf(out,
            "        config: path to the configuration file or its content "
            "(default \"server.json\")\n");
    fprintf(out, "  -h    Print this message\n");
    fprintf(out, "  -k    Generate a pair of public and private key and output to STDOUT in "
                 "the format of <public key>,<private key>\n");
    fprintf(out, "  -key  Generate and print out a public-private key pair\n");
    fprintf(out, "  -u    Generate a UID to STDOUT\n");
    fprintf(out, "  -uid  Generate and print out a UID\n");
    fprintf(out, "  -v    Print the version number\n");
    fprintf(out, "  -verbosity string\n");
    fprintf(out, "        verbosity level: error, warn, info, debug or trace "
                 "(default \"info\")\n");
}

/* ------------------------------------------------------------------ */
/* Key and UID generation                                              */
/* ------------------------------------------------------------------ */

/* -u and -uid are the same value in two dresses: one for a script to
 * capture, one for a human to read. Same for -k and -key. */

static int print_uid(int human) {
    char uid[64];
    if (cloak_keygen_uid(uid, sizeof(uid)) != 0) {
        fprintf(stderr, "failed to generate a UID\n");
        return CK_EXIT_RUNTIME;
    }
    if (human) {
        printf("\x1B[35mYour UID is:\x1B[0m %s\n", uid);
    } else {
        printf("%s\n", uid);
    }
    return CK_EXIT_OK;
}

static int print_keypair(int human) {
    char pub[64];
    char priv[64];
    if (cloak_keygen_keypair(pub, sizeof(pub), priv, sizeof(priv)) != 0) {
        fprintf(stderr, "failed to generate a key pair\n");
        return CK_EXIT_RUNTIME;
    }
    if (human) {
        printf("\x1B[36mYour PUBLIC key is:\x1B[0m %s\n", pub);
        printf("\x1B[33mYour PRIVATE key is (keep it secret):\x1B[0m %s\n", priv);
    } else {
        printf("%s,%s\n", pub, priv);
    }
    return CK_EXIT_OK;
}

/* ------------------------------------------------------------------ */
/* Bind address canonicalisation                                       */
/* ------------------------------------------------------------------ */

/* Go's resolveBindAddr runs every BindAddr through net.ResolveTCPAddr and
 * then listens on the RESULT's String(), not on the string from the
 * config -- which is also what makes parseSSBindAddr's de-duplication
 * comparisons work, since they compare those canonical forms. This is
 * that step: resolve, then re-render in Go's net.TCPAddr.String() shape.
 *
 * The empty host is special-cased rather than resolved, because that is
 * what Go produces: ResolveTCPAddr("tcp", ":443") yields TCPAddr{IP: nil,
 * Port: 443}, whose String() is ":443" -- NOT "0.0.0.0:443", which is what
 * getaddrinfo(NULL, ...) with AI_PASSIVE would render. The distinction is
 * load-bearing: parseSSBindAddr's rules test for ":port" and for
 * "0.0.0.0:port" separately and mean different things by them.
 *
 * This resolves, so it BLOCKS on DNS. Startup only, which is where it is
 * called -- the same licence cloak/net.h gives cloak_net_resolve and
 * cloak_server_stack_open's step 1 takes. */
static int canon_addr(const char *addr, char *out, size_t cap, char *err, size_t err_cap) {
    char host[CLOAK_MAX_HOST_LEN];
    char port[CLOAK_MAX_PORT_LEN];
    if (cloak_net_split_hostport(addr, host, sizeof(host), port, sizeof(port)) != 0) {
        return ck_err(err, err_cap, "unable to parse bind address \"%s\": expected host:port",
                      addr);
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (host[0] == '\0') {
        hints.ai_flags = AI_PASSIVE;
    }

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host[0] == '\0' ? NULL : host, port, &hints, &res);
    if (rc != 0 || res == NULL) {
        return ck_err(err, err_cap, "unable to resolve bind address \"%s\": %s", addr,
                      gai_strerror(rc));
    }

    char hbuf[256];
    char pbuf[32];
    rc = getnameinfo(res->ai_addr, res->ai_addrlen, hbuf, sizeof(hbuf), pbuf, sizeof(pbuf),
                     NI_NUMERICHOST | NI_NUMERICSERV);
    freeaddrinfo(res);
    if (rc != 0) {
        return ck_err(err, err_cap, "unable to render bind address \"%s\": %s", addr,
                      gai_strerror(rc));
    }

    if (host[0] == '\0') {
        snprintf(out, cap, ":%s", pbuf);
    } else if (strchr(hbuf, ':') != NULL) {
        /* Go's net.JoinHostPort / TCPAddr.String() bracket an IPv6 literal. */
        snprintf(out, cap, "[%s]:%s", hbuf, pbuf);
    } else {
        snprintf(out, cap, "%s:%s", hbuf, pbuf);
    }
    return 0;
}

typedef char ck_bind_list_t[CLOAK_MAX_BIND_ADDR][CLOAK_MAX_HOST_LEN];

static int bind_list_append(ck_bind_list_t list, size_t *n, const char *addr, char *err,
                            size_t err_cap) {
    if (*n >= CLOAK_MAX_BIND_ADDR) {
        return ck_err(err, err_cap, "more than %d bind addresses", CLOAK_MAX_BIND_ADDR);
    }
    snprintf(list[*n], CLOAK_MAX_HOST_LEN, "%s", addr);
    (*n)++;
    return 0;
}

/* Drops later duplicates, loudly.
 *
 * Go has no such pass and does not need one for its own config -- but its
 * parseSSBindAddr CAN produce one (see merge_ss_bind_addr) and a config
 * that simply lists the same address twice reaches net.Listen twice, where
 * the second bind fails with EADDRINUSE and log.Fatal takes the server
 * down. Dropping the duplicate with a WARN is strictly better than dying,
 * and the WARN is what keeps it from being a silent repair: this port's
 * own tests assert the line is ABSENT in the cases where the merge rules
 * are supposed to have prevented the duplicate in the first place. */
static void bind_list_dedupe(ck_bind_list_t list, size_t *n) {
    size_t out = 0;
    for (size_t i = 0; i < *n; i++) {
        int dup = 0;
        for (size_t j = 0; j < out; j++) {
            if (strcmp(list[i], list[j]) == 0) {
                dup = 1;
                break;
            }
        }
        if (dup) {
            CLOAK_LOGW("dropping duplicate bind address %s", list[i]);
            continue;
        }
        if (out != i) {
            memcpy(list[out], list[i], CLOAK_MAX_HOST_LEN);
        }
        out++;
    }
    *n = out;
}

/* ------------------------------------------------------------------ */
/* Plugin mode (D5)                                                    */
/* ------------------------------------------------------------------ */

/* Go's parseSSBindAddr, ported rule for rule.
 *
 * SS gives the plugin the address IT wants the plugin to listen on. When
 * ss-server listens on both address families it reports the pair joined by
 * a pipe -- "::|0.0.0.0" -- which means "both", and which Go turns into
 * the wildcard ":port". The rest of the function harmonises that with
 * whatever the operator's own BindAddr already says, so the two do not
 * produce two listeners on the same socket:
 *
 *   R1 an entry that already equals the SS address     -> do not append.
 *   R2 an entry that is already the wildcard ":port"   -> do not append
 *      (it covers whatever SS asked for on that port).
 *   R3 an entry that is "0.0.0.0:port" or "[::]:port"  -> if SS wants
 *      BOTH families, UPGRADE that entry in place to ":port".
 *
 * ONE DELIBERATE FIX. Go sets shouldAppend = true inside R3 and then
 * appends anyway, so ["0.0.0.0:P"] + SS "::|0.0.0.0" becomes [":P", ":P"]
 * -- two listeners on the same wildcard socket, the second of which fails
 * to bind and calls log.Fatal. The upgrade already put the SS address into
 * the list, so appending it again can only ever be wrong; this port
 * suppresses the append instead. (A config listing BOTH "0.0.0.0:P" and
 * "[::]:P" still collapses to one entry, but through bind_list_dedupe's
 * WARN rather than here.) */
static int merge_ss_bind_addr(const char *ss_host, const char *ss_port, ck_bind_list_t list,
                              size_t *n, char *err, size_t err_cap) {
    if (ss_host == NULL || ss_host[0] == '\0' || ss_port == NULL || ss_port[0] == '\0') {
        return ck_err(err, err_cap,
                      "plugin mode: SS_REMOTE_HOST and SS_REMOTE_PORT must both be set");
    }

    /* Go: len(strings.Split(ssRemoteHost, "|")) == 2 -- exactly one pipe. */
    int pipes = 0;
    for (const char *p = ss_host; *p != '\0'; p++) {
        if (*p == '|') {
            pipes++;
        }
    }

    char ss_bind[CLOAK_MAX_HOST_LEN];
    if (pipes == 1) {
        snprintf(ss_bind, sizeof(ss_bind), ":%s", ss_port);
    } else if (strchr(ss_host, ':') != NULL) {
        snprintf(ss_bind, sizeof(ss_bind), "[%s]:%s", ss_host, ss_port);
    } else {
        snprintf(ss_bind, sizeof(ss_bind), "%s:%s", ss_host, ss_port);
    }

    char ss_canon[CLOAK_MAX_HOST_LEN];
    char sub[CK_ERR_LEN];
    if (canon_addr(ss_bind, ss_canon, sizeof(ss_canon), sub, sizeof(sub)) != 0) {
        return ck_err(err, err_cap, "unable to resolve bind address provided by SS: %s", sub);
    }

    char any[CLOAK_MAX_HOST_LEN];
    char v4any[CLOAK_MAX_HOST_LEN];
    char v6any[CLOAK_MAX_HOST_LEN];
    snprintf(any, sizeof(any), ":%s", ss_port);
    snprintf(v4any, sizeof(v4any), "0.0.0.0:%s", ss_port);
    snprintf(v6any, sizeof(v6any), "[::]:%s", ss_port);

    int should_append = 1;
    for (size_t i = 0; i < *n; i++) {
        if (strcmp(list[i], ss_canon) == 0) { /* R1 */
            should_append = 0;
        }
        if (strcmp(list[i], any) == 0) { /* R2 */
            should_append = 0;
        }
        if (strcmp(list[i], v4any) == 0 || strcmp(list[i], v6any) == 0) { /* R3 */
            if (strcmp(ss_canon, any) == 0) {
                snprintf(list[i], CLOAK_MAX_HOST_LEN, "%s", ss_canon);
                should_append = 0; /* the fix; see this function's comment */
            }
        }
    }
    if (should_append) {
        return bind_list_append(list, n, ss_canon, err, err_cap);
    }
    return 0;
}

/* ProxyBook["shadowsocks"] = ["tcp", host:port], overwriting whatever the
 * config said, exactly as Go's assignment into the map does. */
static int inject_ss_proxy(cJSON *root, const char *host, const char *port, char *err,
                           size_t err_cap) {
    char joined[CLOAK_MAX_HOST_LEN];
    if (strchr(host, ':') != NULL) {
        snprintf(joined, sizeof(joined), "[%s]:%s", host, port);
    } else {
        snprintf(joined, sizeof(joined), "%s:%s", host, port);
    }

    cJSON *book = cJSON_GetObjectItemCaseSensitive(root, "ProxyBook");
    if (!cJSON_IsObject(book)) {
        cJSON_DeleteItemFromObjectCaseSensitive(root, "ProxyBook");
        book = cJSON_CreateObject();
        if (book == NULL || !cJSON_AddItemToObject(root, "ProxyBook", book)) {
            cJSON_Delete(book);
            return ck_err(err, err_cap, "out of memory building ProxyBook");
        }
    }
    cJSON_DeleteItemFromObjectCaseSensitive(book, "shadowsocks");

    cJSON *pair = cJSON_CreateArray();
    cJSON *net_item = cJSON_CreateString("tcp");
    cJSON *addr_item = cJSON_CreateString(joined);
    if (pair == NULL || net_item == NULL || addr_item == NULL) {
        cJSON_Delete(pair);
        cJSON_Delete(net_item);
        cJSON_Delete(addr_item);
        return ck_err(err, err_cap, "out of memory building ProxyBook");
    }
    cJSON_AddItemToArray(pair, net_item);
    cJSON_AddItemToArray(pair, addr_item);
    if (!cJSON_AddItemToObject(book, "shadowsocks", pair)) {
        cJSON_Delete(pair);
        return ck_err(err, err_cap, "out of memory building ProxyBook");
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Configuration loading                                               */
/* ------------------------------------------------------------------ */

static char *read_whole_file(const char *path, char *err, size_t err_cap) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        ck_err(err, err_cap, "%s", strerror(errno));
        return NULL;
    }
    size_t cap = 4096;
    size_t len = 0;
    char *buf = malloc(cap);
    if (buf == NULL) {
        fclose(f);
        ck_err(err, err_cap, "out of memory");
        return NULL;
    }
    for (;;) {
        size_t got = fread(buf + len, 1, cap - len - 1, f);
        len += got;
        if (got == 0) {
            break;
        }
        if (len + 1 >= cap) {
            if (cap >= CK_MAX_CONFIG_FILE) {
                free(buf);
                fclose(f);
                ck_err(err, err_cap, "larger than %d bytes", CK_MAX_CONFIG_FILE);
                return NULL;
            }
            cap *= 2;
            char *grown = realloc(buf, cap);
            if (grown == NULL) {
                free(buf);
                fclose(f);
                ck_err(err, err_cap, "out of memory");
                return NULL;
            }
            buf = grown;
        }
    }
    int bad = ferror(f);
    fclose(f);
    if (bad) {
        free(buf);
        ck_err(err, err_cap, "read error");
        return NULL;
    }
    buf[len] = '\0';
    return buf;
}

/* D3. Returns a heap buffer the caller frees, or NULL with err set. */
static char *load_config_text(const char *conf, char *err, size_t err_cap) {
    char file_err[CK_ERR_LEN] = {0};
    char *text = read_whole_file(conf, file_err, sizeof(file_err));
    if (text != NULL) {
        return text;
    }
    /* Not a readable file. Unlike Go, try the value itself as JSON. */
    cJSON *probe = cJSON_Parse(conf);
    if (probe == NULL) {
        ck_err(err, err_cap,
               "cannot read \"%s\" (%s), and its content is not valid JSON either", conf,
               file_err);
        return NULL;
    }
    cJSON_Delete(probe);
    char *copy = strdup(conf);
    if (copy == NULL) {
        ck_err(err, err_cap, "out of memory");
    }
    return copy;
}

/* Reads the document's BindAddr into list, applies the defaults and the
 * plugin merge, writes the result back, and hands the whole document to
 * the library parser. This is Go's main() between ParseConfig and
 * InitState, done on the document rather than on a half-built struct --
 * cloak_server_config_t is the parser's output, not its input, and
 * cloak/config.h's parser (correctly) refuses a config with no BindAddr at
 * all, which is precisely the case Go's main is there to fix up. */
static int build_config(const char *text, int plugin_mode, cloak_server_config_t *cfg,
                        char *err, size_t err_cap) {
    cJSON *root = cJSON_Parse(text);
    if (root == NULL) {
        return ck_err(err, err_cap, "not valid JSON");
    }
    if (!cJSON_IsObject(root)) {
        cJSON_Delete(root);
        return ck_err(err, err_cap, "config must be a JSON object");
    }

    ck_bind_list_t list;
    memset(list, 0, sizeof(list));
    size_t n = 0;

    const cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "BindAddr");
    if (arr != NULL && !cJSON_IsNull(arr)) {
        if (!cJSON_IsArray(arr)) {
            cJSON_Delete(root);
            return ck_err(err, err_cap, "BindAddr must be an array of strings");
        }
        const cJSON *item = NULL;
        cJSON_ArrayForEach(item, arr) {
            if (!cJSON_IsString(item) || item->valuestring == NULL ||
                item->valuestring[0] == '\0') {
                cJSON_Delete(root);
                return ck_err(err, err_cap, "BindAddr must be an array of non-empty strings");
            }
            char canon[CLOAK_MAX_HOST_LEN];
            if (canon_addr(item->valuestring, canon, sizeof(canon), err, err_cap) != 0) {
                cJSON_Delete(root);
                return -1;
            }
            if (bind_list_append(list, &n, canon, err, err_cap) != 0) {
                cJSON_Delete(root);
                return -1;
            }
        }
    }

    if (plugin_mode) {
        const char *local_host = getenv("SS_LOCAL_HOST");
        const char *local_port = getenv("SS_LOCAL_PORT");
        if (inject_ss_proxy(root, local_host, local_port, err, err_cap) != 0) {
            cJSON_Delete(root);
            return -1;
        }
        if (merge_ss_bind_addr(getenv("SS_REMOTE_HOST"), getenv("SS_REMOTE_PORT"), list, &n,
                               err, err_cap) != 0) {
            cJSON_Delete(root);
            return -1;
        }
    } else if (n == 0) {
        /* Go: "in case the user hasn't specified any local address to bind
         * to, we listen on 443 and 80". */
        char canon[CLOAK_MAX_HOST_LEN];
        if (canon_addr(":443", canon, sizeof(canon), err, err_cap) != 0 ||
            bind_list_append(list, &n, canon, err, err_cap) != 0 ||
            canon_addr(":80", canon, sizeof(canon), err, err_cap) != 0 ||
            bind_list_append(list, &n, canon, err, err_cap) != 0) {
            cJSON_Delete(root);
            return -1;
        }
    }

    bind_list_dedupe(list, &n);

    cJSON_DeleteItemFromObjectCaseSensitive(root, "BindAddr");
    cJSON *out_arr = cJSON_CreateArray();
    if (out_arr == NULL || !cJSON_AddItemToObject(root, "BindAddr", out_arr)) {
        cJSON_Delete(out_arr);
        cJSON_Delete(root);
        return ck_err(err, err_cap, "out of memory building BindAddr");
    }
    for (size_t i = 0; i < n; i++) {
        cJSON *s = cJSON_CreateString(list[i]);
        if (s == NULL) {
            cJSON_Delete(root);
            return ck_err(err, err_cap, "out of memory building BindAddr");
        }
        cJSON_AddItemToArray(out_arr, s);
    }

    char *rendered = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (rendered == NULL) {
        return ck_err(err, err_cap, "out of memory rendering config");
    }

    char parse_err[CLOAK_CONFIG_ERR_LEN] = {0};
    int rc = cloak_server_config_parse_json(rendered, cfg, parse_err, sizeof(parse_err));
    free(rendered);
    if (rc != 0) {
        return ck_err(err, err_cap, "%s", parse_err);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Shutdown                                                            */
/* ------------------------------------------------------------------ */

static void on_signal(int signo, void *userdata) {
    cloak_reactor_t *r = (cloak_reactor_t *)userdata;
    CLOAK_LOGI("received signal %d, shutting down", signo);
    cloak_reactor_stop(r);
}

static int exit_code_for_stack_err(int code) {
    switch (code) {
    case CLOAK_SERVER_STACK_ERR_CONFIG:
    case CLOAK_SERVER_STACK_ERR_TEMPLATE:
    case CLOAK_SERVER_STACK_ERR_RETRY_LADDER:
    case CLOAK_SERVER_STACK_ERR_SERVER:
    case CLOAK_SERVER_STACK_ERR_DATABASE:
        return CK_EXIT_CONFIG;
    case CLOAK_SERVER_STACK_ERR_LISTEN:
        return CK_EXIT_BIND;
    default:
        return CK_EXIT_RUNTIME;
    }
}

/* ------------------------------------------------------------------ */
/* Argument handling                                                   */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *config;
    const char *verbosity;
    int ask_version;
    int print_usage;
    int gen_uid_script;
    int gen_key_script;
    int gen_uid_human;
    int gen_key_human;
} ck_args_t;

/* Go's flag package accepts -x, --x, -x=v and (for non-bool flags) -x v.
 * Boolean flags never consume the following argument, which is why -u and
 * -v take no value here either. */
static int parse_args(int argc, char **argv, ck_args_t *a, char *err, size_t err_cap) {
    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (arg[0] != '-' || arg[1] == '\0') {
            return ck_err(err, err_cap, "unexpected argument \"%s\"", arg);
        }
        const char *name = arg + 1;
        if (name[0] == '-') {
            name++;
        }
        const char *eq = strchr(name, '=');
        char base[64];
        const char *inline_value = NULL;
        if (eq != NULL) {
            size_t len = (size_t)(eq - name);
            if (len >= sizeof(base)) {
                return ck_err(err, err_cap, "unknown flag \"%s\"", arg);
            }
            memcpy(base, name, len);
            base[len] = '\0';
            inline_value = eq + 1;
        } else {
            snprintf(base, sizeof(base), "%s", name);
        }

        const char **target = NULL;
        if (strcmp(base, "c") == 0) {
            target = &a->config;
        } else if (strcmp(base, "verbosity") == 0) {
            target = &a->verbosity;
        } else if (strcmp(base, "d") == 0) {
            return ck_err(err, err_cap,
                          "-d (pprof) is not implemented and will not be: a profiling HTTP "
                          "server would be a second listening socket in a program whose "
                          "whole purpose is not being noticed");
        } else if (strcmp(base, "v") == 0) {
            a->ask_version = 1;
        } else if (strcmp(base, "h") == 0) {
            a->print_usage = 1;
        } else if (strcmp(base, "u") == 0) {
            a->gen_uid_script = 1;
        } else if (strcmp(base, "k") == 0) {
            a->gen_key_script = 1;
        } else if (strcmp(base, "uid") == 0) {
            a->gen_uid_human = 1;
        } else if (strcmp(base, "key") == 0) {
            a->gen_key_human = 1;
        } else {
            return ck_err(err, err_cap, "unknown flag \"%s\"", arg);
        }

        if (target == NULL) {
            continue;
        }
        if (inline_value != NULL) {
            *target = inline_value;
        } else if (i + 1 < argc) {
            *target = argv[++i];
        } else {
            return ck_err(err, err_cap, "flag needs an argument: -%s", base);
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv) {
    char err[CK_ERR_LEN] = {0};

    /* SIGPIPE IS IGNORED, AND THAT IS FIDELITY TO GO, NOT A PRECAUTION.
     * Go's runtime installs a handler that swallows SIGPIPE for every
     * descriptor that is not stdout/stderr (runtime.sigpipe / os/signal's
     * "SIGPIPE ... on any other file descriptor ... is ignored"), so Go
     * Cloak has never been able to die this way and a C port that leaves
     * the default disposition in place is DIVERGING.
     *
     * What it costs us to get wrong: this server writes to sockets whose
     * peer is an unauthenticated stranger, and the default disposition of
     * SIGPIPE is to terminate the process. That is a remotely-triggerable
     * death in a program whose whole purpose is to stay up. Every socket
     * write in the tree also passes MSG_NOSIGNAL (see relay.c's note);
     * this is the second of the two, and it is the one that covers a write
     * somebody adds later. */
    signal(SIGPIPE, SIG_IGN);

    const char *ss_local_host = getenv("SS_LOCAL_HOST");
    const char *ss_local_port = getenv("SS_LOCAL_PORT");
    int plugin_mode = (ss_local_host != NULL && ss_local_host[0] != '\0' &&
                       ss_local_port != NULL && ss_local_port[0] != '\0');

    ck_args_t args;
    memset(&args, 0, sizeof(args));
    args.config = "server.json";
    args.verbosity = "info";

    const char *config_source = NULL;
    char *config_text = NULL;

    if (plugin_mode) {
        /* Go does not look at argv at all in plugin mode. Neither do we. */
        const char *opts = getenv("SS_PLUGIN_OPTIONS");
        config_source = "SS_PLUGIN_OPTIONS";
        config_text = strdup(opts != NULL ? opts : "");
        if (config_text == NULL) {
            fprintf(stderr, "ck-server: out of memory\n");
            return CK_EXIT_RUNTIME;
        }
        CLOAK_LOGI("starting shadowsocks plugin mode");
    } else {
        if (parse_args(argc, argv, &args, err, sizeof(err)) != 0) {
            fprintf(stderr, "ck-server: %s\n", err);
            usage(stderr);
            return CK_EXIT_USAGE;
        }
        if (args.ask_version) {
            printf("ck-server %s\n", cloak_common_version());
            return CK_EXIT_OK;
        }
        if (args.print_usage) {
            usage(stdout);
            return CK_EXIT_OK;
        }
        if (args.gen_uid_script || args.gen_uid_human) {
            return print_uid(args.gen_uid_script ? 0 : 1);
        }
        if (args.gen_key_script || args.gen_key_human) {
            return print_keypair(args.gen_key_script ? 0 : 1);
        }

        cloak_log_level_t level;
        if (cloak_log_level_from_string(args.verbosity, &level) != 0) {
            fprintf(stderr, "ck-server: unknown verbosity level \"%s\"\n", args.verbosity);
            usage(stderr);
            return CK_EXIT_USAGE;
        }
        cloak_log_set_level(level);
        CLOAK_LOGI("starting standalone mode");

        config_source = args.config;
        config_text = load_config_text(args.config, err, sizeof(err));
        if (config_text == NULL) {
            CLOAK_LOGE("configuration error: %s", err);
            return CK_EXIT_CONFIG;
        }
    }

    cloak_server_config_t cfg;
    int rc = build_config(config_text, plugin_mode, &cfg, err, sizeof(err));
    free(config_text);
    if (rc != 0) {
        CLOAK_LOGE("configuration error in %s: %s", config_source, err);
        return CK_EXIT_CONFIG;
    }

    /* Logged from the PARSED config, not from the inputs that produced it,
     * so what an operator reads here is what the server is actually about
     * to use -- and so this port's tests can assert the plugin-mode
     * translation through the same struct the server reads. */
    for (size_t i = 0; i < cfg.num_bind_addr; i++) {
        CLOAK_LOGI("bind address: %s", cfg.bind_addr[i]);
    }
    for (size_t i = 0; i < cfg.num_proxy_entries; i++) {
        CLOAK_LOGI("proxy book: %s -> %s %s", cfg.proxy_book[i].name,
                   cfg.proxy_book[i].is_udp ? "udp" : "tcp", cfg.proxy_book[i].addr);
    }

    /* A GAP, MADE AUDIBLE RATHER THAN LEFT SILENT -- AND THE SAME WORDS
     * ck-client USES. cloak_server_config_t::keep_alive_sec is parsed and
     * has no readers anywhere in libcloak-server or in this file; no
     * socket in this build sets SO_KEEPALIVE at all, which is the same gap
     * ck-client already warned about. The two programs are meant to be
     * read side by side, and a setting that one of them calls out and the
     * other ignores in silence is worse than either choice made twice: an
     * operator who moved a KeepAlive from their client config to their
     * server config would have watched the warning disappear and concluded
     * the server honours it. (The parser stores -1 for "unset", so this
     * fires only when an operator actually wrote one.) */
    if (cfg.keep_alive_sec > 0) {
        CLOAK_LOGW("KeepAlive %d is configured but no socket in this build sets "
                   "SO_KEEPALIVE; the setting is ignored",
                   cfg.keep_alive_sec);
    }

    cloak_reactor_t *reactor = cloak_reactor_create();
    if (reactor == NULL) {
        CLOAK_LOGE("unable to create the reactor");
        return CK_EXIT_RUNTIME;
    }

    cloak_server_stack_config_t sc;
    memset(&sc, 0, sizeof(sc));
    sc.reactor = reactor;
    sc.config = &cfg;

    cloak_server_stack_t *stack = NULL;
    char stack_err[CLOAK_CONFIG_ERR_LEN] = {0};
    int open_rc = cloak_server_stack_open(&stack, &sc, stack_err, sizeof(stack_err));
    if (open_rc != 0) {
        CLOAK_LOGE("unable to start the server (%s): %s",
                   cloak_server_stack_strerror(open_rc), stack_err);
        cloak_reactor_destroy(reactor);
        return exit_code_for_stack_err(open_rc);
    }

    /* As close to the top as the rest of startup allows: everything before
     * this point exits on its own, and everything after it is the reactor
     * (cloak/signals.h's note about the uncovered window). */
    cloak_signalfd_t *sfd = cloak_signalfd_create(reactor, on_signal, reactor);
    if (sfd == NULL) {
        CLOAK_LOGE("unable to install the signal handler");
        cloak_server_stack_close(stack);
        cloak_reactor_destroy(reactor);
        return CK_EXIT_RUNTIME;
    }

    size_t listeners = cloak_server_stack_listener_count(stack);
    for (size_t i = 0; i < listeners; i++) {
        CLOAK_LOGI("listening on %s (port %d)", cfg.bind_addr[i],
                   cloak_server_stack_listener_port(stack, i));
    }
    CLOAK_LOGI("ck-server ready, %zu listener(s)", listeners);

    cloak_reactor_run(reactor);

    /* The last metering interval, billed before the panel drops it --
     * cloak_server_stack_close's documented trade. */
    cloak_server_stack_upload_now(stack);
    cloak_signalfd_destroy(sfd);
    cloak_server_stack_close(stack);
    cloak_reactor_destroy(reactor);
    CLOAK_LOGI("ck-server stopped");
    return CK_EXIT_OK;
}
