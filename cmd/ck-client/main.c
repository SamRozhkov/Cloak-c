#define _POSIX_C_SOURCE 200809L

/* ck-client -- the Cloak client, as a program.
 *
 * The port of Go Cloak's cmd/ck-client/ck-client.go. Everything that file
 * does after its flags -- build the session maker, open the local
 * listener, route, reconnect forever -- is one call to
 * cloak_client_stack_open here, because libcloak-client owns the object
 * graph, its NINE forced ordering edges and the reconnect ladder
 * (cloak/client_stack.h explains at length why none of that is a binary's
 * business, and in particular why edge E1 fails SILENTLY when a binary
 * gets it wrong). What is left in this file is argument handling,
 * configuration loading, and the plugin mode's environment translation.
 *
 * ---------------------------------------------------------------------
 * EXIT CODES -- THE SAME FIVE ck-server USES, and deliberately not a
 * superset. An operator running both binaries under one supervisor must
 * not have to learn two schemes:
 *
 *   0  success: the client ran and shut down cleanly on SIGINT/SIGTERM.
 *   1  usage error: an unknown flag, a flag missing its value, a
 *      -verbosity that is not a level name, an -a whose value is not a
 *      16-byte base64 UID, or -u (see below). The command line is wrong;
 *      retrying it is pointless.
 *   2  configuration error: the config could not be read or parsed, a
 *      required field is missing after the flags and the environment have
 *      had their say, or cloak_client_stack_open rejected the
 *      configuration itself (CONFIG / TEMPLATE). Retrying is pointless
 *      until the config changes.
 *   3  the endpoint could not be established: the local address could not
 *      be opened (LISTEN -- a port still in TIME_WAIT, an interface that
 *      has not come up) or RemoteHost could not be RESOLVED. THESE ARE
 *      THE RETRYABLE ONES, which is the whole reason they are not folded
 *      into 2, and RESOLVE is here rather than under 2 because a name
 *      server that did not answer this second is the same kind of
 *      transient as a port that was busy this second. A permanently
 *      wrong hostname is the cost of that choice and it is a cost an
 *      operator sees in the log line, which names the host.
 *   4  runtime failure: the reactor, the signalfd, or an allocation.
 *
 * WHETHER FIVE WAS ENOUGH. Every failure this binary can produce lands in
 * one of them, and the one that might have wanted a sixth does not
 * reach exit at all: a client that cannot bring a session up does not
 * FAIL, it retries on cloak/client_stack.h's ladder forever, narrating
 * every round. That is Go's behaviour and it is the right one for a
 * client an operator can see and interrupt -- so "could not connect" is
 * a log line, not an exit code, and the five stand.
 *
 * ---------------------------------------------------------------------
 * -c TAKES A PATH, AN ssv STRING, OR LITERAL JSON.
 *
 * Go's client.ParseConfig switches on the STRING: a value containing both
 * ';' and '=' is a semicolon-separated option list, anything else is a
 * path to a JSON file. That heuristic is cloak_client_config_load's, and
 * it is reproduced here rather than reimplemented -- with ONE addition,
 * the same one ck-server makes: a value that is neither an ssv string nor
 * a readable path is tried as literal JSON before being refused, and the
 * refusal then names both failures.
 *
 * NOTE THE ASYMMETRY WITH ck-server, because it looks like an
 * inconsistency and is not. The SERVER's inline configuration form is
 * JSON, and its SS_PLUGIN_OPTIONS is JSON, because server.ParseConfig
 * only ever calls json.Unmarshal. The CLIENT's is ssv, because
 * client.ParseConfig has the ssvToJson branch above it. Both are Go's own
 * shapes, verified in Go's source rather than assumed from the other
 * binary.
 *
 * ---------------------------------------------------------------------
 * THE FLAGS OVERRIDE THE JSON, and the ORDER THIS HAPPENS IN IS THE
 * WHOLE PROBLEM. Go parses the config with no validation at all, applies
 * flag.Visit's overrides to the resulting struct, fills the three fields
 * that have defaults, and only then calls ProcessRawConfig, which is what
 * rejects an empty RemoteHost. cloak/config.h's parser does not separate
 * those two steps -- it validates as it parses -- so a config handed
 * straight to it would be rejected for a field the command line was about
 * to supply.
 *
 * So the overrides are applied to the config DOCUMENT, before it is
 * parsed, exactly as ck-server edits the BindAddr array before handing
 * the document to its parser. ck_conf_t below is that document in
 * whichever of the two formats it arrived in, with get and set on it, so
 * that plugin mode's four SS_* fill-ins and standalone mode's five flag
 * overrides are one piece of code over two representations rather than
 * two pieces of code.
 *
 * ---------------------------------------------------------------------
 * PLUGIN MODE IS DETECTED FROM SS_LOCAL_HOST ALONE, which is Go's client
 * (`ssPluginMode := os.Getenv("SS_LOCAL_HOST") != ""`) and is NOT what
 * ck-server does -- Go's server requires SS_LOCAL_HOST *and*
 * SS_LOCAL_PORT. Each binary follows its own original. In plugin mode Go
 * does not look at -i/-l/-s/-p/-c/-proxy/-a at all; only -verbosity, -V
 * and -fast-open are registered, and the latter two are accepted and
 * ignored. This file does the same, and refuses anything else rather than
 * silently ignoring a flag a launcher thought it was passing.
 *
 * ---------------------------------------------------------------------
 * -u IS A DOCUMENT EDIT, not a branch. Earlier versions of this file
 * REFUSED -u and "UDP": true outright, because nothing in the build
 * carried UDP end to end; both refusals are gone and neither left a
 * special case behind. The flag's whole implementation is one
 * conf_set_bool into the configuration document, in the same place and
 * for the same reason as -i, -l, -s and -p: the library decides what
 * `udp` means, this file only decides that the command line beat the
 * file. A branch here would be a second definition of the mode.
 *
 * The precedence is Go's flag.Visit, which runs only for flags actually
 * PRESENT on the command line: -u sets UDP true, -u=false sets it false
 * and therefore overrides a "UDP": true in the document, and an absent -u
 * changes nothing. That is why ck_args_t carries udp_given as well as
 * udp -- one field cannot say "absent" and "false" at the same time.
 * (-u=false was silently TRUE in this file until this module; see
 * parse_args.)
 *
 * "UDP": true and -u therefore reach the SAME place by two roads, and
 * test_ck_client_cli.c's case 4 asserts both roads separately for that
 * reason -- a flag handled here and a key handled in the library would
 * look identical from one of them.
 *
 * ---------------------------------------------------------------------
 * THREE SMALLER THINGS, recorded here because a reader comparing the two
 * implementations will reach for this block and not for a report. Two of
 * them are places where this file and ck-server differ from EACH OTHER,
 * which looks like an inconsistency and is Go's own shape in both.
 *
 * P1. -verbosity IS HONOURED IN PLUGIN MODE HERE, and is IGNORED in
 *     ck-server's. In Go's client log.SetLevel sits outside the if/else
 *     and applies to both modes; in Go's server it sits inside the
 *     standalone branch. Each port follows its own original, so
 *     `-verbosity error` silences a plugin-mode ck-client and does not
 *     silence a plugin-mode ck-server.
 *
 * P2. AN UNKNOWN FLAG IS REFUSED BY NAME IN PLUGIN MODE HERE, and is
 *     ignored in ck-server's plugin mode, which looks at no argv token at
 *     all. Same reason: Go's client registers a (small) flag set in
 *     plugin mode and Go's server registers none.
 *
 * P3. ADMIN MODE LOGS ONE LINE MORE THAN GO. Go logs "API base is %v" in
 *     the admin branch and "Listening on %v %v for %v client" only in the
 *     non-admin one; this file logs its admin line AND then the
 *     "listening on TCP ... for ... client" line unconditionally, because
 *     that second line reports the BOUND port (which matters when
 *     LocalPort is "0") and an admin operator needs it just as much. An
 *     extra informational line, deliberately.
 */

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"

#include "cloak/base64.h"
#include "cloak/client_stack.h"
#include "cloak/common.h"
#include "cloak/config.h"
#include "cloak/log.h"
#include "cloak/reactor.h"
#include "cloak/signals.h"

#define CK_EXIT_OK      0
#define CK_EXIT_USAGE   1
#define CK_EXIT_CONFIG  2
#define CK_EXIT_BIND    3
#define CK_EXIT_RUNTIME 4

/* Matches the library's own cap on a config file. */
#define CK_MAX_CONFIG_FILE (1024 * 1024)

#define CK_ERR_LEN 512

/* Go's own defaults, from the flag declarations in ck-client.go. */
#define CK_DEFAULT_LOCAL_HOST  "127.0.0.1"
#define CK_DEFAULT_LOCAL_PORT  "1984"
#define CK_DEFAULT_REMOTE_PORT "443"
#define CK_DEFAULT_CONFIG      "ckclient.json"

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
    fprintf(out, "Usage of ck-client:\n");
    fprintf(out, "  -a string\n");
    fprintf(out, "        adminUID: enter the adminUID to serve the admin api\n");
    fprintf(out, "  -c string\n");
    fprintf(out, "        config: path to the configuration file, options separated with "
                 "semicolons, or the configuration itself (default \"" CK_DEFAULT_CONFIG
                 "\")\n");
    fprintf(out, "  -h    Print this message\n");
    fprintf(out, "  -i string\n");
    fprintf(out, "        localHost: Cloak listens to proxy clients on this ip (default \""
                 CK_DEFAULT_LOCAL_HOST "\")\n");
    fprintf(out, "  -l string\n");
    fprintf(out, "        localPort: Cloak listens to proxy clients on this port (default \""
                 CK_DEFAULT_LOCAL_PORT "\")\n");
    fprintf(out, "  -p string\n");
    fprintf(out, "        remotePort: proxy port, should be 443 (default \""
                 CK_DEFAULT_REMOTE_PORT "\")\n");
    fprintf(out, "  -proxy string\n");
    fprintf(out, "        proxy: the proxy method's name. It must match exactly with the "
                 "corresponding entry in server's ProxyBook\n");
    fprintf(out, "  -s string\n");
    fprintf(out, "        remoteHost: IP of your proxy server\n");
    /* Go's own wording, verbatim (cmd/ck-client/main.go): a pluggable
     * transport's -h output is read by people migrating a deployment that
     * already works, and a line that says something different from the
     * one they know is a line they have to go and check. */
    fprintf(out, "  -u    udp: set this flag if the underlying proxy is using UDP protocol\n");
    fprintf(out, "  -v    Print the version number\n");
    fprintf(out, "  -verbosity string\n");
    fprintf(out, "        verbosity level: error, warn, info, debug or trace "
                 "(default \"info\")\n");
}

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

/* ------------------------------------------------------------------ */
/* ck_conf_t -- the configuration DOCUMENT, in either of its two forms  */
/* ------------------------------------------------------------------ */

/* See this file's opening: the overrides have to happen BEFORE the
 * parser sees the document, because the parser validates as it parses and
 * would reject a field the command line was about to supply. The document
 * arrives in one of two formats and both need the same three operations,
 * so they are one interface here and not two code paths at every call
 * site. */
typedef struct {
    int ssv;    /* 1: a semicolon-separated option string */
    cJSON *doc; /* ssv == 0 */
    char *text; /* ssv == 1 */
} ck_conf_t;

static void conf_free(ck_conf_t *c) {
    if (c == NULL) {
        return;
    }
    cJSON_Delete(c->doc);
    free(c->text);
    c->doc = NULL;
    c->text = NULL;
}

/* The three escapes ssv defines, resolved. A copy of the library's rule
 * (src/config_ssv.c) rather than a reimplementation of its parser: only
 * key and value BOUNDARIES and this unescape are needed here, and the
 * library remains the only thing that turns an option string into a
 * config. Returns -1 if the result would not fit. */
static int ssv_unescape(const char *src, size_t src_len, char *dst, size_t dst_cap) {
    size_t o = 0;
    for (size_t i = 0; i < src_len; i++) {
        char ch = src[i];
        if (ch == '\\' && i + 1 < src_len) {
            char next = src[i + 1];
            if (next == '\\' || next == '=' || next == ';') {
                ch = next;
                i++;
            }
        }
        if (o + 1 >= dst_cap) {
            return -1;
        }
        dst[o++] = ch;
    }
    if (o >= dst_cap) {
        return -1;
    }
    dst[o] = '\0';
    return 0;
}

/* The inverse, for a value this file writes into an option string. */
static int ssv_escape(const char *src, char *dst, size_t dst_cap) {
    size_t o = 0;
    for (const char *p = src; *p != '\0'; p++) {
        if (*p == '\\' || *p == '=' || *p == ';') {
            if (o + 2 >= dst_cap) {
                return -1;
            }
            dst[o++] = '\\';
        } else if (o + 1 >= dst_cap) {
            return -1;
        }
        dst[o++] = *p;
    }
    if (o >= dst_cap) {
        return -1;
    }
    dst[o] = '\0';
    return 0;
}

/* The end of the field starting at cur: the next UNESCAPED ';', or the
 * end of the string. */
static const char *ssv_field_end(const char *cur) {
    const char *end = cur;
    while (*end != '\0') {
        if (*end == '\\' && *(end + 1) != '\0') {
            end += 2;
            continue;
        }
        if (*end == ';') {
            break;
        }
        end++;
    }
    return end;
}

/* The first UNESCAPED '=' in [cur, limit), or limit. */
static const char *ssv_key_end(const char *cur, const char *limit) {
    const char *eq = cur;
    while (eq < limit) {
        if (*eq == '\\' && eq + 1 < limit) {
            eq += 2;
            continue;
        }
        if (*eq == '=') {
            break;
        }
        eq++;
    }
    return eq;
}

static int ssv_key_is(const char *cur, const char *eq, const char *key) {
    char k[128];
    if (ssv_unescape(cur, (size_t)(eq - cur), k, sizeof(k)) != 0) {
        return 0;
    }
    return strcmp(k, key) == 0;
}

/* 1 when key is present with a non-empty value, which is copied into out.
 * "Present but empty" reads as absent, matching Go, whose jsonOptional
 * fields are filled in whenever the parsed struct's string is "". */
static int conf_get(const ck_conf_t *c, const char *key, char *out, size_t cap) {
    if (out != NULL && cap > 0) {
        out[0] = '\0';
    }
    if (!c->ssv) {
        const cJSON *item = cJSON_GetObjectItemCaseSensitive(c->doc, key);
        if (!cJSON_IsString(item) || item->valuestring == NULL ||
            item->valuestring[0] == '\0') {
            return 0;
        }
        if (out != NULL) {
            snprintf(out, cap, "%s", item->valuestring);
        }
        return 1;
    }
    const char *cur = c->text;
    while (*cur != '\0') {
        const char *end = ssv_field_end(cur);
        if (end > cur) {
            const char *eq = ssv_key_end(cur, end);
            if (eq < end && ssv_key_is(cur, eq, key)) {
                char val[CLOAK_MAX_PATH_LEN];
                if (ssv_unescape(eq + 1, (size_t)(end - (eq + 1)), val, sizeof(val)) != 0) {
                    return 0;
                }
                if (val[0] == '\0') {
                    return 0;
                }
                if (out != NULL) {
                    snprintf(out, cap, "%s", val);
                }
                return 1;
            }
        }
        if (*end == '\0') {
            break;
        }
        cur = end + 1;
    }
    return 0;
}

/* Sets key to value, replacing whatever was there. The ssv form is
 * rebuilt rather than patched in place: every field is copied through
 * except the one being replaced, and the replacement is appended. That
 * leaves exactly one field with this key, which matters because the
 * library's parser builds a cJSON object from the fields in order and
 * two entries with the same name are not a documented resolution. */
static int conf_set(ck_conf_t *c, const char *key, const char *value, char *err,
                    size_t err_cap) {
    if (!c->ssv) {
        cJSON_DeleteItemFromObjectCaseSensitive(c->doc, key);
        if (cJSON_AddStringToObject(c->doc, key, value) == NULL) {
            return ck_err(err, err_cap, "out of memory setting %s", key);
        }
        return 0;
    }

    char esc[CLOAK_MAX_PATH_LEN * 2];
    if (ssv_escape(value, esc, sizeof(esc)) != 0) {
        return ck_err(err, err_cap, "value of %s is too long", key);
    }
    size_t cap = strlen(c->text) + strlen(key) + strlen(esc) + 4;
    char *out = malloc(cap);
    if (out == NULL) {
        return ck_err(err, err_cap, "out of memory setting %s", key);
    }
    size_t o = 0;
    const char *cur = c->text;
    while (*cur != '\0') {
        const char *end = ssv_field_end(cur);
        int drop = 0;
        if (end > cur) {
            const char *eq = ssv_key_end(cur, end);
            drop = (eq < end && ssv_key_is(cur, eq, key));
        } else {
            drop = 1; /* an empty field carries nothing */
        }
        if (!drop) {
            if (o > 0) {
                out[o++] = ';';
            }
            memcpy(out + o, cur, (size_t)(end - cur));
            o += (size_t)(end - cur);
        }
        if (*end == '\0') {
            break;
        }
        cur = end + 1;
    }
    if (o > 0) {
        out[o++] = ';';
    }
    o += (size_t)snprintf(out + o, cap - o, "%s=%s", key, esc);
    (void)o;
    free(c->text);
    c->text = out;
    return 0;
}

/* Go's heuristic, plus ck-server's one addition. See this file's opening.
 * source, when non-NULL, receives a short description of where the
 * document came from, for the log line an operator actually reads. */
static int conf_load(const char *conf, ck_conf_t *c, const char **source, char *err,
                     size_t err_cap) {
    memset(c, 0, sizeof(*c));
    if (conf == NULL || conf[0] == '\0') {
        return ck_err(err, err_cap, "no configuration given");
    }

    if (strchr(conf, ';') != NULL && strchr(conf, '=') != NULL) {
        c->ssv = 1;
        c->text = strdup(conf);
        if (c->text == NULL) {
            return ck_err(err, err_cap, "out of memory");
        }
        if (source != NULL) {
            *source = "the option string";
        }
        return 0;
    }

    char file_err[CK_ERR_LEN] = {0};
    char *text = read_whole_file(conf, file_err, sizeof(file_err));
    if (text != NULL) {
        c->doc = cJSON_Parse(text);
        free(text);
        if (c->doc == NULL) {
            return ck_err(err, err_cap, "\"%s\" is not valid JSON", conf);
        }
        if (!cJSON_IsObject(c->doc)) {
            conf_free(c);
            return ck_err(err, err_cap, "\"%s\" must be a JSON object", conf);
        }
        if (source != NULL) {
            *source = conf;
        }
        return 0;
    }

    /* Not a readable file. Unlike Go, try the value itself as JSON. */
    c->doc = cJSON_Parse(conf);
    if (c->doc == NULL || !cJSON_IsObject(c->doc)) {
        conf_free(c);
        return ck_err(err, err_cap,
                      "cannot read \"%s\" (%s), and its content is neither an option "
                      "string nor a JSON object",
                      conf, file_err);
    }
    if (source != NULL) {
        *source = "the -c value";
    }
    return 0;
}

/* conf_set for a value that must NOT arrive at the parser as a string.
 *
 * cloak_config_get_bool refuses anything that is not a JSON boolean, so
 * "UDP": "true" is a configuration error rather than a true flag -- which
 * is exactly what conf_set would have produced, silently, because every
 * other flag this file forwards is a string. The ssv form needs no such
 * care: config_ssv.c already types NumConn, StreamTimeout, KeepAlive and
 * UDP itself, turning the literal text "true" into a JSON bool, so that
 * half is conf_set with the word. */
static int conf_set_bool(ck_conf_t *c, const char *key, int value, char *err, size_t err_cap) {
    if (c->ssv) {
        return conf_set(c, key, value ? "true" : "false", err, err_cap);
    }
    cJSON_DeleteItemFromObjectCaseSensitive(c->doc, key);
    if (cJSON_AddBoolToObject(c->doc, key, value) == NULL) {
        return ck_err(err, err_cap, "out of memory setting %s", key);
    }
    return 0;
}

static int conf_finish(const ck_conf_t *c, cloak_client_config_t *cfg, char *err,
                       size_t err_cap) {
    char parse_err[CLOAK_CONFIG_ERR_LEN] = {0};
    int rc;
    if (c->ssv) {
        rc = cloak_client_config_parse_ssv(c->text, cfg, parse_err, sizeof(parse_err));
    } else {
        char *rendered = cJSON_PrintUnformatted(c->doc);
        if (rendered == NULL) {
            return ck_err(err, err_cap, "out of memory rendering the configuration");
        }
        rc = cloak_client_config_parse_json(rendered, cfg, parse_err, sizeof(parse_err));
        free(rendered);
    }
    if (rc != 0) {
        return ck_err(err, err_cap, "%s", parse_err);
    }
    return 0;
}

/* Sets key only when the document does not already carry a non-empty
 * value for it and the fill-in itself is non-empty. This is Go's
 * `if rawConfig.X == "" { rawConfig.X = x }`, which is how BOTH the
 * standalone defaults and plugin mode's four SS_* fields are applied. */
static int conf_default(ck_conf_t *c, const char *key, const char *value, char *err,
                        size_t err_cap) {
    if (value == NULL || value[0] == '\0') {
        return 0;
    }
    if (conf_get(c, key, NULL, 0)) {
        return 0;
    }
    return conf_set(c, key, value, err, err_cap);
}

/* ------------------------------------------------------------------ */
/* Shutdown and narration                                              */
/* ------------------------------------------------------------------ */

static void on_signal(int signo, void *userdata) {
    cloak_reactor_t *r = (cloak_reactor_t *)userdata;
    CLOAK_LOGI("received signal %d, shutting down", signo);
    cloak_reactor_stop(r);
}

/* WHAT MAKES AN UNBOUNDED RETRY DEFENSIBLE IS THAT IT IS NARRATED --
 * cloak/client_stack.h's words, and this is where they are made true.
 * Nothing here closes the stack: that header says doing so from inside an
 * event callback is a use-after-free one frame up, not merely
 * unsupported. */
static void on_event(cloak_client_stack_t *s, cloak_client_stack_event_t ev,
                     uint32_t session_id, int round, uint64_t retry_in_ms, void *userdata) {
    (void)s;
    (void)userdata;
    if (retry_in_ms > 0) {
        CLOAK_LOGI("%s (session %08x, round %d), retrying in %llu ms",
                   cloak_client_stack_event_name(ev), session_id, round,
                   (unsigned long long)retry_in_ms);
    } else {
        CLOAK_LOGI("%s (session %08x, round %d)", cloak_client_stack_event_name(ev),
                   session_id, round);
    }
}

static int exit_code_for_stack_err(int code) {
    switch (code) {
    case CLOAK_CLIENT_STACK_ERR_CONFIG:
    case CLOAK_CLIENT_STACK_ERR_TEMPLATE:
        return CK_EXIT_CONFIG;
    case CLOAK_CLIENT_STACK_ERR_RESOLVE:
    case CLOAK_CLIENT_STACK_ERR_LISTEN:
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
    const char *local_host;
    const char *local_port;
    const char *remote_host;
    const char *remote_port;
    const char *proxy_method;
    const char *admin_uid;
    int udp;
    /* WHETHER -u WAS GIVEN AT ALL, which is a different question from
     * whether it was true, and Go asks exactly this one: its flag.Visit
     * callback runs only for flags actually present on the command line,
     * so an absent -u leaves the document's "UDP" alone while an explicit
     * -u=false clears it. A single `udp` field cannot express that. */
    int udp_given;
    int ask_version;
    int print_usage;
} ck_args_t;

/* strconv.ParseBool's accepted spellings, which is what Go's flag package
 * uses for a bool flag's inline value. Returns 0 and writes *out, or -1
 * if the text is not one of them. */
static int parse_bool_value(const char *v, int *out) {
    static const char *const yes[] = {"1", "t", "T", "TRUE", "true", "True"};
    static const char *const no[] = {"0", "f", "F", "FALSE", "false", "False"};
    for (size_t i = 0; i < sizeof(yes) / sizeof(yes[0]); i++) {
        if (strcmp(v, yes[i]) == 0) {
            *out = 1;
            return 0;
        }
        if (strcmp(v, no[i]) == 0) {
            *out = 0;
            return 0;
        }
    }
    return -1;
}

/* Go's flag package accepts -x, --x, -x=v and (for non-bool flags) -x v.
 * Boolean flags never consume the FOLLOWING argument -- so -u, -v and -h
 * never eat the next word -- but they do take an INLINE one, -u=false,
 * which this file parses because Go's flag.Bool does (strconv.ParseBool).
 * See the bool branch below for what used to happen to it.
 *
 * WHICH FLAGS ARE LEGAL DEPENDS ON THE MODE, exactly as in Go, where
 * plugin mode registers a different (and much smaller) flag set. An
 * unknown flag is refused rather than ignored in both. */
static int parse_args(int argc, char **argv, int plugin_mode, ck_args_t *a, char *err,
                      size_t err_cap) {
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
        if (strcmp(base, "verbosity") == 0) {
            target = &a->verbosity;
        } else if (plugin_mode) {
            /* Go registers exactly these two in plugin mode, both
             * documented as "ignored." -- so they are accepted and
             * ignored here too, and nothing else is. */
            if (strcmp(base, "V") == 0 || strcmp(base, "fast-open") == 0) {
                continue;
            }
            return ck_err(err, err_cap,
                          "unknown flag \"%s\" in shadowsocks plugin mode (only "
                          "-verbosity, -V and -fast-open are accepted)",
                          arg);
        } else if (strcmp(base, "c") == 0) {
            target = &a->config;
        } else if (strcmp(base, "i") == 0) {
            target = &a->local_host;
        } else if (strcmp(base, "l") == 0) {
            target = &a->local_port;
        } else if (strcmp(base, "s") == 0) {
            target = &a->remote_host;
        } else if (strcmp(base, "p") == 0) {
            target = &a->remote_port;
        } else if (strcmp(base, "proxy") == 0) {
            target = &a->proxy_method;
        } else if (strcmp(base, "a") == 0) {
            target = &a->admin_uid;
        } else if (strcmp(base, "u") == 0 || strcmp(base, "v") == 0 ||
                   strcmp(base, "h") == 0) {
            /* THE THREE BOOL FLAGS, and the one form of them this file
             * used to get wrong. `-u` is true, as it is in Go; but
             * `-u=false` is FALSE in Go (flag.Bool goes through
             * strconv.ParseBool) and was silently true here, because the
             * inline value was parsed off the name and then discarded for
             * every flag that took no argument. That was invisible while
             * -u was refused outright; the moment -u started selecting a
             * datagram tunnel it became a flag that does the opposite of
             * what it says, so it is parsed now. The accepted spellings
             * are strconv.ParseBool's, and an unparseable one is a usage
             * error exactly as it is in Go rather than a silent true. */
            int on = 1;
            if (inline_value != NULL && parse_bool_value(inline_value, &on) != 0) {
                return ck_err(err, err_cap, "invalid boolean value \"%s\" for flag -%s",
                              inline_value, base);
            }
            if (base[0] == 'u') {
                a->udp = on;
                a->udp_given = 1;
            } else if (base[0] == 'v') {
                a->ask_version = on;
            } else {
                a->print_usage = on;
            }
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
     * descriptor that is not stdout/stderr, so Go Cloak has never been
     * able to die this way and a C port that leaves the default
     * disposition in place is DIVERGING. The default disposition
     * TERMINATES the process, and this client writes to a socket whose far
     * end is a server it does not control and to local sockets an
     * application may close at any moment. Every socket write in the tree
     * also passes MSG_NOSIGNAL (see relay.c's note); this is the second of
     * the two, and it is the one that covers a write somebody adds later.
     * ck-server does exactly the same thing, for the same reason. */
    signal(SIGPIPE, SIG_IGN);

    /* Go's client: SS_LOCAL_HOST alone. See this file's opening for why
     * that differs from ck-server's two-variable test. */
    const char *ss_local_host = getenv("SS_LOCAL_HOST");
    int plugin_mode = (ss_local_host != NULL && ss_local_host[0] != '\0');

    ck_args_t args;
    memset(&args, 0, sizeof(args));
    args.verbosity = "info";

    if (parse_args(argc, argv, plugin_mode, &args, err, sizeof(err)) != 0) {
        fprintf(stderr, "ck-client: %s\n", err);
        usage(stderr);
        return CK_EXIT_USAGE;
    }
    if (args.ask_version) {
        printf("ck-client %s\n", cloak_common_version());
        return CK_EXIT_OK;
    }
    if (args.print_usage) {
        usage(stdout);
        return CK_EXIT_OK;
    }

    cloak_log_level_t level;
    if (cloak_log_level_from_string(args.verbosity, &level) != 0) {
        fprintf(stderr, "ck-client: unknown verbosity level \"%s\"\n", args.verbosity);
        usage(stderr);
        return CK_EXIT_USAGE;
    }
    cloak_log_set_level(level);

    const char *conf_arg;
    if (plugin_mode) {
        CLOAK_LOGI("starting shadowsocks plugin mode");
        conf_arg = getenv("SS_PLUGIN_OPTIONS");
    } else {
        CLOAK_LOGI("starting standalone mode");
        conf_arg = args.config != NULL ? args.config : CK_DEFAULT_CONFIG;
    }

    ck_conf_t conf;
    const char *source = "the configuration";
    if (conf_load(conf_arg, &conf, &source, err, sizeof(err)) != 0) {
        CLOAK_LOGE("configuration error: %s", err);
        return CK_EXIT_CONFIG;
    }

    int rc = 0;
    if (plugin_mode) {
        /* Go: the json takes precedence over the environment, so every
         * one of these is a fill-in and not an override. */
        rc = conf_default(&conf, "ProxyMethod", "shadowsocks", err, sizeof(err));
        if (rc == 0) {
            rc = conf_default(&conf, "RemoteHost", getenv("SS_REMOTE_HOST"), err,
                              sizeof(err));
        }
        if (rc == 0) {
            rc = conf_default(&conf, "RemotePort", getenv("SS_REMOTE_PORT"), err,
                              sizeof(err));
        }
        if (rc == 0) {
            rc = conf_default(&conf, "LocalHost", ss_local_host, err, sizeof(err));
        }
        if (rc == 0) {
            rc = conf_default(&conf, "LocalPort", getenv("SS_LOCAL_PORT"), err, sizeof(err));
        }
    } else {
        /* THE COMMAND LINE WINS. A flag that was actually given replaces
         * whatever the document said; a flag that was not given supplies
         * its default only where the document left the field empty --
         * which is Go's two-step (flag.Visit, then the three
         * `if X == ""` fill-ins) reproduced exactly, including that the
         * fill-in value is the FLAG VARIABLE and not the literal, so
         * `-i ""` leaves LocalHost empty rather than defaulted. */
        const char *local_host =
            args.local_host != NULL ? args.local_host : CK_DEFAULT_LOCAL_HOST;
        const char *local_port =
            args.local_port != NULL ? args.local_port : CK_DEFAULT_LOCAL_PORT;
        const char *remote_port =
            args.remote_port != NULL ? args.remote_port : CK_DEFAULT_REMOTE_PORT;

        if (rc == 0 && args.local_host != NULL) {
            rc = conf_set(&conf, "LocalHost", args.local_host, err, sizeof(err));
        }
        if (rc == 0 && args.local_port != NULL) {
            rc = conf_set(&conf, "LocalPort", args.local_port, err, sizeof(err));
        }
        if (rc == 0 && args.remote_host != NULL) {
            rc = conf_set(&conf, "RemoteHost", args.remote_host, err, sizeof(err));
        }
        if (rc == 0 && args.remote_port != NULL) {
            rc = conf_set(&conf, "RemotePort", args.remote_port, err, sizeof(err));
        }
        if (rc == 0 && args.proxy_method != NULL) {
            rc = conf_set(&conf, "ProxyMethod", args.proxy_method, err, sizeof(err));
        }
        /* -u, and the whole of what -u does. Gated on GIVEN and not on
         * TRUE, which is Go's flag.Visit exactly: -u=false clears a
         * "UDP": true in the document, and an absent -u leaves it. */
        if (rc == 0 && args.udp_given) {
            rc = conf_set_bool(&conf, "UDP", args.udp, err, sizeof(err));
        }
        if (rc == 0) {
            rc = conf_default(&conf, "LocalHost", local_host, err, sizeof(err));
        }
        if (rc == 0) {
            rc = conf_default(&conf, "LocalPort", local_port, err, sizeof(err));
        }
        if (rc == 0) {
            rc = conf_default(&conf, "RemotePort", remote_port, err, sizeof(err));
        }
    }
    if (rc != 0) {
        CLOAK_LOGE("configuration error in %s: %s", source, err);
        conf_free(&conf);
        return CK_EXIT_CONFIG;
    }

    cloak_client_config_t cfg;
    rc = conf_finish(&conf, &cfg, err, sizeof(err));
    conf_free(&conf);
    if (rc != 0) {
        CLOAK_LOGE("configuration error in %s: %s", source, err);
        return CK_EXIT_CONFIG;
    }

    /* A GAP, MADE AUDIBLE RATHER THAN LEFT SILENT. cloak/client_stack.h
     * records that keep_alive_sec is consumed by nothing -- no socket in
     * this port sets SO_KEEPALIVE -- and Go's client passes it to
     * net.Dialer.KeepAlive, so a config carried over from Go Cloak asks
     * for something this build does not do. A setting silently ignored is
     * the shape of bug that is only ever found by packet capture; one
     * WARN at startup costs nothing and is the only honest thing a binary
     * can do about a gap it cannot close. (The parser stores -1 for
     * "unset", so this fires only when an operator actually wrote one.) */
    if (cfg.keep_alive_sec > 0) {
        CLOAK_LOGW("KeepAlive %d is configured but no socket in this build sets "
                   "SO_KEEPALIVE; the setting is ignored",
                   cfg.keep_alive_sec);
    }

    /* -a, exactly as Go: the admin UID replaces the config's, the session
     * id becomes 0 and NumConn becomes 1. THREE ASSIGNMENTS, WHICH IS
     * GO'S COUNT (ck-client.go, the `if adminUID != nil` branch) -- the
     * session id is the half a caller cannot supply on its own, see
     * cloak_client_stack_config_t::admin_session and the server's
     * `is_admin = admin uid AND session id 0`.
     *
     * SINGLEPLEX IS DELIBERATELY NOT TOUCHED, and this is the one part of
     * this block worth reading twice. There was a fourth assignment here,
     * `cfg.singleplex = 0`, and it was wrong in both directions at once.
     * Go does not make it. And by making it, this binary pre-satisfied
     * cloak_client_stack_config_t::admin_session's documented ERR_CONFIG
     * guard, so the guard could never fire from the only program that sets
     * the field -- while the operator's configuration was rewritten
     * underneath them in total silence, in a file that WARNs about an
     * ignored KeepAlive precisely because a silently ignored setting is a
     * bug only packet capture finds.
     *
     * What an operator sees now: both parsers, Go's and this one, turn
     * NumConn <= 0 into "NumConn 1, singleplex", so a config that omits
     * NumConn IS a singleplex config. Go runs admin mode on it anyway and
     * hands every local connection a fresh session id, which the server
     * admits only at id 0 -- broken, silently. Here the stack refuses it
     * with exit 2 and a message naming the remedy ("NumConn": 1), which
     * is the same thing that makes Go's admin mode work. Refusing is the
     * faithful choice AND the better one; that is not usually true, so it
     * is written down. */
    int admin_session = 0;
    if (args.admin_uid != NULL && args.admin_uid[0] != '\0') {
        uint8_t uid[CLOAK_UID_LEN];
        size_t uid_len = 0;
        if (cloak_base64_decode(args.admin_uid, uid, sizeof(uid), &uid_len) != 0 ||
            uid_len != CLOAK_UID_LEN) {
            fprintf(stderr,
                    "ck-client: -a must be a base64-encoded %d-byte UID, got \"%s\"\n",
                    CLOAK_UID_LEN, args.admin_uid);
            return CK_EXIT_USAGE;
        }
        memcpy(cfg.uid, uid, CLOAK_UID_LEN);
        cfg.num_conn = 1;
        admin_session = 1;
        CLOAK_LOGI("admin mode: serving the admin api on the local address "
                   "(session id 0, NumConn 1)");
    }

    CLOAK_LOGI("remote is %s:%s, proxy method %s, %d connection(s)%s", cfg.remote_host,
               cfg.remote_port, cfg.proxy_method, cfg.num_conn,
               cfg.singleplex ? ", singleplex" : "");

    cloak_reactor_t *reactor = cloak_reactor_create();
    if (reactor == NULL) {
        CLOAK_LOGE("unable to create the reactor");
        return CK_EXIT_RUNTIME;
    }

    cloak_client_stack_config_t sc;
    memset(&sc, 0, sizeof(sc));
    sc.reactor = reactor;
    sc.config = &cfg;
    sc.admin_session = admin_session;
    /* Unbounded, which is Go's behaviour and is defensible here for the
     * reason cloak/client_stack.h gives: it is a BINARY, an operator can
     * see it and interrupt it, and on_event above narrates every round. */
    sc.max_rounds = CLOAK_CLIENT_STACK_ROUNDS_UNBOUNDED;
    sc.on_event = on_event;

    cloak_client_stack_t *stack = NULL;
    char stack_err[CLOAK_CONFIG_ERR_LEN] = {0};
    int open_rc = cloak_client_stack_open(&stack, &sc, stack_err, sizeof(stack_err));
    if (open_rc != 0) {
        CLOAK_LOGE("unable to start the client (%s): %s",
                   cloak_client_stack_strerror(open_rc), stack_err);
        cloak_reactor_destroy(reactor);
        return exit_code_for_stack_err(open_rc);
    }

    /* As close to the top as the rest of startup allows: everything
     * before this point exits on its own, and everything after it is the
     * reactor (cloak/signals.h's note about the uncovered window). */
    cloak_signalfd_t *sfd = cloak_signalfd_create(reactor, on_signal, reactor);
    if (sfd == NULL) {
        CLOAK_LOGE("unable to install the signal handler");
        cloak_client_stack_close(stack);
        cloak_reactor_destroy(reactor);
        return CK_EXIT_RUNTIME;
    }

    /* The BOUND port, not the configured one: a LocalPort of "0" is what
     * makes the difference worth printing -- and the PROTOCOL, because in
     * unordered mode this endpoint is a datagram socket and an operator
     * pointing a TCP client at it gets connection refused with nothing
     * anywhere saying why. Go prints the protocol here too. */
    CLOAK_LOGI("listening on %s %s:%d for %s client", cfg.udp ? "UDP" : "TCP", cfg.local_host,
               cloak_client_stack_local_port(stack), cfg.proxy_method);
    CLOAK_LOGI("ck-client ready");

    cloak_reactor_run(reactor);

    cloak_signalfd_destroy(sfd);
    cloak_client_stack_close(stack);
    cloak_reactor_destroy(reactor);
    CLOAK_LOGI("ck-client stopped");
    return CK_EXIT_OK;
}
