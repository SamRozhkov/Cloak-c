#ifndef CLOAK_CONFIG_H
#define CLOAK_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#include "cloak/crypto.h"

/* Configuration structs for both binaries, parsed from the JSON format Go
 * Cloak uses (see ../Cloak/example_config/). Every struct here is a
 * fixed-size POD with no owned pointers: parse fills one in place, and a
 * caller can hold one on the stack, copy it, and discard it without any
 * cleanup.
 *
 * Every parse function reports failure by returning -1 and writing a
 * human-readable, NUL-terminated message into err (truncated to err_cap).
 * err may be NULL if the caller does not want the message. On failure the
 * config struct's contents are unspecified. */

#define CLOAK_CONFIG_ERR_LEN 256

/* Field capacities. Hostnames follow the DNS limit; the port fields hold a
 * decimal port number or a service name. */
#define CLOAK_MAX_HOST_LEN 256
#define CLOAK_MAX_PORT_LEN 16
#define CLOAK_MAX_PATH_LEN 512

/* THE LONGEST DNS HOSTNAME IN PRESENTATION FORM, and the bound on every
 * field of this config that becomes an SNI.
 *
 * RFC 1035 sec. 2.3.4 caps a name at 255 OCTETS in wire format, clarified
 * by RFC 4343; two of those octets -- the first label's length prefix and
 * the root label's zero length -- have no character in the dotted text
 * form, so the presentation limit is 253. RFC 6066 sec. 3 requires the
 * HostName in a TLS server_name extension to be "a fully qualified DNS
 * hostname", which makes the DNS limit the operative one even though the
 * extension's own length field is 16 bits.
 *
 * CLOAK_MAX_HOST_LEN above is a BUFFER SIZE and is deliberately not this
 * number: the two mean different things and conflating them is what put a
 * 254-character ServerName past this parser and into the connector, which
 * refused it -- a permanent configuration error arriving as a retryable
 * runtime failure. Go bounds ServerName nowhere at all, so neither number
 * is Go's and the RFCs decide it. libcloak-client's
 * CLOAK_CLIENT_SERVER_NAME_MAX is defined from this constant so the
 * parser and its consumer cannot disagree again. */
#define CLOAK_MAX_DNS_NAME_LEN 253

/* The wire auth payload carries the proxy method in a fixed 12-byte field
 * (see the Go original's authentication payload layout), so a longer name
 * could never reach the server. Configs are rejected rather than
 * silently truncated. */
#define CLOAK_PROXY_METHOD_LEN 12

#define CLOAK_UID_LEN 16

/* Collection caps. These are limits this implementation imposes (the Go
 * version's slices are unbounded); exceeding one is a config error, never
 * a silent truncation. */
#define CLOAK_MAX_ALT_NAMES 16
#define CLOAK_MAX_PROXY_BOOK 16
#define CLOAK_MAX_BIND_ADDR 16
#define CLOAK_MAX_BYPASS_UID 64

typedef enum {
    CLOAK_BROWSER_CHROME = 0,
    CLOAK_BROWSER_FIREFOX = 1,
    CLOAK_BROWSER_SAFARI = 2,
} cloak_browser_t;

typedef enum {
    CLOAK_TRANSPORT_DIRECT = 0,
    CLOAK_TRANSPORT_CDN = 1,
} cloak_transport_mode_t;

typedef struct {
    /* The SNI presented in the forged ClientHello. The literal string
     * "random" is preserved here as-is; generating a random domain per
     * connection is the transport layer's job, not the parser's. */
    char server_name[CLOAK_MAX_HOST_LEN];

    /* Additional mock domains. The transport picks uniformly from
     * server_name together with these, matching Go's MockDomainList. */
    char alt_names[CLOAK_MAX_ALT_NAMES][CLOAK_MAX_HOST_LEN];
    size_t num_alt_names;

    char proxy_method[CLOAK_PROXY_METHOD_LEN + 1];
    cloak_aead_method_t encryption_method;

    uint8_t uid[CLOAK_UID_LEN];
    uint8_t server_pub_key[CLOAK_X25519_KEY_LEN];

    /* num_conn is always >= 1. singleplex is 1 when the config asked for
     * NumConn <= 0, which in Go means "one connection, one stream, and the
     * session closes with that stream". */
    int num_conn;
    int singleplex;

    char local_host[CLOAK_MAX_HOST_LEN];
    char local_port[CLOAK_MAX_PORT_LEN];
    char remote_host[CLOAK_MAX_HOST_LEN];
    char remote_port[CLOAK_MAX_PORT_LEN];

    /* 1 when the wrapped proxy speaks UDP, which puts the session in
     * unordered/datagram mode. */
    int udp;

    cloak_browser_t browser;
    cloak_transport_mode_t transport;

    /* Only meaningful when transport == CLOAK_TRANSPORT_CDN. If the config
     * omitted CDNOriginHost, cdn_origin_host is empty and the caller uses
     * remote_host in its place (Go does this substitution in
     * ProcessRawConfig). cdn_ws_url_path defaults to "/". */
    char cdn_origin_host[CLOAK_MAX_HOST_LEN];
    char cdn_ws_url_path[CLOAK_MAX_PATH_LEN];

    /* Seconds. stream_timeout_sec defaults to 300. A negative
     * StreamTimeout is a config error here; Go's client
     * (internal/client/state.go:271-276) accepts a negative value
     * silently and passes it straight through to time.Duration. keep_alive_sec is -1 when TCP keepalive is disabled,
     * which is the default. */
    int stream_timeout_sec;
    int keep_alive_sec;

    /* "FlowControl": false turns off the per-stream window updates this
     * port adds. They are a frame type Go Cloak does not know, and this
     * is the switch that lets our binaries still be driven against Go's
     * in the reference tests. Default (key absent) is ON. */
    int disable_flow_control;
} cloak_client_config_t;

typedef struct {
    /* Lower-cased proxy method name, matched against the method the client
     * sends in its auth payload. */
    char name[CLOAK_PROXY_METHOD_LEN + 1];
    /* 0 for "tcp", 1 for "udp". A ProxyBook entry naming any other network
     * is a config error here; Go's parseProxyBook (internal/server/state.go:88-105) has no
     * default case in its switch, so such an entry is silently dropped
     * from the proxy book rather than rejected -- a server config that
     * boots under Go Cloak may fail to parse under this implementation. */
    int is_udp;
    /* The upstream proxy endpoint as written in the config, e.g.
     * "localhost:51443". Resolution happens at dial time, not here. */
    char addr[CLOAK_MAX_HOST_LEN];
} cloak_proxy_entry_t;

typedef struct {
    cloak_proxy_entry_t proxy_book[CLOAK_MAX_PROXY_BOOK];
    size_t num_proxy_entries;

    /* Addresses to listen on, e.g. ":443". At least one is required. */
    char bind_addr[CLOAK_MAX_BIND_ADDR][CLOAK_MAX_HOST_LEN];
    size_t num_bind_addr;

    /* UIDs exempt from all credit and bandwidth accounting. Does NOT
     * include admin_uid: a caller that needs the full bypass set must
     * union bypass_uid with admin_uid (when has_admin_uid) itself. */
    uint8_t bypass_uid[CLOAK_MAX_BYPASS_UID][CLOAK_UID_LEN];
    size_t num_bypass_uid;

    /* Where non-Cloak traffic is forwarded. Required: without it the
     * server has no cover story. Held as written ("host" or "host:port"). */
    char redir_addr[CLOAK_MAX_HOST_LEN];

    uint8_t private_key[CLOAK_X25519_KEY_LEN];

    /* has_admin_uid is 0 when the config omitted AdminUID, in which case
     * admin_uid is all zeroes and must not be used. Not part of
     * bypass_uid above; see that field's comment. */
    uint8_t admin_uid[CLOAK_UID_LEN];
    int has_admin_uid;

    /* Empty when unset, which means no user database: only bypass and
     * admin UIDs can connect. */
    char database_path[CLOAK_MAX_PATH_LEN];

    /* Seconds, -1 when disabled (the default). Applies to connections the
     * server makes to upstream proxies. */
    int keep_alive_sec;
    int disable_flow_control; /* see the client config's field */
} cloak_server_config_t;

/* Parses a NUL-terminated JSON document. Returns 0 / -1. */
int cloak_client_config_parse_json(const char *text, cloak_client_config_t *cfg,
                                   char *err, size_t err_cap);

/* Reads path and parses it as JSON. Returns 0 / -1; a missing or
 * unreadable file is a -1 with the reason in err. */
int cloak_client_config_parse_file(const char *path, cloak_client_config_t *cfg,
                                   char *err, size_t err_cap);

int cloak_server_config_parse_json(const char *text, cloak_server_config_t *cfg,
                                   char *err, size_t err_cap);

int cloak_server_config_parse_file(const char *path, cloak_server_config_t *cfg,
                                   char *err, size_t err_cap);

/* Parses the semicolon-separated form Shadowsocks passes in
 * SS_PLUGIN_OPTIONS, e.g.
 *   "UID=...;PublicKey=...;ServerName=www.bing.com;NumConn=4"
 * Within a value, "\\", "\=" and "\;" escape a backslash, an equals sign
 * and a semicolon respectively. AlternativeNames takes a comma-separated
 * list. Returns 0 / -1 with the same error convention as the JSON
 * parsers. */
int cloak_client_config_parse_ssv(const char *ssv, cloak_client_config_t *cfg,
                                  char *err, size_t err_cap);

/* Go's heuristic, reproduced: if conf contains both ';' and '=' it is
 * treated as an ssv option string, otherwise as a path to a JSON file.
 * Returns 0 / -1. */
int cloak_client_config_load(const char *conf, cloak_client_config_t *cfg,
                             char *err, size_t err_cap);

#endif
