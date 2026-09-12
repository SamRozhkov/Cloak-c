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

static void switchboard_conn_drained_adapter(cloak_conn_t *c, void *userdata) {
    (void)c;
    cloak_switchboard_t *sb = (cloak_switchboard_t *)userdata;
    if (sb->on_drained != NULL) {
        sb->on_drained(sb, sb->on_drained_userdata);
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
    cloak_conn_set_drained_cb(c, switchboard_conn_drained_adapter, sb);
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

void cloak_switchboard_set_drained_cb(cloak_switchboard_t *sb, cloak_switchboard_drained_cb cb,
                                       void *userdata) {
    if (sb == NULL) {
        return;
    }
    sb->on_drained = cb;
    sb->on_drained_userdata = userdata;
}

size_t cloak_switchboard_send_queued(const cloak_switchboard_t *sb) {
    if (sb == NULL) {
        return 0;
    }
    size_t total = 0;
    for (size_t i = 0; i < sb->conns_len; i++) {
        total += cloak_conn_send_queued(sb->conns[i]);
    }
    return total;
}

size_t cloak_switchboard_send_capacity(const cloak_switchboard_t *sb) {
    if (sb == NULL) {
        return 0;
    }
    size_t total = 0;
    for (size_t i = 0; i < sb->conns_len; i++) {
        total += cloak_conn_send_capacity(sb->conns[i]);
    }
    return total;
}
