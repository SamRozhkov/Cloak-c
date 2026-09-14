#include "cloak/valve.h"

#include <stddef.h>

void cloak_valve_add_rx(cloak_valve_t *v, int64_t n) {
    if (v == NULL) {
        return; /* unmetered session -- see cloak/valve.h */
    }
    v->rx += n;
}

void cloak_valve_add_tx(cloak_valve_t *v, int64_t n) {
    if (v == NULL) {
        return;
    }
    v->tx += n;
}

int64_t cloak_valve_rx(const cloak_valve_t *v) {
    return v == NULL ? 0 : v->rx;
}

int64_t cloak_valve_tx(const cloak_valve_t *v) {
    return v == NULL ? 0 : v->tx;
}

void cloak_valve_nullify(cloak_valve_t *v, int64_t *out_rx, int64_t *out_tx) {
    int64_t rx = 0, tx = 0;
    if (v != NULL) {
        /* Read and reset with nothing in between -- see this function's
         * doc comment: any byte counted between a separate read and a
         * separate reset would be zeroed away unbilled. */
        rx = v->rx;
        tx = v->tx;
        v->rx = 0;
        v->tx = 0;
    }
    if (out_rx != NULL) {
        *out_rx = rx;
    }
    if (out_tx != NULL) {
        *out_tx = tx;
    }
}
