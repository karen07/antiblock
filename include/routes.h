#ifndef ANTIBLOCK_ROUTES_H
#define ANTIBLOCK_ROUTES_H

#include "array_hashmap.h"
#include "common.h"
#include "config.h"
#include "telemetry.h"

typedef struct route_state {
    array_hashmap_t map;
    int route_fd;
    uint8_t capacity_warned;
    ab_config_t *cfg;
    telemetry_t *telemetry;
} route_state_t;

int routes_open(route_state_t *state, ab_config_t *cfg, telemetry_t *telemetry);
void routes_close(route_state_t *state);
int routes_clean_stale(route_state_t *state);
int routes_observe(route_state_t *state, uint8_t gateway, uint32_t dst_be, uint32_t ttl,
                   uint32_t now);
void routes_expire(route_state_t *state, uint32_t now);
void routes_shutdown(route_state_t *state);

#endif
