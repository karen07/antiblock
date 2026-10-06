/* Exercise the real userspace route hashmap without touching kernel routes. */
#include "../../src/routes.c"

#include <arpa/inet.h>
#include <stdio.h>

int main(void)
{
    ab_config_t cfg = { 0 };
    telemetry_t telemetry = { 0 };
    route_state_t state = { 0 };
    const uint32_t ip = inet_addr("11.22.35.96");
    const uint32_t now = 100;
    route_entry_t entry;
    int success = 0;

    cfg.test_mode = 1;
    cfg.rule_count = 2;
    state.cfg = &cfg;
    state.telemetry = &telemetry;
    state.route_fd = -1;
    state.map = array_hashmap_init(AB_ROUTE_CAPACITY, 1.0, sizeof(route_entry_t));
    if (state.map == NULL) {
        fprintf(stderr, "cannot allocate test route map\n");
        return 1;
    }
    array_hashmap_set_func(state.map, route_add_hash, route_add_cmp, route_find_hash,
                           route_find_cmp, route_find_hash, route_find_cmp);

    if (routes_observe(&state, 0, ip, 0, now) != 0 || array_hashmap_now_in_map(state.map) != 0 ||
        telemetry.route_count[0] != 0) {
        fprintf(stderr, "TTL=0 unexpectedly added a route\n");
        goto done;
    }
    if (routes_observe(&state, 0, ip, 5, now) != 0 || array_hashmap_now_in_map(state.map) != 1 ||
        telemetry.route_count[0] != 1) {
        fprintf(stderr, "positive TTL did not add a route\n");
        goto done;
    }
    if (routes_observe(&state, 1, ip, 0, now + 1u) != 0 ||
        routes_observe(&state, 0, ip, 0, now + 2u) != 0 ||
        array_hashmap_find_elem(state.map, &ip, &entry) != array_hashmap_elem_finded ||
        entry.gateway_index != 0 || entry.expires_at != now + 5u) {
        fprintf(stderr, "TTL=0 moved or refreshed an existing route\n");
        goto done;
    }
    routes_expire(&state, now + 5u);
    if (array_hashmap_now_in_map(state.map) != 0 || telemetry.route_count[0] != 0) {
        fprintf(stderr, "TTL=0 prevented original route expiry\n");
        goto done;
    }
    puts("PASS: TTL=0 skips route add, refresh, and move");
    success = 1;

done:
    array_hashmap_del(&state.map);
    return success ? 0 : 1;
}
