/* Verify own route state after simulated SIOCADDRT and rollback failures. */
#define ioctl test_ioctl
#include "../../src/routes.c"
#undef ioctl

#include <stdarg.h>
#include <stdio.h>

static int kernel_gateway = -1;
static int fail_first_add;
static int fail_new_add;
static int fail_rollback_add;
static unsigned int add_calls;
static unsigned int delete_calls;

int test_ioctl(int fd, unsigned long request, ...)
{
    va_list ap;
    const struct rtentry *rt;
    int gateway;

    (void)fd;
    va_start(ap, request);
    rt = va_arg(ap, const struct rtentry *);
    va_end(ap);
    gateway = strcmp(rt->rt_dev, "wg0") == 0 ? 0 : 1;

    if (request == SIOCADDRT) {
        ++add_calls;
        if ((gateway == 0 && fail_first_add) || (gateway == 1 && fail_new_add) ||
            (gateway == 0 && fail_rollback_add && delete_calls > 0)) {
            errno = EIO;
            return -1;
        }
        kernel_gateway = gateway;
        return 0;
    }
    if (request == SIOCDELRT) {
        ++delete_calls;
        if (kernel_gateway != gateway) {
            errno = ESRCH;
            return -1;
        }
        kernel_gateway = -1;
        return 0;
    }
    errno = EINVAL;
    return -1;
}

static int check_route(route_state_t *state, uint32_t ip, int expected_gateway,
                       telemetry_t *telemetry)
{
    route_entry_t entry;
    array_hashmap_ret_t rc = array_hashmap_find_elem(state->map, &ip, &entry);

    if (expected_gateway < 0) {
        return rc == array_hashmap_elem_not_finded && telemetry->route_count[0] == 0 &&
               telemetry->route_count[1] == 0 && kernel_gateway == -1;
    }
    return rc == array_hashmap_elem_finded && entry.gateway_index == (uint32_t)expected_gateway &&
           telemetry->route_count[0] == (expected_gateway == 0) &&
           telemetry->route_count[1] == (expected_gateway == 1) &&
           kernel_gateway == expected_gateway;
}

int main(void)
{
    ab_config_t cfg = { 0 };
    telemetry_t telemetry = { 0 };
    route_state_t state = { 0 };
    const uint32_t ip = inet_addr("11.22.33.44");
    int ok = 0;

    cfg.rule_count = 2;
    strcpy(cfg.rules[0].ifname, "wg0");
    strcpy(cfg.rules[1].ifname, "wg1");
    state.cfg = &cfg;
    state.telemetry = &telemetry;
    state.route_fd = -1;
    state.map = array_hashmap_init(AB_ROUTE_CAPACITY, 1.0, sizeof(route_entry_t));
    if (state.map == NULL) {
        return 1;
    }
    array_hashmap_set_func(state.map, route_add_hash, route_add_cmp, route_find_hash,
                           route_find_cmp, route_find_hash, route_find_cmp);

    /* Failure on initial add must not create userspace state. */
    fail_first_add = 1;
    if (routes_observe(&state, 0, ip, 30, 100) == 0 || !check_route(&state, ip, -1, &telemetry) ||
        telemetry.route_add_errors != 1) {
        goto done;
    }
    fail_first_add = 0;
    if (routes_observe(&state, 0, ip, 30, 101) != 0 || !check_route(&state, ip, 0, &telemetry)) {
        goto done;
    }

    /* Failed move with successful rollback must retain the old route. */
    fail_new_add = 1;
    if (routes_observe(&state, 1, ip, 30, 102) == 0 || !check_route(&state, ip, 0, &telemetry) ||
        telemetry.route_add_errors != 2) {
        goto done;
    }

    /* Failed move and failed rollback must discard stale userspace state. */
    fail_rollback_add = 1;
    if (routes_observe(&state, 1, ip, 30, 103) == 0 || !check_route(&state, ip, -1, &telemetry) ||
        telemetry.route_add_errors != 4 || add_calls != 6 || delete_calls != 2) {
        goto done;
    }

    puts("PASS: add failure, move rollback, and rollback failure preserve route invariants");
    ok = 1;

done:
    if (!ok) {
        fprintf(stderr, "FAIL: route state after ioctl error, adds=%u deletes=%u errors=%llu\n",
                add_calls, delete_calls, (unsigned long long)telemetry.route_add_errors);
    }
    array_hashmap_del(&state.map);
    return ok ? 0 : 1;
}
