#include "routes.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <linux/if_arp.h>
#include <linux/route.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct route_entry {
    uint32_t dst;
    uint32_t expires_at;
    uint32_t gateway_index;
} route_entry_t;

typedef char route_entry_must_be_12_bytes[(sizeof(route_entry_t) == 12u) ? 1 : -1];

static route_state_t *delete_context_state;
static uint32_t delete_context_now;
static int delete_context_all;

static uint32_t route_hash_value(uint32_t dst)
{
    uint32_t x = dst;
    x ^= x >> 16;
    x *= 0x7feb352du;
    x ^= x >> 15;
    x *= 0x846ca68bu;
    x ^= x >> 16;
    return x;
}

static array_hashmap_hash route_add_hash(const void *data)
{
    return route_hash_value(((const route_entry_t *)data)->dst);
}

static array_hashmap_bool route_add_cmp(const void *add_data, const void *map_data)
{
    return ((const route_entry_t *)add_data)->dst == ((const route_entry_t *)map_data)->dst;
}

static array_hashmap_hash route_find_hash(const void *data)
{
    return route_hash_value(*(const uint32_t *)data);
}

static array_hashmap_bool route_find_cmp(const void *find_data, const void *map_data)
{
    return *(const uint32_t *)find_data == ((const route_entry_t *)map_data)->dst;
}

static array_hashmap_bool route_replace(const void *add_data, const void *map_data)
{
    (void)add_data;
    (void)map_data;
    return array_hashmap_save_new;
}

static void fill_rtentry(struct rtentry *rt, const char *ifname, uint32_t dst_be,
                         uint32_t gateway_be, int use_gateway)
{
    struct sockaddr_in *addr;

    memset(rt, 0, sizeof(*rt));

    addr = (struct sockaddr_in *)&rt->rt_dst;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = dst_be;

    addr = (struct sockaddr_in *)&rt->rt_genmask;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = INADDR_NONE;

    rt->rt_dev = (char *)ifname;
    rt->rt_flags = RTF_UP;
    rt->rt_metric = (short)(AB_ROUTE_METRIC + 1u);

    if (use_gateway) {
        addr = (struct sockaddr_in *)&rt->rt_gateway;
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = gateway_be;
        rt->rt_flags |= RTF_GATEWAY;
    }
}

static int kernel_add(route_state_t *state, uint8_t gateway, uint32_t dst_be)
{
    struct rtentry rt;
    const ab_rule_t *rule = &state->cfg->rules[gateway];
    struct in_addr dst;
    char ip[INET_ADDRSTRLEN];

    if (state->cfg->test_mode) {
        return 0;
    }
    fill_rtentry(&rt, rule->ifname, dst_be, rule->nexthop_be, rule->is_l2);
    if (ioctl(state->route_fd, SIOCADDRT, &rt) == 0) {
        return 0;
    }

    dst.s_addr = dst_be;
    if (inet_ntop(AF_INET, &dst, ip, sizeof(ip)) == NULL) {
        strcpy(ip, "?");
    }
    fprintf(stderr, "Can't add route %s via %s: %s\n", ip, rule->ifname, strerror(errno));
    telemetry_route_add_failed(state->telemetry);
    return -1;
}

/* 0 deleted, 1 already absent, -1 hard error. */
static int kernel_delete(route_state_t *state, uint8_t gateway, uint32_t dst_be)
{
    struct rtentry rt;
    const ab_rule_t *rule = &state->cfg->rules[gateway];
    struct in_addr dst;
    char ip[INET_ADDRSTRLEN];

    if (state->cfg->test_mode) {
        return 0;
    }
    fill_rtentry(&rt, rule->ifname, dst_be, rule->nexthop_be, rule->is_l2);
    if (ioctl(state->route_fd, SIOCDELRT, &rt) == 0) {
        return 0;
    }
    if (errno == ESRCH || errno == ENOENT) {
        return 1;
    }

    dst.s_addr = dst_be;
    if (inet_ntop(AF_INET, &dst, ip, sizeof(ip)) == NULL) {
        strcpy(ip, "?");
    }
    fprintf(stderr, "Can't delete route %s via %s: %s\n", ip, rule->ifname, strerror(errno));
    return -1;
}

static int kernel_delete_raw(route_state_t *state, const char *ifname, uint32_t dst_be,
                             uint32_t gateway_be, uint32_t flags)
{
    struct rtentry rt;
    int use_gateway = (flags & RTF_GATEWAY) != 0;

    if (state->cfg->test_mode) {
        return 0;
    }
    fill_rtentry(&rt, ifname, dst_be, gateway_be, use_gateway);
    if (ioctl(state->route_fd, SIOCDELRT, &rt) == 0 || errno == ESRCH || errno == ENOENT) {
        return 0;
    }
    fprintf(stderr, "Can't delete stale AntiBlock route on %s: %s\n", ifname, strerror(errno));
    return -1;
}

static int find_default_gateway(const char *ifname, uint32_t *gateway_be)
{
    FILE *fp;
    char line[512];
    char iface[IFNAMSIZ];
    unsigned int dst;
    unsigned int gateway;
    unsigned int flags;
    unsigned int refcnt;
    unsigned int use;
    unsigned int metric;
    unsigned int mask;
    unsigned int mtu;
    unsigned int window;
    unsigned int irtt;
    unsigned int best_metric = UINT_MAX;
    uint32_t best_gateway = 0;

    fp = fopen("/proc/net/route", "r");
    if (fp == NULL) {
        fprintf(stderr, "Can't open /proc/net/route: %s\n", strerror(errno));
        return -1;
    }
    (void)fgets(line, sizeof(line), fp);

    while (fscanf(fp, "%15s %x %x %x %u %u %u %x %u %u %u", iface, &dst, &gateway, &flags, &refcnt,
                  &use, &metric, &mask, &mtu, &window, &irtt) == 11) {
        (void)refcnt;
        (void)use;
        (void)mtu;
        (void)window;
        (void)irtt;
        if (strcmp(iface, ifname) != 0 || dst != 0 || mask != 0) {
            continue;
        }
        if ((flags & (RTF_UP | RTF_GATEWAY)) != (RTF_UP | RTF_GATEWAY)) {
            continue;
        }
        if (metric < best_metric) {
            best_metric = metric;
            best_gateway = gateway;
        }
    }
    fclose(fp);

    if (best_gateway == 0) {
        return 0;
    }
    *gateway_be = best_gateway;
    return 1;
}

static int prepare_gateways(route_state_t *state)
{
    uint8_t i;

    for (i = 0; i < state->cfg->rule_count; ++i) {
        struct ifreq ifr;
        int gw_rc;

        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, state->cfg->rules[i].ifname, IFNAMSIZ - 1u);
        if (ioctl(state->route_fd, SIOCGIFHWADDR, &ifr) != 0) {
            fprintf(stderr, "Can't inspect interface %s: %s\n", state->cfg->rules[i].ifname,
                    strerror(errno));
            return -1;
        }

        if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
            state->cfg->rules[i].is_l2 = 0;
            state->cfg->rules[i].nexthop_be = 0;
            continue;
        }

        state->cfg->rules[i].is_l2 = 1;
        gw_rc = find_default_gateway(state->cfg->rules[i].ifname, &state->cfg->rules[i].nexthop_be);
        if (gw_rc <= 0) {
            fprintf(stderr, "L2 interface %s has no usable default gateway\n",
                    state->cfg->rules[i].ifname);
            return -1;
        }
    }
    return 0;
}

static array_hashmap_bool route_delete_by_policy(const void *data)
{
    const route_entry_t *entry = data;
    uint8_t gateway;
    int rc;

    if (!delete_context_all && !ab_time_reached(delete_context_now, entry->expires_at)) {
        return array_hashmap_not_del_by_func;
    }
    if (entry->gateway_index >= AB_MAX_RULES ||
        entry->gateway_index >= delete_context_state->cfg->rule_count) {
        return array_hashmap_not_del_by_func;
    }

    gateway = (uint8_t)entry->gateway_index;
    rc = kernel_delete(delete_context_state, gateway, entry->dst);
    if (rc < 0) {
        return array_hashmap_not_del_by_func;
    }

    telemetry_route_deleted(delete_context_state->telemetry, gateway);
    return array_hashmap_del_by_func;
}

int routes_open(route_state_t *state, ab_config_t *cfg, telemetry_t *telemetry)
{
    memset(state, 0, sizeof(*state));
    state->route_fd = -1;
    state->cfg = cfg;
    state->telemetry = telemetry;

    state->map =
        array_hashmap_init((int32_t)AB_ROUTE_CAPACITY, 1.0, (int32_t)sizeof(route_entry_t));
    if (state->map == NULL) {
        fprintf(stderr, "Can't allocate route hashmap\n");
        return -1;
    }
    array_hashmap_set_func(state->map, route_add_hash, route_add_cmp, route_find_hash,
                           route_find_cmp, route_find_hash, route_find_cmp);

    state->route_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (state->route_fd < 0) {
        fprintf(stderr, "Can't create route socket: %s\n", strerror(errno));
        routes_close(state);
        return -1;
    }
    if (prepare_gateways(state) != 0) {
        routes_close(state);
        return -1;
    }
    return 0;
}

void routes_close(route_state_t *state)
{
    if (state->route_fd >= 0) {
        close(state->route_fd);
        state->route_fd = -1;
    }
    array_hashmap_del(&state->map);
}

static int configured_iface(const route_state_t *state, const char *ifname)
{
    uint8_t i;

    for (i = 0; i < state->cfg->rule_count; ++i) {
        if (strcmp(state->cfg->rules[i].ifname, ifname) == 0) {
            return 1;
        }
    }
    return 0;
}

int routes_clean_stale(route_state_t *state)
{
    FILE *fp;
    char line[512];
    char iface[IFNAMSIZ];
    unsigned int dst;
    unsigned int gateway;
    unsigned int flags;
    unsigned int refcnt;
    unsigned int use;
    unsigned int metric;
    unsigned int mask;
    unsigned int mtu;
    unsigned int window;
    unsigned int irtt;
    int status = 0;

    if (state->cfg->test_mode) {
        return 0;
    }
    fp = fopen("/proc/net/route", "r");
    if (fp == NULL) {
        fprintf(stderr, "Can't open /proc/net/route: %s\n", strerror(errno));
        return -1;
    }
    (void)fgets(line, sizeof(line), fp);

    while (fscanf(fp, "%15s %x %x %x %u %u %u %x %u %u %u", iface, &dst, &gateway, &flags, &refcnt,
                  &use, &metric, &mask, &mtu, &window, &irtt) == 11) {
        (void)refcnt;
        (void)use;
        (void)mtu;
        (void)window;
        (void)irtt;
        if (metric != AB_ROUTE_METRIC || mask != UINT32_MAX || !configured_iface(state, iface)) {
            continue;
        }
        if (kernel_delete_raw(state, iface, dst, gateway, flags) != 0) {
            status = -1;
        }
    }
    fclose(fp);
    return status;
}

int routes_observe(route_state_t *state, uint8_t gateway, uint32_t dst_be, uint32_t ttl,
                   uint32_t now)
{
    route_entry_t old_entry;
    route_entry_t new_entry;
    array_hashmap_ret_t find_rc;
    array_hashmap_ret_t map_rc;
    uint32_t bounded_ttl = ttl > INT32_MAX ? INT32_MAX : ttl;
    uint32_t new_expiry = now + bounded_ttl;

    if (gateway >= state->cfg->rule_count || dst_be == 0 || state->map == NULL) {
        return -1;
    }
    /* TTL=0 is not cacheable: do not add, refresh, or move a kernel route. */
    if (ttl == 0) {
        return 0;
    }

    find_rc = array_hashmap_find_elem(state->map, &dst_be, &old_entry);
    if (find_rc == array_hashmap_elem_finded) {
        if (old_entry.gateway_index == gateway) {
            if (!ab_time_after(new_expiry, old_entry.expires_at)) {
                return 0;
            }
            new_entry = old_entry;
            new_entry.expires_at = new_expiry;
            map_rc = array_hashmap_add_elem(state->map, &new_entry, NULL, route_replace);
            return map_rc == array_hashmap_elem_already_in ? 0 : -1;
        }

        if (old_entry.gateway_index >= state->cfg->rule_count) {
            return -1;
        }
        if (kernel_delete(state, (uint8_t)old_entry.gateway_index, dst_be) < 0) {
            return -1;
        }

        if (kernel_add(state, gateway, dst_be) == 0) {
            new_entry.dst = dst_be;
            new_entry.expires_at = new_expiry;
            new_entry.gateway_index = gateway;
            map_rc = array_hashmap_add_elem(state->map, &new_entry, NULL, route_replace);
            if (map_rc == array_hashmap_elem_already_in) {
                telemetry_route_moved(state->telemetry, (uint8_t)old_entry.gateway_index, gateway,
                                      dst_be, state->cfg);
                return 0;
            }

            (void)kernel_delete(state, gateway, dst_be);
        }

        if (kernel_add(state, (uint8_t)old_entry.gateway_index, dst_be) == 0) {
            return -1;
        }

        if (array_hashmap_del_elem(state->map, &dst_be, NULL) == array_hashmap_elem_deled) {
            telemetry_route_deleted(state->telemetry, (uint8_t)old_entry.gateway_index);
        }
        return -1;
    }
    if (find_rc != array_hashmap_elem_not_finded) {
        return -1;
    }

    if (array_hashmap_now_in_map(state->map) >= (int32_t)AB_ROUTE_CAPACITY) {
        if (!state->capacity_warned) {
            fprintf(stderr, "Route hashmap is full (%u entries)\n", AB_ROUTE_CAPACITY);
            state->capacity_warned = 1;
        }
        return -1;
    }
    state->capacity_warned = 0;

    if (kernel_add(state, gateway, dst_be) != 0) {
        return -1;
    }

    new_entry.dst = dst_be;
    new_entry.expires_at = new_expiry;
    new_entry.gateway_index = gateway;
    map_rc = array_hashmap_add_elem(state->map, &new_entry, NULL, NULL);
    if (map_rc == array_hashmap_elem_added) {
        telemetry_route_added(state->telemetry, gateway);
        return 0;
    }

    (void)kernel_delete(state, gateway, dst_be);
    fprintf(stderr, "Can't commit route to userspace hashmap\n");
    return -1;
}

void routes_expire(route_state_t *state, uint32_t now)
{
    if (state->map == NULL) {
        return;
    }
    delete_context_state = state;
    delete_context_now = now;
    delete_context_all = 0;
    (void)array_hashmap_del_elem_by_func(state->map, route_delete_by_policy);
    if (array_hashmap_now_in_map(state->map) < (int32_t)AB_ROUTE_CAPACITY) {
        state->capacity_warned = 0;
    }
    delete_context_state = NULL;
}

void routes_shutdown(route_state_t *state)
{
    if (state->map == NULL) {
        return;
    }
    delete_context_state = state;
    delete_context_now = 0;
    delete_context_all = 1;
    (void)array_hashmap_del_elem_by_func(state->map, route_delete_by_policy);
    delete_context_state = NULL;
}
