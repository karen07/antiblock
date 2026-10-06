/* Capacity tests exercise the existing maps without kernel route changes. */
#include "domains.h"
#include "../../src/routes.c"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int count_warnings(FILE *fp, const char *needle)
{
    char line[256];
    int count = 0;

    rewind(fp);
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, needle) != NULL) {
            ++count;
        }
    }
    return count;
}

static int check_domains(void)
{
    char source[] = "/tmp/ab-capacity-XXXXXX";
    ab_config_t cfg = { 0 };
    domain_table_t table = { 0 };
    FILE *messages = NULL;
    int saved_stderr = -1;
    char name[64];
    unsigned int i;
    unsigned int capacity;
    int rc = -1;
    int fd = mkstemp(source);

    if (fd < 0) {
        return -1;
    }
    close(fd);
    cfg.rule_count = 1;
    cfg.rules[0].source = source;
    if (domains_reload(&table, &cfg) != 0) {
        goto cleanup;
    }
    messages = tmpfile();
    saved_stderr = dup(STDERR_FILENO);
    if (messages == NULL || saved_stderr < 0 || dup2(fileno(messages), STDERR_FILENO) < 0) {
        goto cleanup;
    }
    /* The map includes reserve slots plus one line for the empty source. */
    capacity = table.map_capacity;
    for (i = 0; i < capacity; ++i) {
        snprintf(name, sizeof(name), "alias-%u.test", i);
        if (domains_learn(&table, name, 0, 1) != 1) {
            goto cleanup;
        }
    }
    for (i = 0; i < 5; ++i) {
        snprintf(name, sizeof(name), "overflow-%u.test", i);
        if (domains_learn(&table, name, 0, 1) != -1) {
            goto cleanup;
        }
    }
    fflush(stderr);
    if (table.learned_count != capacity ||
        count_warnings(messages, "Learned domain capacity reached") != 1) {
        goto cleanup;
    }
    /* Reload rearms the warning. Force the pre-reserved arena to look full. */
    if (domains_reload(&table, &cfg) != 0) {
        goto cleanup;
    }
    table.arena_capacity = table.arena_size;
    if (domains_learn(&table, "arena.test", 0, 1) != -1 ||
        domains_learn(&table, "another.test", 0, 1) != -1) {
        goto cleanup;
    }
    fflush(stderr);
    if (count_warnings(messages, "Learned domain capacity reached") != 2) {
        goto cleanup;
    }
    rc = 0;

cleanup:
    if (saved_stderr >= 0) {
        fflush(stderr);
        (void)dup2(saved_stderr, STDERR_FILENO);
        close(saved_stderr);
    }
    if (messages != NULL) {
        fclose(messages);
    }
    domains_destroy(&table);
    unlink(source);
    return rc;
}

static int check_routes(void)
{
    ab_config_t cfg = { 0 };
    telemetry_t telemetry = { 0 };
    route_state_t state = { 0 };
    FILE *messages = NULL;
    FILE *stats = NULL;
    int saved_stderr = -1;
    unsigned int round;
    unsigned int i;
    int rc = -1;

    cfg.test_mode = 1;
    cfg.rule_count = 1;
    strcpy(cfg.rules[0].ifname, "lo");
    state.cfg = &cfg;
    state.telemetry = &telemetry;
    state.route_fd = -1;
    state.map = array_hashmap_init(AB_ROUTE_CAPACITY, 1.0, sizeof(route_entry_t));
    if (state.map == NULL) {
        return -1;
    }
    array_hashmap_set_func(state.map, route_add_hash, route_add_cmp, route_find_hash,
                           route_find_cmp, route_find_hash, route_find_cmp);
    messages = tmpfile();
    saved_stderr = dup(STDERR_FILENO);
    if (messages == NULL || saved_stderr < 0 || dup2(fileno(messages), STDERR_FILENO) < 0) {
        goto cleanup;
    }
    for (round = 0; round < 2; ++round) {
        for (i = 0; i < AB_ROUTE_CAPACITY; ++i) {
            uint32_t ip = htonl(0x0b160000u + i + 1u);
            if (routes_observe(&state, 0, ip, 2, round * 10u + 1u) != 0) {
                goto cleanup;
            }
        }
        if (array_hashmap_now_in_map(state.map) != (int32_t)AB_ROUTE_CAPACITY) {
            goto cleanup;
        }
        for (i = 0; i < 5; ++i) {
            uint32_t ip = htonl(0x0b170000u + i + 1u);
            if (routes_observe(&state, 0, ip, 2, round * 10u + 1u) != -1) {
                goto cleanup;
            }
        }
        routes_expire(&state, round * 10u + 4u);
        if (array_hashmap_now_in_map(state.map) != 0 || state.capacity_warned != 0) {
            goto cleanup;
        }
    }
    fflush(stderr);
    if (count_warnings(messages, "Route hashmap is full") != 2) {
        goto cleanup;
    }
    /* A failed real ioctl counts once, not as a full-hashmap error. */
    cfg.test_mode = 0;
    if (routes_observe(&state, 0, htonl(0x0b180001u), 2, 30) != -1 ||
        telemetry.route_add_errors != 1 || array_hashmap_now_in_map(state.map) != 0) {
        goto cleanup;
    }
    stats = tmpfile();
    if (stats == NULL) {
        goto cleanup;
    }
    telemetry.stat_fp = stats;
    telemetry_print(&telemetry, &cfg);
    rewind(stats);
    {
        char line[256];
        int found = 0;
        while (fgets(line, sizeof(line), stats) != NULL) {
            if (strstr(line, "Route add errors     : 1") != NULL) {
                found = 1;
            }
        }
        if (!found) {
            goto cleanup;
        }
    }
    telemetry_reset_period(&telemetry);
    if (telemetry.route_add_errors != 0) {
        goto cleanup;
    }
    rc = 0;

cleanup:
    if (saved_stderr >= 0) {
        fflush(stderr);
        (void)dup2(saved_stderr, STDERR_FILENO);
        close(saved_stderr);
    }
    if (messages != NULL) {
        fclose(messages);
    }
    if (stats != NULL) {
        fclose(stats);
    }
    array_hashmap_del(&state.map);
    return rc;
}

int main(void)
{
    if (check_domains() != 0 || check_routes() != 0) {
        fprintf(stderr, "FAIL: capacity/telemetry regression\n");
        return 1;
    }
    puts("PASS: learned/route limits, bounded warnings, and route-add error stats");
    return 0;
}
