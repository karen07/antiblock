#ifndef ANTIBLOCK_DOMAINS_H
#define ANTIBLOCK_DOMAINS_H

#include "array_hashmap.h"
#include "common.h"
#include "config.h"

typedef struct domain_table {
    char *arena;
    uint32_t arena_size;
    uint32_t arena_capacity;

    array_hashmap_t map;
    uint32_t map_capacity;
    uint32_t static_count;
    uint32_t learned_count;
    uint8_t learn_capacity_warned;
} domain_table_t;

void domains_destroy(domain_table_t *table);
int domains_reload(domain_table_t *table, const ab_config_t *cfg);
int domains_lookup(const domain_table_t *table, const char *domain);
int domains_learn(domain_table_t *table, const char *domain, uint8_t gateway, int match_subdomains);

#endif
