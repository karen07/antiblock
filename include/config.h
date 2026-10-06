#ifndef ANTIBLOCK_CONFIG_H
#define ANTIBLOCK_CONFIG_H

#include "common.h"

#include <linux/if.h>

#include <stdio.h>

typedef struct ab_subnet {
    uint32_t network;
    uint32_t mask;
} ab_subnet_t;

typedef struct ab_rule {
    char ifname[IFNAMSIZ];
    const char *source;
    uint32_t nexthop_be;
    uint8_t is_l2;
} ab_rule_t;

typedef struct ab_config {
    ab_rule_t rules[AB_MAX_RULES];
    uint8_t rule_count;

    uint32_t dns_src_ip_be;
    uint16_t dns_src_port;

    ab_subnet_t blacklist[AB_MAX_BLACKLIST];
    uint16_t blacklist_count;
    const char *blacklist_path;

    const char *output_dir;
    uint8_t log_enabled;
    uint8_t stat_enabled;
    uint8_t test_mode;
} ab_config_t;

void config_init(ab_config_t *cfg);
int config_parse(ab_config_t *cfg, int argc, char **argv);
int config_load_blacklist(ab_config_t *cfg);
int config_ip_blocked(const ab_config_t *cfg, uint32_t ip_be);
void config_print_help(FILE *out);

#endif
