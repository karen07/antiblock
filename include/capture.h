#ifndef ANTIBLOCK_CAPTURE_H
#define ANTIBLOCK_CAPTURE_H

#include "common.h"
#include "config.h"

#include <pcap/pcap.h>

typedef struct capture {
    pcap_t *pcap;
    int datalink;
} capture_t;

typedef struct capture_stats {
    uint64_t received;
    uint64_t dropped;
    uint64_t interface_dropped;
} capture_stats_t;

int capture_open(capture_t *cap, const ab_config_t *cfg);
void capture_close(capture_t *cap);
int capture_next_dns(capture_t *cap, const ab_config_t *cfg, ab_bytes_t *dns);
int capture_wait(capture_t *cap, int timeout_ms);
int capture_get_stats(capture_t *cap, capture_stats_t *stats);

#endif
