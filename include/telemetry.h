#ifndef ANTIBLOCK_TELEMETRY_H
#define ANTIBLOCK_TELEMETRY_H

#include "common.h"
#include "config.h"

#include <stdio.h>
#include <time.h>

typedef struct telemetry {
    FILE *log_fp;
    FILE *stat_fp;

    uint64_t processed;
    uint64_t parse_errors;
    uint64_t route_add_errors;
    int32_t route_count[AB_MAX_RULES];
    time_t stat_start;
} telemetry_t;

int telemetry_open(telemetry_t *t, const ab_config_t *cfg);
void telemetry_close(telemetry_t *t);
void telemetry_reset_period(telemetry_t *t);
void telemetry_print(const telemetry_t *t, const ab_config_t *cfg);
void telemetry_log_header(telemetry_t *t);
void telemetry_flush(telemetry_t *t);
void telemetry_print_capture_stats(telemetry_t *t, uint64_t received, uint64_t dropped,
                                   uint64_t interface_dropped);

void telemetry_dns_processed(telemetry_t *t);
void telemetry_dns_error(telemetry_t *t, int code, const uint8_t *packet, size_t len);
void telemetry_log_query(telemetry_t *t, uint16_t type, const char *name);
void telemetry_log_a(telemetry_t *t, int gateway, int blocked, const char *name, uint32_t ip_be);
void telemetry_log_cname(telemetry_t *t, int gateway, const char *owner, const char *target);
void telemetry_log_https_alias(telemetry_t *t, int gateway, const char *owner, const char *target);
void telemetry_log_other(telemetry_t *t, uint16_t type, const char *owner);

void telemetry_route_add_failed(telemetry_t *t);
void telemetry_route_added(telemetry_t *t, uint8_t gateway);
void telemetry_route_deleted(telemetry_t *t, uint8_t gateway);
void telemetry_route_moved(telemetry_t *t, uint8_t old_gateway, uint8_t new_gateway,
                           uint32_t dst_be, const ab_config_t *cfg);

#endif
