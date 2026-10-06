#ifndef ANTIBLOCK_DNS_H
#define ANTIBLOCK_DNS_H

#include "common.h"
#include "config.h"
#include "domains.h"
#include "routes.h"
#include "telemetry.h"

int dns_process_response(const ab_bytes_t *packet, const ab_config_t *cfg, domain_table_t *domains,
                         route_state_t *routes, telemetry_t *telemetry, uint32_t now);

#endif
