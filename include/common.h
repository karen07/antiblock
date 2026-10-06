#ifndef ANTIBLOCK_COMMON_H
#define ANTIBLOCK_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define AB_VERSION "3.0.0"

#define AB_MAX_RULES 32u
#define AB_MAX_BLACKLIST 128u
#define AB_DOMAIN_MAX 256u
#define AB_LEARNED_DOMAIN_RESERVE_COUNT 500u
#define AB_LEARNED_DOMAIN_RESERVE_BYTES (AB_LEARNED_DOMAIN_RESERVE_COUNT * AB_DOMAIN_MAX)
#define AB_DOMAIN_OFFSET_BITS 26u
#define AB_DOMAIN_OFFSET_LIMIT (1u << AB_DOMAIN_OFFSET_BITS)

#define AB_ROUTE_CAPACITY 1024u
#define AB_ROUTE_METRIC 23117u

#define AB_PCAP_WAIT_MS 10u
#define AB_STAT_INTERVAL_SEC 10u
#define AB_DOMAIN_RELOAD_SEC (24u * 60u * 60u)
#ifndef AB_HTTP_CONNECT_TIMEOUT_SEC
#define AB_HTTP_CONNECT_TIMEOUT_SEC 5L
#endif
#ifndef AB_HTTP_TIMEOUT_SEC
#define AB_HTTP_TIMEOUT_SEC 30L
#endif
#ifndef AB_DOMAIN_RETRY_SEC
#define AB_DOMAIN_RETRY_SEC (5u * 60u)
#endif
#define AB_ALIAS_MAX_PASSES 32u

#define AB_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

typedef struct ab_bytes {
    const uint8_t *data;
    size_t len;
} ab_bytes_t;

static inline uint16_t ab_read_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline uint32_t ab_read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline uint32_t ab_mono_sec(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint32_t)ts.tv_sec;
}

static inline bool ab_time_reached(uint32_t now, uint32_t when)
{
    return (int32_t)(now - when) >= 0;
}

static inline bool ab_time_after(uint32_t a, uint32_t b)
{
    return (int32_t)(a - b) > 0;
}

#endif
