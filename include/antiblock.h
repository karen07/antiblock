#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <linux/if_arp.h>
#include <linux/if.h>
#include <linux/limits.h>
#include <linux/route.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#include "array_hashmap.h"

#define ANTIBLOCK_VERSION "2.2.0"

#define PCAP_MODE
/* #define PROXY_MODE */
/* #define MULTIPLE_DNS */

#ifdef PCAP_MODE
#ifdef MULTIPLE_DNS
#error "You can't use PCAP_MODE and MULTIPLE_DNS"
#endif
#ifdef PROXY_MODE
#error "You can't use PCAP_MODE and PROXY_MODE"
#endif
#endif

#ifdef PCAP_MODE
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <pcap.h>
#include <pcap/sll.h>
#endif

#define PACKET_MAX_SIZE 1600
#define DOMAIN_MAX_SIZE 300

#define CNAME_DOMAINS_MAP_MAX_SIZE 500
#define ROUTES_MAP_MAX_SIZE 1000

#define STAT_PRINT_TIME 10
#define DOMAINS_UPDATE_TIME 60 * 60 * 24

#define BLACKLIST_MAX_COUNT 128

#define GATEWAY_BITS_COUNT 5
#define MATCH_SUBDOMAINS 1
#define OFFSET_BITS_COUNT (32 - GATEWAY_BITS_COUNT - MATCH_SUBDOMAINS)
#define GATEWAY_MAX_COUNT (1 << GATEWAY_BITS_COUNT)

#ifndef _DOMAINS_TYPE
#define _DOMAINS_TYPE
typedef struct domains_gateway {
    unsigned int gateway : GATEWAY_BITS_COUNT;
    unsigned int match_subdomains : MATCH_SUBDOMAINS;
    unsigned int offset : OFFSET_BITS_COUNT;
} domains_gateway_t;
#endif

#ifndef _MEMORY_TYPE
#define _MEMORY_TYPE
typedef struct memory {
    char *data;
    size_t size;
    size_t max_size;
} memory_t;
#endif

#ifndef _SUBNET_TYPE
#define _SUBNET_TYPE
typedef struct subnet {
    uint32_t ip;
    uint32_t mask;
} subnet_t;
#endif

extern FILE *log_fd;
extern FILE *stat_fd;

extern int32_t gateways_count;
extern char *gateway_domains_paths[GATEWAY_MAX_COUNT];

extern int32_t blacklist_count;
extern subnet_t blacklist[BLACKLIST_MAX_COUNT];

extern struct sockaddr_in listen_addr;

extern volatile uint64_t now_unix_time;

#ifdef PROXY_MODE
#ifdef MULTIPLE_DNS
#define DNS_COUNT (gateways_count + 1)
#define DNS_MAX_COUNT (GATEWAY_MAX_COUNT + 1)
#else
#define DNS_COUNT (1)
#define DNS_MAX_COUNT (1)
#endif

extern struct sockaddr_in dns_addr[DNS_MAX_COUNT];
#endif

void errmsg(const char *format, ...);

void add_route(int32_t gateway_index, uint32_t dst, uint32_t ans_ttl);
void del_route(int32_t gateway_index, uint32_t dst);
