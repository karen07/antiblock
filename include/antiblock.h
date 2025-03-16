#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <linux/if.h>
#include <linux/limits.h>
#include <linux/route.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* Initial setup */
//#define ONE_DNS
//#define MULTIPLE_DNS

//#define PROXY_MODE
#define PCAP_MODE

#define ROUTE_TABLE_MODE
//#define TUN_MODE
/* Initial setup */

//Defines check
#ifdef PCAP_MODE
#ifdef ONE_DNS
#error "You can't use PCAP_MODE and ONE_DNS"
#endif
#ifdef MULTIPLE_DNS
#error "You can't use PCAP_MODE and MULTIPLE_DNS"
#endif
#ifdef PROXY_MODE
#error "You can't use PCAP_MODE and PROXY_MODE"
#endif
#ifdef TUN_MODE
#error "You can't use PCAP_MODE and TUN_MODE"
#endif
#endif
//Defines check

#ifdef PCAP_MODE
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <pcap.h>
#include <pcap/sll.h>
#endif

#ifdef TUN_MODE
#include <fcntl.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#endif

#include "array_hashmap.h"

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

#define BLACKLIST_MAX_COUNT 128

#define GATEWAY_BITS_COUNT 5
#define OFFSET_BITS_COUNT (32 - GATEWAY_BITS_COUNT)
#define GATEWAY_MAX_COUNT (1 << GATEWAY_BITS_COUNT)

#ifndef _DOMAINS_TYPE
#define _DOMAINS_TYPE
typedef struct domains_gateway {
    unsigned int gateway : GATEWAY_BITS_COUNT;
    unsigned int offset : OFFSET_BITS_COUNT;
} domains_gateway_t;
#endif

extern FILE *log_fd;
extern FILE *stat_fd;

extern int32_t gateways_count;
extern char *gateway_domains_paths[GATEWAY_MAX_COUNT];

extern int32_t blacklist_count;
extern subnet_t blacklist[BLACKLIST_MAX_COUNT];

extern struct sockaddr_in listen_addr;

#ifdef TUN_MODE
extern uint32_t tun_ip;
extern uint32_t tun_prefix;
#endif

#ifdef PCAP_MODE
extern char sniffer_interface[IFNAMSIZ];
#endif

#ifdef PROXY_MODE
#define DNS_COUNT (gateways_count + 1)
#define DNS_MAX_COUNT (GATEWAY_MAX_COUNT + 1)

extern pthread_barrier_t threads_barrier;
extern struct sockaddr_in dns_addr[DNS_MAX_COUNT];
#endif

void errmsg(const char *format, ...);

#ifdef ROUTE_TABLE_MODE
void add_route(int32_t gateway_index, uint32_t dst);
#endif
