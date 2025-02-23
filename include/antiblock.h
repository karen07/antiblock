#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <net/route.h>
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

//#define MULTIPLE_DNS

//#define PCAP_MODE
#ifdef PCAP_MODE
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <pcap.h>
#endif

//#define TUN_MODE
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

#define GATEWAY_BITS_COUNT 5
#define OFFSET_BITS_COUNT (32 - GATEWAY_BITS_COUNT)
#define GATEWAY_MAX_COUNT (1 << GATEWAY_BITS_COUNT)

#ifndef _DOMAINS_TYPE
#define _DOMAINS_TYPE
typedef struct domains_gateway {
    unsigned int offset : OFFSET_BITS_COUNT;
    unsigned int gateway : GATEWAY_BITS_COUNT;
} domains_gateway_t;
#endif

extern pthread_barrier_t threads_barrier;

extern FILE *log_fd;
extern FILE *stat_fd;

extern int32_t gateways_count;
extern char *gateway_domains_paths[GATEWAY_MAX_COUNT];

#ifdef TUN_MODE
extern uint32_t tun_ip;
extern uint32_t tun_prefix;
#endif

#ifndef PCAP_MODE
#define DNS_COUNT (gateways_count + 1)
#define DNS_MAX_COUNT (GATEWAY_MAX_COUNT + 1)

extern struct sockaddr_in listen_addr;
extern struct sockaddr_in dns_addr[DNS_MAX_COUNT];
#endif

void errmsg(const char *format, ...);

#ifndef TUN_MODE
void add_route(int32_t gateway_index, uint32_t dst);
#endif

#ifdef PCAP_MODE
#ifdef MULTIPLE_DNS
#error "You can't use PCAP_MODE and MULTIPLE_DNS"
#endif
#ifdef TUN_MODE
#error "You can't use PCAP_MODE and TUN_MODE"
#endif
#endif
