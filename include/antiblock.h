#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <net/route.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if.h>
//#define TUN_MODE
#ifdef TUN_MODE
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <fcntl.h>
#endif
#include "array_hashmap.h"

#ifndef _STRUCT_MEMORY_ANTIBLOCK
#define _STRUCT_MEMORY_ANTIBLOCK
typedef struct memory {
    char *data;
    size_t size;
    size_t max_size;
} memory_t;
#endif

#define GATEWAY_BITS_COUNT 5
#define OFFSET_BITS_COUNT (32 - GATEWAY_BITS_COUNT)

#ifndef _STRUCT_DOMAINS_GATEWAY
#define _STRUCT_DOMAINS_GATEWAY
typedef struct domains_gateway {
    unsigned int offset : OFFSET_BITS_COUNT;
    unsigned int gateway : GATEWAY_BITS_COUNT;
} domains_gateway_t;
#endif

extern pthread_barrier_t threads_barrier;

#ifdef TUN_MODE
extern uint32_t tun_ip;
extern uint32_t tun_prefix;
#endif

extern struct sockaddr_in listen_addr;

extern FILE *log_fd;

#define GATEWAY_MAX_COUNT (1 << GATEWAY_BITS_COUNT)

#define DNS_COUNT (gateways_count + 1)
#define DNS_MAX_COUNT (GATEWAY_MAX_COUNT + 1)

extern int32_t gateways_count;
extern char *gateway_domains_paths[GATEWAY_MAX_COUNT];
extern struct sockaddr_in dns_addr[DNS_MAX_COUNT];

void errmsg(const char *format, ...);
#ifndef TUN_MODE
void add_route(int32_t gateway_index, uint32_t dst);
#endif
