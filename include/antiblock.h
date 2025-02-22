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
#define TUN_MODE
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

#ifndef _STRUCT_DOMAINS_GATEWAY
#define _STRUCT_DOMAINS_GATEWAY
typedef struct domains_gateway {
    unsigned int offset : 26;
    unsigned int gateway : 6;
} domains_gateway_t;
#endif

extern pthread_barrier_t threads_barrier;

#ifdef TUN_MODE
extern uint32_t tun_ip;
extern uint32_t tun_prefix;
#endif

extern struct sockaddr_in listen_addr;

extern FILE *log_fd;

#define GATEWAY_MAX_COUNT 61
extern int32_t gateways_count;

extern char gateway_name[GATEWAY_MAX_COUNT][IFNAMSIZ];
extern char *gateway_domains_paths[GATEWAY_MAX_COUNT];

extern uint32_t gateway_domains_offset[GATEWAY_MAX_COUNT + 1];
extern int32_t gateway_domains_count[GATEWAY_MAX_COUNT];

extern struct sockaddr_in dns_addr[GATEWAY_MAX_COUNT + 1];

void errmsg(const char *format, ...);
#ifndef TUN_MODE
void add_route(int32_t gateway_index, uint32_t dst);
#endif
