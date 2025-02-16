#include <pthread.h>
#include <stdint.h>
#include <linux/limits.h>
#include <linux/if.h>
#include <stdio.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <errno.h>
#ifdef TUN_MODE
#include <linux/if_tun.h>
#endif
#include <limits.h>
#include <sys/time.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <signal.h>
#include <net/route.h>
#include <stdlib.h>
#include <string.h>
#include "array_hashmap.h"

extern pthread_barrier_t threads_barrier;

extern int32_t is_log_print;
extern int32_t is_stat_print;

extern char log_or_stat_folder[PATH_MAX - 100];

#ifdef TUN_MODE
extern char tun_name[IFNAMSIZ];

extern uint32_t tun_ip;
extern uint32_t tun_prefix;
#endif

extern uint32_t dns_ip;
extern uint16_t dns_port;

extern uint32_t listen_ip;
extern uint16_t listen_port;

extern FILE *log_fd;
extern FILE *stat_fd;

extern int32_t gateways_ip_count;
extern uint32_t gateways_ip[256];
extern char *domains_paths[256];
extern int32_t readed_bytes[256];

void errmsg(const char *format, ...);
void add_route(uint32_t gateway, uint32_t dst);

#ifndef _STRUCT_DOMAINS_AND_GATEWAY
#define _STRUCT_DOMAINS_AND_GATEWAY
typedef struct {
    int32_t domain_offset;
    char gateway_index;
} domains_and_gateway_t;
#endif

#ifndef _STRUCT_MEMORY_ANTIBLOCK
#define _STRUCT_MEMORY_ANTIBLOCK
typedef struct memory {
    char *data;
    size_t size;
    size_t max_size;
} memory_t;
#endif
