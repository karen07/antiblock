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

extern int32_t is_domains_file_url;
extern char domains_file_url[PATH_MAX];

extern int32_t is_domains_file_path;
extern char domains_file_path[PATH_MAX - 100];

extern int32_t is_log_or_stat_folder;
extern char log_or_stat_folder[PATH_MAX - 100];

#ifdef TUN_MODE
extern int32_t is_tun_name;
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

extern int32_t route_socket;
extern struct rtentry route;

void errmsg(const char *format, ...);
