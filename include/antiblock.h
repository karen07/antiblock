#include "config.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <linux/limits.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/route.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

extern pthread_barrier_t threads_barrier;

extern int32_t is_log_print;
extern int32_t is_stat_print;
extern int32_t is_domains_file_url;
extern int32_t is_domains_file_path;
extern int32_t is_route_ip;
extern int32_t is_log_or_stat_path;

extern char domains_file_url[PATH_MAX];
extern char domains_file_path[PATH_MAX - 100];
extern char log_or_stat_folder[PATH_MAX - 100];

extern char route_ip[IP4_STR_MAX_SIZE];
extern char dns_ip[IP4_STR_MAX_SIZE];
extern char tun_ip[IP4_STR_MAX_SIZE];

extern char tun_name[IFNAMSIZ];

extern int32_t dns_port;
extern int32_t listen_port;
extern int32_t tun_prefix;
