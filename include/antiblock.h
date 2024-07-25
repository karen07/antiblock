#include "config.h"
#include "const.h"
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
extern char domains_file_url[PATH_MAX];

extern int32_t is_domains_file_path;
extern char domains_file_path[PATH_MAX - 100];

extern int32_t is_log_or_stat_folder;
extern char log_or_stat_folder[PATH_MAX - 100];

extern int32_t is_tun_name;
extern char tun_name[IFNAMSIZ];

extern uint32_t route_ip;

extern uint32_t tun_ip;
extern uint32_t tun_prefix;

extern uint32_t dns_ip;
extern uint16_t dns_port;

extern uint32_t listen_ip;
extern uint16_t listen_port;
