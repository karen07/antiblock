#include "config.h"
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <net/route.h>
#include <poll.h>
#include <pthread.h>
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
extern char domains_file_path[PATH_MAX];
extern char log_or_stat_folder[PATH_MAX];

extern char route_ip[IP4_STR_MAX_SIZE];
extern char dns_ip[IP4_STR_MAX_SIZE];

extern int32_t dns_port;
extern int32_t listen_port;
