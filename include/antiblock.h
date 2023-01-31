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

#define PACKET_MAX_SIZE 1500
#define URL_MAX_SIZE 1500

#define ID_MAP_MAX_SIZE 1000
#define TTL_MAP_MAX_SIZE 5000
#define URLS_MAP_MAX_SIZE 500000
#define PACKETS_RING_BUFFER_MAX_SIZE 100

#define DNS_SOCKET_COUNT 10

#define POLL_SLEEP_TIME 1000
#define STAT_PRINT_TIME 10
#define TTL_CHECK_TIME 60
#define ID_CHECK_TIME 60
#define URLS_UPDATE_TIME 60 * 60 * 24
#define URLS_ERROR_UPDATE_TIME 30

#define REPEATER_CLIENT_PORT 5053
#define REPEATER_CLIENT_IP "0.0.0.0"

#define REPEATER_DNS_PORT 5054
#define REPEATER_DNS_IP "0.0.0.0"

#define DNS_PORT 5055
#define DNS_IP "127.0.0.1"

#define VPN_IP "192.168.6.37"
#define VPN_MASK "255.255.255.255"

#define FILES_FOLDER "/smb/"

#define FIRST_BIT 0x8000
#define MIL 1000000

extern pthread_barrier_t threads_barrier;
