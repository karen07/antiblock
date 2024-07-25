#define PACKET_MAX_SIZE 1500
#define URL_MAX_SIZE 1500
#define IP4_STR_MAX_SIZE 20
#define DATE_STR_MAX_SIZE 200

#define FIRST_BIT 0x8000
#define FIRST_TWO_BITS 0xC0

#define ID_MAP_MAX_SIZE 65000
#define TTL_MAP_MAX_SIZE 50000
#define CNAME_URLS_MAP_MAX_SIZE 10000
#define LOC_TO_GLOBIP_MAP_MAX_SIZE 50000
#define NAT_MAP_MAX_SIZE 50000
#define PACKETS_RING_BUFFER_MAX_SIZE 1000

#define POLL_SLEEP_TIME 1000
#define STAT_PRINT_TIME 10
#define TTL_CHECK_TIME 60
#define ID_CHECK_TIME 60
#define URLS_UPDATE_TIME 60 * 60 * 24
#define URLS_ERROR_UPDATE_TIME 30
