#include "antiblock.h"
#include "array_hashmap.h"

// ip route add default via 10.8.0.5 dev VPN table 2
// curl --resolve 2ip.ru:80:10.7.1.2 http://2ip.ru

typedef struct tun_header {
    uint16_t flags;
    uint16_t proto;
} __attribute__((packed)) tun_header_t;

typedef struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint16_t protocol;
    uint16_t tcp_length;
} __attribute__((packed)) pseudo_header_t;

typedef struct ip_ip_map {
    uint32_t ip_local;
    uint32_t ip_global;
} ip_ip_map_t;

extern const array_hashmap_t* ip_ip_map_struct;
extern uint32_t start_subnet_ip;

int tun_alloc(char* dev, int flags);
unsigned short checksum(const char* buf, unsigned size);
int32_t ip_ip_cmp(const void* void_elem1, const void* void_elem2);
void* tun(void* arg);
void init_tun_thread(void);