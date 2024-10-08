#include "antiblock.h"

typedef struct tun_header {
    uint16_t flags;
    uint16_t proto;
} __attribute__((packed)) tun_header_t;

typedef struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint16_t protocol;
    uint16_t length;
} __attribute__((packed)) pseudo_header_t;

typedef struct ip_ip_map {
    uint32_t ip_local;
    uint32_t ip_global;
} ip_ip_map_t;

typedef struct nat_map_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    char proto;
} __attribute__((packed)) nat_map_key_t;

typedef struct nat_map_value {
    uint32_t old_src_ip;
    uint16_t old_src_port;
} nat_map_value_t;

typedef struct nat_map {
    nat_map_key_t key;
    nat_map_value_t value;
} nat_map_t;

extern const array_hashmap_t *ip_ip_map_struct;

extern uint32_t NAT_subnet_start;
extern uint32_t NAT_subnet_end;

void init_tun_thread(void);
int32_t ip_ip_on_collision(const void *void_elem1, const void *void_elem2);
