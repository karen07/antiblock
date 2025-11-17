#include "antiblock.h"

#ifdef TUN_MODE

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

typedef struct subnet_range {
    uint32_t network_ip;
    uint32_t network_prefix;
    uint32_t start_ip;
    uint32_t end_ip;
    int32_t subnet_size;
} subnet_range_t;

extern array_hashmap_t ip_ip_map;

extern subnet_range_t NAT;

void init_tun_thread(void);
void subnet_init(subnet_range_t *subnet);

#endif
