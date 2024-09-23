#include "antiblock.h"

typedef struct id_map {
    uint32_t ip;
    uint16_t port;
} __attribute__((packed)) id_map_t;

extern id_map_t *id_map;
extern int32_t repeater_DNS_socket;
extern int32_t repeater_client_socket;

void init_net_data_threads(void);
