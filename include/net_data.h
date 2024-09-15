#include "antiblock.h"

typedef struct id_map {
    uint32_t ip;
    uint16_t port;
} __attribute__((packed)) id_map_t;

extern id_map_t *id_map;
extern int32_t repeater_DNS_socket;
extern int32_t repeater_client_socket;

void *DNS_data(void *arg);
void *client_data(void *arg);
void init_data_threads(void);
void send_packet(int packets_num);
