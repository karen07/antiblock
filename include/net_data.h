#include "antiblock.h"

typedef struct id_map {
    uint64_t send_time;
    uint32_t ip;
    uint32_t url_hash;
    uint16_t port;
    uint16_t client_id;
} __attribute__((packed)) id_map_t;

extern id_map_t* id_map;
extern int32_t repeater_DNS_socket[DNS_SOCKET_COUNT];
extern int32_t repeater_client_socket;

uint32_t djb33_hash_len(const char* s, size_t len);
void* DNS_data(void* arg);
void* client_data(void* arg);
void init_data_threads(void);
