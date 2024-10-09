#include "antiblock.h"

typedef struct id_map {
    uint32_t ip;
    uint16_t port;
} id_map_t;

extern memory_t que_url;
extern memory_t ans_url;
extern memory_t cname_url;

void init_net_data_threads(void);
