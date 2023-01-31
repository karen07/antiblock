#include "antiblock.h"
#include "hashmap/array_hashmap.h"

typedef struct ttl_map {
    time_t end_time;
    uint32_t ip;
} ttl_map_t;

extern const array_hashmap_t* ttl_map_struct;
extern time_t now_ttl_check;

int32_t ttl_decide(const void* void_elem);
int32_t ttl_on_collision(const void* void_elem1, const void* void_elem2);
uint32_t ttl_hash(const void* void_elem);
int32_t ttl_cmp(const void* void_elem1, const void* void_elem2);
void* ttl_check(void* arg);
void init_ttl_check_thread(void);
