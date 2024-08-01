#include "antiblock.h"
#include "array_hashmap.h"

typedef struct urls_map {
    int32_t url_pos;
    int32_t next_pos;
} urls_map_t;

extern char *urls;
extern const array_hashmap_t *urls_map_struct;

uint32_t add_url_hash(const void *void_elem);
int32_t add_url_cmp(const void *void_elem1, const void *void_elem2);
uint32_t find_url_hash(const void *void_elem);
int32_t find_url_cmp(const void *void_elem1, const void *void_elem2);
void *urls_read(void *arg);
void init_urls_read_thread(void);
