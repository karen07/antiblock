#include "antiblock.h"

typedef struct urls_map {
    int32_t url_pos;
    int32_t next_pos;
} urls_map_t;

struct memory {
    char *data;
    size_t size;
};

extern struct memory urls;
extern const array_hashmap_t *urls_map_struct;

int64_t urls_read(void);
