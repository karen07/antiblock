#include "antiblock.h"

#ifndef _STRUCT_MEMORY_ANTIBLOCK
#define _STRUCT_MEMORY_ANTIBLOCK
typedef struct memory {
    char *data;
    size_t size;
    size_t max_size;
} memory_t;
#endif

extern memory_t urls;
extern array_hashmap_t urls_map_struct;

int64_t urls_read(void);
