#include "hash.h"

uint32_t djb33_hash_len(const char* s, size_t len)
{
    uint32_t h = 5381;
    while (*s && len--) {
        h += (h << 5);
        h ^= *s++;
    }
    return h;
}
