#include "antiblock.h"

typedef struct statistics {
    volatile int32_t processed_count;
    volatile int32_t request_parsing_error;
    volatile int32_t in_route_table[GATEWAY_MAX_COUNT];
    time_t stat_start;
} statistics_t;

extern statistics_t statistics_data;

void stat_print(FILE *stat_fd);
