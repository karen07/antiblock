#include "antiblock.h"

typedef struct statistics {
    int32_t processed_count;
    int32_t request_parsing_error;
    int32_t in_route_table[GATEWAY_MAX_COUNT];

#ifdef TUN_MODE
    int32_t nat_sended_to_client_error;
    double nat_sended_to_client_size;
    int32_t nat_sended_to_client;

    int32_t nat_sended_to_dev_error;
    double nat_sended_to_dev_size;
    int32_t nat_sended_to_dev;

    int32_t nat_records;
#endif

    time_t stat_start;
} statistics_t;

extern statistics_t statistics_data;

void stat_print(FILE *stat_fd);
