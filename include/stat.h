#include "antiblock.h"

typedef struct statistics {
    int32_t rec_from_client;
    int32_t rec_from_dns;

    int32_t send_to_client_error;
    int32_t send_to_dns_error;

    int32_t request_parsing_error;

    int32_t nat_sended_to_client_error;
    double nat_sended_to_client_size;
    int32_t nat_sended_to_client;

    int32_t nat_sended_to_dev_error;
    double nat_sended_to_dev_size;
    int32_t nat_sended_to_dev;

    int32_t nat_records;
} statistics_t;

extern statistics_t stat;
extern FILE *log_fd;
extern FILE *stat_fd;

void stat_print(void);
