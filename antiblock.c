#include "antiblock.h"
#include "DNS.h"
#include "dns_ans.h"
#include "net_data.h"
#include "route.h"
#include "stat.h"
#include "ttl_check.h"
#include "urls_read.h"

pthread_barrier_t threads_barrier;
int32_t is_log_print;
int32_t is_stat_print;

int main(int argc, char* argv[])
{
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "-log")) {
            is_log_print = 1;
        }
        if (!strcmp(argv[i], "-stat")) {
            is_stat_print = 1;
        }
    }

    if (is_stat_print) {
        if (pthread_barrier_init(&threads_barrier, NULL, 7)) {
            printf("Can't create threads_barrier\n");
            exit(EXIT_FAILURE);
        }
    } else {
        if (pthread_barrier_init(&threads_barrier, NULL, 6)) {
            printf("Can't create threads_barrier\n");
            exit(EXIT_FAILURE);
        }
    }

    init_stat_print_thread();

    init_route_socket();

    init_urls_read_thread();

    init_ttl_check_thread();

    init_dns_ans_check_thread();

    init_data_threads();

    pthread_barrier_wait(&threads_barrier);

    while (1) {
        sleep(1000);
    }

    return EXIT_SUCCESS;
}
