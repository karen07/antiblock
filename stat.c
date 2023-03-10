#include "stat.h"

statistics_t stat;
FILE* log_fd;
FILE* stat_fd;

void* stat_print(__attribute__((unused)) void* arg)
{
    pthread_barrier_wait(&threads_barrier);

    uint32_t count = 0;

    while (1) {
        if (count++ % 3 == 0) {
            fseek(stat_fd, 0, SEEK_SET);
        }

        time_t now = time(NULL);
        struct tm* tm_struct = localtime(&now);
        fprintf(stat_fd, "Statistics %d:%d:%d\n",
            tm_struct->tm_hour, tm_struct->tm_min, tm_struct->tm_sec);

        fprintf(stat_fd, "Recive from client: %d\n", stat.rec_from_client);
        fprintf(stat_fd, "Recive from dns: %d\n", stat.rec_from_dns);
        fprintf(stat_fd, "Recive difference: %d\n", stat.rec_from_client - stat.rec_from_dns);
        fprintf(stat_fd, "Now in route table: %d\n", stat.now_in_route_table);
        fprintf(stat_fd, "Route not block urls: %d\n", stat.route_not_block_ip_count);
        if (stat.ping_count) {
            fprintf(stat_fd, "Min ping: %lf\n", stat.ping_min);
            fprintf(stat_fd, "Avarage ping: %lf\n", stat.ping_sum / stat.ping_count);
            fprintf(stat_fd, "Max ping: %lf\n", stat.ping_max);
        } else {
            fprintf(stat_fd, "Min ping: %lf\n", -1.0);
            fprintf(stat_fd, "Avarage ping: %lf\n", -1.0);
            fprintf(stat_fd, "Max ping: %lf\n", -1.0);
        }
        fprintf(stat_fd, "Send to client error: %d\n", stat.send_to_client_error);
        fprintf(stat_fd, "Send to dns error: %d\n", stat.send_to_dns_error);
        fprintf(stat_fd, "Recive from client error: %d\n", stat.from_client_error);
        fprintf(stat_fd, "Recive from dns error: %d\n", stat.from_dns_error);

        fprintf(stat_fd, "Ring buffer overflow: %d\n", stat.packets_ring_buffer_error);
        fprintf(stat_fd, "TTL map overflow: %d\n", stat.ttl_map_error);
        fprintf(stat_fd, "\n");

        fflush(stat_fd);
        fflush(log_fd);

        stat.ping_min = MIL;
        stat.ping_max = 0;
        stat.ping_sum = 0;
        stat.ping_count = 0;

        sleep(STAT_PRINT_TIME);
    }

    return NULL;
}

void init_stat_print_thread(void)
{
    memset(&stat, 0, sizeof(stat));
    stat.ping_min = MIL;

    log_fd = fopen(FILES_FOLDER "log.txt", "w");
    if (log_fd == NULL) {
        printf("Can't open log file\n");
        exit(EXIT_FAILURE);
    }

    stat_fd = fopen(FILES_FOLDER "stat.txt", "w");
    if (stat_fd == NULL) {
        printf("Can't open stat file\n");
        exit(EXIT_FAILURE);
    }

    pthread_t stat_print_thread;
    if (pthread_create(&stat_print_thread, NULL, stat_print, NULL)) {
        printf("Can't create stat_print_thread\n");
        exit(EXIT_FAILURE);
    }

    if (pthread_detach(stat_print_thread)) {
        printf("Can't detach stat_print_thread\n");
        exit(EXIT_FAILURE);
    }
}
