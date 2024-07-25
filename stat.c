#include "stat.h"

statistics_t stat;
FILE* log_fd;
FILE* stat_fd;

void* stat_print(__attribute__((unused)) void* arg)
{
    pthread_barrier_wait(&threads_barrier);

    printf("Thread stat print started\n");

    while (1) {
        ftruncate(fileno(stat_fd), 0);
        fseek(stat_fd, 0, SEEK_SET);

        time_t now = time(NULL);
        struct tm* tm_struct = localtime(&now);
        fprintf(stat_fd, "Statistics %d:%d:%d\n",
            tm_struct->tm_hour, tm_struct->tm_min, tm_struct->tm_sec);

        fprintf(stat_fd, "Recive from client: %d\n", stat.rec_from_client);
        fprintf(stat_fd, "Recive from dns: %d\n", stat.rec_from_dns);
        fprintf(stat_fd, "Recive difference: %d\n", stat.rec_from_client - stat.rec_from_dns);
        fprintf(stat_fd, "Now in route table: %d\n", stat.now_in_route_table);
        fprintf(stat_fd, "Now cname urls: %d\n", stat.now_cname_url_count);
        fprintf(stat_fd, "Route not block urls: %d\n", stat.route_not_block_ip_count);
        fprintf(stat_fd, "Request parsing error: %d\n", stat.request_parsing_error);
        fprintf(stat_fd, "Send to client error: %d\n", stat.send_to_client_error);
        fprintf(stat_fd, "Send to dns error: %d\n", stat.send_to_dns_error);
        fprintf(stat_fd, "Recive from client error: %d\n", stat.from_client_error);
        fprintf(stat_fd, "Recive from dns error: %d\n", stat.from_dns_error);
        fprintf(stat_fd, "Ring buffer overflow: %d\n", stat.packets_ring_buffer_error);
        fprintf(stat_fd, "TTL map overflow: %d\n", stat.ttl_map_error);
        fprintf(stat_fd, "Cname url map overflow: %d\n", stat.cname_url_map_error);

        fflush(stat_fd);

        sleep(STAT_PRINT_TIME);
    }

    return NULL;
}

void init_stat_print_thread(void)
{
    memset(&stat, 0, sizeof(stat));

    if (is_log_print) {
        char log_path[PATH_MAX];
        sprintf(log_path, "%s%s", log_or_stat_folder, "/log.txt");
        log_fd = fopen(log_path, "w");
        if (log_fd == NULL) {
            printf("Can't open log file\n");
            exit(EXIT_FAILURE);
        }
    }

    if (is_stat_print) {
        char stat_path[PATH_MAX];
        sprintf(stat_path, "%s%s", log_or_stat_folder, "/stat.txt");
        stat_fd = fopen(stat_path, "w");
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
}
