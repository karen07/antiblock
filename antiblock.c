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
int32_t is_domains_file_url;
int32_t is_domains_file_path;
int32_t is_route_ip;
int32_t is_dns_ip;
int32_t is_log_or_stat_path;

char domains_file_url[PATH_MAX];
char domains_file_path[PATH_MAX];
char log_or_stat_folder[PATH_MAX];

char route_ip[20];
char dns_ip[20];

int main(int argc, char* argv[])
{
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "-log")) {
            is_log_print = 1;
        }
        if (!strcmp(argv[i], "-stat")) {
            is_stat_print = 1;
        }
        if (!strcmp(argv[i], "-url")) {
            if (i != argc - 1) {
                if (strlen(argv[i + 1]) < PATH_MAX) {
                    is_domains_file_url = 1;
                    strcpy(domains_file_url, argv[i + 1]);
                }
            }
        }
        if (!strcmp(argv[i], "-file")) {
            if (i != argc - 1) {
                if (strlen(argv[i + 1]) < PATH_MAX) {
                    is_domains_file_path = 1;
                    strcpy(domains_file_path, argv[i + 1]);
                }
            }
        }
        if (!strcmp(argv[i], "-o")) {
            if (i != argc - 1) {
                if (strlen(argv[i + 1]) < PATH_MAX) {
                    is_log_or_stat_path = 1;
                    strcpy(log_or_stat_folder, argv[i + 1]);
                }
            }
        }
        if (!strcmp(argv[i], "-route_IP")) {
            if (i != argc - 1) {
                if (strlen(argv[i + 1]) < 20) {
                    is_route_ip = 1;
                    strcpy(route_ip, argv[i + 1]);
                }
            }
        }
        if (!strcmp(argv[i], "-DNS_IP")) {
            if (i != argc - 1) {
                if (strlen(argv[i + 1]) < 20) {
                    is_dns_ip = 1;
                    strcpy(dns_ip, argv[i + 1]);
                }
            }
        }
        if (!strcmp(argv[i], "-help")) {
            printf("-log         Show operations log\n"
                   "-stat        Show statistics data\n"
                   "-url         Domains file url\n"
                   "-file        Domains file path\n"
                   "-route_IP    Route IP\n"
                   "-o           Log or statistics output folder\n"
                   "-DNS_IP      DNS IP\n");
            exit(EXIT_FAILURE);
        }
    }

    if (!is_route_ip) {
        printf("Programm need route IP\n");
        exit(EXIT_FAILURE);
    }

    if (!(is_domains_file_url || is_domains_file_path)) {
        printf("Programm need domains file url or domains file path\n");
        exit(EXIT_FAILURE);
    }

    if (!is_dns_ip) {
        printf("Programm need DNS IP\n");
        exit(EXIT_FAILURE);
    }

    if (is_log_print || is_stat_print) {
        if (!is_log_or_stat_path) {
            printf("Programm need output folder for log or statistics\n");
            exit(EXIT_FAILURE);
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
