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

char route_ip[IP4_STR_MAX_SIZE];
char dns_ip[IP4_STR_MAX_SIZE];

int32_t dns_port;
int32_t listen_port;

void print_help()
{
    printf("Commands:\n"
           "-log                          Show operations log\n"
           "-stat                         Show statistics data\n"
           "-url https://example.com      Domains file url\n"
           "-file /example                Domains file path\n"
           "-route_IP 0.0.0.0             Route IP\n"
           "-output /example              Log or statistics output folder\n"
           "-DNS_IP 0.0.0.0               DNS IP\n"
           "-DNS_port 00                  DNS port\n"
           "-listen_port 0000             Listen port\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char* argv[])
{
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-log")) {
            is_log_print = 1;
            continue;
        }
        if (!strcmp(argv[i], "-stat")) {
            is_stat_print = 1;
            continue;
        }
        if (!strcmp(argv[i], "-url")) {
            if (i != argc - 1) {
                if (strlen(argv[i + 1]) < PATH_MAX) {
                    is_domains_file_url = 1;
                    strcpy(domains_file_url, argv[i + 1]);
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-file")) {
            if (i != argc - 1) {
                if (strlen(argv[i + 1]) < PATH_MAX) {
                    is_domains_file_path = 1;
                    strcpy(domains_file_path, argv[i + 1]);
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-output")) {
            if (i != argc - 1) {
                if (strlen(argv[i + 1]) < PATH_MAX) {
                    is_log_or_stat_path = 1;
                    strcpy(log_or_stat_folder, argv[i + 1]);
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-route_IP")) {
            if (i != argc - 1) {
                if (strlen(argv[i + 1]) < IP4_STR_MAX_SIZE) {
                    is_route_ip = 1;
                    strcpy(route_ip, argv[i + 1]);
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-DNS_IP")) {
            if (i != argc - 1) {
                if (strlen(argv[i + 1]) < IP4_STR_MAX_SIZE) {
                    is_dns_ip = 1;
                    strcpy(dns_ip, argv[i + 1]);
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-DNS_port")) {
            if (i != argc - 1) {
                sscanf(argv[i + 1], "%d", &dns_port);
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-listen_port")) {
            if (i != argc - 1) {
                sscanf(argv[i + 1], "%d", &listen_port);
                i++;
            }
            continue;
        }
        printf("Unknown command %s\n", argv[i]);
        print_help();
    }

    if (!is_route_ip) {
        printf("Programm need route IP\n");
        print_help();
    }

    if (!(is_domains_file_url || is_domains_file_path)) {
        printf("Programm need domains file url or domains file path\n");
        print_help();
    }

    if (!is_dns_ip) {
        printf("Programm need DNS IP\n");
        print_help();
    }

    if (!listen_port) {
        printf("Programm need listen port\n");
        print_help();
    }

    if (listen_port > USHRT_MAX) {
        printf("Programm need listen port under 65535\n");
        print_help();
    }

    if (!dns_port) {
        printf("Programm need dns port\n");
        print_help();
    }

    if (dns_port > USHRT_MAX) {
        printf("Programm need dns port under 65535\n");
        print_help();
    }

    if (is_log_print || is_stat_print) {
        if (!is_log_or_stat_path) {
            printf("Programm need output folder for log or statistics\n");
            print_help();
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
