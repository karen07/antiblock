#include "antiblock.h"
#include "DNS.h"
#include "dns_ans.h"
#include "net_data.h"
#include "route.h"
#include "stat.h"
#include "ttl_check.h"
#include "tun.h"
#include "urls_read.h"

pthread_barrier_t threads_barrier;

int32_t is_log_print;
int32_t is_stat_print;

int32_t is_domains_file_url;
char domains_file_url[PATH_MAX];

int32_t is_domains_file_path;
char domains_file_path[PATH_MAX - 100];

int32_t is_log_or_stat_folder;
char log_or_stat_folder[PATH_MAX - 100];

int32_t is_tun_name;
char tun_name[IFNAMSIZ];

uint32_t route_ip;

uint32_t tun_ip;
uint32_t tun_prefix;

uint32_t dns_ip;
uint16_t dns_port;

uint32_t listen_ip;
uint16_t listen_port;

void print_help()
{
    printf("Commands:\n"
           "-log                          Show operations log\n"
           "-stat                         Show statistics data\n"
           "-url https://example.com      Domains file url\n"
           "-file /example.txt            Domains file path\n"
           "-route_IP 0.0.0.0             Route IP\n"
           "-output /example/             Log or statistics output folder\n"
           "-DNS_IP 0.0.0.0               DNS IP\n"
           "-DNS_port 00                  DNS port\n"
           "-listen_IP 0.0.0.0            Listen IP\n"
           "-listen_port 0000             Listen port\n"
           "-TUN_net 0.0.0.0/0            TUN net\n"
           "-TUN_name example             TUN name\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char* argv[])
{
    printf("\nAntiblock started\n");

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-log")) {
            printf("Log enabled\n");
            is_log_print = 1;
            continue;
        }
        if (!strcmp(argv[i], "-stat")) {
            printf("Stat enabled\n");
            is_stat_print = 1;
            continue;
        }
        if (!strcmp(argv[i], "-url")) {
            if (i != argc - 1) {
                printf("Get urls from url %s\n", argv[i + 1]);
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
                printf("Get urls from file %s\n", argv[i + 1]);
                if (strlen(argv[i + 1]) < PATH_MAX - 100) {
                    is_domains_file_path = 1;
                    strcpy(domains_file_path, argv[i + 1]);
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-output")) {
            if (i != argc - 1) {
                printf("Output log or stat to %s\n", argv[i + 1]);
                if (strlen(argv[i + 1]) < PATH_MAX - 100) {
                    is_log_or_stat_folder = 1;
                    strcpy(log_or_stat_folder, argv[i + 1]);
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-route_IP")) {
            if (i != argc - 1) {
                printf("Route IP %s\n", argv[i + 1]);
                if (strlen(argv[i + 1]) < INET_ADDRSTRLEN) {
                    route_ip = inet_addr(argv[i + 1]);
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-DNS_IP")) {
            if (i != argc - 1) {
                printf("DNS IP %s\n", argv[i + 1]);
                if (strlen(argv[i + 1]) < INET_ADDRSTRLEN) {
                    dns_ip = inet_addr(argv[i + 1]);
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-DNS_port")) {
            if (i != argc - 1) {
                printf("DNS port %s\n", argv[i + 1]);
                sscanf(argv[i + 1], "%hu", &dns_port);
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-listen_IP")) {
            if (i != argc - 1) {
                printf("Listen IP %s\n", argv[i + 1]);
                if (strlen(argv[i + 1]) < INET_ADDRSTRLEN) {
                    listen_ip = inet_addr(argv[i + 1]);
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-listen_port")) {
            if (i != argc - 1) {
                printf("Listen port %s\n", argv[i + 1]);
                sscanf(argv[i + 1], "%hu", &listen_port);
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-TUN_net")) {
            if (i != argc - 1) {
                printf("TUN net %s\n", argv[i + 1]);
                char* slash_ptr = strchr(argv[i + 1], '/');
                if (slash_ptr) {
                    sscanf(slash_ptr + 1, "%u", &tun_prefix);
                    *slash_ptr = 0;
                    if (strlen(argv[i + 1]) < INET_ADDRSTRLEN) {
                        tun_ip = inet_addr(argv[i + 1]);
                    }
                    *slash_ptr = '/';
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-TUN_name")) {
            if (i != argc - 1) {
                printf("TUN name %s\n", argv[i + 1]);
                is_tun_name = 1;
                strcpy(tun_name, argv[i + 1]);
                i++;
            }
            continue;
        }
        printf("Unknown command %s\n", argv[i]);
        print_help();
    }

    if ((route_ip == 0) == (tun_ip == 0)) {
        printf("Programm need route IP or TUN net\n");
        print_help();
    }

    // Check TUN_name, tun_prefix

    if (!(is_domains_file_url || is_domains_file_path)) {
        printf("Programm need domains file url or domains file path\n");
        print_help();
    }

    if (dns_ip == 0) {
        printf("Programm need DNS IP\n");
        print_help();
    }

    if (dns_port == 0) {
        printf("Programm need DNS port\n");
        print_help();
    }

    if (dns_port > USHRT_MAX) {
        printf("Programm need DNS port under 65535\n");
        print_help();
    }

    if (listen_ip == 0) {
        printf("Programm need listen IP\n");
        print_help();
    }

    if (listen_port == 0) {
        printf("Programm need listen port\n");
        print_help();
    }

    if (listen_port > USHRT_MAX) {
        printf("Programm need listen port under 65535\n");
        print_help();
    }

    if (is_log_print || is_stat_print) {
        if (!is_log_or_stat_folder) {
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

    printf("\n");

    init_stat_print_thread();

    if (route_ip != 0) {
        init_route_socket();
    }

    if (tun_ip != 0) {
        init_tun_thread();
    }

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
