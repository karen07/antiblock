#include "antiblock.h"
#include "config.h"
#include "const.h"
#include "dns_ans.h"
#include "hash.h"
#include "net_data.h"
#include "stat.h"
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

uint32_t tun_ip;
uint32_t tun_prefix;

uint32_t dns_ip;
uint16_t dns_port;

uint32_t listen_ip;
uint16_t listen_port;

FILE *log_fd;
FILE *stat_fd;

static void print_help(void)
{
    printf("Commands:\n"
           "-log                          Show operations log\n"
           "-stat                         Show statistics data\n"
           "-url https://example.com      Domains file url\n"
           "-file /example.txt            Domains file path\n"
           "-output /example/             Log or statistics output folder\n"
           "-DNS_IP 0.0.0.0               DNS IP\n"
           "-DNS_port 00                  DNS port\n"
           "-listen_IP 0.0.0.0            Listen IP\n"
           "-listen_port 0000             Listen port\n"
           "-TUN_net 0.0.0.0/0            TUN net\n"
           "-TUN_name example             TUN name\n");
    exit(EXIT_FAILURE);
}

static void main_catch_function(__attribute__((unused)) int signo)
{
    printf("SIGSEGV catched main\n");
    fflush(stdout);
    fflush(stat_fd);
    fflush(log_fd);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    printf("\nAntiblock started\n");

    if (signal(SIGSEGV, main_catch_function) == SIG_ERR) {
        printf("Can't set signal handler main\n");
        exit(EXIT_FAILURE);
    }

    for (int32_t i = 1; i < argc; i++) {
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
                if (strlen(argv[i + 1]) < PATH_MAX) {
                    printf("Get urls from url %s\n", argv[i + 1]);
                    is_domains_file_url = 1;
                    strcpy(domains_file_url, argv[i + 1]);
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-file")) {
            if (i != argc - 1) {
                if (strlen(argv[i + 1]) < PATH_MAX - 100) {
                    printf("Get urls from file %s\n", argv[i + 1]);
                    is_domains_file_path = 1;
                    strcpy(domains_file_path, argv[i + 1]);
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-output")) {
            if (i != argc - 1) {
                if (strlen(argv[i + 1]) < PATH_MAX - 100) {
                    printf("Output log or stat to %s\n", argv[i + 1]);
                    is_log_or_stat_folder = 1;
                    strcpy(log_or_stat_folder, argv[i + 1]);
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-DNS_IP")) {
            if (i != argc - 1) {
                if (strlen(argv[i + 1]) < INET_ADDRSTRLEN) {
                    dns_ip = inet_addr(argv[i + 1]);
                    struct in_addr dns_ip_in_addr;
                    dns_ip_in_addr.s_addr = dns_ip;
                    printf("DNS IP %s\n", inet_ntoa(dns_ip_in_addr));
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-DNS_port")) {
            if (i != argc - 1) {
                sscanf(argv[i + 1], "%hu", &dns_port);
                printf("DNS port %d\n", dns_port);
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-listen_IP")) {
            if (i != argc - 1) {
                if (strlen(argv[i + 1]) < INET_ADDRSTRLEN) {
                    listen_ip = inet_addr(argv[i + 1]);
                    struct in_addr listen_ip_in_addr;
                    listen_ip_in_addr.s_addr = listen_ip;
                    printf("Listen IP %s\n", inet_ntoa(listen_ip_in_addr));
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-listen_port")) {
            if (i != argc - 1) {
                sscanf(argv[i + 1], "%hu", &listen_port);
                printf("Listen port %d\n", listen_port);
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-TUN_net")) {
            if (i != argc - 1) {
                char *slash_ptr = strchr(argv[i + 1], '/');
                if (slash_ptr) {
                    sscanf(slash_ptr + 1, "%u", &tun_prefix);
                    *slash_ptr = 0;
                    if (strlen(argv[i + 1]) < INET_ADDRSTRLEN) {
                        tun_ip = inet_addr(argv[i + 1]);
                        struct in_addr tun_ip_in_addr;
                        tun_ip_in_addr.s_addr = tun_ip;
                        printf("TUN net %s/%d\n", inet_ntoa(tun_ip_in_addr), tun_prefix);
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

    printf("\n");

    if (!is_tun_name) {
        printf("Programm need TUN name\n");
        print_help();
    }

    if (!tun_ip || !tun_prefix) {
        printf("Programm need TUN net\n");
        print_help();
    }

    if (!(is_domains_file_url || is_domains_file_path)) {
        printf("Programm need domains file url or domains file path\n");
        print_help();
    }

    if (!dns_ip) {
        printf("Programm need DNS IP\n");
        print_help();
    }

    if (!dns_port) {
        printf("Programm need DNS port\n");
        print_help();
    }

    if (!listen_ip) {
        printf("Programm need listen IP\n");
        print_help();
    }

    if (!listen_port) {
        printf("Programm need listen port\n");
        print_help();
    }

    if (is_log_print || is_stat_print) {
        if (!is_log_or_stat_folder) {
            printf("Programm need output folder for log or statistics\n");
            print_help();
        }
    }

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
        memset(&stat, 0, sizeof(stat));

        char stat_path[PATH_MAX];
        sprintf(stat_path, "%s%s", log_or_stat_folder, "/stat.txt");
        stat_fd = fopen(stat_path, "w");
        if (stat_fd == NULL) {
            printf("Can't open stat file\n");
            exit(EXIT_FAILURE);
        }
    }

    int32_t threads_barrier_count = 4;
    if (pthread_barrier_init(&threads_barrier, NULL, threads_barrier_count)) {
        printf("Can't create threads_barrier\n");
        exit(EXIT_FAILURE);
    }

    init_tun_thread();

    init_net_data_threads();

    pthread_barrier_wait(&threads_barrier);

    int32_t sleep_circles = 0;
    int64_t urls_web_file_size = 0;

    while (true) {
        if (sleep_circles == 0) {
            urls_web_file_size = urls_read();
        }

        sleep_circles++;
        if (urls_web_file_size > 0 || !is_domains_file_url) {
            sleep_circles %= URLS_UPDATE_TIME / STAT_PRINT_TIME;
        } else {
            sleep_circles %= URLS_ERROR_UPDATE_TIME / STAT_PRINT_TIME;
        }

        if (is_stat_print) {
            stat_print();
        }

        if (is_log_print) {
            fflush(log_fd);
        }

        fflush(stdout);

        sleep(STAT_PRINT_TIME);
    }

    return EXIT_SUCCESS;
}
