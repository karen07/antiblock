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

uint32_t gateway_ip;
uint32_t gateway_mask;

int32_t route_socket;
struct rtentry route;

static void init_route_socket(void)
{
    route_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (route_socket < 0) {
        printf("Can't create route_socket :%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    gateway_mask = inet_addr("255.255.255.255");

    memset(&route, 0, sizeof(route));

    struct sockaddr_in *route_addr;
    route_addr = (struct sockaddr_in *)&route.rt_gateway;
    route_addr->sin_family = AF_INET;
    route_addr->sin_addr.s_addr = gateway_ip;

    route_addr = (struct sockaddr_in *)&route.rt_genmask;
    route_addr->sin_family = AF_INET;
    route_addr->sin_addr.s_addr = gateway_mask;

    route.rt_flags = RTF_UP | RTF_GATEWAY;
}

static void clean_route_table(void)
{
    FILE *route_fd = fopen("/proc/net/route", "r");
    if (route_fd == NULL) {
        printf("Can't open /proc/net/route\n");
        exit(EXIT_FAILURE);
    }

    fseek(route_fd, 128, SEEK_SET);

    char iface[128];
    uint32_t dest_ip;
    uint32_t gate_ip;
    uint32_t flags;
    uint32_t refcnt;
    uint32_t use;
    uint32_t metric;
    uint32_t mask;
    uint32_t mtu;
    uint32_t window;
    uint32_t irtt;

    while (fscanf(route_fd, "%s %x %x %x %x %x %x %x %x %x %x", iface, &dest_ip, &gate_ip, &flags,
                  &refcnt, &use, &metric, &mask, &mtu, &window, &irtt) != EOF) {
        if ((gate_ip == gateway_ip) && (mask == gateway_mask)) {
            struct in_addr rec_ip;
            rec_ip.s_addr = dest_ip;

            struct sockaddr_in *route_addr = (struct sockaddr_in *)&route.rt_dst;
            route_addr->sin_family = AF_INET;
            route_addr->sin_addr.s_addr = rec_ip.s_addr;

            if (ioctl(route_socket, SIOCDELRT, &route) < 0) {
                printf("Ioctl can't delete %s from route table :%s\n", inet_ntoa(rec_ip),
                       strerror(errno));
            }
        }
    }

    fclose(route_fd);
}

static void print_help(void)
{
    printf("Commands:\n"
           "-log                          Show operations log\n"
           "-stat                         Show statistics data\n"
           "-url https://example.com      Domains file url\n"
           "-file /example.txt            Domains file path\n"
           "-output /example/             Log or statistics output folder\n"
           "-DNS 0.0.0.0:00               DNS address\n"
           "-listen 0.0.0.0:00            Listen address\n"
           "-gateway 0.0.0.0              Gateway IP\n"
           "-TUN_net 0.0.0.0/0            TUN net\n"
           "-TUN_name example             TUN name\n");
    exit(EXIT_FAILURE);
}

static void main_catch_function(int32_t signo)
{
    if (signo == SIGSEGV) {
        printf("SIGSEGV catched main\n");
    } else if (signo == SIGINT) {
        printf("SIGINT catched main\n");
    }
    fflush(stdout);
    if (stat_fd) {
        fflush(stat_fd);
    }
    if (log_fd) {
        fflush(log_fd);
    }
    exit(EXIT_FAILURE);
}

int32_t main(int32_t argc, char *argv[])
{
    printf("\nAntiblock started " ANTIBLOCK_VERSION "\n");

    if (signal(SIGINT, main_catch_function) == SIG_ERR) {
        printf("Can't set signal handler main\n");
        exit(EXIT_FAILURE);
    }

    if (signal(SIGSEGV, main_catch_function) == SIG_ERR) {
        printf("Can't set signal handler main\n");
        exit(EXIT_FAILURE);
    }

    for (int32_t i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-log")) {
            is_log_print = 1;
            printf("Log enabled\n");
            continue;
        }
        if (!strcmp(argv[i], "-stat")) {
            is_stat_print = 1;
            printf("Stat enabled\n");
            continue;
        }
        if (!strcmp(argv[i], "-url")) {
            if (i != argc - 1) {
                if (strlen(argv[i + 1]) < PATH_MAX) {
                    is_domains_file_url = 1;
                    strcpy(domains_file_url, argv[i + 1]);
                    printf("Get urls from url %s\n", domains_file_url);
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-file")) {
            if (i != argc - 1) {
                if (strlen(argv[i + 1]) < PATH_MAX - 100) {
                    is_domains_file_path = 1;
                    strcpy(domains_file_path, argv[i + 1]);
                    printf("Get urls from file %s\n", domains_file_path);
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-output")) {
            if (i != argc - 1) {
                if (strlen(argv[i + 1]) < PATH_MAX - 100) {
                    is_log_or_stat_folder = 1;
                    strcpy(log_or_stat_folder, argv[i + 1]);
                    printf("Output log or stat to %s\n", log_or_stat_folder);
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-DNS")) {
            if (i != argc - 1) {
                char *colon_ptr = strchr(argv[i + 1], ':');
                if (colon_ptr) {
                    sscanf(colon_ptr + 1, "%hu", &dns_port);
                    *colon_ptr = 0;
                    if (strlen(argv[i + 1]) < INET_ADDRSTRLEN) {
                        dns_ip = inet_addr(argv[i + 1]);
                        struct in_addr dns_ip_in_addr;
                        dns_ip_in_addr.s_addr = dns_ip;
                        printf("DNS %s:%hu\n", inet_ntoa(dns_ip_in_addr), dns_port);
                    }
                    *colon_ptr = ':';
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-listen")) {
            if (i != argc - 1) {
                char *colon_ptr = strchr(argv[i + 1], ':');
                if (colon_ptr) {
                    sscanf(colon_ptr + 1, "%hu", &listen_port);
                    *colon_ptr = 0;
                    if (strlen(argv[i + 1]) < INET_ADDRSTRLEN) {
                        listen_ip = inet_addr(argv[i + 1]);
                        struct in_addr listen_ip_in_addr;
                        listen_ip_in_addr.s_addr = listen_ip;
                        printf("Listen %s:%hu\n", inet_ntoa(listen_ip_in_addr), listen_port);
                    }
                    *colon_ptr = ':';
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-gateway")) {
            if (i != argc - 1) {
                if (strlen(argv[i + 1]) < INET_ADDRSTRLEN) {
                    gateway_ip = inet_addr(argv[i + 1]);
                    struct in_addr gateway_ip_in_addr;
                    gateway_ip_in_addr.s_addr = gateway_ip;
                    printf("Gateway IP %s\n", inet_ntoa(gateway_ip_in_addr));
                }
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
                if (strlen(argv[i + 1]) < IFNAMSIZ) {
                    is_tun_name = 1;
                    strcpy(tun_name, argv[i + 1]);
                    printf("TUN name %s\n", tun_name);
                }
                i++;
            }
            continue;
        }
        printf("\nUnknown command %s\n", argv[i]);
        print_help();
    }

    printf("\n");

    if (!gateway_ip) {
        printf("Programm need Gateway IP\n");
        print_help();
    }

    if (is_tun_name) {
        if (!tun_ip || !tun_prefix) {
            printf("Programm need TUN net\n");
            print_help();
        }
    }

    if (tun_ip || tun_prefix) {
        if (!is_tun_name) {
            printf("Programm need TUN name\n");
            print_help();
        }
    }

    if (tun_prefix > 24) {
        printf("Programm need TUN net prefix 1 - 24\n");
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
        char stat_path[PATH_MAX];
        sprintf(stat_path, "%s%s", log_or_stat_folder, "/stat.txt");
        stat_fd = fopen(stat_path, "w");
        if (stat_fd == NULL) {
            printf("Can't open stat file\n");
            exit(EXIT_FAILURE);
        }
    }

    int32_t threads_barrier_count = 3 + is_tun_name;
    if (pthread_barrier_init(&threads_barrier, NULL, threads_barrier_count)) {
        printf("Can't create threads_barrier\n");
        exit(EXIT_FAILURE);
    }

    if (is_tun_name) {
        init_tun_thread();
    } else {
        init_route_socket();
    }

    init_net_data_threads();

    pthread_barrier_wait(&threads_barrier);

    printf("\n");

    int32_t circles = 0;
    int32_t sleep_circles = 0;

    while (true) {
        if (circles++ == 0) {
            memset(&stat, 0, sizeof(stat));
            stat.stat_start = time(NULL);

            if (!is_tun_name) {
                clean_route_table();
            }

            int64_t urls_web_file_size = urls_read();

            if (urls_web_file_size > 0 || !is_domains_file_url) {
                sleep_circles = URLS_UPDATE_TIME / STAT_PRINT_TIME;
            } else {
                sleep_circles = URLS_ERROR_UPDATE_TIME / STAT_PRINT_TIME;
            }
        }

        circles %= sleep_circles;

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
