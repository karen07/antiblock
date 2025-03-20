#include "antiblock.h"
#include "config.h"
#include "const.h"
#include "dns_ans.h"
#include "hash.h"
#include "net_data.h"
#include "stat.h"
#include "tun.h"
#include "domains_read.h"

FILE *log_fd;
FILE *stat_fd;

int32_t gateways_count;
char *gateway_domains_paths[GATEWAY_MAX_COUNT];

int32_t blacklist_count;
subnet_t blacklist[BLACKLIST_MAX_COUNT];

struct sockaddr_in listen_addr;
pthread_barrier_t threads_barrier;

static char gateway_name[GATEWAY_MAX_COUNT][IFNAMSIZ];

#ifdef PROXY_MODE
struct sockaddr_in dns_addr[DNS_MAX_COUNT];
#endif

#ifdef TUN_MODE
uint32_t tun_ip = INADDR_NONE;
uint32_t tun_prefix;
#endif

#ifdef ROUTE_TABLE_MODE
static int32_t test_mode;
static int32_t route_socket;
static void clean_route_table(void);
#endif

void errmsg(const char *format, ...)
{
    va_list args;

    printf("Error: ");

    va_start(args, format);
    vprintf(format, args);
    va_end(args);

#ifdef ROUTE_TABLE_MODE
    clean_route_table();
#endif

    if (stat_fd) {
        stat_print(stat_fd);
    }

    if (log_fd) {
        fflush(log_fd);
    }

    fflush(stdout);

    exit(EXIT_FAILURE);
}

#ifdef ROUTE_TABLE_MODE
static void set_route(struct rtentry *route, int32_t gateway_index, uint32_t dst)
{
    memset(route, 0, sizeof(*route));

    struct sockaddr_in *route_addr;

    route_addr = (struct sockaddr_in *)(&(route->rt_dst));
    route_addr->sin_family = AF_INET;
    route_addr->sin_addr.s_addr = dst;

    route_addr = (struct sockaddr_in *)(&(route->rt_genmask));
    route_addr->sin_family = AF_INET;
    route_addr->sin_addr.s_addr = INADDR_NONE;

    route->rt_dev = gateway_name[gateway_index];
    route->rt_flags = RTF_UP;
}

void add_route(int32_t gateway_index, uint32_t dst)
{
    struct rtentry route;

    set_route(&route, gateway_index, dst);

    if (test_mode) {
        return;
    }

    if (ioctl(route_socket, SIOCADDRT, &route) >= 0) {
        statistics_data.add_to_route_table++;
        return;
    }

    if (strcmp(strerror(errno), "File exists")) {
        struct in_addr rec_ip;
        rec_ip.s_addr = dst;
        printf("Ioctl can't add %s for routing via %s \"%s\"\n", inet_ntoa(rec_ip),
               gateway_name[gateway_index], strerror(errno));
    }
}

static void del_route(int32_t gateway_index, uint32_t dst)
{
    struct rtentry route;

    set_route(&route, gateway_index, dst);

    if (test_mode) {
        return;
    }

    if (ioctl(route_socket, SIOCDELRT, &route) >= 0) {
        return;
    }

    if (strcmp(strerror(errno), "No such process")) {
        struct in_addr rec_ip;
        rec_ip.s_addr = dst;
        printf("Ioctl can't delete %s for routing via %s \"%s\"\n", inet_ntoa(rec_ip),
               gateway_name[gateway_index], strerror(errno));
    }
}

static void clean_route_table(void)
{
    FILE *route_fd = fopen("/proc/net/route", "r");
    if (route_fd == NULL) {
        errmsg("Can't open /proc/net/route\n");
    }

    fseek(route_fd, 128, SEEK_SET);

    char iface[IFNAMSIZ];
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
        for (int32_t i = 0; i < gateways_count; i++) {
            if ((!strcmp(iface, gateway_name[i])) && (mask == INADDR_NONE)) {
                del_route(gate_ip, dest_ip);
            }
        }
    }

    fclose(route_fd);
}
#endif

static void add_blacklist(const char *subnet_str)
{
    char tmp_subnet[100];
    strcpy(tmp_subnet, subnet_str);

    char *slash_ptr = strchr(tmp_subnet, '/');
    if (slash_ptr) {
        uint32_t tmp_prefix = 0;
        sscanf(slash_ptr + 1, "%u", &tmp_prefix);
        *slash_ptr = 0;
        if (strlen(tmp_subnet) < INET_ADDRSTRLEN) {
            if (blacklist_count < BLACKLIST_MAX_COUNT) {
                blacklist[blacklist_count].ip = inet_addr(tmp_subnet);
                blacklist[blacklist_count].mask = (0xFFFFFFFF << (32 - tmp_prefix)) & 0xFFFFFFFF;
            }
            blacklist_count++;
        }
        *slash_ptr = '/';
    } else {
        errmsg("Every blacklist line \"x.x.x.x/xx\"\n");
    }
}

static void print_help(void)
{
    printf("Commands:\n"
           "  At least one parameters needs to be filled:\n"
#ifdef MULTIPLE_DNS
           "    Route domains from path/url through gateway,\n"
           "    resolve domains from path/url via DNS:\n"
           "      -r  \"DNS2 gateway1 https://test1.com\"\n"
           "      -r  \"DNS2 gateway2 /test1.txt\"\n"
           "      -r  \"DNS1 gateway2 /test2.txt\"\n"
           "      -r  \"DNS1 gateway1 https://test2.com\"\n"
#else
           "    Route domains from path/url through gateway:\n"
           "      -r  \"gateway1 https://test1.com\"\n"
           "      -r  \"gateway2 /test1.txt\"\n"
           "      -r  \"gateway2 /test2.txt\"\n"
           "      -r  \"gateway1 https://test2.com\"\n"
#endif
           "      .....................................\n"
           "  Required parameters:\n"
#ifdef PROXY_MODE
           "    -l  \"x.x.x.x:xx\"  Listen address\n"
           "    -d  \"x.x.x.x:xx\"  DNS address\n"
#else
           "    -l  \"x.x.x.x:xx\"  Address for sniffing packets with this src\n"
#endif
#ifdef TUN_MODE
           "    -n  \"x.x.x.x/xx\"  TUN net\n"
#endif
           "  Optional parameters:\n"
           "    -b  \"/test.txt\"   Subnets not add to the routing table\n"
           "    -o  \"/test/\"      Log or stat output folder\n"
           "    --log             Show operations log\n"
           "    --stat            Show statistics data\n"
           "    --test            Test mode\n");
}

static void main_catch_function(int32_t signo)
{
    if (signo == SIGINT) {
        errmsg("SIGINT catched main\n");
    } else if (signo == SIGSEGV) {
        errmsg("SIGSEGV catched main\n");
    } else if (signo == SIGTERM) {
        errmsg("SIGTERM catched main\n");
    }
}

int32_t main(int32_t argc, char *argv[])
{
#ifdef PCAP_MODE
    printf("AntiBlock " ANTIBLOCK_VERSION " sniffer DNS requests. The IP addresses of\n"
           "the specified domains are added to the routing table for\n"
           "routing through the specified interfaces.\n");
#else
    printf("AntiBlock " ANTIBLOCK_VERSION " proxies DNS requests. The IP addresses of\n"
           "the specified domains are added to the routing table for\n"
           "routing through the specified interfaces.\n");
#endif

    if (signal(SIGINT, main_catch_function) == SIG_ERR) {
        errmsg("Can't set SIGINT signal handler main\n");
    }

    if (signal(SIGSEGV, main_catch_function) == SIG_ERR) {
        errmsg("Can't set SIGSEGV signal handler main\n");
    }

    if (signal(SIGTERM, main_catch_function) == SIG_ERR) {
        errmsg("Can't set SIGTERM signal handler main\n");
    }

    int32_t is_log_print = 0;
    int32_t is_stat_print = 0;

    char log_or_stat_folder[PATH_MAX - 100];
    memset(log_or_stat_folder, 0, PATH_MAX - 100);

    char blacklist_file_path[PATH_MAX];
    memset(blacklist_file_path, 0, PATH_MAX);

    listen_addr.sin_addr.s_addr = INADDR_NONE;

#ifdef PROXY_MODE
    for (int32_t i = 0; i < DNS_MAX_COUNT; i++) {
        dns_addr[i].sin_addr.s_addr = INADDR_NONE;
    }
#endif

    printf("Launch parameters:\n");

    for (int32_t i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-r")) {
            if (i != argc - 1) {
                printf("  Routes     \"%s\"\n", argv[i + 1]);
                char *first_space_ptr = strchr(argv[i + 1], ' ');
                if (first_space_ptr) {
                    *first_space_ptr = 0;
#ifdef MULTIPLE_DNS
                    char *colon_ptr = strchr(argv[i + 1], ':');
                    if (colon_ptr) {
                        uint16_t tmp_port = 0;
                        sscanf(colon_ptr + 1, "%hu", &tmp_port);
                        *colon_ptr = 0;
                        if (strlen(argv[i + 1]) < INET_ADDRSTRLEN) {
                            dns_addr[DNS_COUNT].sin_family = AF_INET;
                            dns_addr[DNS_COUNT].sin_port = htons(tmp_port);
                            dns_addr[DNS_COUNT].sin_addr.s_addr = inet_addr(argv[i + 1]);
                        }
                        *colon_ptr = ':';
                    }
                    *first_space_ptr = ' ';
                    char *second_space_ptr = strchr(first_space_ptr + 1, ' ');
                    if (second_space_ptr) {
                        *second_space_ptr = 0;
                        if (gateways_count < GATEWAY_MAX_COUNT) {
                            if (strlen(first_space_ptr + 1) < IFNAMSIZ) {
                                strcpy(gateway_name[gateways_count], first_space_ptr + 1);
                            }
                            gateway_domains_paths[gateways_count] = second_space_ptr + 1;
                        }
                        *second_space_ptr = ' ';
                        gateways_count++;
                    }
#else
                    *first_space_ptr = 0;
                    if (gateways_count < GATEWAY_MAX_COUNT) {
                        if (strlen(argv[i + 1]) < IFNAMSIZ) {
                            strcpy(gateway_name[gateways_count], argv[i + 1]);
                        }
                        gateway_domains_paths[gateways_count] = first_space_ptr + 1;
                    }
                    *first_space_ptr = ' ';
                    gateways_count++;
#endif
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-l")) {
            if (i != argc - 1) {
                printf("  Listen     \"%s\"\n", argv[i + 1]);
                char *colon_ptr = strchr(argv[i + 1], ':');
                if (colon_ptr) {
                    uint16_t tmp_port = 0;
                    sscanf(colon_ptr + 1, "%hu", &tmp_port);
                    *colon_ptr = 0;
                    if (strlen(argv[i + 1]) < INET_ADDRSTRLEN) {
                        listen_addr.sin_family = AF_INET;
                        listen_addr.sin_port = htons(tmp_port);
                        listen_addr.sin_addr.s_addr = inet_addr(argv[i + 1]);
                    }
                    *colon_ptr = ':';
                }
                i++;
            }
            continue;
        }
#ifdef PROXY_MODE
        if (!strcmp(argv[i], "-d")) {
            if (i != argc - 1) {
                printf("  DNS     \"%s\"\n", argv[i + 1]);
                char *colon_ptr = strchr(argv[i + 1], ':');
                if (colon_ptr) {
                    uint16_t tmp_port = 0;
                    sscanf(colon_ptr + 1, "%hu", &tmp_port);
                    *colon_ptr = 0;
                    if (strlen(argv[i + 1]) < INET_ADDRSTRLEN) {
                        dns_addr[0].sin_family = AF_INET;
                        dns_addr[0].sin_port = htons(tmp_port);
                        dns_addr[0].sin_addr.s_addr = inet_addr(argv[i + 1]);
                    }
                    *colon_ptr = ':';
                }
                i++;
            }
            continue;
        }
#endif
#ifdef TUN_MODE
        if (!strcmp(argv[i], "-n")) {
            if (i != argc - 1) {
                printf("  TUN     \"%s\"\n", argv[i + 1]);
                char *slash_ptr = strchr(argv[i + 1], '/');
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
#endif
        if (!strcmp(argv[i], "-b")) {
            if (i != argc - 1) {
                if (strlen(argv[i + 1]) < PATH_MAX) {
                    strcpy(blacklist_file_path, argv[i + 1]);
                    printf("  BlackList  \"%s\"\n", blacklist_file_path);
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-o")) {
            if (i != argc - 1) {
                if (strlen(argv[i + 1]) < PATH_MAX - 100) {
                    strcpy(log_or_stat_folder, argv[i + 1]);
                    printf("  Output     \"%s\"\n", log_or_stat_folder);
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "--log")) {
            is_log_print = 1;
            printf("  Log        enabled\n");
            continue;
        }
        if (!strcmp(argv[i], "--stat")) {
            is_stat_print = 1;
            printf("  Stat       enabled\n");
            continue;
        }
        if (!strcmp(argv[i], "--test")) {
#ifdef ROUTE_TABLE_MODE
            test_mode = 1;
#endif
            printf("  Test       enabled\n");
            continue;
        }
        print_help();
        errmsg("Unknown command: %s\n", argv[i]);
    }

    if (gateways_count == 0) {
        print_help();
        errmsg("The program needs at least one correct pair of \"gateway domains\"\n");
    }

    if (gateways_count > GATEWAY_MAX_COUNT) {
        int32_t tmp_gateways_count = gateways_count;
        gateways_count = GATEWAY_MAX_COUNT;
        print_help();
        errmsg("The program needs a maximum of %d pair of \"gateway domains\", seted %d\n",
               GATEWAY_MAX_COUNT, tmp_gateways_count);
    }

    for (int32_t i = 0; i < gateways_count; i++) {
        if ((gateway_name[i][0] == 0) || (gateway_domains_paths[i][0] == 0)) {
            print_help();
            errmsg("The program needs correct pairs of \"gateway domains\"\n");
        }
    }

    if (listen_addr.sin_addr.s_addr == INADDR_NONE) {
        print_help();
        errmsg("The program need correct listen IP\n");
    }

    if (listen_addr.sin_port == 0) {
        print_help();
        errmsg("The program need correct listen port\n");
    }

#ifdef PROXY_MODE
    for (int32_t i = 0; i < DNS_COUNT; i++) {
        if (dns_addr[i].sin_addr.s_addr == INADDR_NONE) {
            print_help();
            errmsg("The program need correct DNS IP\n");
        }
        if (dns_addr[i].sin_port == 0) {
            print_help();
            errmsg("The program need correct DNS port\n");
        }
    }
#endif

#ifdef TUN_MODE
    if (tun_ip == INADDR_NONE) {
        print_help();
        errmsg("The program need correct TUN IP\n");
    }

    if (tun_prefix == 0) {
        print_help();
        errmsg("The program need correct TUN prefix\n");
    }

    if (tun_prefix > 24) {
        print_help();
        errmsg("The program need TUN net prefix 1 - 24\n");
    }
#endif

    if (is_log_print || is_stat_print) {
        if (log_or_stat_folder[0] == 0) {
            print_help();
            errmsg("The program need output folder for log or statistics\n");
        }
    }

    add_blacklist("0.0.0.0/8");
    add_blacklist("10.0.0.0/8");
    add_blacklist("100.64.0.0/10");
    add_blacklist("127.0.0.0/8");
    add_blacklist("172.16.0.0/12");
    add_blacklist("192.168.0.0/16");

    if (blacklist_file_path[0] != 0) {
        FILE *blacklist_fd;
        blacklist_fd = fopen(blacklist_file_path, "r");
        if (blacklist_fd == NULL) {
            errmsg("Can't open blacklist file %s\n", blacklist_file_path);
        }

        char tmp_line[100];

        while (fscanf(blacklist_fd, "%s", tmp_line) != EOF) {
            add_blacklist(tmp_line);
        }

        if (blacklist_count > BLACKLIST_MAX_COUNT) {
            errmsg("The program needs a maximum of %d blacklist subnets, seted %d\n",
                   BLACKLIST_MAX_COUNT, blacklist_count);
        }
    }

    if (is_log_print) {
        char log_path[PATH_MAX];
        sprintf(log_path, "%s%s", log_or_stat_folder, "/log.txt");
        log_fd = fopen(log_path, "w");
        if (log_fd == NULL) {
            errmsg("Can't open log file\n");
        }
    }

    if (is_stat_print) {
        char stat_path[PATH_MAX];
        sprintf(stat_path, "%s%s", log_or_stat_folder, "/stat.txt");
        stat_fd = fopen(stat_path, "w");
        if (stat_fd == NULL) {
            errmsg("Can't open stat file\n");
        }
    }

    int32_t threads_barrier_count = 3;

#ifdef TUN_MODE
    threads_barrier_count += 1;
#endif

#ifdef PCAP_MODE
    threads_barrier_count -= 1;
#endif

    if (pthread_barrier_init(&threads_barrier, NULL, threads_barrier_count)) {
        errmsg("Can't create threads_barrier\n");
    }

#ifdef TUN_MODE
    init_tun_thread();
#else
    route_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (route_socket < 0) {
        errmsg("Can't create route_socket \"%s\"\n", strerror(errno));
    }
#endif

    init_net_data_threads();

    dns_ans_check_test();

    pthread_barrier_wait(&threads_barrier);

    int32_t circles = 0;
    int32_t sleep_circles = 0;

    while (true) {
        if (circles++ == 0) {
            memset(&statistics_data, 0, sizeof(statistics_data));
            statistics_data.stat_start = time(NULL);

#ifdef ROUTE_TABLE_MODE
            clean_route_table();
#endif

            int32_t domains_read_status = 0;
            domains_read_status = domains_read();

            if (domains_read_status) {
                sleep_circles = DOMAINS_UPDATE_TIME;
            } else {
                sleep_circles = DOMAINS_ERROR_UPDATE_TIME;
            }

            sleep_circles /= STAT_PRINT_TIME;
        }

        circles %= sleep_circles;

        if (stat_fd) {
            stat_print(stat_fd);
        }

        if (log_fd) {
            fflush(log_fd);
        }

        fflush(stdout);

        sleep(STAT_PRINT_TIME);
    }

    return EXIT_SUCCESS;
}
