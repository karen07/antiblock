#include "antiblock.h"
#include "config.h"
#include "const.h"
#include "dns_ans.h"
#include "hash.h"
#include "net_data.h"
#include "stat.h"
#include "tun.h"
#include "domains_read.h"

pthread_barrier_t threads_barrier;

int32_t is_log_print;
int32_t is_stat_print;

char log_or_stat_folder[PATH_MAX - 100];

#ifdef TUN_MODE
char tun_name[IFNAMSIZ];

uint32_t tun_ip = 0xFFFFFFFF;
uint32_t tun_prefix;
#endif

uint32_t dns_ip = 0xFFFFFFFF;
uint16_t dns_port;

uint32_t listen_ip = 0xFFFFFFFF;
uint16_t listen_port;

FILE *log_fd;
FILE *stat_fd;

int32_t gateways_count;

char gateway_name[GATEWAY_MAX_COUNT][IFNAMSIZ];
char *gateway_domains_paths[GATEWAY_MAX_COUNT];

uint32_t gateway_domains_offset[GATEWAY_MAX_COUNT];
int32_t gateway_domains_count[GATEWAY_MAX_COUNT];

#ifndef TUN_MODE
int32_t route_socket;
#endif

void errmsg(const char *format, ...)
{
    va_list args;

    printf("\nError: ");

    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    exit(EXIT_FAILURE);
}

#ifndef TUN_MODE
void set_route(struct rtentry *route, int32_t gateway_index, uint32_t dst)
{
    memset(route, 0, sizeof(*route));

    struct sockaddr_in *route_addr;

    route_addr = (struct sockaddr_in *)(&(route->rt_dst));
    route_addr->sin_family = AF_INET;
    route_addr->sin_addr.s_addr = dst;

    route_addr = (struct sockaddr_in *)(&(route->rt_genmask));
    route_addr->sin_family = AF_INET;
    route_addr->sin_addr.s_addr = 0xFFFFFFFF;

    route->rt_dev = gateway_name[gateway_index];
    route->rt_flags = RTF_UP;
}

void add_route(int32_t gateway_index, uint32_t dst)
{
    struct rtentry route;

    set_route(&route, gateway_index, dst);

    if (ioctl(route_socket, SIOCADDRT, &route) < 0) {
        if (strcmp(strerror(errno), "File exists")) {
            struct in_addr rec_ip;
            rec_ip.s_addr = dst;
            printf("Ioctl can't add %s from route table :%s\n", inet_ntoa(rec_ip), strerror(errno));
        }
    }
}

void del_route(int32_t gateway_index, uint32_t dst)
{
    struct rtentry route;

    set_route(&route, gateway_index, dst);

    if (ioctl(route_socket, SIOCDELRT, &route) < 0) {
        if (strcmp(strerror(errno), "No such process")) {
            struct in_addr rec_ip;
            rec_ip.s_addr = dst;
            printf("Ioctl can't delete %s from route table :%s\n", inet_ntoa(rec_ip),
                   strerror(errno));
        }
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
            if ((!strcmp(iface, gateway_name[i])) && (mask == 0xFFFFFFFF)) {
                del_route(gate_ip, dest_ip);
            }
        }
    }

    fclose(route_fd);
}
#endif

static void print_help(void)
{
    printf(
        "\nCommands:\n"
        "  At least one parameters needs to be filled:\n"
        "    -domains  \"test1 https://test1.com\"  Route domains from path/url through gateway\n"
        "    -domains  \"test2 /test1.txt\"         Route domains from path/url through gateway\n"
        "    -domains  \"test3 /test2.txt\"         Route domains from path/url through gateway\n"
        "    -domains  \"test4 https://test2.com\"  Route domains from path/url through gateway\n"
        "    ........\n"
        "  Required parameters:\n"
        "    -listen    x.x.x.x:xx                Listen address\n"
        "    -DNS       x.x.x.x:xx                DNS address\n"
#ifdef TUN_MODE
        "    -TUN_net   x.x.x.x/xx                TUN net\n"
        "    -TUN_name  example                   TUN name\n"
#endif
        "  Optional parameters:\n"
        "    -output    /test/                    Log or statistics output folder\n"
        "    -log                                 Show operations log\n"
        "    -stat                                Show statistics data\n");
}

static void main_catch_function(int32_t signo)
{
    if (signo == SIGINT) {
        printf("SIGINT catched main\n");
    } else if (signo == SIGSEGV) {
        printf("SIGSEGV catched main\n");
    } else if (signo == SIGTERM) {
        printf("SIGTERM catched main\n");
    }
#ifndef TUN_MODE
    clean_route_table();
#endif
    fflush(stdout);
    if (stat_fd) {
        fflush(stat_fd);
    }
    if (log_fd) {
        fflush(log_fd);
    }
    exit(EXIT_SUCCESS);
}

int32_t main(int32_t argc, char *argv[])
{
    printf("\nAntiBlock started " ANTIBLOCK_VERSION "\n\n");
    printf("AntiBlock program proxies DNS requests. The IP addresses of the specified domains\n"
           "are added to the routing table for routing through the specified interfaces.\n\n");

    if (signal(SIGINT, main_catch_function) == SIG_ERR) {
        errmsg("Can't set SIGINT signal handler main\n");
    }

    if (signal(SIGSEGV, main_catch_function) == SIG_ERR) {
        errmsg("Can't set SIGSEGV signal handler main\n");
    }

    if (signal(SIGTERM, main_catch_function) == SIG_ERR) {
        errmsg("Can't set SIGTERM signal handler main\n");
    }

    printf("Launch parameters:\n");

    for (int32_t i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-log")) {
            is_log_print = 1;
            printf("  Log enabled\n");
            continue;
        }
        if (!strcmp(argv[i], "-stat")) {
            is_stat_print = 1;
            printf("  Stat enabled\n");
            continue;
        }
        if (!strcmp(argv[i], "-domains")) {
            if (i != argc - 1) {
                printf("  Domains %s\n", argv[i + 1]);
                char *space_ptr = strchr(argv[i + 1], ' ');
                if (space_ptr) {
                    *space_ptr = 0;
                    if (gateways_count < GATEWAY_MAX_COUNT) {
                        if (strlen(argv[i + 1]) < IFNAMSIZ) {
                            strcpy(gateway_name[gateways_count], argv[i + 1]);
                        }
                        gateway_domains_paths[gateways_count] = space_ptr + 1;
                    }
                    *space_ptr = ' ';
                    gateways_count++;
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-output")) {
            if (i != argc - 1) {
                if (strlen(argv[i + 1]) < PATH_MAX - 100) {
                    strcpy(log_or_stat_folder, argv[i + 1]);
                    printf("  Output log or stat to %s\n", log_or_stat_folder);
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-DNS")) {
            if (i != argc - 1) {
                printf("  DNS %s\n", argv[i + 1]);
                char *colon_ptr = strchr(argv[i + 1], ':');
                if (colon_ptr) {
                    sscanf(colon_ptr + 1, "%hu", &dns_port);
                    *colon_ptr = 0;
                    if (strlen(argv[i + 1]) < INET_ADDRSTRLEN) {
                        dns_ip = inet_addr(argv[i + 1]);
                    }
                    *colon_ptr = ':';
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-listen")) {
            if (i != argc - 1) {
                printf("  Listen %s\n", argv[i + 1]);
                char *colon_ptr = strchr(argv[i + 1], ':');
                if (colon_ptr) {
                    sscanf(colon_ptr + 1, "%hu", &listen_port);
                    *colon_ptr = 0;
                    if (strlen(argv[i + 1]) < INET_ADDRSTRLEN) {
                        listen_ip = inet_addr(argv[i + 1]);
                    }
                    *colon_ptr = ':';
                }
                i++;
            }
            continue;
        }
#ifdef TUN_MODE
        if (!strcmp(argv[i], "-TUN_net")) {
            if (i != argc - 1) {
                printf("  TUN net %s\n", argv[i + 1]);
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
        if (!strcmp(argv[i], "-TUN_name")) {
            if (i != argc - 1) {
                if (strlen(argv[i + 1]) < IFNAMSIZ) {
                    strcpy(tun_name, argv[i + 1]);
                    printf("  TUN name %s\n", tun_name);
                }
                i++;
            }
            continue;
        }
#endif
        print_help();
        errmsg("Unknown command: %s\n", argv[i]);
    }

#ifdef TUN_MODE
    if (tun_name[0] == 0) {
        print_help();
        errmsg("The program need TUN_name\n");
    }

    if (tun_ip == 0xFFFFFFFF) {
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

    if (gateways_count == 0) {
        print_help();
        errmsg("The program needs at least one correct pair of \"gateway domains\"\n");
    }

    if (!(gateways_count < GATEWAY_MAX_COUNT)) {
        print_help();
        errmsg("The program needs a maximum of %d pair of \"gateway domains\"\n",
               GATEWAY_MAX_COUNT - 1);
    }

    for (int32_t i = 0; i < gateways_count; i++) {
        if ((gateway_name[i][0] == 0) || (gateway_domains_paths[i][0] == 0)) {
            print_help();
            errmsg("The program needs at least one correct pair of \"gateway domains\"\n");
        }
    }

    if (dns_ip == 0xFFFFFFFF) {
        print_help();
        errmsg("The program need correct DNS IP\n");
    }

    if (dns_port == 0) {
        print_help();
        errmsg("The program need correct DNS port\n");
    }

    if (listen_ip == 0xFFFFFFFF) {
        print_help();
        errmsg("The program need correct listen IP\n");
    }

    if (listen_port == 0) {
        print_help();
        errmsg("The program need correct listen port\n");
    }

    if (is_log_print || is_stat_print) {
        if (log_or_stat_folder[0] == 0) {
            print_help();
            errmsg("The program need output folder for log or statistics\n");
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

    printf("\n");

    int32_t threads_barrier_count = 3;
#ifdef TUN_MODE
    threads_barrier_count += 1;
#endif
    if (pthread_barrier_init(&threads_barrier, NULL, threads_barrier_count)) {
        errmsg("Can't create threads_barrier\n");
    }

#ifdef TUN_MODE
    init_tun_thread();
#else
    route_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (route_socket < 0) {
        errmsg("Can't create route_socket :%s\n", strerror(errno));
    }
#endif

    init_net_data_threads();

    pthread_barrier_wait(&threads_barrier);

    int32_t circles = 0;
    int32_t sleep_circles = 0;

    while (true) {
        if (circles++ == 0) {
            memset(&stat, 0, sizeof(stat));
            stat.stat_start = time(NULL);

#ifndef TUN_MODE
            clean_route_table();
#endif

            int32_t domains_read_status = domains_read();

            if (domains_read_status) {
                sleep_circles = DOMAINS_UPDATE_TIME;
            } else {
                sleep_circles = DOMAINS_ERROR_UPDATE_TIME;
            }

            sleep_circles /= STAT_PRINT_TIME;
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
