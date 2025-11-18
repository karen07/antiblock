#include "antiblock.h"
#include "config.h"
#include "dns_ans.h"
#include "hash.h"
#include "net_data.h"
#include "stat.h"
#include "domains_read.h"

#define TICK_MS 10
#define SEC_TICKS (1000 / TICK_MS)
#define TEN_SEC_TICKS (10 * SEC_TICKS)
#define DAY_TICKS ((24 * 60 * 60 * 1000) / TICK_MS)

typedef struct gateway_data {
    char name[IFNAMSIZ];
    uint32_t nexthop_ip;
} gateway_data_t;

FILE *log_fd;
FILE *stat_fd;

int32_t gateways_count;
char *gateway_domains_paths[GATEWAY_MAX_COUNT];

int32_t blacklist_count;
subnet_t blacklist[BLACKLIST_MAX_COUNT];

struct sockaddr_in listen_addr;

volatile uint64_t now_unix_time;

static gateway_data_t gateways[GATEWAY_MAX_COUNT];

#ifdef PROXY_MODE
struct sockaddr_in dns_addr[DNS_MAX_COUNT];
#endif

static int32_t test_mode;
static int32_t route_socket;
static void clean_route_table(void);

void errmsg(const char *format, ...)
{
    va_list args;

    printf("Error: ");

    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    clean_route_table();

    if (stat_fd) {
        stat_print(stat_fd);
    }

    if (log_fd) {
        fflush(log_fd);
    }

    fflush(stdout);

    exit(EXIT_FAILURE);
}

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

    route->rt_dev = gateways[gateway_index].name;
    route->rt_flags = RTF_UP;

    if (gateways[gateway_index].nexthop_ip) {
        route_addr = (struct sockaddr_in *)(&route->rt_gateway);
        route_addr->sin_family = AF_INET;
        route_addr->sin_addr.s_addr = gateways[gateway_index].nexthop_ip;

        route->rt_flags |= RTF_GATEWAY;
    }
}

void add_route(int32_t gateway_index, uint32_t dst, uint32_t ans_ttl)
{
    struct rtentry route;

    int32_t add_res = add_route_to_hashmap(gateway_index, dst, ans_ttl);

    if (add_res == array_hashmap_elem_already_in) {
        return;
    }

    if (test_mode) {
        return;
    }

    set_route(&route, gateway_index, dst);

    if (ioctl(route_socket, SIOCADDRT, &route) >= 0) {
        statistics_data.in_route_table[gateway_index]++;
        return;
    }

    struct in_addr rec_ip;
    rec_ip.s_addr = dst;
    printf("Ioctl can't add %s for routing via %s \"%s\"\n", inet_ntoa(rec_ip),
           gateways[gateway_index].name, strerror(errno));
}

void del_route(int32_t gateway_index, uint32_t dst)
{
    struct rtentry route;

    if (test_mode) {
        return;
    }

    set_route(&route, gateway_index, dst);

    if (ioctl(route_socket, SIOCDELRT, &route) >= 0) {
        statistics_data.in_route_table[gateway_index]--;
        return;
    }

    struct in_addr rec_ip;
    rec_ip.s_addr = dst;
    printf("Ioctl can't delete %s for routing via %s \"%s\"\n", inet_ntoa(rec_ip),
           gateways[gateway_index].name, strerror(errno));
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
            if ((!strcmp(iface, gateways[i].name)) && (mask == INADDR_NONE)) {
                del_route(i, dest_ip);
            }
        }
    }

    fclose(route_fd);
}

static uint32_t get_iface_default_gw(char *iface_in)
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
        if ((!strcmp(iface, iface_in)) && (dest_ip == 0)) {
            fclose(route_fd);
            return gate_ip;
        }
    }

    fclose(route_fd);
    return 0;
}

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

static void print_log_head(void)
{
    if (log_fd) {
        if (ftruncate(fileno(log_fd), 0) == 0) {
            fseek(log_fd, 0, SEEK_SET);
            fprintf(log_fd, "Reductions:\n");
            fprintf(log_fd, "    Q(x)-DNS question x type\n");
            fprintf(log_fd, "    A(x)-DNS answer x type\n");
            fprintf(log_fd, "    BA(x)-A in x route\n");
            fprintf(log_fd, "    BC(x)-CNAME in x route\n");
            fprintf(log_fd, "    BL-IP in blacklist\n");
            fprintf(log_fd, "    NA-A not in routes\n");
            fprintf(log_fd, "    NC-CNAME not in routes\n");
        }
    }
}

static void print_help(void)
{
    printf("Commands:\n"
           "  It is necessary to enter from 1 to %d values:\n"
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
           "  Optional parameters:\n"
           "    -b  \"/test.txt\"   Subnets not add to the routing table\n"
           "    -o  \"/test/\"      Log or stat output folder\n"
           "    --log             Show operations log\n"
           "    --stat            Show statistics data\n"
           "    --test            Test mode\n",
           GATEWAY_MAX_COUNT);
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
    /* Init msg */
#ifdef PCAP_MODE
    printf("AntiBlock " ANTIBLOCK_VERSION " sniffer DNS requests. The IP addresses of\n"
           "the specified domains are added to the routing table for\n"
           "routing through the specified interfaces.\n");
#else
    printf("AntiBlock " ANTIBLOCK_VERSION " proxies DNS requests. The IP addresses of\n"
           "the specified domains are added to the routing table for\n"
           "routing through the specified interfaces.\n");
#endif
    /* Init msg */

    /* Set signal catch_functions */
    if (signal(SIGINT, main_catch_function) == SIG_ERR) {
        errmsg("Can't set SIGINT signal handler main\n");
    }

    if (signal(SIGSEGV, main_catch_function) == SIG_ERR) {
        errmsg("Can't set SIGSEGV signal handler main\n");
    }

    if (signal(SIGTERM, main_catch_function) == SIG_ERR) {
        errmsg("Can't set SIGTERM signal handler main\n");
    }
    /* Set signal catch_functions */

    /* Set init values */
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
    /* Set init values */

    printf("Launch parameters:\n");

    /* Process command-line arguments */
    for (int32_t i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-r")) {
            if (i != argc - 1) {
                printf("  Route      \"%s\"\n", argv[i + 1]);
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
                                strcpy(gateways[gateways_count].name, first_space_ptr + 1);
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
                            strcpy(gateways[gateways_count].name, argv[i + 1]);
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
#ifdef PROXY_MODE
                printf("  Listen     \"%s\"\n", argv[i + 1]);
#else
                printf("  Sniffer    \"%s\"\n", argv[i + 1]);
#endif
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
            test_mode = 1;
            printf("  Test       enabled\n");
            continue;
        }
        print_help();
        errmsg("Unknown command: %s\n", argv[i]);
    }
    /* Process command-line arguments */

    /* Check arguments */
    if (gateways_count == 0) {
        print_help();
        errmsg("The program needs at least one correct pair of \"gateway domains\"\n");
    }

    if (gateways_count > GATEWAY_MAX_COUNT) {
        print_help();
        errmsg("The program needs a maximum of %d pair of \"gateway domains\", seted %d\n",
               GATEWAY_MAX_COUNT, gateways_count);
    }

    for (int32_t i = 0; i < gateways_count; i++) {
        if ((gateways[i].name[0] == 0) || (gateway_domains_paths[i][0] == 0)) {
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

    if (is_log_print || is_stat_print) {
        if (log_or_stat_folder[0] == 0) {
            strcpy(log_or_stat_folder, ".");
        }
    }
    /* Check arguments */

    /* Set default blacklist subnets */
    add_blacklist("0.0.0.0/8");
    add_blacklist("10.0.0.0/8");
    add_blacklist("100.64.0.0/10");
    add_blacklist("127.0.0.0/8");
    add_blacklist("172.16.0.0/12");
    add_blacklist("192.168.0.0/16");
    /* Set default blacklist subnets */

    /* Read blacklist file */
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
    /* Read blacklist file */

    dns_ans_check_test();

    /* Open log and stat files */
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
    /* Open log and stat files */

    /* Init ioctl socket */
    route_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (route_socket < 0) {
        errmsg("Can't create route_socket \"%s\"\n", strerror(errno));
    }
    /* Init ioctl socket */

    /* Get nexthop ip for L2 gateways */
    for (int32_t i = 0; i < gateways_count; i++) {
        struct ifreq ifreq;
        memset(&ifreq, 0, sizeof(ifreq));
        strcpy(ifreq.ifr_name, gateways[i].name);

        int32_t ret;
        ret = ioctl(route_socket, SIOCGIFHWADDR, &ifreq);
        if (ret < 0) {
            errmsg("Can't get mac address of interface %s\n", gateways[i].name);
        }

        if (ifreq.ifr_hwaddr.sa_family == ARPHRD_ETHER) {
            gateways[i].nexthop_ip = get_iface_default_gw(gateways[i].name);
        }
    }
    /* Get nexthop ip for L2 gateways */

    /* Init memory for msgs */
    memory_t receive_msg;

    memory_t que_domain;
    que_domain.size = 0;
    que_domain.max_size = DOMAIN_MAX_SIZE;
    que_domain.data = (char *)malloc(que_domain.max_size * sizeof(char));
    if (que_domain.data == 0) {
        errmsg("No free memory for que_domain\n");
    }

    memory_t ans_domain;
    ans_domain.size = 0;
    ans_domain.max_size = DOMAIN_MAX_SIZE;
    ans_domain.data = (char *)malloc(ans_domain.max_size * sizeof(char));
    if (ans_domain.data == 0) {
        errmsg("No free memory for ans_domain\n");
    }

    memory_t cname_domain;
    cname_domain.size = 0;
    cname_domain.max_size = DOMAIN_MAX_SIZE;
    cname_domain.data = (char *)malloc(cname_domain.max_size * sizeof(char));
    if (cname_domain.data == 0) {
        errmsg("No free memory for cname_domain\n");
    }
    /* Init memory for msgs */

    PCAP_mode_init();

    /* Init tick timers */
    uint32_t sec_counter = SEC_TICKS;
    uint32_t ten_sec_counter = TEN_SEC_TICKS;
    uint32_t day_counter = DAY_TICKS;

    int32_t first_cycle = true;
    /* Init tick timers */

    while (true) {
        if (first_cycle || --day_counter == 0) {
            clean_route_table();

            print_log_head();

            memset(&statistics_data, 0, sizeof(statistics_data));
            statistics_data.stat_start = time(NULL);

            domains_read();

            day_counter = DAY_TICKS;
        }

        if (first_cycle || --ten_sec_counter == 0) {
            if (stat_fd) {
                stat_print(stat_fd);
            }

            if (log_fd) {
                fflush(log_fd);
            }

            fflush(stdout);

            ten_sec_counter = TEN_SEC_TICKS;
        }

        if (first_cycle || --sec_counter == 0) {
            now_unix_time = time(NULL);
            del_expired_routes_from_hashmap();
            sec_counter = SEC_TICKS;
        }

        int32_t ret = PCAP_get_msg(&receive_msg);
        if (ret) {
            dns_ans_check(DNS_ANS, &receive_msg, &que_domain, &ans_domain, &cname_domain);
        }

        first_cycle = false;

        usleep(TICK_MS * 1000);
    }

    return EXIT_SUCCESS;
}
