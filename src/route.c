#include "route.h"
#include "stat.h"

int32_t route_socket;
struct rtentry route;

void add_url_cname(char *ans_url, time_t check_time, char *data_url)
{
    stat.now_cname_url_count++;

    if (log_fd) {
        char now_time_str[DATE_STR_MAX_SIZE];
        time_t now = time(NULL);
        struct tm *tm_struct = localtime(&now);
        sprintf(now_time_str, "%d:%d:%d", tm_struct->tm_hour, tm_struct->tm_min, tm_struct->tm_sec);

        char time_str[DATE_STR_MAX_SIZE];
        tm_struct = localtime(&check_time);
        sprintf(time_str, "%d:%d:%d", tm_struct->tm_hour, tm_struct->tm_min, tm_struct->tm_sec);

        fprintf(log_fd, "%s,add url,%s,%s,%s\n", now_time_str, ans_url, data_url, time_str);
        fflush(log_fd);
    }
}

void update_url_cname(char *ans_url, time_t check_time, char *data_url)
{
    if (log_fd) {
        char now_time_str[DATE_STR_MAX_SIZE];
        time_t now = time(NULL);
        struct tm *tm_struct = localtime(&now);
        sprintf(now_time_str, "%d:%d:%d", tm_struct->tm_hour, tm_struct->tm_min, tm_struct->tm_sec);

        char time_str[DATE_STR_MAX_SIZE];
        tm_struct = localtime(&check_time);
        sprintf(time_str, "%d:%d:%d", tm_struct->tm_hour, tm_struct->tm_min, tm_struct->tm_sec);

        fprintf(log_fd, "%s,copy url,%s,%s,%s\n", now_time_str, ans_url, data_url, time_str);
        fflush(log_fd);
    }
}

void del_url_cname(char *data_url, time_t check_time)
{
    stat.now_cname_url_count--;

    if (log_fd) {
        char now_time_str[DATE_STR_MAX_SIZE];
        time_t now = time(NULL);
        struct tm *tm_struct = localtime(&now);
        sprintf(now_time_str, "%d:%d:%d", tm_struct->tm_hour, tm_struct->tm_min, tm_struct->tm_sec);

        char time_str[DATE_STR_MAX_SIZE];
        tm_struct = localtime(&check_time);
        sprintf(time_str, "%d:%d:%d", tm_struct->tm_hour, tm_struct->tm_min, tm_struct->tm_sec);

        fprintf(log_fd, "%s,del url,,%s,%s\n", now_time_str, data_url, time_str);
        fflush(log_fd);
    }

    free(data_url);
}

void add_ip_to_route_table(uint32_t ip, time_t check_time, char *url)
{
    struct in_addr rec_ip;
    rec_ip.s_addr = ip;

    struct sockaddr_in *route_addr = (struct sockaddr_in *)&route.rt_dst;
    route_addr->sin_family = AF_INET;
    route_addr->sin_addr.s_addr = rec_ip.s_addr;

    if (ioctl(route_socket, SIOCADDRT, &route) < 0) {
        printf("Ioctl can't add %s to route table :%s\n", inet_ntoa(rec_ip), strerror(errno));
    }

    stat.now_in_route_table++;

    if (log_fd) {
        char ip_str[INET_ADDRSTRLEN];
        sprintf(ip_str, "%s", inet_ntoa(rec_ip));

        char now_time_str[DATE_STR_MAX_SIZE];
        time_t now = time(NULL);
        struct tm *tm_struct = localtime(&now);
        sprintf(now_time_str, "%d:%d:%d", tm_struct->tm_hour, tm_struct->tm_min, tm_struct->tm_sec);

        char time_str[DATE_STR_MAX_SIZE];
        tm_struct = localtime(&check_time);
        sprintf(time_str, "%d:%d:%d", tm_struct->tm_hour, tm_struct->tm_min, tm_struct->tm_sec);

        fprintf(log_fd, "%s,add ip,%s,%s,%s\n", now_time_str, url, ip_str, time_str);
        fflush(log_fd);
    }
}

void update_ip_in_route_table(uint32_t ip, time_t check_time, char *url)
{
    if (log_fd) {
        struct in_addr rec_ip;
        rec_ip.s_addr = ip;

        char ip_str[INET_ADDRSTRLEN];
        sprintf(ip_str, "%s", inet_ntoa(rec_ip));

        char now_time_str[DATE_STR_MAX_SIZE];
        time_t now = time(NULL);
        struct tm *tm_struct = localtime(&now);
        sprintf(now_time_str, "%d:%d:%d", tm_struct->tm_hour, tm_struct->tm_min, tm_struct->tm_sec);

        char time_str[DATE_STR_MAX_SIZE];
        tm_struct = localtime(&check_time);
        sprintf(time_str, "%d:%d:%d", tm_struct->tm_hour, tm_struct->tm_min, tm_struct->tm_sec);

        fprintf(log_fd, "%s,copy ip,%s,%s,%s\n", now_time_str, url, ip_str, time_str);
        fflush(log_fd);
    }
}

void not_block_ip_in_route_table(uint32_t ip, time_t check_time, char *url)
{
    struct in_addr rec_ip;
    rec_ip.s_addr = ip;

    stat.route_not_block_ip_count++;

    if (log_fd) {
        char ip_str[INET_ADDRSTRLEN];
        sprintf(ip_str, "%s", inet_ntoa(rec_ip));

        char now_time_str[DATE_STR_MAX_SIZE];
        time_t now = time(NULL);
        struct tm *tm_struct = localtime(&now);
        sprintf(now_time_str, "%d:%d:%d", tm_struct->tm_hour, tm_struct->tm_min, tm_struct->tm_sec);

        char time_str[DATE_STR_MAX_SIZE];
        tm_struct = localtime(&check_time);
        sprintf(time_str, "%d:%d:%d", tm_struct->tm_hour, tm_struct->tm_min, tm_struct->tm_sec);

        fprintf(log_fd, "%s,free ip,%s,%s,%s\n", now_time_str, url, ip_str, time_str);
        fflush(log_fd);
    }
}

void del_ip_from_route_table(uint32_t ip, time_t check_time)
{
    struct in_addr rec_ip;
    rec_ip.s_addr = ip;

    struct sockaddr_in *route_addr = (struct sockaddr_in *)&route.rt_dst;
    route_addr->sin_family = AF_INET;
    route_addr->sin_addr.s_addr = rec_ip.s_addr;

    if (ioctl(route_socket, SIOCDELRT, &route) < 0) {
        printf("Ioctl can't delete %s from route table :%s\n", inet_ntoa(rec_ip), strerror(errno));
    }

    if (!check_time) {
        return;
    }

    stat.now_in_route_table--;

    if (log_fd) {
        char ip_str[INET_ADDRSTRLEN];
        sprintf(ip_str, "%s", inet_ntoa(rec_ip));

        char now_time_str[DATE_STR_MAX_SIZE];
        time_t now = time(NULL);
        struct tm *tm_struct = localtime(&now);
        sprintf(now_time_str, "%d:%d:%d", tm_struct->tm_hour, tm_struct->tm_min, tm_struct->tm_sec);

        char time_str[DATE_STR_MAX_SIZE];
        tm_struct = localtime(&check_time);
        sprintf(time_str, "%d:%d:%d", tm_struct->tm_hour, tm_struct->tm_min, tm_struct->tm_sec);

        fprintf(log_fd, "%s,del ip,,%s,%s\n", now_time_str, ip_str, time_str);
        fflush(log_fd);
    }
}

void init_route_socket(void)
{
    printf("Function init route started\n");

    route_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (route_socket < 0) {
        printf("Can't create route_socket :%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    char *VPN_MASK = "255.255.255.255";

    memset(&route, 0, sizeof(route));

    struct sockaddr_in *route_addr;
    route_addr = (struct sockaddr_in *)&route.rt_gateway;
    route_addr->sin_family = AF_INET;
    route_addr->sin_addr.s_addr = route_ip;

    route_addr = (struct sockaddr_in *)&route.rt_genmask;
    route_addr->sin_family = AF_INET;
    route_addr->sin_addr.s_addr = inet_addr(VPN_MASK);

    route.rt_flags = RTF_UP | RTF_GATEWAY;

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
        if ((gate_ip == route_ip) && (mask == inet_addr(VPN_MASK))) {
            del_ip_from_route_table(dest_ip, 0);
        }
    }

    fclose(route_fd);
}
