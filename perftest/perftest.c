#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

typedef struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t quest;
    uint16_t ans;
    uint16_t auth;
    uint16_t add;
} __attribute__((packed)) dns_header_t;

typedef struct end_name {
    uint16_t type;
    uint16_t class;
} __attribute__((packed)) end_name_t;

int main(void)
{
    FILE* fp = fopen("top.csv", "r");
    if (!fp) {
        printf("Error opening file top.csv\n");
        return 0;
    }

    struct sockaddr_in repeater_addr, dns_addr;

    repeater_addr.sin_family = AF_INET;
    repeater_addr.sin_port = htons(5052);
    repeater_addr.sin_addr.s_addr = inet_addr("0.0.0.0");

    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(5053);
    dns_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    int repeater_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (repeater_socket < 0) {
        printf("Error:Error while creating socket %s\n", strerror(errno));
        return 0;
    }

    if (bind(repeater_socket, (struct sockaddr*)&repeater_addr, sizeof(repeater_addr)) < 0) {
        printf("Error:Couldn't bind to the port %s\n", strerror(errno));
        return 0;
    }

    char packet[10000], line_buf[10000];
    int line_count = 0;

    while (fscanf(fp, "%s", line_buf) != EOF) {
        if (line_count % 10000 == 0) {
            time_t now = time(NULL);
            struct tm* tm_struct = localtime(&now);
            printf("\nSended %d %d:%d\n", line_count, tm_struct->tm_min, tm_struct->tm_sec);
        }

        line_count++;

        dns_header_t* header = (dns_header_t*)packet;
        uint16_t id = line_count;
        header->id = htons(id);
        header->flags = htons(0x0100);
        header->quest = htons(1);
        header->ans = htons(0);
        header->auth = htons(0);
        header->add = htons(0);

        int k = 0;
        char* dot_pos_new = line_buf;
        char* dot_pos_old = line_buf;
        while ((dot_pos_new = strchr(dot_pos_old + 1, '.')) != NULL) {
            dot_pos_new++;
            packet[12 + k] = dot_pos_new - dot_pos_old - 1;
            memcpy(&packet[12 + k + 1], dot_pos_old, packet[12 + k]);
            k += packet[12 + k] + 1;
            dot_pos_old = dot_pos_new;
        }

        packet[12 + k] = strlen(line_buf) - k;
        memcpy(&packet[12 + k + 1], &line_buf[k], packet[12 + k]);
        k += packet[12 + k] + 1;
        packet[12 + k] = 0;

        end_name_t* end_name = (end_name_t*)&packet[12 + k + 1];
        end_name->type = htons(1);
        end_name->class = htons(1);

        usleep(500);

        if (sendto(repeater_socket, packet, 12 + k + 5, 0, (struct sockaddr*)&dns_addr, sizeof(dns_addr)) < 0) {
            printf("Error:Can't send %s\n", strerror(errno));
        }
    }

    time_t now = time(NULL);
    struct tm* tm_struct = localtime(&now);
    printf("\nSended %d %d:%d\n", line_count, tm_struct->tm_min, tm_struct->tm_sec);

    return 0;
}
