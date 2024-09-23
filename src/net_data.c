#include "antiblock.h"
#include "config.h"
#include "const.h"
#include "dns_ans.h"
#include "hash.h"
#include "net_data.h"
#include "stat.h"
#include "tun.h"
#include "urls_read.h"

id_map_t *id_map;
int32_t repeater_DNS_socket;
int32_t repeater_client_socket;

static void *DNS_data(__attribute__((unused)) void *arg)
{
    printf("Thread DNS data started\n");

    struct sockaddr_in repeater_DNS_addr, receive_DNS_addr, client_addr;

    repeater_DNS_addr.sin_family = AF_INET;
    repeater_DNS_addr.sin_port = htons(listen_port + 1);
    repeater_DNS_addr.sin_addr.s_addr = listen_ip;

    uint32_t receive_DNS_addr_length = sizeof(receive_DNS_addr);

    repeater_DNS_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (repeater_DNS_socket < 0) {
        printf("Can't create socket for listen from DNS :%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (bind(repeater_DNS_socket, (struct sockaddr *)&repeater_DNS_addr,
             sizeof(repeater_DNS_addr)) < 0) {
        printf("Can't bind to the port for listen from DNS :%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    pthread_barrier_wait(&threads_barrier);

    packet_t receive_msg;

    while (true) {
        receive_msg.packet_size = recvfrom(repeater_DNS_socket, receive_msg.packet, PACKET_MAX_SIZE,
                                           0, (struct sockaddr *)&receive_DNS_addr,
                                           &receive_DNS_addr_length);

        if (receive_msg.packet_size < (int32_t)sizeof(dns_header_t)) {
            continue;
        }

        dns_header_t *header = (dns_header_t *)receive_msg.packet;
        uint16_t id = ntohs(header->id);

        dns_ans_check(&receive_msg);

        client_addr.sin_family = AF_INET;
        client_addr.sin_port = id_map[id].port;
        client_addr.sin_addr.s_addr = id_map[id].ip;

        if (sendto(repeater_client_socket, receive_msg.packet, receive_msg.packet_size, 0,
                   (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
            stat.send_to_client_error++;
            printf("Can't send to client %s\n", strerror(errno));
        } else {
            stat.rec_from_dns++;
        }
    }

    return NULL;
}

static void *client_data(__attribute__((unused)) void *arg)
{
    printf("Thread client data started\n");

    struct sockaddr_in repeater_client_addr, dns_addr, receive_client_addr;

    repeater_client_addr.sin_family = AF_INET;
    repeater_client_addr.sin_port = htons(listen_port);
    repeater_client_addr.sin_addr.s_addr = listen_ip;

    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(dns_port);
    dns_addr.sin_addr.s_addr = dns_ip;

    uint32_t receive_client_addr_length = sizeof(receive_client_addr);

    repeater_client_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (repeater_client_socket < 0) {
        printf("Can't create socket for listen from client :%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (bind(repeater_client_socket, (struct sockaddr *)&repeater_client_addr,
             sizeof(repeater_client_addr)) < 0) {
        printf("Can't bind to the port for listen from client :%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    pthread_barrier_wait(&threads_barrier);

    packet_t receive_msg;

    while (true) {
        receive_msg.packet_size =
            recvfrom(repeater_client_socket, receive_msg.packet, PACKET_MAX_SIZE, 0,
                     (struct sockaddr *)&receive_client_addr, &receive_client_addr_length);

        if (receive_msg.packet_size < (int32_t)sizeof(dns_header_t)) {
            continue;
        }

        dns_header_t *header = (dns_header_t *)receive_msg.packet;
        uint16_t id = ntohs(header->id);

        id_map[id].ip = receive_client_addr.sin_addr.s_addr;
        id_map[id].port = receive_client_addr.sin_port;

        if (sendto(repeater_DNS_socket, receive_msg.packet, receive_msg.packet_size, 0,
                   (struct sockaddr *)&dns_addr, sizeof(dns_addr)) < 0) {
            stat.send_to_dns_error++;
            printf("Can't send to DNS :%s\n", strerror(errno));
        } else {
            stat.rec_from_client++;
        }
    }

    return NULL;
}

void init_net_data_threads(void)
{
    id_map = malloc((USHRT_MAX + 1) * sizeof(id_map_t));
    if (id_map == NULL) {
        printf("No free memory for id_map\n");
        exit(EXIT_FAILURE);
    }
    memset(id_map, 0, (USHRT_MAX + 1) * sizeof(id_map_t));

    pthread_t client_data_thread;
    if (pthread_create(&client_data_thread, NULL, client_data, NULL)) {
        printf("Can't create client_data_thread\n");
        exit(EXIT_FAILURE);
    }

    if (pthread_detach(client_data_thread)) {
        printf("Can't detach client_data_thread\n");
        exit(EXIT_FAILURE);
    }

    pthread_t DNS_data_thread;
    if (pthread_create(&DNS_data_thread, NULL, DNS_data, NULL)) {
        printf("Can't create DNS_data_thread\n");
        exit(EXIT_FAILURE);
    }

    if (pthread_detach(DNS_data_thread)) {
        printf("Can't detach DNS_data_thread\n");
        exit(EXIT_FAILURE);
    }
}
