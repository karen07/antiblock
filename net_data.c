#include "net_data.h"
#include "DNS.h"
#include "dns_ans.h"
#include "hash.h"
#include "stat.h"

id_map_t* id_map;
int32_t repeater_DNS_socket;
int32_t repeater_client_socket;

void* DNS_data(__attribute__((unused)) void* arg)
{
    struct sockaddr_in repeater_DNS_addr, receive_DNS_addr;

    repeater_DNS_addr.sin_family = AF_INET;
    repeater_DNS_addr.sin_port = htons(REPEATER_DNS_PORT);
    repeater_DNS_addr.sin_addr.s_addr = inet_addr(REPEATER_DNS_IP);

    uint32_t receive_DNS_addr_length = sizeof(receive_DNS_addr);

    struct pollfd fd_DNS;

    repeater_DNS_socket = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (repeater_DNS_socket < 0) {
        printf("Can't create socket for listen from DNS :%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (bind(repeater_DNS_socket, (struct sockaddr*)&repeater_DNS_addr,
            sizeof(repeater_DNS_addr))
        < 0) {
        printf("Can't bind to the port for listen from DNS :%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    fd_DNS.fd = repeater_DNS_socket;
    fd_DNS.events = POLLIN;

    pthread_barrier_wait(&threads_barrier);

    char* receive_msg;
    int32_t receive_msg_len = 0;
    while (1) {
        while (poll(&fd_DNS, 1, POLL_SLEEP_TIME) < 1) { }

        if ((fd_DNS.revents & POLLIN) == 0) {
            continue;
        }

        fd_DNS.revents = 0;

        int32_t remain_div = packets_ring_buffer_end % packets_ring_buffer_size;
        if (packets_ring_buffer[remain_div].packet_size > 0) {
            send_packet(remain_div);
            stat.packets_ring_buffer_error++;
        }
        packets_ring_buffer[remain_div].packet_size = 0;

        receive_msg = packets_ring_buffer[remain_div].packet;
        receive_msg_len = recvfrom(repeater_DNS_socket, receive_msg, PACKET_MAX_SIZE, 0,
            (struct sockaddr*)&receive_DNS_addr, &receive_DNS_addr_length);

        if (receive_msg_len < (int32_t)sizeof(dns_header_t)) {
            continue;
        }

        dns_header_t* header = (dns_header_t*)receive_msg;

        uint16_t id = ntohs(header->id);
        uint16_t flags = ntohs(header->flags);

        if ((flags & FIRST_BIT) == 0) {
            continue;
        }

        struct timeval now_timeval;
        gettimeofday(&now_timeval, NULL);
        uint64_t now_us = now_timeval.tv_sec * MIL + now_timeval.tv_usec;
        uint64_t delta_t = ID_CHECK_TIME * MIL;
        if (now_us > id_map[id].send_time + delta_t) {
            stat.from_dns_error++;
            continue;
        }

        char* url_start = &receive_msg[sizeof(dns_header_t)];
        uint32_t url_hash = djb33_hash_len(url_start, receive_msg_len - sizeof(dns_header_t));
        if (url_hash != id_map[id].url_hash) {
            stat.from_dns_error++;
            continue;
        }

        stat.rec_from_dns++;

        packets_ring_buffer[remain_div].packet_size = receive_msg_len;

        pthread_mutex_lock(&packets_ring_buffer_mutex);
        packets_ring_buffer_end++;
        pthread_cond_signal(&packets_ring_buffer_step);
        pthread_mutex_unlock(&packets_ring_buffer_mutex);
    }

    return NULL;
}

void send_packet(int32_t packets_num)
{
    struct sockaddr_in client_addr;
    char* receive_msg;
    int32_t receive_msg_len = 0;

    receive_msg = packets_ring_buffer[packets_num].packet;
    receive_msg_len = packets_ring_buffer[packets_num].packet_size;

    dns_header_t* header = (dns_header_t*)receive_msg;

    uint16_t id = ntohs(header->id);

    header->id = htons(id_map[id].client_id);
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = id_map[id].port;
    client_addr.sin_addr.s_addr = id_map[id].ip;

    id_map[id].send_time = 0;
    id_map[id].url_hash = 0;

    if (sendto(repeater_client_socket, receive_msg, receive_msg_len, 0,
            (struct sockaddr*)&client_addr, sizeof(client_addr))
        < 0) {
        stat.send_to_client_error++;
        printf("Can't send to client %s\n", strerror(errno));
    }
}

void* client_data(__attribute__((unused)) void* arg)
{
    struct sockaddr_in repeater_client_addr, dns_addr, receive_client_addr;

    repeater_client_addr.sin_family = AF_INET;
    repeater_client_addr.sin_port = htons(REPEATER_CLIENT_PORT);
    repeater_client_addr.sin_addr.s_addr = inet_addr(REPEATER_CLIENT_IP);

    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(DNS_PORT);
    dns_addr.sin_addr.s_addr = inet_addr(dns_ip);

    uint32_t receive_client_addr_length = sizeof(receive_client_addr);

    repeater_client_socket = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (repeater_client_socket < 0) {
        printf("Can't create socket for listen from client :%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (bind(repeater_client_socket, (struct sockaddr*)&repeater_client_addr,
            sizeof(repeater_client_addr))
        < 0) {
        printf("Can't bind to the port for listen from client :%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct pollfd fd_in;
    fd_in.fd = repeater_client_socket;
    fd_in.events = POLLIN;

    pthread_barrier_wait(&threads_barrier);

    uint16_t new_id = 0;

    packet_t receive_msg;

    while (1) {
        while (poll(&fd_in, 1, POLL_SLEEP_TIME) < 1) { }

        if ((fd_in.revents & POLLIN) == 0) {
            continue;
        }

        fd_in.revents = 0;

        receive_msg.packet_size = recvfrom(repeater_client_socket, receive_msg.packet, PACKET_MAX_SIZE, 0,
            (struct sockaddr*)&receive_client_addr, &receive_client_addr_length);

        if (receive_msg.packet_size < (int32_t)sizeof(dns_header_t)) {
            continue;
        }

        dns_header_t* header = (dns_header_t*)receive_msg.packet;

        uint16_t id = ntohs(header->id);
        uint16_t flags = ntohs(header->flags);

        if (flags & FIRST_BIT) {
            continue;
        }

        struct timeval now_timeval;
        gettimeofday(&now_timeval, NULL);
        uint64_t now_us = now_timeval.tv_sec * MIL + now_timeval.tv_usec;
        uint64_t delta_t = (ID_CHECK_TIME + 1) * MIL;
        if (now_us < id_map[new_id].send_time + delta_t) {
            stat.from_client_error++;
            new_id = (new_id + 1) % ID_MAP_MAX_SIZE;
            continue;
        }

        stat.rec_from_client++;

        header->id = htons(new_id);

        char* url_start = &receive_msg.packet[sizeof(dns_header_t)];
        id_map[new_id].url_hash = djb33_hash_len(url_start, receive_msg.packet_size - sizeof(dns_header_t));
        id_map[new_id].ip = receive_client_addr.sin_addr.s_addr;
        id_map[new_id].port = receive_client_addr.sin_port;
        id_map[new_id].client_id = id;
        gettimeofday(&now_timeval, NULL);
        now_us = now_timeval.tv_sec * MIL + now_timeval.tv_usec;
        id_map[new_id].send_time = now_us;

        new_id = (new_id + 1) % ID_MAP_MAX_SIZE;

        if (sendto(repeater_DNS_socket, receive_msg.packet, receive_msg.packet_size, 0,
                (struct sockaddr*)&dns_addr, sizeof(dns_addr))
            < 0) {
            stat.send_to_dns_error++;
            printf("Can't send to DNS :%s\n", strerror(errno));
        }
    }

    return NULL;
}

void init_data_threads(void)
{
    id_map = malloc(ID_MAP_MAX_SIZE * sizeof(id_map_t));
    if (id_map == NULL) {
        printf("No free memory for id_map\n");
        exit(EXIT_FAILURE);
    }
    memset(id_map, 0, ID_MAP_MAX_SIZE * sizeof(id_map_t));

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
