#include "antiblock.h"
#include "config.h"
#include "const.h"
#include "dns_ans.h"
#include "hash.h"
#include "net_data.h"
#include "stat.h"
#include "tun.h"
#include "urls_read.h"

static id_map_t *id_map;
static int32_t repeater_DNS_socket;
static int32_t repeater_client_socket;

memory_t que_url;
memory_t ans_url;
memory_t cname_url;

static void DNS_data_catch_function(__attribute__((unused)) int signo)
{
    printf("SIGSEGV catched DNS_data\n");
    fflush(stdout);
    if (stat_fd) {
        fflush(stat_fd);
    }
    if (log_fd) {
        fflush(log_fd);
    }
    exit(EXIT_FAILURE);
}

static void *DNS_data(__attribute__((unused)) void *arg)
{
    printf("Thread DNS data started\n");

    if (signal(SIGSEGV, DNS_data_catch_function) == SIG_ERR) {
        printf("Can't set signal handler DNS_data\n");
        exit(EXIT_FAILURE);
    }

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

    memory_t receive_msg;
    receive_msg.size = 0;
    receive_msg.max_size = PACKET_MAX_SIZE;
    receive_msg.data = (char *)malloc(receive_msg.max_size * sizeof(char));

    if (receive_msg.data == 0) {
        printf("No free memory for receive_msg from DNS\n");
        exit(EXIT_FAILURE);
    }

    que_url.size = 0;
    que_url.max_size = URL_MAX_SIZE;
    que_url.data = (char *)malloc(que_url.max_size * sizeof(char));

    if (que_url.data == 0) {
        printf("No free memory for que_url\n");
        exit(EXIT_FAILURE);
    }

    ans_url.size = 0;
    ans_url.max_size = URL_MAX_SIZE;
    ans_url.data = (char *)malloc(ans_url.max_size * sizeof(char));

    if (ans_url.data == 0) {
        printf("No free memory for ans_url\n");
        exit(EXIT_FAILURE);
    }

    cname_url.size = 0;
    cname_url.max_size = URL_MAX_SIZE;
    cname_url.data = (char *)malloc(cname_url.max_size * sizeof(char));

    if (cname_url.data == 0) {
        printf("No free memory for cname_url\n");
        exit(EXIT_FAILURE);
    }

    FILE *log_fd_tmp = log_fd;
    log_fd = NULL;

    char correct_test[] = { 0x0f, 0x32, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
                            0x03, 0x79, 0x74, 0x33, 0x05, 0x67, 0x67, 0x70, 0x68, 0x74, 0x03, 0x63,
                            0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00,
                            0x01, 0x00, 0x00, 0x01, 0x09, 0x00, 0x18, 0x0c, 0x77, 0x69, 0x64, 0x65,
                            0x2d, 0x79, 0x6f, 0x75, 0x74, 0x75, 0x62, 0x65, 0x01, 0x6c, 0x06, 0x67,
                            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0xc0, 0x16, 0xc0, 0x2b, 0x00, 0x01, 0x00,
                            0x01, 0x00, 0x00, 0x01, 0x09, 0x00, 0x04, 0x40, 0xe9, 0xa1, 0xc6 };

    receive_msg.size = sizeof(correct_test);
    memcpy(receive_msg.data, correct_test, receive_msg.size);
    if (dns_ans_check(&receive_msg) != 0) {
        printf("Test correct fail\n");
        exit(EXIT_FAILURE);
    }

    receive_msg.size = 11;
    if (dns_ans_check(&receive_msg) != 1) {
        printf("Test DNS header size fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.size = sizeof(correct_test);

    receive_msg.data[2] = 1;
    if (dns_ans_check(&receive_msg) != 2) {
        printf("Test DNS flag fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.data[2] = correct_test[2];

    receive_msg.data[5] = 2;
    if (dns_ans_check(&receive_msg) != 3) {
        printf("Test DNS quest count fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.data[5] = correct_test[5];

    receive_msg.data[7] = 0;
    if (dns_ans_check(&receive_msg) != 4) {
        printf("Test DNS ans count fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.data[7] = correct_test[7];

    receive_msg.size = 26;
    if (dns_ans_check(&receive_msg) != 5) {
        printf("Test DNS que url fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.size = sizeof(correct_test);

    receive_msg.size = 30;
    if (dns_ans_check(&receive_msg) != 6) {
        printf("Test DNS header que size fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.size = sizeof(correct_test);

    receive_msg.size = 32;
    if (dns_ans_check(&receive_msg) != 7) {
        printf("Test DNS ans url fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.size = sizeof(correct_test);

    receive_msg.size = 42;
    if (dns_ans_check(&receive_msg) != 8) {
        printf("Test DNS header ans size fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.size = sizeof(correct_test);

    receive_msg.size = 66;
    if (dns_ans_check(&receive_msg) != 9) {
        printf("Test DNS header ans data size fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.size = sizeof(correct_test);

    receive_msg.data[58] = 0x3F;
    if (dns_ans_check(&receive_msg) != 10) {
        printf("Test DNS cname url fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.data[58] = correct_test[58];

    receive_msg.size = sizeof(correct_test) + 1;
    if (dns_ans_check(&receive_msg) != 11) {
        printf("Test DNS end fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.size = sizeof(correct_test);

    log_fd = log_fd_tmp;

    /*receive_msg.data[32] = 0x43;
    receive_msg.data[68] = 0x1F;
    if (dns_ans_check(&receive_msg) != -1) {
        printf("Test endless jumping fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.data[32] = correct_test[32];
    receive_msg.data[68] = correct_test[68];*/

    pthread_barrier_wait(&threads_barrier);

    while (true) {
        receive_msg.size = recvfrom(repeater_DNS_socket, receive_msg.data, receive_msg.max_size, 0,
                                    (struct sockaddr *)&receive_DNS_addr, &receive_DNS_addr_length);

        if (receive_msg.size < (int32_t)sizeof(dns_header_t)) {
            stat.sended_to_client_error++;
            continue;
        }

        dns_header_t *header = (dns_header_t *)receive_msg.data;
        uint16_t id = ntohs(header->id);

        if (id_map[id].port == 0 || id_map[id].ip == 0) {
            stat.sended_to_client_error++;
            continue;
        }

        dns_ans_check(&receive_msg);

        client_addr.sin_family = AF_INET;
        client_addr.sin_port = id_map[id].port;
        client_addr.sin_addr.s_addr = id_map[id].ip;

        id_map[id].port = 0;
        id_map[id].ip = 0;

        if (sendto(repeater_client_socket, receive_msg.data, receive_msg.size, 0,
                   (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
            stat.sended_to_client_error++;
            printf("Can't send to client %s\n", strerror(errno));
        } else {
            stat.sended_to_client++;
        }
    }

    return NULL;
}

static void client_data_catch_function(__attribute__((unused)) int signo)
{
    printf("SIGSEGV catched client_data\n");
    fflush(stdout);
    if (stat_fd) {
        fflush(stat_fd);
    }
    if (log_fd) {
        fflush(log_fd);
    }
    exit(EXIT_FAILURE);
}

static void *client_data(__attribute__((unused)) void *arg)
{
    printf("Thread client data started\n");

    if (signal(SIGSEGV, client_data_catch_function) == SIG_ERR) {
        printf("Can't set signal handler client_data\n");
        exit(EXIT_FAILURE);
    }

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

    memory_t receive_msg;
    receive_msg.size = 0;
    receive_msg.max_size = PACKET_MAX_SIZE;
    receive_msg.data = (char *)malloc(receive_msg.max_size * sizeof(char));

    if (receive_msg.data == 0) {
        printf("No free memory for receive_msg from client\n");
        exit(EXIT_FAILURE);
    }

    pthread_barrier_wait(&threads_barrier);

    while (true) {
        receive_msg.size = recvfrom(repeater_client_socket, receive_msg.data, receive_msg.max_size,
                                    0, (struct sockaddr *)&receive_client_addr,
                                    &receive_client_addr_length);

        if (receive_msg.size < (int32_t)sizeof(dns_header_t)) {
            stat.sended_to_dns_error++;
            continue;
        }

        dns_header_t *header = (dns_header_t *)receive_msg.data;
        uint16_t id = ntohs(header->id);

        id_map[id].ip = receive_client_addr.sin_addr.s_addr;
        id_map[id].port = receive_client_addr.sin_port;

        if (sendto(repeater_DNS_socket, receive_msg.data, receive_msg.size, 0,
                   (struct sockaddr *)&dns_addr, sizeof(dns_addr)) < 0) {
            stat.sended_to_dns_error++;
            printf("Can't send to DNS :%s\n", strerror(errno));
        } else {
            stat.sended_to_dns++;
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
