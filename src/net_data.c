#include "antiblock.h"
#include "config.h"
#include "const.h"
#include "dns_ans.h"
#include "hash.h"
#include "net_data.h"
#include "stat.h"
#include "tun.h"
#include "domains_read.h"

#ifndef PCAP_MODE

static id_map_t *id_map;
static int32_t repeater_DNS_socket;
static int32_t repeater_client_socket;

static void *DNS_data(__attribute__((unused)) void *arg)
{
    struct sockaddr_in repeater_DNS_addr, receive_DNS_addr, client_addr;

    repeater_DNS_addr = listen_addr;
    repeater_DNS_addr.sin_port = htons(ntohs(repeater_DNS_addr.sin_port) + 1);

    uint32_t receive_DNS_addr_length = sizeof(receive_DNS_addr);

    repeater_DNS_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (repeater_DNS_socket < 0) {
        errmsg("Can't create socket for listen from DNS \"%s\"\n", strerror(errno));
    }

    if (bind(repeater_DNS_socket, (struct sockaddr *)&repeater_DNS_addr,
             sizeof(repeater_DNS_addr)) < 0) {
        errmsg("Can't bind to the port for listen from DNS \"%s\"\n", strerror(errno));
    }

    memory_t receive_msg;
    receive_msg.size = 0;
    receive_msg.max_size = PACKET_MAX_SIZE;
    receive_msg.data = (char *)malloc(receive_msg.max_size * sizeof(char));
    if (receive_msg.data == 0) {
        errmsg("No free memory for receive_msg from DNS\n");
    }

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

    pthread_barrier_wait(&threads_barrier);

    while (true) {
        receive_msg.size = recvfrom(repeater_DNS_socket, receive_msg.data, receive_msg.max_size, 0,
                                    (struct sockaddr *)&receive_DNS_addr, &receive_DNS_addr_length);

        if (receive_msg.size < (int32_t)sizeof(dns_header_t)) {
            statistics_data.sended_to_client_error++;
            continue;
        }

        dns_header_t *header = (dns_header_t *)receive_msg.data;
        uint16_t id = ntohs(header->id);

        if (id_map[id].port == 0 || id_map[id].ip == 0) {
            statistics_data.sended_to_client_error++;
            continue;
        }

        dns_ans_check(&receive_msg, &que_domain, &ans_domain, &cname_domain);

        client_addr.sin_family = AF_INET;
        client_addr.sin_port = id_map[id].port;
        client_addr.sin_addr.s_addr = id_map[id].ip;

        id_map[id].port = 0;
        id_map[id].ip = 0;

        if (sendto(repeater_client_socket, receive_msg.data, receive_msg.size, 0,
                   (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
            statistics_data.sended_to_client_error++;
            printf("Can't send to client \"%s\"\n", strerror(errno));
        } else {
            statistics_data.sended_to_client++;
        }
    }

    free(receive_msg.data);
    free(que_domain.data);
    free(ans_domain.data);
    free(cname_domain.data);

    return NULL;
}

static void *client_data(__attribute__((unused)) void *arg)
{
    struct sockaddr_in receive_client_addr;

    uint32_t receive_client_addr_length = sizeof(receive_client_addr);

    repeater_client_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (repeater_client_socket < 0) {
        errmsg("Can't create socket for listen from client \"%s\"\n", strerror(errno));
    }

    if (bind(repeater_client_socket, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        errmsg("Can't bind to the port for listen from client \"%s\"\n", strerror(errno));
    }

    memory_t receive_msg;
    receive_msg.size = 0;
    receive_msg.max_size = PACKET_MAX_SIZE;
    receive_msg.data = (char *)malloc(receive_msg.max_size * sizeof(char));
    if (receive_msg.data == 0) {
        errmsg("No free memory for receive_msg from client\n");
    }

    memory_t que_domain;
    que_domain.size = 0;
    que_domain.max_size = DOMAIN_MAX_SIZE;
    que_domain.data = (char *)malloc(que_domain.max_size * sizeof(char));
    if (que_domain.data == 0) {
        errmsg("No free memory for que_domain\n");
    }

    pthread_barrier_wait(&threads_barrier);

    while (true) {
        receive_msg.size = recvfrom(repeater_client_socket, receive_msg.data, receive_msg.max_size,
                                    0, (struct sockaddr *)&receive_client_addr,
                                    &receive_client_addr_length);

        if (receive_msg.size < (int32_t)sizeof(dns_header_t)) {
            statistics_data.sended_to_dns_error++;
            continue;
        }

        int32_t dns_id;
        dns_id = dns_ans_check(&receive_msg, &que_domain, NULL, NULL) + 1;

        if (dns_id < 0) {
            dns_id = 0;
        }

        dns_header_t *header = (dns_header_t *)receive_msg.data;
        uint16_t id = ntohs(header->id);

        id_map[id].ip = receive_client_addr.sin_addr.s_addr;
        id_map[id].port = receive_client_addr.sin_port;

        if (sendto(repeater_DNS_socket, receive_msg.data, receive_msg.size, 0,
                   (struct sockaddr *)&dns_addr[dns_id], sizeof(dns_addr[dns_id])) < 0) {
            statistics_data.sended_to_dns_error++;
            printf("Can't send to DNS \"%s\"\n", strerror(errno));
        } else {
            statistics_data.sended_to_dns++;
        }
    }

    free(receive_msg.data);

    return NULL;
}

void init_net_data_threads(void)
{
    id_map = malloc((USHRT_MAX + 1) * sizeof(id_map_t));
    if (id_map == NULL) {
        errmsg("No free memory for id_map\n");
    }
    memset(id_map, 0, (USHRT_MAX + 1) * sizeof(id_map_t));

    pthread_t client_data_thread;
    if (pthread_create(&client_data_thread, NULL, client_data, NULL)) {
        errmsg("Can't create client_data_thread\n");
    }

    if (pthread_detach(client_data_thread)) {
        errmsg("Can't detach client_data_thread\n");
    }

    pthread_t DNS_data_thread;
    if (pthread_create(&DNS_data_thread, NULL, DNS_data, NULL)) {
        errmsg("Can't create DNS_data_thread\n");
    }

    if (pthread_detach(DNS_data_thread)) {
        errmsg("Can't detach DNS_data_thread\n");
    }
}

#else

#define DNS_port 53

memory_t receive_msg;
memory_t que_domain;
memory_t ans_domain;
memory_t cname_domain;

static void callback_sll(__attribute__((unused)) u_char *useless, const struct pcap_pkthdr *pkthdr,
                         const u_char *packet)
{
    if (pkthdr->len <
        (int32_t)(sizeof(struct sll_header) + sizeof(struct iphdr) + sizeof(struct udphdr))) {
        return;
    }

    struct sll_header *eth_h = (struct sll_header *)packet;
    if (eth_h->sll_protocol != htons(ETH_P_IP)) {
        return;
    }

    struct iphdr *iph = (struct iphdr *)((char *)eth_h + sizeof(*eth_h));
    if (iph->protocol != IPPROTO_UDP) {
        return;
    }

    struct udphdr *udph = (struct udphdr *)((char *)iph + sizeof(*iph));
    if (udph->source != htons(DNS_port)) {
        return;
    }

    receive_msg.size = ntohs(udph->len) - sizeof(*udph);
    receive_msg.data = (char *)udph + sizeof(*udph);

    dns_ans_check(&receive_msg, &que_domain, &ans_domain, &cname_domain);
}

static void callback_eth(__attribute__((unused)) u_char *useless, const struct pcap_pkthdr *pkthdr,
                         const u_char *packet)
{
    if (pkthdr->len <
        (int32_t)(sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))) {
        return;
    }

    struct ethhdr *eth_h = (struct ethhdr *)packet;
    if (eth_h->h_proto != htons(ETH_P_IP)) {
        return;
    }

    struct iphdr *iph = (struct iphdr *)((char *)eth_h + sizeof(*eth_h));
    if (iph->protocol != IPPROTO_UDP) {
        return;
    }

    struct udphdr *udph = (struct udphdr *)((char *)iph + sizeof(*iph));
    if (udph->source != htons(DNS_port)) {
        return;
    }

    receive_msg.size = ntohs(udph->len) - sizeof(*udph);
    receive_msg.data = (char *)udph + sizeof(*udph);

    dns_ans_check(&receive_msg, &que_domain, &ans_domain, &cname_domain);
}

static void *PCAP(__attribute__((unused)) void *arg)
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[1000];

    struct in_addr listen_ip;
    listen_ip.s_addr = listen_addr.sin_addr.s_addr;

    sprintf(filter_exp, "udp and src %s and src port %hu", inet_ntoa(listen_ip),
            htons(listen_addr.sin_port));

    handle = pcap_open_live(sniffer_interface, BUFSIZ, 0, 1, errbuf);
    if (handle == NULL) {
        errmsg("Can't open device %s: %s\n", sniffer_interface, errbuf);
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) != 0) {
        errmsg("Can't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }
    if (pcap_setfilter(handle, &fp) != 0) {
        errmsg("Can't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }

    receive_msg.size = 0;
    receive_msg.max_size = PACKET_MAX_SIZE;
    receive_msg.data = (char *)malloc(receive_msg.max_size * sizeof(char));
    if (receive_msg.data == 0) {
        errmsg("No free memory for receive_msg from DNS\n");
    }

    que_domain.size = 0;
    que_domain.max_size = DOMAIN_MAX_SIZE;
    que_domain.data = (char *)malloc(que_domain.max_size * sizeof(char));
    if (que_domain.data == 0) {
        errmsg("No free memory for que_domain\n");
    }

    ans_domain.size = 0;
    ans_domain.max_size = DOMAIN_MAX_SIZE;
    ans_domain.data = (char *)malloc(ans_domain.max_size * sizeof(char));
    if (ans_domain.data == 0) {
        errmsg("No free memory for ans_domain\n");
    }

    cname_domain.size = 0;
    cname_domain.max_size = DOMAIN_MAX_SIZE;
    cname_domain.data = (char *)malloc(cname_domain.max_size * sizeof(char));
    if (cname_domain.data == 0) {
        errmsg("No free memory for cname_domain\n");
    }

    if (!strcmp(sniffer_interface, "any")) {
        pcap_loop(handle, 0, callback_sll, NULL);
    } else {
        pcap_loop(handle, 0, callback_eth, NULL);
    }

    return NULL;
}

void init_net_data_threads(void)
{
    pthread_t PCAP_thread;
    if (pthread_create(&PCAP_thread, NULL, PCAP, NULL)) {
        errmsg("Can't create client_data_thread\n");
    }

    if (pthread_detach(PCAP_thread)) {
        errmsg("Can't detach client_data_thread\n");
    }
}

#endif
