#include "antiblock.h"
#include "dns_ans.h"
#include "domains_read.h"
#include "net_data.h"
#include "stat.h"

#ifdef PROXY_MODE

typedef struct id_map {
    uint32_t ip;
    uint16_t port;
} id_map_t;

static id_map_t *id_map;
static int32_t repeater_DNS_socket;
static int32_t repeater_client_socket;

static void *DNS_data(void *arg)
{
    (void)arg;

    struct sockaddr_in repeater_DNS_addr, receive_DNS_addr, client_addr;

    repeater_DNS_addr = listen_addr;
    repeater_DNS_addr.sin_port = htons(ntohs(repeater_DNS_addr.sin_port) + 1);

    socklen_t receive_DNS_addr_length = sizeof(receive_DNS_addr);

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
            continue;
        }

        dns_header_t *header = (dns_header_t *)receive_msg.data;
        uint16_t id = ntohs(header->id);

        if (id_map[id].port == 0 || id_map[id].ip == 0) {
            continue;
        }

        dns_ans_check(DNS_ANS, &receive_msg, &que_domain, &ans_domain, &cname_domain);

        client_addr.sin_family = AF_INET;
        client_addr.sin_port = id_map[id].port;
        client_addr.sin_addr.s_addr = id_map[id].ip;

        id_map[id].port = 0;
        id_map[id].ip = 0;

        if (sendto(repeater_client_socket, receive_msg.data, receive_msg.size, 0,
                   (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
            printf("Can't send to client \"%s\"\n", strerror(errno));
        }
    }

    free(receive_msg.data);
    free(que_domain.data);
    free(ans_domain.data);
    free(cname_domain.data);

    return NULL;
}

static void *client_data(void *arg)
{
    (void)arg;

    struct sockaddr_in receive_client_addr;

    socklen_t receive_client_addr_length = sizeof(receive_client_addr);

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
            continue;
        }

        int32_t dns_id = 0;
#ifdef MULTIPLE_DNS
        dns_id = dns_ans_check(DNS_QUE, &receive_msg, &que_domain, NULL, NULL) + 1;
        if (dns_id < 0) {
            dns_id = 0;
        }
#endif

        dns_header_t *header = (dns_header_t *)receive_msg.data;
        uint16_t id = ntohs(header->id);

        id_map[id].ip = receive_client_addr.sin_addr.s_addr;
        id_map[id].port = receive_client_addr.sin_port;

        if (sendto(repeater_DNS_socket, receive_msg.data, receive_msg.size, 0,
                   (struct sockaddr *)&dns_addr[dns_id], sizeof(dns_addr[dns_id])) < 0) {
            printf("Can't send to DNS \"%s\"\n", strerror(errno));
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

#define PCAP_FILTER_MAX_SIZE 1000

typedef struct route_entry {
    uint32_t dst;
    uint64_t expires_at;
    int32_t gateway_index;
} route_entry_t;

static pcap_t *handle;
static array_hashmap_t ips_routes;

static array_hashmap_hash ips_hash(const void *elem_data)
{
    const route_entry_t *elem = elem_data;
    uint32_t x = elem->dst;
    x ^= x >> 16;
    x *= 0x7feb352d;
    x ^= x >> 15;
    x *= 0x846ca68b;
    x ^= x >> 16;
    return x;
}

static array_hashmap_bool ips_cmp(const void *elem_data, const void *hashmap_elem_data)
{
    const route_entry_t *elem1 = elem_data;
    const route_entry_t *elem2 = hashmap_elem_data;
    return elem1->dst == elem2->dst;
}

static array_hashmap_bool ips_del_func(const void *del_elem_data)
{
    const route_entry_t *elem = del_elem_data;

    if (elem->expires_at < last_del_expired_routes) {
        /*
        struct in_addr new_ip;
        new_ip.s_addr = elem->dst;
        printf("DEL ROUTE TO HASHMAP %s %lu %lu %d\n", inet_ntoa(new_ip), elem->expires_at, now,
               elem->gateway_index);
        */

        del_route(elem->gateway_index, elem->dst);

        return array_hashmap_del_by_func;
    } else {
        return array_hashmap_not_del_by_func;
    }
}

static array_hashmap_bool ips_on_already_in(const void *add_elem_data,
                                            const void *hashmap_elem_data)
{
    const route_entry_t *elem1 = add_elem_data;
    const route_entry_t *elem2 = hashmap_elem_data;

    if (elem1->expires_at > elem2->expires_at) {
        return array_hashmap_save_new;
    } else {
        return array_hashmap_save_old;
    }
}

int32_t add_route_to_hashmap(int32_t gateway_index, uint32_t dst, uint32_t ans_ttl)
{
    route_entry_t add_elem;
    add_elem.dst = dst;
    add_elem.expires_at = last_del_expired_routes + ans_ttl;
    add_elem.gateway_index = gateway_index;

    /*
    struct in_addr new_ip;
    new_ip.s_addr = add_elem.dst;
    printf("ADD ROUTE TO HASHMAP %s %lu %lu %d\n", inet_ntoa(new_ip), add_elem.expires_at, now,
           add_elem.gateway_index);
    */

    return array_hashmap_add_elem(ips_routes, &add_elem, NULL, ips_on_already_in);
}

void del_expired_routes_from_hashmap(void)
{
    array_hashmap_del_elem_by_func(ips_routes, ips_del_func);
}

void PCAP_mode_init(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[PCAP_FILTER_MAX_SIZE];

    struct in_addr listen_ip;
    listen_ip.s_addr = listen_addr.sin_addr.s_addr;

    sprintf(filter_exp, "udp and src %s and src port %hu", inet_ntoa(listen_ip),
            ntohs(listen_addr.sin_port));

    char *device_name = "any";

    handle = pcap_open_live(device_name, BUFSIZ, 0, 1, errbuf);
    if (handle == NULL) {
        errmsg("Can't open device %s: %s\n", device_name, errbuf);
    }
    if (pcap_datalink(handle) != DLT_LINUX_SLL) {
        errmsg("This program handles only SLL captures\n");
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) != 0) {
        errmsg("Can't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }
    if (pcap_setfilter(handle, &fp) != 0) {
        errmsg("Can't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }
    if (pcap_setnonblock(handle, 1, errbuf) != 0) {
        errmsg("Can't pcap setnonblock %s\n", errbuf);
    }

    ips_routes = array_hashmap_init(ROUTES_MAP_MAX_SIZE, 1.0, sizeof(route_entry_t));
    if (ips_routes == NULL) {
        errmsg("No free memory for ips_routes\n");
    }
    array_hashmap_set_func(ips_routes, ips_hash, ips_cmp, ips_hash, ips_cmp, ips_hash, ips_cmp);
}

int32_t PCAP_get_msg(memory_t *receive_msg)
{
    struct pcap_pkthdr *pkthdr;
    const u_char *packet;
    int32_t ret = pcap_next_ex(handle, &pkthdr, &packet);

    if (ret != 1) {
        return 0;
    }

    if (pkthdr->len != pkthdr->caplen) {
        return 0;
    }

    if (pkthdr->len < (sizeof(struct sll_header) + sizeof(struct iphdr))) {
        return 0;
    }

    struct sll_header *eth_h = (struct sll_header *)packet;
    if (eth_h->sll_protocol != htons(ETH_P_IP)) {
        return 0;
    }

    struct iphdr *iph = (struct iphdr *)((char *)eth_h + sizeof(*eth_h));
    if (iph->protocol != IPPROTO_UDP) {
        return 0;
    }

    uint32_t iphdr_len = iph->ihl * 4;
    if (iphdr_len < sizeof(struct iphdr)) {
        return 0;
    }

    if (pkthdr->len < (sizeof(struct sll_header) + iphdr_len + sizeof(struct udphdr))) {
        return 0;
    }

    struct udphdr *udph = (struct udphdr *)((char *)iph + iphdr_len);

    uint16_t udp_len = ntohs(udph->len);
    if (udp_len < sizeof(struct udphdr)) {
        return 0;
    }

    if (pkthdr->len < (sizeof(struct sll_header) + iphdr_len + udp_len)) {
        return 0;
    }

    if (udph->source != listen_addr.sin_port) {
        return 0;
    }

    receive_msg->size = udp_len - sizeof(*udph);
    receive_msg->max_size = receive_msg->size;
    receive_msg->data = (char *)udph + sizeof(*udph);

    return 1;
}

#endif
