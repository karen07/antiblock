#include "tun.h"
#include "hash.h"

const array_hashmap_t* ip_ip_map_struct;
const array_hashmap_t* nat_map_struct;

uint32_t start_subnet_ip;
uint32_t end_subnet_ip;

int tun_alloc(char* dev, int flags)
{
    struct ifreq ifr;
    int fd, err;
    char* clonedev = "/dev/net/tun";

    if ((fd = open(clonedev, O_RDWR)) < 0) {
        perror("Opening /dev/net/tun");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;

    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if ((err = ioctl(fd, TUNSETIFF, (void*)&ifr)) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return err;
    }

    strcpy(dev, ifr.ifr_name);

    return fd;
}

unsigned short checksum(const char* buf, unsigned size)
{
    unsigned sum = 0, i;

    for (i = 0; i < size - 1; i += 2) {
        unsigned short word16 = *(unsigned short*)&buf[i];
        sum += word16;
    }

    if (size & 1) {
        unsigned short word16 = (unsigned char)buf[i];
        sum += word16;
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}

uint32_t ip_ip_hash(const void* void_elem)
{
    const ip_ip_map_t* elem = void_elem;
    return elem->ip_local;
}

int32_t ip_ip_cmp(const void* void_elem1, const void* void_elem2)
{
    const ip_ip_map_t* elem1 = void_elem1;
    const ip_ip_map_t* elem2 = void_elem2;

    if (elem1->ip_local == elem2->ip_local) {
        return 1;
    } else {
        return 0;
    }
}

int32_t ip_ip_on_collision(const void* void_elem1, const void* void_elem2)
{
    return 1;
}

uint32_t nat_hash(const void* void_elem)
{
    const nat_map_t* elem = void_elem;
    return djb33_hash_len((const char*)elem, 6);
}

int32_t nat_cmp(const void* void_elem1, const void* void_elem2)
{
    const nat_map_t* elem1 = void_elem1;
    const nat_map_t* elem2 = void_elem2;

    if ((elem1->dst_ip == elem2->dst_ip) && (elem1->src_port == elem2->src_port)) {
        return 1;
    } else {
        return 0;
    }
}

void* tun(__attribute__((unused)) void* arg)
{
    int tap_fd;
    char buffer[4096];
    char pseudogram[4096];

    tap_fd = tun_alloc(tun_name, IFF_TUN);

    if (tap_fd < 0) {
        printf("Can't allocate tun interface\n");
        exit(EXIT_FAILURE);
    }

    while (1) {
        int nread = read(tap_fd, buffer, sizeof(buffer));
        if (nread < 0) {
            printf("Can't read from interface\n");
            exit(EXIT_FAILURE);
        }

        tun_header_t* tun_header = (tun_header_t*)buffer;

        int proto_L3 = ntohs(tun_header->proto);
        if (proto_L3 != ETH_P_IP) {
            continue;
        }

        char* L3_start_pointer = buffer + sizeof(tun_header_t);
        struct iphdr* iph = (struct iphdr*)L3_start_pointer;

        char proto_L4 = iph->protocol;
        if ((proto_L4 != IPPROTO_TCP) && (proto_L4 != IPPROTO_UDP)) {
            continue;
        }

        uint16_t src_port;
        uint16_t dst_port;

        char* L4_start_pointer = L3_start_pointer + sizeof(struct iphdr);
        if (proto_L4 == IPPROTO_TCP) {
            struct tcphdr* tcph = (struct tcphdr*)L4_start_pointer;

            src_port = tcph->source;
            dst_port = tcph->dest;

            tcph->check = 0;
        }

        if (proto_L4 == IPPROTO_UDP) {
            struct udphdr* udph = (struct udphdr*)L4_start_pointer;

            src_port = udph->source;
            dst_port = udph->dest;

            udph->check = 0;
        }

        int32_t iph_daddr_h = ntohl(iph->daddr);
        int32_t mask = 1;
        mask <<= 32 - (tun_prefix + 1);

        if (iph_daddr_h & mask) {
            nat_map_t find_elem;
            find_elem.dst_ip = iph->saddr;
            find_elem.src_port = dst_port;

            nat_map_t res_elem;
            int32_t find_elem_flag = array_hashmap_find_elem(nat_map_struct, &find_elem, &res_elem);

            if (find_elem_flag != 1) {
                continue;
            }

            iph_daddr_h &= ~mask;
            iph->saddr = htonl(iph_daddr_h);
            iph->daddr = res_elem.src_ip;
        } else {
            ip_ip_map_t find_elem;
            find_elem.ip_local = iph->daddr;

            ip_ip_map_t res_elem;
            int32_t find_elem_flag = array_hashmap_find_elem(ip_ip_map_struct, &find_elem, &res_elem);

            if (find_elem_flag != 1) {
                continue;
            }

            nat_map_t add_elem_nat;
            add_elem_nat.dst_ip = res_elem.ip_global;
            add_elem_nat.src_port = src_port;
            add_elem_nat.src_ip = iph->saddr;

            array_hashmap_add_elem(nat_map_struct, &add_elem_nat, NULL, NULL);

            iph_daddr_h |= mask;
            iph->saddr = htonl(iph_daddr_h);
            iph->daddr = res_elem.ip_global;
        }

        iph->check = 0;

        uint16_t L4_len = ntohs(iph->tot_len) - (iph->ihl << 2);

        pseudo_header_t psh;
        psh.source_address = iph->saddr;
        psh.dest_address = iph->daddr;
        psh.protocol = htons(proto_L4);
        psh.length = htons(L4_len);

        memcpy(pseudogram, (char*)&psh, sizeof(pseudo_header_t));
        memcpy(pseudogram + sizeof(pseudo_header_t), L4_start_pointer, L4_len);

        int psize = sizeof(pseudo_header_t) + L4_len;
        uint16_t checksum_value = checksum((const char*)pseudogram, psize);

        if (proto_L4 == IPPROTO_TCP) {
            struct tcphdr* tcph = (struct tcphdr*)L4_start_pointer;

            tcph->check = checksum_value;
        }

        if (proto_L4 == IPPROTO_UDP) {
            struct udphdr* udph = (struct udphdr*)L4_start_pointer;

            udph->check = checksum_value;
        }

        iph->check = checksum(L3_start_pointer, iph->ihl << 2);

        write(tap_fd, buffer, nread);
    }
}

void init_tun_thread(void)
{
    start_subnet_ip = ntohl(inet_addr(tun_ip)) + 1;

    int32_t subnet_size = 1;
    subnet_size <<= 32 - (tun_prefix + 1);
    end_subnet_ip = start_subnet_ip + subnet_size - 3;

    ip_ip_map_struct = init_array_hashmap(LOC_TO_GLOBIP_MAP_MAX_SIZE, 1.0, sizeof(ip_ip_map_t));
    if (ip_ip_map_struct == NULL) {
        printf("No free memory for ip_ip_map_struct\n");
        exit(EXIT_FAILURE);
    }

    array_hashmap_set_func(ip_ip_map_struct, ip_ip_hash, ip_ip_cmp, ip_ip_hash, ip_ip_cmp);

    nat_map_struct = init_array_hashmap(NAT_MAP_MAX_SIZE, 1.0, sizeof(nat_map_t));
    if (nat_map_struct == NULL) {
        printf("No free memory for nat_map_struct\n");
        exit(EXIT_FAILURE);
    }

    array_hashmap_set_func(nat_map_struct, nat_hash, nat_cmp, nat_hash, nat_cmp);

    pthread_t tun_thread;
    if (pthread_create(&tun_thread, NULL, tun, NULL)) {
        printf("Can't create tun_thread\n");
        exit(EXIT_FAILURE);
    }

    if (pthread_detach(tun_thread)) {
        printf("Can't detach tun_thread\n");
        exit(EXIT_FAILURE);
    }
}
