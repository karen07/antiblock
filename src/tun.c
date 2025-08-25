#include "antiblock.h"
#include "config.h"
#include "const.h"
#include "dns_ans.h"
#include "net_data.h"
#include "stat.h"
#include "tun.h"
#include "domains_read.h"

#ifdef TUN_MODE

array_hashmap_t ip_ip_map_struct;
static array_hashmap_t nat_map_struct;

subnet_range_t NAT;

void subnet_init(subnet_range_t *subnet)
{
    uint32_t netMask = (INADDR_NONE << (32 - (subnet->network_prefix + 1)) & INADDR_NONE);
    subnet->start_ip = (ntohl(subnet->network_ip) & netMask) + 2;

    subnet->subnet_size = 1;
    subnet->subnet_size <<= 32 - (subnet->network_prefix + 1);
    subnet->end_ip = (ntohl(subnet->network_ip) & netMask) + subnet->subnet_size - 2;
}

int32_t tun_alloc(char *dev, int32_t flags)
{
    struct ifreq ifr;
    int32_t fd_create;
    int32_t fd_setip;
    int32_t err;
    struct sockaddr_in sin;

    if ((fd_create = open("/dev/net/tun", O_RDWR)) < 0) {
        return fd_create;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if ((err = ioctl(fd_create, TUNSETIFF, (void *)&ifr)) < 0) {
        return err;
    }

    if ((fd_setip = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return fd_setip;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if ((err = ioctl(fd_setip, SIOCGIFFLAGS, &ifr)) < 0) {
        return err;
    }

    if (!(ifr.ifr_flags & IFF_UP)) {
        ifr.ifr_flags |= IFF_UP;
        if ((err = ioctl(fd_setip, SIOCSIFFLAGS, &ifr)) < 0) {
            return err;
        }
    }

    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = tun_ip;
    memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));

    if ((err = ioctl(fd_setip, SIOCSIFADDR, &ifr)) < 0) {
        return err;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_NONE << (32 - tun_prefix) & INADDR_NONE);
    memcpy(&ifr.ifr_netmask, &sin, sizeof(struct sockaddr));

    if ((err = ioctl(fd_setip, SIOCSIFNETMASK, &ifr)) < 0) {
        return err;
    }

    return fd_create;
}

static uint16_t checksum(char *buf, uint32_t size)
{
    uint32_t sum = 0, i;

    for (i = 0; i < size - 1; i += 2) {
        uint16_t word16 = *(uint16_t *)&buf[i];
        sum += word16;
    }

    if (size & 1) {
        uint16_t word16 = (uint8_t)buf[i];
        sum += word16;
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}

static array_hashmap_hash ip_ip_hash(const void *elem_data)
{
    const ip_ip_map_t *elem = elem_data;
    return elem->ip_local;
}

static array_hashmap_bool ip_ip_cmp(const void *elem_data, const void *hashmap_elem_data)
{
    const ip_ip_map_t *elem1 = elem_data;
    const ip_ip_map_t *elem2 = hashmap_elem_data;

    return elem1->ip_local == elem2->ip_local;
}

static array_hashmap_hash nat_hash(const void *elem_data)
{
    const nat_map_t *elem = elem_data;
    return djb33_hash_len((const char *)(&elem->key), sizeof(elem->key));
}

static array_hashmap_bool nat_cmp(const void *elem_data, const void *hashmap_elem_data)
{
    const nat_map_t *elem1 = elem_data;
    const nat_map_t *elem2 = hashmap_elem_data;

    return !memcmp(&elem1->key, &elem2->key, sizeof(elem1->key));
}

static void *tun(__attribute__((unused)) void *arg)
{
    //char *tap_buffer = NULL;
    char *tun_buffer = NULL;
    char *pseudogram = NULL;

    //tap_buffer = (char *)malloc(PACKET_MAX_SIZE * sizeof(char));
    tun_buffer = (char *)malloc(PACKET_MAX_SIZE * sizeof(char));
    pseudogram = (char *)malloc(PACKET_MAX_SIZE * sizeof(char));

    //int32_t tap_fd = 0;
    int32_t tun_fd = 0;

    //tap_fd = tun_alloc("AntiBlock_NAT_TAP", IFF_TAP | IFF_NO_PI);
    //if (tap_fd < 0) {
    //    errmsg("Can't allocate TAP interface\n");
    //}

    tun_fd = tun_alloc("AntiBlock_NAT", IFF_TUN);
    if (tun_fd < 0) {
        errmsg("Can't allocate TUN interface\n");
    }

    pthread_barrier_wait(&threads_barrier);

    uint32_t nat_icmp_client_ip = 0;

    while (true) {
        int32_t nread = read(tun_fd, tun_buffer, PACKET_MAX_SIZE);

        if (nread < 1) {
            continue;
        }

        struct tun_pi *tun_header = (struct tun_pi *)tun_buffer;

        int32_t proto_L3 = ntohs(tun_header->proto);
        if (proto_L3 != ETH_P_IP) {
            continue;
        }

        char *L3_start_pointer = tun_buffer + sizeof(struct tun_pi);
        struct iphdr *iph = (struct iphdr *)L3_start_pointer;

        char proto_L4 = iph->protocol;
        if ((proto_L4 != IPPROTO_TCP) && (proto_L4 != IPPROTO_UDP) && (proto_L4 != IPPROTO_ICMP)) {
            continue;
        }

        if (proto_L4 == IPPROTO_ICMP) {
            int32_t iph_daddr_h = ntohl(iph->daddr);
            int32_t mask = 1;
            mask <<= 32 - (tun_prefix + 1);

            if (iph_daddr_h & mask) {
                iph_daddr_h &= ~mask;

                iph->saddr = htonl(iph_daddr_h);
                iph->daddr = nat_icmp_client_ip;
            } else {
                ip_ip_map_t find_elem_ip_ip;
                find_elem_ip_ip.ip_local = iph->daddr;

                ip_ip_map_t res_elem_ip_ip;
                int32_t find_elem_ip_ip_flag = 0;

                find_elem_ip_ip_flag =
                    array_hashmap_find_elem(ip_ip_map_struct, &find_elem_ip_ip, &res_elem_ip_ip);
                if (find_elem_ip_ip_flag != array_hashmap_elem_finded) {
                    statistics_data.nat_sended_to_dev_error++;
                    continue;
                }

                iph_daddr_h |= mask;

                nat_icmp_client_ip = iph->saddr;

                iph->saddr = htonl(iph_daddr_h);
                iph->daddr = res_elem_ip_ip.ip_global;
            }

            iph->check = 0;
            iph->check = checksum(L3_start_pointer, iph->ihl << 2);

            //memcpy(tap_buffer + sizeof(struct ethhdr), L3_start_pointer,
            //       nread - sizeof(struct tun_pi));
            //struct ethhdr *ethh = (struct ethhdr *)tap_buffer;
            //ethh->h_proto = htons(ETH_P_IP);
            //memset(ethh->h_dest, 0xFF, 6);
            //memset(ethh->h_source, 0xFF, 6);
            //write(tap_fd, tap_buffer, nread - sizeof(struct tun_pi) + sizeof(struct ethhdr));

            write(tun_fd, tun_buffer, nread);

            continue;
        }

        uint16_t src_port = 0;
        uint16_t dst_port = 0;

        char *L4_start_pointer = L3_start_pointer + sizeof(struct iphdr);
        if (proto_L4 == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr *)L4_start_pointer;

            src_port = tcph->source;
            dst_port = tcph->dest;

            tcph->check = 0;
        }
        if (proto_L4 == IPPROTO_UDP) {
            struct udphdr *udph = (struct udphdr *)L4_start_pointer;

            src_port = udph->source;
            dst_port = udph->dest;

            udph->check = 0;
        }

        struct in_addr src_ip_old;
        src_ip_old.s_addr = iph->saddr;

        struct in_addr dst_ip_old;
        dst_ip_old.s_addr = iph->daddr;

        uint16_t src_port_old = src_port;
        uint16_t dst_port_old = dst_port;

        int32_t in_out_flag = 0;

        int32_t iph_daddr_h = ntohl(iph->daddr);
        int32_t mask = 1;
        mask <<= 32 - (tun_prefix + 1);

        if (iph_daddr_h & mask) {
            nat_map_t find_elem_nat;
            find_elem_nat.key.src_ip = iph->daddr;
            find_elem_nat.key.dst_ip = iph->saddr;
            find_elem_nat.key.src_port = dst_port;
            find_elem_nat.key.dst_port = src_port;
            find_elem_nat.key.proto = proto_L4;

            nat_map_t res_elem_nat;
            int32_t find_elem_nat_flag = 0;

            find_elem_nat_flag =
                array_hashmap_find_elem(nat_map_struct, &find_elem_nat, &res_elem_nat);
            if (find_elem_nat_flag != array_hashmap_elem_finded) {
                statistics_data.nat_sended_to_client_error++;

                continue;
            }

            iph_daddr_h &= ~mask;
            iph->saddr = htonl(iph_daddr_h);
            iph->daddr = res_elem_nat.value.old_src_ip;
            dst_port = res_elem_nat.value.old_src_port;

            in_out_flag = 0;

            statistics_data.nat_sended_to_client++;
            statistics_data.nat_sended_to_client_size += nread;
        } else {
            ip_ip_map_t find_elem_ip_ip;
            find_elem_ip_ip.ip_local = iph->daddr;

            ip_ip_map_t res_elem_ip_ip;
            int32_t find_elem_ip_ip_flag = 0;

            find_elem_ip_ip_flag =
                array_hashmap_find_elem(ip_ip_map_struct, &find_elem_ip_ip, &res_elem_ip_ip);
            if (find_elem_ip_ip_flag != array_hashmap_elem_finded) {
                statistics_data.nat_sended_to_dev_error++;
                continue;
            }

            uint16_t start_new_srt_port = ntohs(src_port);
            int32_t correct_new_srt_port = 1;
            nat_map_t add_elem_nat;
            iph_daddr_h |= mask;

            while (correct_new_srt_port) {
                add_elem_nat.key.src_ip = htonl(iph_daddr_h);
                add_elem_nat.key.dst_ip = res_elem_ip_ip.ip_global;
                add_elem_nat.key.src_port = htons(start_new_srt_port);
                add_elem_nat.key.dst_port = dst_port;
                add_elem_nat.key.proto = proto_L4;
                add_elem_nat.value.old_src_ip = iph->saddr;
                add_elem_nat.value.old_src_port = src_port;

                nat_map_t res_elem_nat;
                int32_t add_elem_nat_flag = 0;
                add_elem_nat_flag =
                    array_hashmap_add_elem(nat_map_struct, &add_elem_nat, &res_elem_nat, NULL);
                if (add_elem_nat_flag == array_hashmap_elem_finded) {
                    correct_new_srt_port = 0;
                    statistics_data.nat_records++;
                }
                if (add_elem_nat_flag == 0) {
                    if ((add_elem_nat.value.old_src_ip == res_elem_nat.value.old_src_ip) &&
                        (add_elem_nat.value.old_src_port == res_elem_nat.value.old_src_port)) {
                        correct_new_srt_port = 0;
                    }
                }
                start_new_srt_port++;
            }

            iph->saddr = add_elem_nat.key.src_ip;
            iph->daddr = add_elem_nat.key.dst_ip;
            src_port = add_elem_nat.key.src_port;

            in_out_flag = 1;

            statistics_data.nat_sended_to_dev++;
            statistics_data.nat_sended_to_dev_size += nread;
        }

        if (proto_L4 == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr *)L4_start_pointer;

            tcph->source = src_port;
            tcph->dest = dst_port;
        }
        if (proto_L4 == IPPROTO_UDP) {
            struct udphdr *udph = (struct udphdr *)L4_start_pointer;

            udph->source = src_port;
            udph->dest = dst_port;
        }

        iph->check = 0;

        uint16_t L4_len = ntohs(iph->tot_len) - (iph->ihl << 2);

        pseudo_header_t psh;
        psh.source_address = iph->saddr;
        psh.dest_address = iph->daddr;
        psh.protocol = htons(proto_L4);
        psh.length = htons(L4_len);

        memcpy(pseudogram, (char *)&psh, sizeof(pseudo_header_t));
        memcpy(pseudogram + sizeof(pseudo_header_t), L4_start_pointer, L4_len);

        int32_t psize = sizeof(pseudo_header_t) + L4_len;
        uint16_t checksum_value = checksum(pseudogram, psize);

        if (proto_L4 == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr *)L4_start_pointer;

            tcph->check = checksum_value;
        }

        if (proto_L4 == IPPROTO_UDP) {
            struct udphdr *udph = (struct udphdr *)L4_start_pointer;

            udph->check = checksum_value;
        }

        iph->check = checksum(L3_start_pointer, iph->ihl << 2);

        //memcpy(tap_buffer + sizeof(struct ethhdr), L3_start_pointer,
        //       nread - sizeof(struct tun_pi));
        //struct ethhdr *ethh = (struct ethhdr *)tap_buffer;
        //ethh->h_proto = htons(ETH_P_IP);
        //memset(ethh->h_dest, 0xFF, 6);
        //memset(ethh->h_source, 0xFF, 6);
        //write(tap_fd, tap_buffer, nread - sizeof(struct tun_pi) + sizeof(struct ethhdr));

        write(tun_fd, tun_buffer, nread);
    }

    return NULL;
}

void init_tun_thread(void)
{
    NAT.network_ip = tun_ip;
    NAT.network_prefix = tun_prefix;
    subnet_init(&NAT);

    ip_ip_map_struct = array_hashmap_init(NAT.subnet_size, 1.0, sizeof(ip_ip_map_t));
    if (ip_ip_map_struct == NULL) {
        errmsg("No free memory for ip_ip_map_struct\n");
    }

    array_hashmap_set_func(ip_ip_map_struct, ip_ip_hash, ip_ip_cmp, ip_ip_hash, ip_ip_cmp,
                           ip_ip_hash, ip_ip_cmp);

    //uint32_t NAT_subnet_start_n = htonl(NAT.start_ip++);
    //ip_ip_map_t add_elem;
    //add_elem.ip_local = NAT_subnet_start_n;
    //add_elem.ip_global = inet_addr("192.168.1.10");
    //array_hashmap_add_elem(ip_ip_map_struct, &add_elem, NULL, array_hashmap_save_new_func);

    nat_map_struct = array_hashmap_init(NAT_MAP_MAX_SIZE, 1.0, sizeof(nat_map_t));
    if (nat_map_struct == NULL) {
        errmsg("No free memory for nat_map_struct\n");
    }

    array_hashmap_set_func(nat_map_struct, nat_hash, nat_cmp, nat_hash, nat_cmp, nat_hash, nat_cmp);

    pthread_t tun_thread;
    if (pthread_create(&tun_thread, NULL, tun, NULL)) {
        errmsg("Can't create tun_thread\n");
    }

    if (pthread_detach(tun_thread)) {
        errmsg("Can't detach tun_thread\n");
    }
}

#endif
