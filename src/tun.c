#include "antiblock.h"
#include "config.h"
#include "const.h"
#include "dns_ans.h"
#include "hash.h"
#include "net_data.h"
#include "stat.h"
#include "tun.h"
#include "urls_read.h"

const array_hashmap_t *ip_ip_map_struct;
const array_hashmap_t *nat_map_struct;

uint32_t start_subnet_ip;
uint32_t end_subnet_ip;

static int32_t tun_alloc(char *dev, int32_t flags)
{
    struct ifreq ifr;
    int32_t fd, err;
    char *clonedev = "/dev/net/tun";

    if ((fd = open(clonedev, O_RDWR)) < 0) {
        printf("Opening /dev/net/tun error\n");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;

    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        printf("ioctl(TUNSETIFF) error\n");
        close(fd);
        return err;
    }

    strcpy(dev, ifr.ifr_name);

    //int32_t status = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

    //if (status == -1) {
    //    printf("Set O_NONBLOCK error\n");
    //}

    return fd;
}

static uint16_t checksum(const char *buf, uint32_t size)
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

static uint32_t ip_ip_hash(const void *void_elem)
{
    const ip_ip_map_t *elem = void_elem;
    return elem->ip_local;
}

static int32_t ip_ip_cmp(const void *void_elem1, const void *void_elem2)
{
    const ip_ip_map_t *elem1 = void_elem1;
    const ip_ip_map_t *elem2 = void_elem2;

    if (elem1->ip_local == elem2->ip_local) {
        return 1;
    } else {
        return 0;
    }
}

int32_t ip_ip_on_collision(__attribute__((unused)) const void *void_elem1,
                           __attribute__((unused)) const void *void_elem2)
{
    return 1;
}

static uint32_t nat_hash(const void *void_elem)
{
    const nat_map_t *elem = void_elem;
    return djb33_hash_len((const char *)(&elem->key), sizeof(elem->key));
}

static int32_t nat_cmp(const void *void_elem1, const void *void_elem2)
{
    const nat_map_t *elem1 = void_elem1;
    const nat_map_t *elem2 = void_elem2;

    if (memcmp(&elem1->key, &elem2->key, sizeof(elem1->key)) == 0) {
        return 1;
    } else {
        return 0;
    }
}

static void *tun(__attribute__((unused)) void *arg)
{
    printf("Thread tun started\n");

    int32_t tap_fd;
    char buffer[4096];
    char pseudogram[4096];

    tap_fd = tun_alloc(tun_name, IFF_TUN | IFF_MULTI_QUEUE);

    if (tap_fd < 0) {
        printf("Can't allocate tun interface\n");
        exit(EXIT_FAILURE);
    }

    struct in_addr start_subnet_ip_addr;
    start_subnet_ip_addr.s_addr = htonl(start_subnet_ip);

    struct in_addr end_subnet_ip_addr;
    end_subnet_ip_addr.s_addr = htonl(end_subnet_ip);

    printf("Tun dev %s allocated", tun_name);
    printf(" %s-", inet_ntoa(start_subnet_ip_addr));
    printf("%s\n", inet_ntoa(end_subnet_ip_addr));

    pthread_barrier_wait(&threads_barrier);

    uint32_t nat_icmp_client_ip = 0;

    while (true) {
        int32_t nread = read(tap_fd, buffer, sizeof(buffer));

        struct timeval now_timeval;
        gettimeofday(&now_timeval, NULL);
        uint64_t now_us_start = now_timeval.tv_sec * 1000000 + now_timeval.tv_usec;

        if (nread < 1) {
            continue;
        }

        tun_header_t *tun_header = (tun_header_t *)buffer;

        int32_t proto_L3 = ntohs(tun_header->proto);
        if (proto_L3 != ETH_P_IP) {
            continue;
        }

        char *L3_start_pointer = buffer + sizeof(tun_header_t);
        struct iphdr *iph = (struct iphdr *)L3_start_pointer;

        char proto_L4 = iph->protocol;
        if ((proto_L4 != IPPROTO_TCP) && (proto_L4 != IPPROTO_UDP) && (proto_L4 != IPPROTO_ICMP)) {
            if (log_fd) {
                fprintf(log_fd, "NAT_proto_L4 %d\n", proto_L4);
            }
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
                int32_t find_elem_ip_ip_flag =
                    array_hashmap_find_elem(ip_ip_map_struct, &find_elem_ip_ip, &res_elem_ip_ip);
                if (find_elem_ip_ip_flag != 1) {
                    stat.nat_sended_to_dev_error++;

                    struct in_addr s_ip_new;
                    s_ip_new.s_addr = iph->daddr;

                    if (log_fd) {
                        fprintf(log_fd, "NAT_sended_to_dev_error %s\n", inet_ntoa(s_ip_new));
                    }

                    continue;
                }

                iph_daddr_h |= mask;

                nat_icmp_client_ip = iph->saddr;

                iph->saddr = htonl(iph_daddr_h);
                iph->daddr = res_elem_ip_ip.ip_global;
            }

            iph->check = 0;
            iph->check = checksum(L3_start_pointer, iph->ihl << 2);

            write(tap_fd, buffer, nread);

            continue;
        }

        uint16_t src_port;
        uint16_t dst_port;

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
            int32_t find_elem_nat_flag =
                array_hashmap_find_elem(nat_map_struct, &find_elem_nat, &res_elem_nat);
            if (find_elem_nat_flag != 1) {
                stat.nat_sended_to_client_error++;

                continue;
            }

            iph_daddr_h &= ~mask;
            iph->saddr = htonl(iph_daddr_h);
            iph->daddr = res_elem_nat.value.old_src_ip;
            dst_port = res_elem_nat.value.old_src_port;

            in_out_flag = 0;

            stat.nat_sended_to_client++;
        } else {
            ip_ip_map_t find_elem_ip_ip;
            find_elem_ip_ip.ip_local = iph->daddr;

            ip_ip_map_t res_elem_ip_ip;
            int32_t find_elem_ip_ip_flag =
                array_hashmap_find_elem(ip_ip_map_struct, &find_elem_ip_ip, &res_elem_ip_ip);
            if (find_elem_ip_ip_flag != 1) {
                stat.nat_sended_to_dev_error++;

                struct in_addr s_ip_new;
                s_ip_new.s_addr = iph->daddr;

                if (log_fd) {
                    fprintf(log_fd, "NAT_sended_to_dev_error %s\n", inet_ntoa(s_ip_new));
                }

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
                int32_t add_elem_nat_flag =
                    array_hashmap_add_elem(nat_map_struct, &add_elem_nat, &res_elem_nat, NULL);
                if (add_elem_nat_flag == 1) {
                    correct_new_srt_port = 0;
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

            stat.nat_sended_to_dev++;
        }

        if (log_fd && 0) {
            struct in_addr s_ip_new;
            s_ip_new.s_addr = iph->saddr;

            struct in_addr d_ip_new;
            d_ip_new.s_addr = iph->daddr;

            char log_out_str[1000];

            if (in_out_flag) {
                sprintf(log_out_str, "NAT_sended_to_dev: %s ", inet_ntoa(src_ip_old));
            } else {
                sprintf(log_out_str, "NAT_sended_to_client: %s ", inet_ntoa(src_ip_old));
            }

            sprintf(log_out_str + strlen(log_out_str), "%s ", inet_ntoa(dst_ip_old));
            sprintf(log_out_str + strlen(log_out_str), "%u ", ntohs(src_port_old));
            sprintf(log_out_str + strlen(log_out_str), "%u", ntohs(dst_port_old));

            sprintf(log_out_str + strlen(log_out_str), " - ");

            sprintf(log_out_str + strlen(log_out_str), "%s ", inet_ntoa(s_ip_new));
            sprintf(log_out_str + strlen(log_out_str), "%s ", inet_ntoa(d_ip_new));
            sprintf(log_out_str + strlen(log_out_str), "%u ", ntohs(src_port));
            sprintf(log_out_str + strlen(log_out_str), "%u ", ntohs(dst_port));

            sprintf(log_out_str + strlen(log_out_str), "%d\n", nread);

            fprintf(log_fd, "%s", log_out_str);
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
        uint16_t checksum_value = checksum((const char *)pseudogram, psize);

        if (proto_L4 == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr *)L4_start_pointer;

            tcph->check = checksum_value;
        }

        if (proto_L4 == IPPROTO_UDP) {
            struct udphdr *udph = (struct udphdr *)L4_start_pointer;

            udph->check = checksum_value;
        }

        iph->check = checksum(L3_start_pointer, iph->ihl << 2);

        gettimeofday(&now_timeval, NULL);
        uint64_t now_us_end = now_timeval.tv_sec * 1000000 + now_timeval.tv_usec;

        if (in_out_flag) {
            stat.latency_sended_to_dev_sum += now_us_end - now_us_start;
            stat.latency_sended_to_dev_count++;
        } else {
            stat.latency_sended_to_client_sum += now_us_end - now_us_start;
            stat.latency_sended_to_client_count++;
        }

        write(tap_fd, buffer, nread);
    }
}

void init_tun_thread(void)
{
    start_subnet_ip = ntohl(tun_ip) + 1;

    int32_t subnet_size = 1;
    subnet_size <<= 32 - (tun_prefix + 1);
    end_subnet_ip = start_subnet_ip + subnet_size - 3;

    ip_ip_map_struct = init_array_hashmap(subnet_size, 1.0, sizeof(ip_ip_map_t));
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
