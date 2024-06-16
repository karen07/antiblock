#include "array_hashmap.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

// ip route add default via 10.8.0.5 dev VPN table 2
// curl --resolve 2ip.ru:80:10.7.1.2 http://2ip.ru

#define EtherType_IPv4 0x0800

typedef struct tun_header {
    uint16_t flags;
    uint16_t proto;
} __attribute__((packed)) tun_header_t;

typedef struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint16_t protocol;
    uint16_t tcp_length;
} __attribute__((packed)) pseudo_header_t;

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

typedef struct ip_ip_map {
    uint32_t ip_local;
    uint32_t ip_global;
} ip_ip_map_t;

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

int main()
{
    const array_hashmap_t* ip_ip_map_struct;
    ip_ip_map_struct = init_array_hashmap(1000, 1.0, sizeof(ip_ip_map_t));
    if (ip_ip_map_struct == NULL) {
        printf("No free memory for ip_ip_map_struct\n");
        exit(EXIT_FAILURE);
    }

    array_hashmap_set_func(ip_ip_map_struct, ip_ip_hash, ip_ip_cmp, ip_ip_hash, ip_ip_cmp);

    ip_ip_map_t add_elem;
    add_elem.ip_local = inet_addr("10.7.1.2");
    add_elem.ip_global = inet_addr("195.201.201.32");

    array_hashmap_add_elem(ip_ip_map_struct, &add_elem, NULL, NULL);

    uint32_t tmp;

    int tap_fd;
    char tun_name[IFNAMSIZ];
    char buffer[4096];
    char pseudogram[4096];

    strcpy(tun_name, "antiblock");
    tap_fd = tun_alloc(tun_name, IFF_TUN);

    if (tap_fd < 0) {
        perror("Allocating interface");
        exit(1);
    }

    while (1) {
        int nread = read(tap_fd, buffer, sizeof(buffer));
        if (nread < 0) {
            perror("Reading from interface");
            close(tap_fd);
            exit(1);
        }

        tun_header_t* start_tun_tap = (tun_header_t*)buffer;
        int proto = ntohs(start_tun_tap->proto);

        printf("nread:%d ", nread);
        printf("proto:%d ", proto);

        if (proto == EtherType_IPv4) {
            struct iphdr* iph = (struct iphdr*)(buffer + sizeof(tun_header_t));

            char proto_L3 = iph->protocol;
            printf("proto_L3:%d ", proto_L3);

            if (proto_L3 == IPPROTO_TCP) {
                char str[INET_ADDRSTRLEN];

                inet_ntop(AF_INET, &iph->saddr, str, INET_ADDRSTRLEN);
                printf("SRC_IP:%s ", str);

                inet_ntop(AF_INET, &iph->daddr, str, INET_ADDRSTRLEN);
                printf("DST_IP:%s ", str);

                struct tcphdr* tcph = (struct tcphdr*)(buffer + sizeof(tun_header_t) + sizeof(struct iphdr));

                int src_port = ntohs(tcph->source);
                printf("SRC_PORT:%d ", src_port);

                int dst_port = ntohs(tcph->dest);
                printf("DST_PORT:%d ", dst_port);

                if (iph->daddr & 0b00000000100000000000000000000000) {
                    iph->saddr = iph->daddr & (~0b00000000100000000000000000000000);
                    iph->daddr = tmp;
                } else {
                    ip_ip_map_t elem;

                    add_elem.ip_local = iph->daddr;
                    array_hashmap_find_elem(ip_ip_map_struct, &add_elem, &elem);

                    tmp = iph->saddr;
                    iph->saddr = iph->daddr | (0b00000000100000000000000000000000);
                    iph->daddr = elem.ip_global;
                }

                iph->check = 0;
                tcph->check = 0;

                uint16_t tcpLen = ntohs(iph->tot_len) - (iph->ihl << 2);

                pseudo_header_t psh;
                psh.source_address = iph->saddr;
                psh.dest_address = iph->daddr;
                psh.protocol = htons(IPPROTO_TCP);
                psh.tcp_length = htons(tcpLen);

                memcpy(pseudogram, (char*)&psh, sizeof(pseudo_header_t));
                memcpy(pseudogram + sizeof(pseudo_header_t), tcph, tcpLen);

                int psize = sizeof(pseudo_header_t) + tcpLen;

                tcph->check = checksum((const char*)pseudogram, psize);
                iph->check = checksum((const char*)(buffer + sizeof(tun_header_t)), iph->ihl << 2);

                write(tap_fd, buffer, nread);
            }
        }
        printf("\n");
    }
    return 0;
}
