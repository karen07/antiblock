#include "capture.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define ETH_P_IP 0x0800u
#define IPPROTO_UDP_VALUE 17u
#define SLL_V1_LEN 16u
#define SLL_V2_LEN 20u

int capture_open(capture_t *cap, const ab_config_t *cfg)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char ipbuf[INET_ADDRSTRLEN];
    char filter[256];
    struct in_addr addr;
    struct bpf_program program;

    memset(cap, 0, sizeof(*cap));
    addr.s_addr = cfg->dns_src_ip_be;
    if (inet_ntop(AF_INET, &addr, ipbuf, sizeof(ipbuf)) == NULL) {
        return -1;
    }
    if (snprintf(filter, sizeof(filter), "ip and udp and src host %s and src port %u", ipbuf,
                 (unsigned)cfg->dns_src_port) >= (int)sizeof(filter)) {
        return -1;
    }

    cap->pcap = pcap_open_live("any", 65535, 0, 1, errbuf);
    if (cap->pcap == NULL) {
        fprintf(stderr, "pcap_open_live(any): %s\n", errbuf);
        return -1;
    }
    cap->datalink = pcap_datalink(cap->pcap);
    if (cap->datalink != DLT_LINUX_SLL
#ifdef DLT_LINUX_SLL2
        && cap->datalink != DLT_LINUX_SLL2
#endif
    ) {
        fprintf(stderr, "Unsupported pcap datalink %d (need Linux SLL/SLL2)\n", cap->datalink);
        capture_close(cap);
        return -1;
    }

    if (pcap_compile(cap->pcap, &program, filter, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        fprintf(stderr, "pcap_compile(%s): %s\n", filter, pcap_geterr(cap->pcap));
        capture_close(cap);
        return -1;
    }
    if (pcap_setfilter(cap->pcap, &program) != 0) {
        fprintf(stderr, "pcap_setfilter(%s): %s\n", filter, pcap_geterr(cap->pcap));
        pcap_freecode(&program);
        capture_close(cap);
        return -1;
    }
    pcap_freecode(&program);

    if (pcap_setnonblock(cap->pcap, 1, errbuf) != 0) {
        fprintf(stderr, "pcap_setnonblock: %s\n", errbuf);
        capture_close(cap);
        return -1;
    }
    return 0;
}

void capture_close(capture_t *cap)
{
    if (cap->pcap != NULL) {
        pcap_close(cap->pcap);
        cap->pcap = NULL;
    }
}

int capture_wait(capture_t *cap, int timeout_ms)
{
    struct pollfd pfd;
    int fd;
    int rc;

    if (cap == NULL || cap->pcap == NULL || timeout_ms < 0) {
        return -1;
    }

    fd = pcap_get_selectable_fd(cap->pcap);
    if (fd < 0) {
        struct timespec ts;

        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (long)(timeout_ms % 1000) * 1000000L;
        if (nanosleep(&ts, NULL) != 0 && errno != EINTR) {
            fprintf(stderr, "nanosleep(pcap fallback): %s\n", strerror(errno));
            return -1;
        }
        return 0;
    }

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN;

    rc = poll(&pfd, 1, timeout_ms);
    if (rc < 0) {
        if (errno == EINTR) {
            return 0;
        }
        fprintf(stderr, "poll(pcap): %s\n", strerror(errno));
        return -1;
    }
    if (rc == 0) {
        return 0;
    }
    if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
        fprintf(stderr, "poll(pcap): unexpected revents 0x%x\n", (unsigned)pfd.revents);
        return -1;
    }
    return 1;
}

int capture_get_stats(capture_t *cap, capture_stats_t *stats)
{
    struct pcap_stat pcap_stats_value;

    if (cap == NULL || cap->pcap == NULL || stats == NULL) {
        return -1;
    }
    if (pcap_stats(cap->pcap, &pcap_stats_value) != 0) {
        return -1;
    }

    stats->received = (uint64_t)pcap_stats_value.ps_recv;
    stats->dropped = (uint64_t)pcap_stats_value.ps_drop;
    stats->interface_dropped = (uint64_t)pcap_stats_value.ps_ifdrop;
    return 0;
}

static int link_ipv4_payload(const capture_t *cap, const uint8_t *packet, size_t caplen,
                             const uint8_t **ip, size_t *ip_len)
{
    size_t link_len;
    uint16_t proto;

    if (cap->datalink == DLT_LINUX_SLL) {
        if (caplen < SLL_V1_LEN) {
            return 0;
        }
        link_len = SLL_V1_LEN;
        proto = ab_read_be16(packet + 14u);
    }
#ifdef DLT_LINUX_SLL2
    else if (cap->datalink == DLT_LINUX_SLL2) {
        if (caplen < SLL_V2_LEN) {
            return 0;
        }
        link_len = SLL_V2_LEN;
        proto = ab_read_be16(packet);
    }
#endif
    else {
        return 0;
    }

    if (proto != ETH_P_IP) {
        return 0;
    }
    *ip = packet + link_len;
    *ip_len = caplen - link_len;
    return 1;
}

int capture_next_dns(capture_t *cap, const ab_config_t *cfg, ab_bytes_t *dns)
{
    struct pcap_pkthdr *header;
    const u_char *packet;
    const uint8_t *ip;
    const uint8_t *udp;
    size_t ip_available;
    uint8_t ihl;
    uint16_t ip_total;
    uint16_t frag;
    uint16_t udp_len;
    uint32_t src_ip;
    int rc;

    rc = pcap_next_ex(cap->pcap, &header, &packet);
    if (rc == 0) {
        return 0;
    }
    if (rc < 0) {
        if (rc != -2) {
            fprintf(stderr, "pcap_next_ex: %s\n", pcap_geterr(cap->pcap));
        }
        return -1;
    }
    if (header->caplen != header->len) {
        return 0;
    }
    if (!link_ipv4_payload(cap, packet, header->caplen, &ip, &ip_available)) {
        return 0;
    }
    if (ip_available < 20u || (ip[0] >> 4) != 4u) {
        return 0;
    }
    ihl = (uint8_t)((ip[0] & 0x0fu) * 4u);
    if (ihl < 20u || ip_available < ihl + 8u) {
        return 0;
    }
    ip_total = ab_read_be16(ip + 2u);
    if (ip_total < ihl + 8u || ip_total > ip_available) {
        return 0;
    }
    frag = ab_read_be16(ip + 6u);
    if ((frag & 0x3fffu) != 0u || ip[9] != IPPROTO_UDP_VALUE) {
        return 0;
    }
    memcpy(&src_ip, ip + 12u, sizeof(src_ip));
    if (src_ip != cfg->dns_src_ip_be) {
        return 0;
    }

    udp = ip + ihl;
    if (ab_read_be16(udp) != cfg->dns_src_port) {
        return 0;
    }
    udp_len = ab_read_be16(udp + 4u);
    if (udp_len < 8u || udp_len > (uint16_t)(ip_total - ihl)) {
        return 0;
    }

    dns->data = udp + 8u;
    dns->len = (size_t)udp_len - 8u;
    return 1;
}
