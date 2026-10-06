#include "config.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define AB_BLACKLIST_LINE_MAX 100u

static int add_subnet(ab_config_t *cfg, const char *text)
{
    char buf[AB_BLACKLIST_LINE_MAX];
    char *slash;
    char *end;
    unsigned long prefix;
    struct in_addr addr;
    uint32_t mask;

    if (cfg->blacklist_count >= AB_MAX_BLACKLIST) {
        fprintf(stderr, "Too many blacklist subnets (max %u)\n", AB_MAX_BLACKLIST);
        return -1;
    }
    if (strlen(text) >= sizeof(buf)) {
        fprintf(stderr, "Blacklist entry is too long: %s\n", text);
        return -1;
    }

    strcpy(buf, text);
    slash = strchr(buf, '/');
    if (slash == NULL) {
        fprintf(stderr, "Invalid blacklist entry: %s\n", text);
        return -1;
    }
    *slash++ = '\0';

    errno = 0;
    prefix = strtoul(slash, &end, 10);
    if (errno != 0 || *end != '\0' || prefix == 0 || prefix > 32) {
        fprintf(stderr, "Invalid blacklist prefix: %s\n", text);
        return -1;
    }
    if (inet_pton(AF_INET, buf, &addr) != 1) {
        fprintf(stderr, "Invalid blacklist address: %s\n", text);
        return -1;
    }

    mask = prefix == 32 ? UINT32_MAX : (UINT32_MAX << (32u - (uint32_t)prefix));
    cfg->blacklist[cfg->blacklist_count].mask = mask;
    cfg->blacklist[cfg->blacklist_count].network = ntohl(addr.s_addr) & mask;
    cfg->blacklist_count++;
    return 0;
}

static int add_default_blacklist(ab_config_t *cfg)
{
    static const char *const defaults[] = { "0.0.0.0/8",       "10.0.0.0/8",     "100.64.0.0/10",
                                            "127.0.0.0/8",     "169.254.0.0/16", "172.16.0.0/12",
                                            "192.0.0.0/24",    "192.0.2.0/24",   "192.31.196.0/24",
                                            "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16",
                                            "192.175.48.0/24", "198.18.0.0/15",  "198.51.100.0/24",
                                            "203.0.113.0/24",  "224.0.0.0/4",    "240.0.0.0/4" };
    size_t i;

    for (i = 0; i < AB_ARRAY_SIZE(defaults); ++i) {
        if (add_subnet(cfg, defaults[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

void config_init(ab_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->output_dir = ".";
    (void)add_default_blacklist(cfg);
}

static int parse_rule(ab_config_t *cfg, const char *arg)
{
    const char *p = arg;
    const char *iface_start;
    const char *source;
    size_t iface_len;
    ab_rule_t *rule;

    if (cfg->rule_count >= AB_MAX_RULES) {
        fprintf(stderr, "Too many -r rules (max %u)\n", AB_MAX_RULES);
        return -1;
    }

    while (*p != '\0' && isspace((unsigned char)*p)) {
        ++p;
    }
    iface_start = p;
    while (*p != '\0' && !isspace((unsigned char)*p)) {
        ++p;
    }
    iface_len = (size_t)(p - iface_start);
    while (*p != '\0' && isspace((unsigned char)*p)) {
        ++p;
    }
    source = p;

    if (iface_len == 0 || iface_len >= IFNAMSIZ || *source == '\0') {
        fprintf(stderr, "Invalid -r rule: %s\n", arg);
        return -1;
    }

    rule = &cfg->rules[cfg->rule_count];
    memcpy(rule->ifname, iface_start, iface_len);
    rule->ifname[iface_len] = '\0';
    rule->source = source;
    cfg->rule_count++;
    return 0;
}

static int parse_listen(ab_config_t *cfg, const char *arg)
{
    const char *colon = strrchr(arg, ':');
    char ip[INET_ADDRSTRLEN];
    char *end;
    unsigned long port;
    size_t ip_len;
    struct in_addr addr;

    if (colon == NULL) {
        fprintf(stderr, "Invalid -l value, expected IPv4:port: %s\n", arg);
        return -1;
    }
    ip_len = (size_t)(colon - arg);
    if (ip_len == 0 || ip_len >= sizeof(ip)) {
        fprintf(stderr, "Invalid -l IPv4 address: %s\n", arg);
        return -1;
    }
    memcpy(ip, arg, ip_len);
    ip[ip_len] = '\0';

    if (inet_pton(AF_INET, ip, &addr) != 1) {
        fprintf(stderr, "Invalid -l IPv4 address: %s\n", ip);
        return -1;
    }

    errno = 0;
    port = strtoul(colon + 1, &end, 10);
    if (errno != 0 || *end != '\0' || port == 0 || port > 65535) {
        fprintf(stderr, "Invalid -l port: %s\n", colon + 1);
        return -1;
    }

    cfg->dns_src_ip_be = addr.s_addr;
    cfg->dns_src_port = (uint16_t)port;
    return 0;
}

void config_print_help(FILE *out)
{
    fprintf(out,
            "AntiBlock " AB_VERSION "\n"
            "Usage:\n"
            "  antiblock -r \"iface path-or-url\" ... -l IPv4:port [options]\n\n"
            "Required:\n"
            "  -r \"iface source\"   Domain source routed through iface (repeatable, max %u)\n"
            "  -l IPv4:port        DNS response source to sniff, e.g. 192.168.1.1:53\n\n"
            "Optional:\n"
            "  -b path             Additional IPv4 CIDR blacklist\n"
            "  -o directory        Directory for log.txt/stat.txt (default .)\n"
            "  --log               Enable DNS operation log\n"
            "  --stat              Enable stat.txt\n"
            "  --test              Do not modify the kernel routing table\n"
            "  -h, --help          Show this help\n",
            AB_MAX_RULES);
}

int config_parse(ab_config_t *cfg, int argc, char **argv)
{
    int i;

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-r") == 0) {
            if (++i >= argc || parse_rule(cfg, argv[i]) != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "-l") == 0) {
            if (++i >= argc || parse_listen(cfg, argv[i]) != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "-b") == 0) {
            if (++i >= argc) {
                return -1;
            }
            cfg->blacklist_path = argv[i];
        } else if (strcmp(argv[i], "-o") == 0) {
            if (++i >= argc) {
                return -1;
            }
            cfg->output_dir = argv[i];
        } else if (strcmp(argv[i], "--log") == 0) {
            cfg->log_enabled = 1;
        } else if (strcmp(argv[i], "--stat") == 0) {
            cfg->stat_enabled = 1;
        } else if (strcmp(argv[i], "--test") == 0) {
            cfg->test_mode = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            config_print_help(stdout);
            return 1;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            return -1;
        }
    }

    if (cfg->rule_count == 0) {
        fprintf(stderr, "At least one -r rule is required\n");
        return -1;
    }
    if (cfg->dns_src_ip_be == 0 || cfg->dns_src_port == 0) {
        fprintf(stderr, "A valid -l IPv4:port is required\n");
        return -1;
    }
    return 0;
}

int config_load_blacklist(ab_config_t *cfg)
{
    FILE *fp;
    char line[AB_BLACKLIST_LINE_MAX];

    if (cfg->blacklist_path == NULL) {
        return 0;
    }

    fp = fopen(cfg->blacklist_path, "r");
    if (fp == NULL) {
        fprintf(stderr, "Can't open blacklist file %s: %s\n", cfg->blacklist_path, strerror(errno));
        return -1;
    }

    while (fscanf(fp, "%99s", line) == 1) {
        if (add_subnet(cfg, line) != 0) {
            fclose(fp);
            return -1;
        }
    }
    fclose(fp);
    return 0;
}

int config_ip_blocked(const ab_config_t *cfg, uint32_t ip_be)
{
    uint32_t ip = ntohl(ip_be);
    uint16_t i;

    for (i = 0; i < cfg->blacklist_count; ++i) {
        if ((ip & cfg->blacklist[i].mask) == cfg->blacklist[i].network) {
            return 1;
        }
    }
    return 0;
}
