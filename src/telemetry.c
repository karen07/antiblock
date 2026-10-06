#include "telemetry.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

static void print_time(FILE *fp, time_t value)
{
    struct tm tm_value;
    if (localtime_r(&value, &tm_value) == NULL) {
        fputs("unknown", fp);
        return;
    }
    fprintf(fp, "%02d.%02d.%04d %02d:%02d:%02d", tm_value.tm_mday, tm_value.tm_mon + 1,
            tm_value.tm_year + 1900, tm_value.tm_hour, tm_value.tm_min, tm_value.tm_sec);
}

int telemetry_open(telemetry_t *t, const ab_config_t *cfg)
{
    char path[PATH_MAX];

    memset(t, 0, sizeof(*t));
    t->stat_start = time(NULL);

    if (cfg->log_enabled) {
        if (snprintf(path, sizeof(path), "%s/log.txt", cfg->output_dir) >= (int)sizeof(path)) {
            fprintf(stderr, "Log path is too long\n");
            return -1;
        }
        t->log_fp = fopen(path, "w");
        if (t->log_fp == NULL) {
            fprintf(stderr, "Can't open %s: %s\n", path, strerror(errno));
            return -1;
        }
    }

    if (cfg->stat_enabled) {
        if (snprintf(path, sizeof(path), "%s/stat.txt", cfg->output_dir) >= (int)sizeof(path)) {
            fprintf(stderr, "Stat path is too long\n");
            telemetry_close(t);
            return -1;
        }
        t->stat_fp = fopen(path, "w");
        if (t->stat_fp == NULL) {
            fprintf(stderr, "Can't open %s: %s\n", path, strerror(errno));
            telemetry_close(t);
            return -1;
        }
    }

    telemetry_log_header(t);
    return 0;
}

void telemetry_close(telemetry_t *t)
{
    if (t->log_fp != NULL) {
        fclose(t->log_fp);
    }
    if (t->stat_fp != NULL) {
        fclose(t->stat_fp);
    }
    t->log_fp = NULL;
    t->stat_fp = NULL;
}

void telemetry_reset_period(telemetry_t *t)
{
    t->processed = 0;
    t->parse_errors = 0;
    t->route_add_errors = 0;
    t->stat_start = time(NULL);
}

void telemetry_print(const telemetry_t *t, const ab_config_t *cfg)
{
    FILE *fp = t->stat_fp;
    time_t now;
    uint8_t i;

    if (fp == NULL) {
        return;
    }
    if (ftruncate(fileno(fp), 0) != 0) {
        return;
    }
    rewind(fp);

    fputs("Statistics ", fp);
    print_time(fp, t->stat_start);
    fputs(" - ", fp);
    now = time(NULL);
    print_time(fp, now);
    fputc('\n', fp);

    fprintf(fp, "DNS packets processed: %" PRIu64 "\n", t->processed);
    fprintf(fp, "DNS parsing errors   : %" PRIu64 "\n", t->parse_errors);
    fprintf(fp, "Route add errors     : %" PRIu64 "\n", t->route_add_errors);
    fputs("In route table:\n", fp);
    for (i = 0; i < cfg->rule_count; ++i) {
        fprintf(fp, "    Route %u (%s): %d\n", (unsigned)i + 1u, cfg->rules[i].ifname,
                t->route_count[i]);
    }
    fflush(fp);
}

void telemetry_print_capture_stats(telemetry_t *t, uint64_t received, uint64_t dropped,
                                   uint64_t interface_dropped)
{
    if (t->stat_fp == NULL) {
        return;
    }
    fprintf(t->stat_fp, "PCAP packets received : %" PRIu64 "\n", received);
    fprintf(t->stat_fp, "PCAP packets dropped  : %" PRIu64 "\n", dropped);
    fprintf(t->stat_fp, "PCAP interface dropped: %" PRIu64 "\n", interface_dropped);
    fflush(t->stat_fp);
}

void telemetry_log_header(telemetry_t *t)
{
    FILE *fp = t->log_fp;
    if (fp == NULL) {
        return;
    }
    if (fflush(fp) != 0 || ftruncate(fileno(fp), 0) != 0) {
        return;
    }
    rewind(fp);
    fputs("Reductions:\n"
          "    Q(x)  DNS question type\n"
          "    BA(x) A routed through rule x\n"
          "    BC(x) CNAME classified through rule x\n"
          "    BH(x) HTTPS AliasMode target classified through rule x\n"
          "    BL    IP is blacklisted\n"
          "    NA    A owner is not routed\n"
          "    NC    CNAME is not routed\n"
          "    NH    HTTPS AliasMode target is not routed\n",
          fp);
}

void telemetry_flush(telemetry_t *t)
{
    if (t->log_fp != NULL) {
        fflush(t->log_fp);
    }
    fflush(stdout);
    fflush(stderr);
}

void telemetry_dns_processed(telemetry_t *t)
{
    t->processed++;
}

void telemetry_dns_error(telemetry_t *t, int code, const uint8_t *packet, size_t len)
{
    size_t i;
    t->parse_errors++;
    if (t->log_fp == NULL) {
        return;
    }
    fprintf(t->log_fp, "DNS parse error %d, %zu bytes\n", code, len);
    for (i = 0; i < len; ++i) {
        if (i != 0 && i % 16u == 0) {
            fputc('\n', t->log_fp);
        }
        fprintf(t->log_fp, "%02x ", packet[i]);
    }
    fputc('\n', t->log_fp);
}

static void log_clock(FILE *fp)
{
    time_t now = time(NULL);
    struct tm tm_value;
    if (localtime_r(&now, &tm_value) != NULL) {
        fprintf(fp, "\n%02d:%02d:%02d ", tm_value.tm_hour, tm_value.tm_min, tm_value.tm_sec);
    }
}

void telemetry_log_query(telemetry_t *t, uint16_t type, const char *name)
{
    if (t->log_fp == NULL) {
        return;
    }
    log_clock(t->log_fp);
    fprintf(t->log_fp, "Q(%u) %s\n", (unsigned)type, name);
}

void telemetry_log_a(telemetry_t *t, int gateway, int blocked, const char *name, uint32_t ip_be)
{
    struct in_addr ip;
    char buf[INET_ADDRSTRLEN];

    if (t->log_fp == NULL) {
        return;
    }
    ip.s_addr = ip_be;
    if (inet_ntop(AF_INET, &ip, buf, sizeof(buf)) == NULL) {
        strcpy(buf, "?");
    }

    if (blocked) {
        fputs("    BL", t->log_fp);
    } else if (gateway >= 0) {
        fprintf(t->log_fp, "    BA(%d)", gateway + 1);
    } else {
        fputs("    NA", t->log_fp);
    }
    fprintf(t->log_fp, " %s %s\n", name, buf);
}

void telemetry_log_cname(telemetry_t *t, int gateway, const char *owner, const char *target)
{
    if (t->log_fp == NULL) {
        return;
    }
    if (gateway >= 0) {
        fprintf(t->log_fp, "    BC(%d)", gateway + 1);
    } else {
        fputs("    NC", t->log_fp);
    }
    fprintf(t->log_fp, " %s %s\n", owner, target);
}

void telemetry_log_https_alias(telemetry_t *t, int gateway, const char *owner, const char *target)
{
    if (t->log_fp == NULL) {
        return;
    }
    if (gateway >= 0) {
        fprintf(t->log_fp, "    BH(%d)", gateway + 1);
    } else {
        fputs("    NH", t->log_fp);
    }
    fprintf(t->log_fp, " %s %s\n", owner, target);
}

void telemetry_log_other(telemetry_t *t, uint16_t type, const char *owner)
{
    if (t->log_fp != NULL) {
        fprintf(t->log_fp, "    A(%u) %s\n", (unsigned)type, owner);
    }
}

void telemetry_route_add_failed(telemetry_t *t)
{
    t->route_add_errors++;
}

void telemetry_route_added(telemetry_t *t, uint8_t gateway)
{
    t->route_count[gateway]++;
}

void telemetry_route_deleted(telemetry_t *t, uint8_t gateway)
{
    if (t->route_count[gateway] > 0) {
        t->route_count[gateway]--;
    }
}

void telemetry_route_moved(telemetry_t *t, uint8_t old_gateway, uint8_t new_gateway,
                           uint32_t dst_be, const ab_config_t *cfg)
{
    struct in_addr ip;
    char buf[INET_ADDRSTRLEN];

    telemetry_route_deleted(t, old_gateway);
    telemetry_route_added(t, new_gateway);

    ip.s_addr = dst_be;
    if (inet_ntop(AF_INET, &ip, buf, sizeof(buf)) == NULL) {
        strcpy(buf, "?");
    }
    printf("Route %s moved: %s -> %s\n", buf, cfg->rules[old_gateway].ifname,
           cfg->rules[new_gateway].ifname);
}
