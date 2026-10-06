#include "capture.h"
#include "config.h"
#include "dns.h"
#include "domains.h"
#include "routes.h"
#include "telemetry.h"

#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static volatile sig_atomic_t stop_requested = 0;

static void signal_handler(int signo)
{
    (void)signo;
    stop_requested = 1;
}

static int install_signal_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) != 0 || sigaction(SIGTERM, &sa, NULL) != 0) {
        perror("sigaction");
        return -1;
    }
    return 0;
}

static void print_config(const ab_config_t *cfg)
{
    struct in_addr addr;
    char ip[INET_ADDRSTRLEN];
    uint8_t i;

    addr.s_addr = cfg->dns_src_ip_be;
    if (inet_ntop(AF_INET, &addr, ip, sizeof(ip)) == NULL) {
        strcpy(ip, "?");
    }

    printf("AntiBlock %s\n", AB_VERSION);
    printf("DNS source: %s:%u\n", ip, (unsigned)cfg->dns_src_port);
    for (i = 0; i < cfg->rule_count; ++i) {
        printf("Rule %u: %s <- %s", (unsigned)i + 1u, cfg->rules[i].ifname, cfg->rules[i].source);
        if (cfg->rules[i].is_l2) {
            struct in_addr gw;
            char gwbuf[INET_ADDRSTRLEN];
            gw.s_addr = cfg->rules[i].nexthop_be;
            if (inet_ntop(AF_INET, &gw, gwbuf, sizeof(gwbuf)) == NULL) {
                strcpy(gwbuf, "?");
            }
            printf(" (L2 via %s)", gwbuf);
        } else {
            printf(" (L3)");
        }
        putchar('\n');
    }
    if (cfg->test_mode) {
        puts("Test mode: kernel routes are not modified");
    }
}

static void telemetry_print_with_capture(telemetry_t *telemetry, const ab_config_t *cfg,
                                         capture_t *capture, int capture_ready)
{
    capture_stats_t stats;

    telemetry_print(telemetry, cfg);
    if (capture_ready && capture_get_stats(capture, &stats) == 0) {
        telemetry_print_capture_stats(telemetry, stats.received, stats.dropped,
                                      stats.interface_dropped);
    }
    telemetry_flush(telemetry);
}

int main(int argc, char **argv)
{
    ab_config_t cfg;
    telemetry_t telemetry;
    domain_table_t domains;
    route_state_t routes;
    capture_t capture;
    uint32_t last_domain_reload = 0;
    uint32_t domain_reload_interval = AB_DOMAIN_RELOAD_SEC;
    uint32_t last_route_expire = 0;
    uint32_t last_stat_print = 0;
    int telemetry_ready = 0;
    int routes_ready = 0;
    int capture_ready = 0;
    int exit_code = EXIT_FAILURE;
    int rc;

    memset(&telemetry, 0, sizeof(telemetry));
    memset(&domains, 0, sizeof(domains));
    memset(&routes, 0, sizeof(routes));
    memset(&capture, 0, sizeof(capture));

    config_init(&cfg);
    rc = config_parse(&cfg, argc, argv);
    if (rc > 0) {
        return EXIT_SUCCESS;
    }
    if (rc < 0) {
        config_print_help(stderr);
        return EXIT_FAILURE;
    }
    if (config_load_blacklist(&cfg) != 0) {
        return EXIT_FAILURE;
    }

    if (telemetry_open(&telemetry, &cfg) != 0) {
        goto out;
    }
    telemetry_ready = 1;

    if (routes_open(&routes, &cfg, &telemetry) != 0) {
        goto out;
    }
    routes_ready = 1;
    if (routes_clean_stale(&routes) != 0) {
        fprintf(stderr, "Warning: some stale AntiBlock routes could not be removed\n");
    }

    rc = domains_reload(&domains, &cfg);
    if (rc < 0) {
        goto out;
    }
    if (rc > 0) {
        domain_reload_interval = AB_DOMAIN_RETRY_SEC;
    }
    telemetry_reset_period(&telemetry);

    if (capture_open(&capture, &cfg) != 0) {
        goto out;
    }
    capture_ready = 1;

    print_config(&cfg);

    /* Before this point the process owns no live dynamic routes. */
    if (install_signal_handlers() != 0) {
        goto out;
    }

    last_domain_reload = ab_mono_sec();
    last_route_expire = last_domain_reload;

    while (!stop_requested) {
        uint32_t now = ab_mono_sec();
        ab_bytes_t dns_packet;
        int capture_rc;

        if ((uint32_t)(now - last_domain_reload) >= domain_reload_interval) {
            telemetry_log_header(&telemetry);
            telemetry_reset_period(&telemetry);
            rc = domains_reload(&domains, &cfg);
            if (rc < 0) {
                fprintf(stderr, "Domain reload failed; domain table is empty\n");
            } else if (rc > 0) {
                fprintf(stderr, "Domain reload completed with source errors\n");
            }
            domain_reload_interval = (rc == 0) ? AB_DOMAIN_RELOAD_SEC : AB_DOMAIN_RETRY_SEC;
            last_domain_reload = ab_mono_sec();
        }

        if ((uint32_t)(now - last_route_expire) >= 1u) {
            routes_expire(&routes, now);
            last_route_expire = now;
        }

        if (last_stat_print == 0 || (uint32_t)(now - last_stat_print) >= AB_STAT_INTERVAL_SEC) {
            telemetry_print_with_capture(&telemetry, &cfg, &capture, capture_ready);
            last_stat_print = now;
        }

        capture_rc = capture_next_dns(&capture, &cfg, &dns_packet);
        if (capture_rc > 0) {
            (void)dns_process_response(&dns_packet, &cfg, &domains, &routes, &telemetry, now);
            continue;
        }
        if (capture_rc < 0) {
            fprintf(stderr, "Capture failed\n");
            goto out;
        }
        if (capture_wait(&capture, (int)AB_PCAP_WAIT_MS) < 0) {
            fprintf(stderr, "Capture wait failed\n");
            goto out;
        }
    }

    exit_code = EXIT_SUCCESS;

out:
    if (routes_ready) {
        routes_shutdown(&routes);
    }
    if (telemetry_ready) {
        telemetry_print_with_capture(&telemetry, &cfg, &capture, capture_ready);
    }
    if (capture_ready) {
        capture_close(&capture);
    }
    domains_destroy(&domains);
    if (routes_ready) {
        routes_close(&routes);
    }
    if (telemetry_ready) {
        telemetry_close(&telemetry);
    }
    return exit_code;
}
