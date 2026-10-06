#include "domains.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int write_source(const char *path, const char *data)
{
    FILE *fp = fopen(path, "wb");
    int rc;

    if (fp == NULL) {
        return -1;
    }
    rc = fputs(data, fp) == EOF ? -1 : 0;
    if (fclose(fp) != 0) {
        rc = -1;
    }
    return rc;
}

int main(void)
{
    char empty[] = "/tmp/ab-empty-XXXXXX";
    char mixed[] = "/tmp/ab-mixed-XXXXXX";
    const char *data = "WWW.Mixed.Test\n!WWW.Exact.Test\n";
    ab_config_t cfg = { 0 };
    domain_table_t table = { 0 };
    int fd;
    int rc = 1;

    fd = mkstemp(empty);
    if (fd < 0) {
        perror("mkstemp empty");
        return 1;
    }
    close(fd);
    fd = mkstemp(mixed);
    if (fd < 0) {
        perror("mkstemp mixed");
        unlink(empty);
        return 1;
    }
    close(fd);

    if (write_source(mixed, data) != 0) {
        goto cleanup;
    }
    cfg.rule_count = 1;
    cfg.rules[0].source = empty;
    if (domains_reload(&table, &cfg) != 0 || table.static_count != 0) {
        fprintf(stderr, "empty-only source failed\n");
        goto cleanup;
    }
    if (domains_lookup(&table, "mixed.test") != -1) {
        fprintf(stderr, "empty-only source matched unexpected domain\n");
        goto cleanup;
    }

    cfg.rule_count = 2;
    cfg.rules[1].source = mixed;
    if (domains_reload(&table, &cfg) != 0 || table.static_count != 2) {
        fprintf(stderr, "empty + mixed source failed\n");
        goto cleanup;
    }
    if (domains_lookup(&table, "mixed.test") != 1 ||
        domains_lookup(&table, "www.mixed.test") != 1 ||
        domains_lookup(&table, "child.mixed.test") != 1 ||
        domains_lookup(&table, "exact.test") != 1 ||
        domains_lookup(&table, "child.exact.test") != -1) {
        fprintf(stderr, "WWW normalization or exact matching failed\n");
        goto cleanup;
    }

    puts("PASS: empty first source, uppercase WWW, exact-only domain");
    rc = 0;

cleanup:
    domains_destroy(&table);
    unlink(empty);
    unlink(mixed);
    return rc;
}
