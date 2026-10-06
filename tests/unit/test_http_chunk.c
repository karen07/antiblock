/* Access file-local arena helpers and the libcurl callback without changing the public API. */
#include "../../src/domains.c"

#include <stdio.h>

int main(void)
{
    domain_table_t table = { 0 };
    curl_sink_t sink = { &table, 0 };
    char payload[] = "one\n";
    int ok = 0;

    if (arena_append(&table, NULL, 0) != 0 || table.arena != NULL || table.arena_size != 0 ||
        table.arena_capacity != 0) {
        fprintf(stderr, "zero append allocated or accessed a NULL arena\n");
        goto done;
    }
    if (curl_write_cb(NULL, 0, 4, &sink) != 0 || sink.failed ||
        curl_write_cb(NULL, 1, 0, &sink) != 0 || sink.failed) {
        fprintf(stderr, "empty HTTP chunks were not ignored\n");
        goto done;
    }
    if (curl_write_cb(payload, 1, sizeof(payload) - 1u, &sink) != sizeof(payload) - 1u ||
        sink.failed || table.arena_size != sizeof(payload) - 1u ||
        memcmp(table.arena, payload, sizeof(payload) - 1u) != 0) {
        fprintf(stderr, "nonempty HTTP payload was not appended\n");
        goto done;
    }
    if (curl_write_cb(NULL, 0, 1, &sink) != 0 || sink.failed ||
        table.arena_size != sizeof(payload) - 1u) {
        fprintf(stderr, "trailing empty HTTP chunk corrupted the arena\n");
        goto done;
    }
    puts("PASS: zero-length curl callbacks and subsequent nonempty append");
    ok = 1;

done:
    domains_destroy(&table);
    return ok ? 0 : 1;
}
