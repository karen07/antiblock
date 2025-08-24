#include "antiblock.h"
#include "config.h"
#include "const.h"
#include "dns_ans.h"
#include "hash.h"
#include "net_data.h"
#include "stat.h"
#include "tun.h"
#include "domains_read.h"
#include <curl/curl.h>

#define HTTP_OK 200
#define DOMAINS_ALLOCATION_STEP 1024
#define READ_BUF_SIZE 1024

#define GET_GATEWAY_NOT_IN_ROUTES -1

static uint32_t g_seed32 = 0;
static domains_t global_domains;

static uint32_t rotl32(uint32_t x, int32_t r)
{
    return (x << r) | (x >> (32 - r));
}

static uint32_t murmur3_32(const void *key, size_t len, uint32_t seed)
{
    const uint8_t *data = (const uint8_t *)key;
    int32_t nblocks = (int32_t)(len / 4);
    uint32_t h = seed;
    const uint32_t c1 = 0xcc9e2d51u;
    const uint32_t c2 = 0x1b873593u;

    const uint32_t *blocks = (const uint32_t *)(const void *)(data + ((size_t)nblocks * 4));
    for (int32_t i = -nblocks; i; i++) {
        uint32_t k = blocks[i];
        k *= c1;
        k = rotl32(k, 15);
        k *= c2;
        h ^= k;
        h = rotl32(h, 13);
        h = h * 5 + 0xe6546b64u;
    }

    const uint8_t *tail = data + ((size_t)nblocks * 4);
    uint32_t k1 = 0;
    switch (len & 3u) {
    case 3:
        k1 ^= (uint32_t)tail[2] << 16;
        /* fall through */
    case 2:
        k1 ^= (uint32_t)tail[1] << 8;
        /* fall through */
    case 1:
        k1 ^= (uint32_t)tail[0];
        k1 *= c1;
        k1 = rotl32(k1, 15);
        k1 *= c2;
        h ^= k1;
        /* fall through */
    }

    h ^= (uint32_t)len;
    h ^= h >> 16;
    h *= 0x85ebca6bu;
    h ^= h >> 13;
    h *= 0xc2b2ae35u;
    h ^= h >> 16;
    return h;
}

static uint32_t tag32(const char *s, size_t len)
{
    return murmur3_32(s, len, g_seed32);
}

static void realloc_domains(domains_t *domains)
{
    int32_t new_count = domains->capacity + DOMAINS_ALLOCATION_STEP;
    int32_t new_size = new_count * (int32_t)sizeof(domain_gateway_t);
    domain_gateway_t *tmp_domains = realloc(domains->entries, (size_t)new_size);
    if (!tmp_domains) {
        errmsg("Can't realloc domains\n");
    }
    domains->entries = tmp_domains;
    domains->capacity += DOMAINS_ALLOCATION_STEP;
}

static int32_t lower_bound_hash32(const domains_t *d, uint32_t h)
{
    int32_t lo = 0, hi = d->count;
    while (lo < hi) {
        int32_t mid = lo + ((hi - lo) >> 1);
        uint32_t mh = d->entries[mid].hash;
        if (mh < h) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo;
}

static bool insert_sorted_unique(domains_t *d, uint32_t h, int32_t gateway)
{
    int32_t pos = lower_bound_hash32(d, h);
    if (pos < d->count && d->entries[pos].hash == h) {
        return false;
    }
    if (d->capacity - d->count < 1) {
        realloc_domains(d);
    }
    memmove(&d->entries[pos + 1], &d->entries[pos],
            (size_t)(d->count - pos) * sizeof(domain_gateway_t));
    d->entries[pos].hash = h;
    d->entries[pos].gateway = (unsigned char)gateway;
    d->count++;
    return true;
}

static int cmp_hash_qsort(const void *a, const void *b)
{
    const domain_gateway_t *x = (const domain_gateway_t *)a;
    const domain_gateway_t *y = (const domain_gateway_t *)b;
    if (x->hash < y->hash) {
        return -1;
    }
    if (x->hash > y->hash) {
        return 1;
    }
    return 0;
}

static void finalize_sort_and_unique(domains_t *d)
{
    if (d->count <= 1) {
        d->collision_count = 0;
        return;
    }
    qsort(d->entries, (size_t)d->count, sizeof(domain_gateway_t), cmp_hash_qsort);
    int32_t w = 1;
    for (int32_t r = 1; r < d->count; ++r) {
        if (d->entries[r].hash != d->entries[w - 1].hash) {
            d->entries[w++] = d->entries[r];
        }
    }
    int32_t old = d->count;
    d->count = w;
    d->collision_count = old - w;
}

static void append_entry(domains_t *d, uint32_t h, int32_t gateway)
{
    if (d->capacity - d->count < 1) {
        realloc_domains(d);
    }
    d->entries[d->count].hash = h;
    d->entries[d->count].gateway = (unsigned char)gateway;
    d->count++;
}

static void domain_append_part(domains_t *domains, int32_t start_pos, int32_t now_pos, char *str)
{
    char *str_end = &domains->unprocessed_domain[domains->unprocessed_domain_len];
    int32_t unprocessed_domain_len = now_pos - start_pos;
    memcpy(str_end, &str[start_pos], unprocessed_domain_len);
    domains->unprocessed_domain_len += unprocessed_domain_len;
}

static void domain_save_part(domains_t *domains, int32_t start_pos, int32_t now_pos, char *str)
{
    int32_t unprocessed_domain_len = now_pos - start_pos;
    memcpy(domains->unprocessed_domain, &str[start_pos], unprocessed_domain_len);
    domains->unprocessed_domain_len = unprocessed_domain_len;
}

static size_t cb(void *data, size_t size, size_t nmemb, void *clientp)
{
    char *str = (char *)data;
    domains_t *domains = (domains_t *)clientp;
    int32_t realsize = size * nmemb;

    int32_t start_pos = 0;
    for (int32_t now_pos = 0; now_pos < realsize; now_pos++) {
        if (str[now_pos] == '\n') {
            uint32_t h = 0;
            if (domains->unprocessed_domain_len) {
                domain_append_part(domains, start_pos, now_pos, str);
                h = tag32(domains->unprocessed_domain, domains->unprocessed_domain_len);
                domains->unprocessed_domain_len = 0;
            } else {
                h = tag32(&str[start_pos], now_pos - start_pos);
            }

            domains->lines_count++;

            append_entry(domains, h, domains->current_gateway);
            start_pos = now_pos + 1;
        }
    }

    if (start_pos < realsize) {
        domain_save_part(domains, start_pos, realsize, str);
    }

    return realsize;
}

static void flush_tail(domains_t *domains)
{
    if (!domains->unprocessed_domain_len) {
        return;
    }

    uint32_t h = tag32(domains->unprocessed_domain, domains->unprocessed_domain_len);

    domains->lines_count++;

    append_entry(domains, h, domains->current_gateway);
    domains->unprocessed_domain_len = 0;
}

static uint32_t simple_seed32(void)
{
    uint32_t s = 0;
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        if (fread(&s, 1, 4, f) != 4) {
            s = 0;
        }
        fclose(f);
    }
    if (!s) {
        s = (uint32_t)time(NULL) ^ (uint32_t)getpid();
    }
    return s;
}

int32_t domains_gateway_get(const char *s)
{
    uint32_t h = tag32(s, strlen(s));
    if (global_domains.count <= 0) {
        return GET_GATEWAY_NOT_IN_ROUTES;
    }
    int32_t pos = lower_bound_hash32(&global_domains, h);
    if (pos < global_domains.count && global_domains.entries[pos].hash == h) {
        return (int32_t)global_domains.entries[pos].gateway;
    }

    return GET_GATEWAY_NOT_IN_ROUTES;
}

void domains_gateway_add(const char *s, int32_t gateway)
{
    uint32_t h = tag32(s, strlen(s));
    insert_sorted_unique(&global_domains, h, gateway);
}

int32_t domains_read(void)
{
    domains_t local_domains;
    memset(&local_domains, 0, sizeof(local_domains));

    if (!g_seed32) {
        g_seed32 = simple_seed32();
    }

    int32_t status = 1;

    for (int32_t i = 0; i < gateways_count; i++) {
        local_domains.current_gateway = i;
        local_domains.lines_count = 0;

        if (!memcmp(gateway_domains_paths[i], "http", 4)) {
            curl_global_init(CURL_GLOBAL_DEFAULT);
            CURL *curl = curl_easy_init();
            if (curl) {
                curl_easy_setopt(curl, CURLOPT_URL, gateway_domains_paths[i]);
                curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&local_domains);
                CURLcode response;
                response = curl_easy_perform(curl);
                if (response == CURLE_COULDNT_RESOLVE_HOST) {
                    printf("Wrong domains url %s\n", gateway_domains_paths[i]);
                }
                long http_code = 0;
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
                if (http_code != HTTP_OK) {
                    printf("Wrong status code %s\n", gateway_domains_paths[i]);
                }
                curl_easy_cleanup(curl);
                flush_tail(&local_domains);
            }
            curl_global_cleanup();
        } else {
            FILE *domains_fd = fopen(gateway_domains_paths[i], "rb");
            if (!domains_fd) {
                errmsg("Can't open domains file %s\n", gateway_domains_paths[i]);
            }

            char buf[READ_BUF_SIZE];
            size_t n;
            while ((n = fread(buf, 1, sizeof buf, domains_fd)) > 0) {
                cb(buf, 1, n, &local_domains);
            }

            if (ferror(domains_fd)) {
                errmsg("Read error on %s\n", gateway_domains_paths[i]);
            }

            fclose(domains_fd);
            flush_tail(&local_domains);
        }

        printf("From %s readed %d domains\n", gateway_domains_paths[i], local_domains.lines_count);
    }

    finalize_sort_and_unique(&local_domains);
    printf("Unique %d / Collision %d\n", local_domains.count, local_domains.collision_count);

    domain_gateway_t *entries = global_domains.entries;
    global_domains = local_domains;

    free(entries);

    return status;
}
