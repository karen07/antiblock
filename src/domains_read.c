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

static uint32_t g_seed32 = 0;

static inline uint32_t crc24_openpgp_seeded(const void *key, size_t len, uint32_t seed)
{
    const uint8_t *data = (const uint8_t *)key;
    uint32_t crc = 0xB704CEu ^ (seed & 0x00FFFFFFu);
    for (size_t i = 0; i < len; ++i) {
        crc ^= (uint32_t)data[i] << 16;
        for (int j = 0; j < 8; ++j) {
            crc <<= 1;
            if (crc & 0x01000000u) {
                crc ^= 0x01864CFBu;
            }
        }
    }
    return crc & 0x00FFFFFFu;
}

static inline uint32_t tag32(const char *s, size_t len)
{
    return crc24_openpgp_seeded(s, len, g_seed32);
}

static inline void put24be(uint8_t out[3], uint32_t v)
{
    out[0] = (uint8_t)(v >> 16);
    out[1] = (uint8_t)(v >> 8);
    out[2] = (uint8_t)v;
}

inline uint32_t get24be(const uint8_t in[3])
{
    return ((uint32_t)in[0] << 16) | ((uint32_t)in[1] << 8) | in[2];
}

void realloc_domains(domains_t *domains)
{
    int32_t new_size = (domains->allocated + DOMAINS_ALLOCATION_STEP) * sizeof(domain_gateway_t);
    domain_gateway_t *tmp_domains = realloc(domains->domains, new_size);
    if (!tmp_domains) {
        errmsg("Can't realloc domains\n");
    }
    domains->domains = tmp_domains;
    domains->allocated += DOMAINS_ALLOCATION_STEP;
}

static size_t cb(void *data, size_t size, size_t nmemb, void *clientp)
{
    char *str = (char *)data;
    domains_t *domains = (domains_t *)clientp;
    size_t realsize = size * nmemb;

    int32_t start_pos = 0;
    for (int32_t i = 0; i < (int32_t)realsize; i++) {
        if (str[i] == '\n') {
            if (domains->allocated - domains->used < 1) {
                realloc_domains(domains);
            }

            uint32_t h = 0;
            if (domains->unprocessed_domain_len) {
                char *str_end = &domains->unprocessed_domain[domains->unprocessed_domain_len];
                int32_t unprocessed_domain_len = i - start_pos;
                memcpy(str_end, &str[start_pos], unprocessed_domain_len);
                domains->unprocessed_domain_len += unprocessed_domain_len;
                h = tag32(domains->unprocessed_domain, domains->unprocessed_domain_len);
                domains->unprocessed_domain_len = 0;
            } else {
                h = tag32(&str[start_pos], i - start_pos);
            }

            put24be(domains->domains[domains->used].hash, h);
            domains->domains[domains->used].gateway = domains->current_gateway;

            domains->used++;
            start_pos = i + 1;
        }
    }

    if (start_pos < (int32_t)realsize) {
        int32_t unprocessed_domain_len = (int32_t)realsize - start_pos;
        memcpy(domains->unprocessed_domain, &str[start_pos], unprocessed_domain_len);
        domains->unprocessed_domain_len = unprocessed_domain_len;
    }

    return realsize;
}

int32_t domains_read(void)
{
    domains_t tmp_domains;
    memset(&tmp_domains, 0, sizeof(tmp_domains));

    for (int32_t i = 0; i < gateways_count; i++) {
        if (!memcmp(gateway_domains_paths[i], "http", 4)) {
            curl_global_init(CURL_GLOBAL_DEFAULT);
            CURL *curl = curl_easy_init();
            if (curl) {
                tmp_domains.current_gateway = i;

                curl_easy_setopt(curl, CURLOPT_URL, gateway_domains_paths[i]);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&tmp_domains);

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
            }
            curl_global_cleanup();
        } else {
            FILE *domains_fd = fopen(gateway_domains_paths[i], "r");
            if (domains_fd == NULL) {
                errmsg("Can't open domains file %s\n", gateway_domains_paths[i]);
            }

            fclose(domains_fd);
        }
    }

    int32_t status = 1;

    for (int32_t j = 0; j < gateways_count; j++) {
        //if ((!memcmp(gateway_domains_paths[j], "http", 4)) && (gateway_domains_count[j] == 0)) {
        //    status = 0;
        //}
        //printf("From %s readed %d domains\n", gateway_domains_paths[j], gateway_domains_count[j]);
    }

    return status;
}
