#include "antiblock.h"
#include "config.h"
#include "dns_ans.h"
#include "hash.h"
#include "net_data.h"
#include "stat.h"
#include "tun.h"
#include "domains_read.h"
#include <curl/curl.h>

#define HTTP_OK 200

static memory_t domains;
static array_hashmap_t domain_routes;

int32_t get_gateway(memory_t *domain)
{
    char *dot_pos = domain->data + 1;
    if (!memcmp(dot_pos, "www.", strlen("www."))) {
        dot_pos += strlen("www.");
    }

    domains_gateway_t res_elem;
    int32_t find_res = array_hashmap_find_elem(domain_routes, dot_pos, &res_elem);
    if (find_res == array_hashmap_elem_finded) {
        return res_elem.gateway;
    }

    return GET_GATEWAY_NOT_IN_ROUTES;
}

void add_domain(memory_t *cname_domain, int32_t cname_domain_gateway)
{
    if (domain_routes) {
        if (domains.size + cname_domain->size < domains.max_size) {
            strcpy(&(domains.data[domains.size]), cname_domain->data + 1);

            domains_gateway_t add_elem;
            add_elem.offset = domains.size;
            add_elem.gateway = cname_domain_gateway;

            domains.size += cname_domain->size;

            array_hashmap_add_elem(domain_routes, &add_elem, NULL, NULL);
        }
    }
}

static array_hashmap_hash domain_add_hash(const void *add_elem_data)
{
    const domains_gateway_t *elem = add_elem_data;
    return djb33_hash_len(&domains.data[elem->offset], -1);
}

static array_hashmap_bool domain_add_cmp(const void *add_elem_data, const void *hashmap_elem_data)
{
    const domains_gateway_t *elem1 = add_elem_data;
    const domains_gateway_t *elem2 = hashmap_elem_data;

    return !strcmp(&domains.data[elem1->offset], &domains.data[elem2->offset]);
}

static array_hashmap_hash domain_find_hash(const void *find_elem_data)
{
    const char *elem = find_elem_data;
    return djb33_hash_len(elem, -1);
}

static array_hashmap_bool domain_find_cmp(const void *find_elem_data, const void *hashmap_elem_data)
{
    const char *elem1 = find_elem_data;
    const domains_gateway_t *elem2 = hashmap_elem_data;

    return !strcmp(elem1, &domains.data[elem2->offset]);
}

static size_t cb(void *data, size_t size, size_t nmemb, void *clientp)
{
    size_t realsize = size * nmemb;
    memory_t *mem = (memory_t *)clientp;

    mem->max_size += realsize;
    char *ptr = realloc(mem->data, mem->max_size);
    if (ptr == NULL)
        return 0;
    mem->data = ptr;

    memcpy(&(mem->data[mem->size]), data, realsize);
    mem->size = mem->max_size;

    return realsize;
}

int32_t domains_read(void)
{
    array_hashmap_del(&domain_routes);

    if (domains.data) {
        free(domains.data);
    }

    memset(&domains, 0, sizeof(domains));

    uint32_t gateway_domains_offset[GATEWAY_MAX_COUNT + 1];
    gateway_domains_offset[0] = 0;

    for (int32_t i = 0; i < gateways_count; i++) {
        if (!memcmp(gateway_domains_paths[i], "http", 4)) {
            curl_global_init(CURL_GLOBAL_DEFAULT);
            CURL *curl = curl_easy_init();
            if (curl) {
                curl_easy_setopt(curl, CURLOPT_URL, gateway_domains_paths[i]);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&domains);

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

            fseek(domains_fd, 0, SEEK_END);
            int64_t domains_file_size_add = ftell(domains_fd);
            fseek(domains_fd, 0, SEEK_SET);

            domains.max_size += domains_file_size_add;
            domains.data = realloc(domains.data, domains.max_size);
            if (domains.data == NULL) {
                errmsg("No free memory for domains_file %s\n", gateway_domains_paths[i]);
            }

            if (fread(&(domains.data[domains.size]), 1, domains_file_size_add, domains_fd) !=
                (size_t)domains_file_size_add) {
                errmsg("Can't read domains file %s\n", gateway_domains_paths[i]);
            }
            domains.size = domains.max_size;

            fclose(domains_fd);
        }

        if (!(domains.size < (1 << OFFSET_BITS_COUNT))) {
            errmsg("The total size of all domains must be less than %d MB\n",
                   (1 << OFFSET_BITS_COUNT) / 1024 / 1024);
        }

        if (domains.data && domains.max_size) {
            if (domains.data[domains.max_size - 1] != '\n') {
                domains.max_size += 1;
                domains.data = realloc(domains.data, domains.max_size);
                if (domains.data == NULL) {
                    errmsg("No free memory for domains_file %s\n", gateway_domains_paths[i]);
                }

                domains.data[domains.max_size - 1] = '\n';
                domains.size = domains.max_size;
            }
        }

        gateway_domains_offset[i + 1] = domains.max_size;
    }

    domains.max_size += CNAME_DOMAINS_MAP_MAX_SIZE * DOMAIN_MAX_SIZE;
    domains.data = realloc(domains.data, domains.max_size);
    if (domains.data == NULL) {
        errmsg("No free memory for cname_domains\n");
    }

    if (!(domains.size < (1 << OFFSET_BITS_COUNT))) {
        errmsg("The total size of all domains must be less than %d MB\n",
               (1 << OFFSET_BITS_COUNT) / 1024 / 1024);
    }

    int32_t gateway_domains_count[GATEWAY_MAX_COUNT];
    memset(gateway_domains_count, 0, sizeof(int32_t) * GATEWAY_MAX_COUNT);

    if (domains.size > 0) {
        int32_t domain_routes_size = 0;
        for (int32_t i = 0; i < (int32_t)domains.size; i++) {
            if (domains.data[i] == '\n') {
                domains.data[i] = 0;

                domain_routes_size++;
            }
        }

        int32_t domain_routes_size_cname = domain_routes_size + CNAME_DOMAINS_MAP_MAX_SIZE;
        domain_routes =
            array_hashmap_init(domain_routes_size_cname, 1.0, sizeof(domains_gateway_t));
        if (domain_routes == NULL) {
            errmsg("No free memory for domain_routes\n");
        }

        int32_t is_thread_safety = 0;
        is_thread_safety = array_hashmap_is_thread_safety(domain_routes);
        if (is_thread_safety == 0) {
            errmsg("No thread safety hashmap\n");
        }

        array_hashmap_set_func(domain_routes, domain_add_hash, domain_add_cmp, domain_find_hash,
                               domain_find_cmp, domain_find_hash, domain_find_cmp);

        uint32_t domain_offset = 0;
        int32_t gateway_id = 0;

        for (int32_t i = 0; i < domain_routes_size; i++) {
            for (int32_t j = 1; j <= gateways_count; j++) {
                if ((gateway_domains_offset[j - 1] <= domain_offset) &&
                    (domain_offset < gateway_domains_offset[j])) {
                    gateway_id = j - 1;
                    gateway_domains_count[gateway_id]++;
                }
            }

            if (!memcmp(&domains.data[domain_offset], "www.", strlen("www."))) {
                domain_offset += strlen("www.");
            }

            domains_gateway_t add_elem;
            add_elem.offset = domain_offset;
            add_elem.gateway = gateway_id;

            array_hashmap_add_elem(domain_routes, &add_elem, NULL, NULL);

            domain_offset = strchr(&domains.data[domain_offset + 1], 0) - domains.data + 1;
        }
    }

    int32_t status = 1;

    for (int32_t j = 0; j < gateways_count; j++) {
        if ((!memcmp(gateway_domains_paths[j], "http", 4)) && (gateway_domains_count[j] == 0)) {
            status = 0;
        }
        printf("From %s readed %d domains\n", gateway_domains_paths[j], gateway_domains_count[j]);
    }

    return status;
}
