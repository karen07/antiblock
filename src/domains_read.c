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

memory_t domains;
array_hashmap_t domains_map_struct;

static array_hashmap_hash domain_add_hash(const void *add_elem_data)
{
    const uint32_t *elem = add_elem_data;
    return djb33_hash_len(&domains.data[*elem], -1);
}

static array_hashmap_bool domain_add_cmp(const void *add_elem_data, const void *hashmap_elem_data)
{
    const uint32_t *elem1 = add_elem_data;
    const uint32_t *elem2 = hashmap_elem_data;

    return !strcmp(&domains.data[*elem1], &domains.data[*elem2]);
}

static array_hashmap_hash domain_find_hash(const void *find_elem_data)
{
    const char *elem = find_elem_data;
    return djb33_hash_len(elem, -1);
}

static array_hashmap_bool domain_find_cmp(const void *find_elem_data, const void *hashmap_elem_data)
{
    const char *elem1 = find_elem_data;
    const uint32_t *elem2 = hashmap_elem_data;

    return !strcmp(elem1, &domains.data[*elem2]);
}

static size_t cb(void *data, size_t size, size_t nmemb, void *clientp)
{
    size_t realsize = size * nmemb;
    memory_t *mem = (memory_t *)clientp;

    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if (!ptr)
        return 0;

    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), data, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;

    return realsize;
}

int32_t domains_read(void)
{
    array_hashmap_del(&domains_map_struct);

    if (domains.data) {
        free(domains.data);
        memset(&domains, 0, sizeof(domains));
    }

    if (is_domains_file_url) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        CURL *curl = curl_easy_init();
        if (curl) {
            curl_easy_setopt(curl, CURLOPT_URL, domains_file_url);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&domains);

            CURLcode response;
            response = curl_easy_perform(curl);
            if (response == CURLE_COULDNT_RESOLVE_HOST) {
                errmsg("Wrong domains url %s\n", domains_file_url);
            }

            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            if (http_code != HTTP_OK) {
                errmsg("Received non 200 status code %d\n", http_code);
            }

            curl_easy_cleanup(curl);
        }
        curl_global_cleanup();
    }

    int64_t domains_web_file_size = domains.size;

    if (is_domains_file_path) {
        FILE *domains_fd = fopen(domains_file_path, "r");
        if (domains_fd == NULL) {
            errmsg("Can't open domains file\n");
        }
        fseek(domains_fd, 0, SEEK_END);
        int64_t domains_file_size_add = ftell(domains_fd);
        fseek(domains_fd, 0, SEEK_SET);
        char *ptr = realloc(domains.data, domains.size + domains_file_size_add + 1);
        if (!ptr) {
            errmsg("No free memory for domains_file\n");
        }
        domains.data = ptr;
        if (fread(&(domains.data[domains.size]), domains_file_size_add, 1, domains_fd) != 1) {
            errmsg("Can't read domains file\n");
        }
        domains.size += domains_file_size_add;
        domains.data[domains.size] = 0;
        fclose(domains_fd);
    }

    char *ptr = realloc(domains.data, domains.size + CNAME_DOMAINS_MAP_MAX_SIZE * DOMAIN_MAX_SIZE);
    if (!ptr) {
        errmsg("No free memory for cname_domains\n");
    }
    domains.data = ptr;
    domains.max_size = domains.size + CNAME_DOMAINS_MAP_MAX_SIZE * DOMAIN_MAX_SIZE;

    if (domains.size > 0) {
        int32_t domains_map_size = 0;
        int32_t file_domains_map_size = 0;
        for (int32_t i = 0; i < (int32_t)domains.size; i++) {
            if (domains.data[i] == '\n') {
                domains.data[i] = 0;
                domains_map_size++;
                if (i >= domains_web_file_size) {
                    file_domains_map_size++;
                }
            }
        }

        int32_t domains_map_size_cname = domains_map_size + CNAME_DOMAINS_MAP_MAX_SIZE;
        domains_map_struct = array_hashmap_init(domains_map_size_cname, 1.0, sizeof(uint32_t));
        if (domains_map_struct == NULL) {
            errmsg("No free memory for domains_map\n");
        }

        int32_t is_thread_safety = 0;
        is_thread_safety = array_hashmap_is_thread_safety(domains_map_struct);
        if (!is_thread_safety) {
            errmsg("No thread safety hashmap\n");
        }

        printf("Readed domains from file %d from url %d\n", file_domains_map_size,
               domains_map_size - file_domains_map_size);

        array_hashmap_set_func(domains_map_struct, domain_add_hash, domain_add_cmp,
                               domain_find_hash, domain_find_cmp, domain_find_hash,
                               domain_find_cmp);

        int32_t domain_offset = 0;
        for (int32_t i = 0; i < domains_map_size; i++) {
            if (!memcmp(&domains.data[domain_offset], "www.", 4)) {
                domain_offset += 4;
            }

            array_hashmap_add_elem(domains_map_struct, &domain_offset, NULL, NULL);

            domain_offset = strchr(&domains.data[domain_offset + 1], 0) - domains.data + 1;
        }
    }

    if (domains_web_file_size > 0 || !is_domains_file_url) {
        return 1;
    } else {
        return 0;
    }
}
