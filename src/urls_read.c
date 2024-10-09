#include "antiblock.h"
#include "config.h"
#include "const.h"
#include "dns_ans.h"
#include "hash.h"
#include "net_data.h"
#include "stat.h"
#include "tun.h"
#include "urls_read.h"
#include <curl/curl.h>

memory_t urls;
const array_hashmap_t *urls_map_struct;

static uint32_t add_url_hash(const void *void_elem)
{
    const uint32_t *elem = void_elem;
    return djb33_hash_len(&urls.data[*elem], -1);
}

static int32_t add_url_cmp(const void *void_elem1, const void *void_elem2)
{
    const uint32_t *elem1 = void_elem1;
    const uint32_t *elem2 = void_elem2;

    return !strcmp(&urls.data[*elem1], &urls.data[*elem2]);
}

static uint32_t find_url_hash(const void *void_elem)
{
    const char *elem = void_elem;
    return djb33_hash_len(elem, -1);
}

static int32_t find_url_cmp(const void *void_elem1, const void *void_elem2)
{
    const char *elem1 = void_elem1;
    const uint32_t *elem2 = void_elem2;

    return !strcmp(elem1, &urls.data[*elem2]);
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

int64_t urls_read(void)
{
    if (urls_map_struct) {
        const array_hashmap_t *tmp_urls_map_struct = urls_map_struct;
        urls_map_struct = NULL;
        sleep(1);
        del_array_hashmap(tmp_urls_map_struct);
    }

    if (urls.data) {
        free(urls.data);
        memset(&urls, 0, sizeof(urls));
    }

    if (is_domains_file_url) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        CURL *curl = curl_easy_init();
        if (curl) {
            curl_easy_setopt(curl, CURLOPT_URL, domains_file_url);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&urls);
            curl_easy_perform(curl);
            curl_easy_cleanup(curl);
        }
        curl_global_cleanup();
    }

    int64_t urls_web_file_size = urls.size;

    if (is_domains_file_path) {
        FILE *urls_fd = fopen(domains_file_path, "r");
        if (urls_fd == NULL) {
            printf("Can't open url file\n");
            exit(EXIT_FAILURE);
        }
        fseek(urls_fd, 0, SEEK_END);
        int64_t urls_file_size_add = ftell(urls_fd);
        fseek(urls_fd, 0, SEEK_SET);
        char *ptr = realloc(urls.data, urls.size + urls_file_size_add + 1);
        if (!ptr) {
            printf("No free memory for urls_file\n");
            exit(EXIT_FAILURE);
        }
        urls.data = ptr;
        if (fread(&(urls.data[urls.size]), urls_file_size_add, 1, urls_fd) != 1) {
            printf("Can't read url file\n");
            exit(EXIT_FAILURE);
        }
        urls.size += urls_file_size_add;
        urls.data[urls.size] = 0;
        fclose(urls_fd);
    }

    char *ptr = realloc(urls.data, urls.size + CNAME_URLS_MAP_MAX_SIZE);
    if (!ptr) {
        printf("No free memory for cname_urls\n");
        exit(EXIT_FAILURE);
    }
    urls.data = ptr;

    if (urls.size > 0) {
        int32_t urls_map_size = 0;
        int32_t file_urls_map_size = 0;
        for (int32_t i = 0; i < (int32_t)urls.size; i++) {
            if (urls.data[i] == '\n') {
                urls.data[i] = 0;
                urls_map_size++;
                if (i >= urls_web_file_size) {
                    file_urls_map_size++;
                }
            }
        }

        urls_map_struct = init_array_hashmap(urls_map_size, 1.0, sizeof(uint32_t));
        if (urls_map_struct == NULL) {
            printf("No free memory for urls_map_struct\n");
            exit(EXIT_FAILURE);
        }

        printf("Readed domains from file %d from url %d\n", file_urls_map_size,
               urls_map_size - file_urls_map_size);

        array_hashmap_set_func(urls_map_struct, add_url_hash, add_url_cmp, find_url_hash,
                               find_url_cmp);

        int32_t url_offset = 0;
        for (int32_t i = 0; i < urls_map_size; i++) {
            if (!memcmp(&urls.data[url_offset], "www.", 4)) {
                url_offset += 4;
            }

            array_hashmap_add_elem(urls_map_struct, &url_offset, NULL, NULL);

            url_offset = strchr(&urls.data[url_offset + 1], 0) - urls.data + 1;
        }
    }

    return urls_web_file_size;
}
