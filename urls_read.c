#include "urls_read.h"
#include "hash.h"
#include <curl/curl.h>

char* urls;
const array_hashmap_t* urls_map_struct;

uint32_t add_url_hash(const void* void_elem)
{
    const uint32_t* elem = void_elem;
    return djb33_hash_len(&urls[*elem], -1);
}

int32_t add_url_cmp(const void* void_elem1, const void* void_elem2)
{
    const uint32_t* elem1 = void_elem1;
    const uint32_t* elem2 = void_elem2;

    return !strcmp(&urls[*elem1], &urls[*elem2]);
}

uint32_t find_url_hash(const void* void_elem)
{
    const char* elem = void_elem;
    return djb33_hash_len(elem, -1);
}

int32_t find_url_cmp(const void* void_elem1, const void* void_elem2)
{
    const char* elem1 = void_elem1;
    const uint32_t* elem2 = void_elem2;

    return !strcmp(elem1, &urls[*elem2]);
}

struct memory {
    char* response;
    size_t size;
};

static size_t cb(void* data, size_t size, size_t nmemb, void* clientp)
{
    size_t realsize = size * nmemb;
    struct memory* mem = (struct memory*)clientp;

    char* ptr = realloc(mem->response, mem->size + realsize + 1);
    if (!ptr)
        return 0;  /* out of memory! */

    mem->response = ptr;
    memcpy(&(mem->response[mem->size]), data, realsize);
    mem->size += realsize;
    mem->response[mem->size] = 0;

    return realsize;
}

void* urls_read(__attribute__((unused)) void* arg)
{
    pthread_barrier_wait(&threads_barrier);

    struct memory chunk;
    memset(&chunk, 0, sizeof(chunk));

    while (1) {
        if (chunk.response != NULL) {
            free(chunk.response);
            memset(&chunk, 0, sizeof(chunk));
        }

        curl_global_init(CURL_GLOBAL_DEFAULT);
        CURL* curl = curl_easy_init();
        if (curl) {
            curl_easy_setopt(curl, CURLOPT_URL, "https://antifilter.download/list/domains.lst");
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
            curl_easy_perform(curl);
            curl_easy_cleanup(curl);
        }
        curl_global_cleanup();

        int64_t urls_file_size = chunk.size;
        urls = chunk.response;

        if (urls_file_size > 0) {
            int32_t urls_map_size = 0;
            for (int32_t i = 0; i < urls_file_size; i++) {
                if (urls[i] == '\n') {
                    urls[i] = 0;
                    urls_map_size++;
                }
            }

            if (urls_map_struct) {
                del_array_hashmap(urls_map_struct);
            }

            urls_map_struct = init_array_hashmap(URLS_MAP_MAX_SIZE, 1.0, sizeof(uint32_t));
            if (urls_map_struct == NULL) {
                printf("No free memory for urls_map_struct\n");
                exit(EXIT_FAILURE);
            }

            array_hashmap_set_func(urls_map_struct, add_url_hash, add_url_cmp, find_url_hash, find_url_cmp);

            int32_t url_offset = 0;
            for (int32_t i = 0; i < urls_map_size; i++) {
                if (!memcmp(&urls[url_offset], "www.", 4)) {
                    url_offset += 4;
                }

                array_hashmap_add_elem(urls_map_struct, &url_offset, NULL, NULL);

                url_offset = strchr(&urls[url_offset + 1], 0) - urls + 1;
            }
        }

        if (urls_file_size > 0) {
            sleep(URLS_UPDATE_TIME);
        } else {
            sleep(URLS_ERROR_UPDATE_TIME);
        }
    }

    return NULL;
}

void init_urls_read_thread(void)
{
    pthread_t urls_read_thread;
    if (pthread_create(&urls_read_thread, NULL, urls_read, NULL)) {
        printf("Can't create urls_read_thread\n");
        exit(EXIT_FAILURE);
    }

    if (pthread_detach(urls_read_thread)) {
        printf("Can't detach urls_read_thread\n");
        exit(EXIT_FAILURE);
    }
}
