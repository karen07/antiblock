#include "urls_read.h"

char* urls;
const array_hashmap_t* urls_map_struct;

uint32_t djb33_hash(const char* s)
{
    uint32_t h = 5381;
    while (*s) {
        h += (h << 5);
        h ^= *s++;
    }
    return h;
}

uint32_t add_url_hash(const void* void_elem)
{
    const uint32_t* elem = void_elem;
    return djb33_hash(&urls[*elem]);
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
    return djb33_hash(elem);
}

int32_t find_url_cmp(const void* void_elem1, const void* void_elem2)
{
    const char* elem1 = void_elem1;
    const uint32_t* elem2 = void_elem2;

    return !strcmp(elem1, &urls[*elem2]);
}

void* urls_read(__attribute__((unused)) void* arg)
{
    pthread_barrier_wait(&threads_barrier);

    while (1) {
        system("curl https://antifilter.download/list/domains.lst 2>/dev/null > " FILES_FOLDER "block_urls_lines");

        FILE* urls_fd = fopen(FILES_FOLDER "block_urls_lines", "r");
        if (urls_fd == NULL) {
            printf("Can't open url file\n");
            exit(EXIT_FAILURE);
        }

        fseek(urls_fd, 0, SEEK_END);
        int64_t urls_file_size = ftell(urls_fd);
        fseek(urls_fd, 0, SEEK_SET);

        if (urls_file_size > 0) {
            if (urls) {
                free(urls);
            }

            urls = malloc(urls_file_size);
            if (urls == 0) {
                printf("No free memory for urls\n");
                exit(EXIT_FAILURE);
            }
            if (fread(urls, urls_file_size, 1, urls_fd) != 1) {
                printf("Can't read url file\n");
                exit(EXIT_FAILURE);
            }

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
                array_hashmap_add_elem(urls_map_struct, &url_offset, NULL, NULL);

                url_offset = strchr(&urls[url_offset + 1], 0) - urls + 1;
            }
        }

        fclose(urls_fd);

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
