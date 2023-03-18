#include "ttl_check.h"
#include "dns_ans.h"
#include "route.h"
#include "stat.h"

const array_hashmap_t* ttl_map_struct;
time_t now_ttl_check;

int32_t cname_url_decide(const void* void_elem)
{
    const cname_urls_map* elem = void_elem;

    if (now_ttl_check > elem->end_time) {
        del_url_cname(elem->url, now_ttl_check);
        return 1;
    } else {
        return 0;
    }
}

int32_t ttl_decide(const void* void_elem)
{
    const ttl_map_t* elem = void_elem;

    if (now_ttl_check > elem->end_time) {
        del_ip_from_route_table(elem->ip, now_ttl_check);
        return 1;
    } else {
        return 0;
    }
}

int32_t ttl_on_collision(const void* void_elem1, const void* void_elem2)
{
    const ttl_map_t* elem1 = void_elem1;
    const ttl_map_t* elem2 = void_elem2;

    if (elem1->end_time > elem2->end_time) {
        return 1;
    } else {
        return 0;
    }
}

uint32_t ttl_hash(const void* void_elem)
{
    const ttl_map_t* elem = void_elem;
    return elem->ip;
}

int32_t ttl_cmp(const void* void_elem1, const void* void_elem2)
{
    const ttl_map_t* elem1 = void_elem1;
    const ttl_map_t* elem2 = void_elem2;

    if (elem1->ip == elem2->ip) {
        return 1;
    } else {
        return 0;
    }
}

void* ttl_check(__attribute__((unused)) void* arg)
{
    pthread_barrier_wait(&threads_barrier);

    while (1) {
        now_ttl_check = time(NULL);

        array_hashmap_del_elem_by_func(ttl_map_struct, ttl_decide);
        array_hashmap_del_elem_by_func(cname_urls_map_struct, cname_url_decide);

        sleep(TTL_CHECK_TIME);
    }

    return NULL;
}

void init_ttl_check_thread(void)
{
    ttl_map_struct = init_array_hashmap(TTL_MAP_MAX_SIZE, 1.0, sizeof(ttl_map_t));
    if (ttl_map_struct == NULL) {
        printf("No free memory for ttl_map_struct\n");
        exit(EXIT_FAILURE);
    }

    array_hashmap_set_func(ttl_map_struct, ttl_hash, ttl_cmp, ttl_hash, ttl_cmp);

    pthread_t ttl_check_thread;
    if (pthread_create(&ttl_check_thread, NULL, ttl_check, NULL)) {
        printf("Can't create ttl_check_thread\n");
        exit(EXIT_FAILURE);
    }

    if (pthread_detach(ttl_check_thread)) {
        printf("Can't detach ttl_check_thread\n");
        exit(EXIT_FAILURE);
    }
}
