#include "dns_ans.h"
#include "DNS.h"
#include "route.h"
#include "stat.h"
#include "ttl_check.h"
#include "urls_read.h"

pthread_mutex_t packets_ring_buffer_mutex;
pthread_cond_t packets_ring_buffer_step;
int32_t packets_ring_buffer_size;
int32_t packets_ring_buffer_start;
int32_t packets_ring_buffer_end;
packet_t* packets_ring_buffer;

const array_hashmap_t* cname_urls_map_struct;

uint32_t djb33_hash_cname(const char* s)
{
    uint32_t h = 5381;
    while (*s) {
        h += (h << 5);
        h ^= *s++;
    }
    return h;
}

uint32_t cname_url_hash(const void* void_elem)
{
    const char** elem = (const char**)void_elem;
    return djb33_hash_cname(*elem);
}

int32_t cname_url_cmp(const void* void_elem1, const void* void_elem2)
{
    const char** elem1 = (const char**)void_elem1;
    const char** elem2 = (const char**)void_elem2;

    return !strcmp(*elem1, *elem2);
}

int32_t get_url_from_packet(char* packet_start, char* hand_point, char* receive_msg_end, char* url)
{
    int32_t url_len = 0;
    url[url_len++] = '.';

    while ((*hand_point != 0) && ((*hand_point & 0xc0) != 0xc0)) {
        uint32_t part_len = *hand_point++;
        if (hand_point + part_len > receive_msg_end) {
            return -1;
        }
        memcpy(&url[url_len], hand_point, part_len);
        url_len += part_len;
        hand_point += part_len;
        if (*hand_point != 0) {
            url[url_len++] = '.';
        }
    }

    if ((*hand_point & 0xc0) == 0xc0) {
        url_len--;
        url_len += get_url_from_packet(packet_start, packet_start + *(hand_point + 1), receive_msg_end, &url[url_len]);
    }

    url[url_len] = 0;

    return url_len;
}

int32_t check_url(char* url, int32_t url_len)
{
    char* dot_pos = NULL;
    int32_t dot_count = 0;
    for (int32_t i = url_len; i >= 0; i--) {
        if (url[i] == '.') {
            if (dot_count++ == 0) {
                continue;
            }

            dot_pos = &url[i + 1];

            int32_t find_res = array_hashmap_find_elem(urls_map_struct, dot_pos, NULL);
            if (find_res == 1) {
                return 1;
            }

            find_res = array_hashmap_find_elem(cname_urls_map_struct, &dot_pos, NULL);
            if (find_res == 1) {
                return 1;
            }
        }
    }

    return 0;
}

void* dns_ans_check(__attribute__((unused)) void* arg)
{
    pthread_barrier_wait(&threads_barrier);

    while (1) {
        pthread_mutex_lock(&packets_ring_buffer_mutex);
        while (packets_ring_buffer_start >= packets_ring_buffer_end) {
            pthread_cond_wait(&packets_ring_buffer_step, &packets_ring_buffer_mutex);
        }
        pthread_mutex_unlock(&packets_ring_buffer_mutex);

        int32_t remain_div = packets_ring_buffer_start % packets_ring_buffer_size;
        char* receive_msg = packets_ring_buffer[remain_div].packet;
        int32_t receive_msg_len = packets_ring_buffer[remain_div].packet_size;
        char* receive_msg_end = receive_msg + receive_msg_len;

        if (receive_msg_len <= (int32_t)sizeof(dns_header_t)) {
            goto end;
        }

        dns_header_t* header = (dns_header_t*)receive_msg;

        uint16_t flags = ntohs(header->flags);
        if ((flags & FIRST_BIT) == 0) {
            goto end;
        }

        uint16_t quest_count = ntohs(header->quest);
        if (quest_count != 1) {
            goto end;
        }

        uint16_t ans_count = ntohs(header->ans);
        if (ans_count == 0) {
            goto end;
        }

        char url[URL_MAX_SIZE];
        int32_t url_len = get_url_from_packet(receive_msg, receive_msg + sizeof(dns_header_t), receive_msg_end, url);
        if (url_len == -1) {
            goto end;
        }

        char* hand_point = receive_msg + sizeof(dns_header_t) + url_len + 1;

        hand_point += sizeof(dns_que_t);
        if (hand_point > receive_msg_end) {
            goto end;
        }

        for (int32_t i = 0; i < ans_count; i++) {
            char ans_url[URL_MAX_SIZE];
            int32_t ans_url_len = get_url_from_packet(receive_msg, hand_point, receive_msg_end, ans_url);
            if (ans_url_len == -1) {
                goto end;
            }

            int32_t blocked_url_flag = 0;
            blocked_url_flag = check_url(ans_url, ans_url_len);

            if (*hand_point & 0xc0) {
                hand_point += 2;
            } else {
                while (*hand_point++ != 0) {
                    uint32_t part_len = *(hand_point - 1);
                    if (hand_point + part_len > receive_msg_end) {
                        goto end;
                    }
                    hand_point += part_len;
                }
            }

            if (hand_point + sizeof(dns_ans_t) - sizeof(uint32_t) > receive_msg_end) {
                goto end;
            }
            dns_ans_t* ans = (dns_ans_t*)hand_point;

            uint16_t type = ntohs(ans->type);
            uint32_t ttl = ntohl(ans->ttl);
            time_t check_time = time(NULL) + ttl;

            if (type == 1) {
                if (hand_point + sizeof(dns_ans_t) > receive_msg_end) {
                    goto end;
                }

                ttl_map_t add_elem;
                add_elem.ip = ans->ip4;
                add_elem.end_time = check_time;

                ttl_map_t elem;
                if (blocked_url_flag) {
                    int32_t new_elem_flag = array_hashmap_add_elem(ttl_map_struct, &add_elem, &elem, ttl_on_collision);
                    if (new_elem_flag == 1) {
                        add_ip_to_route_table(add_elem.ip, add_elem.end_time, ans_url + 1);
                    } else if (new_elem_flag == 0) {
                        update_ip_in_route_table(elem.ip, elem.end_time, ans_url + 1);
                    } else if (new_elem_flag == -1) {
                        stat.ttl_map_error++;
                    }
                } else {
                    int32_t find_res = array_hashmap_find_elem(ttl_map_struct, &add_elem, &elem);
                    if (find_res == 1) {
                        not_block_ip_in_route_table(elem.ip, elem.end_time, ans_url + 1);
                    }
                }
            }

            uint16_t len = ntohs(ans->len);
            if (hand_point + sizeof(dns_ans_t) - sizeof(uint32_t) + len > receive_msg_end) {
                goto end;
            }

            if (type == 5 && blocked_url_flag) {
                char data_url[URL_MAX_SIZE];
                int32_t data_url_len = get_url_from_packet(receive_msg,
                    hand_point + sizeof(dns_ans_t) - sizeof(uint32_t), receive_msg_end, data_url);

                char* data_url_str = malloc(data_url_len + 1);
                strcpy(data_url_str, data_url + 1);

                array_hashmap_add_elem(cname_urls_map_struct, &data_url_str, NULL, NULL);

                add_url_cname(ans_url + 1, check_time, data_url + 1);
            }

            hand_point += sizeof(dns_ans_t) - sizeof(uint32_t) + len;
        }

    end:
        packets_ring_buffer[remain_div].packet_size = 0;
        packets_ring_buffer_start++;
    }

    return NULL;
}

void init_dns_ans_check_thread(void)
{
    cname_urls_map_struct = init_array_hashmap(CNAME_URLS_MAP_MAX_SIZE, 1.0, sizeof(char*));
    if (cname_urls_map_struct == NULL) {
        printf("No free memory for cname_urls_map_struct\n");
        exit(EXIT_FAILURE);
    }

    array_hashmap_set_func(cname_urls_map_struct, cname_url_hash, cname_url_cmp, cname_url_hash, cname_url_cmp);

    packets_ring_buffer_size = PACKETS_RING_BUFFER_MAX_SIZE;

    packets_ring_buffer = malloc(packets_ring_buffer_size * sizeof(packet_t));
    if (packets_ring_buffer == NULL) {
        printf("No free memory for packets_ring_buffer\n");
        exit(EXIT_FAILURE);
    }
    memset(packets_ring_buffer, 0, packets_ring_buffer_size * sizeof(packet_t));

    if (pthread_cond_init(&packets_ring_buffer_step, NULL)) {
        printf("Can't create packets_ring_buffer_step\n");
        exit(EXIT_FAILURE);
    }

    if (pthread_mutex_init(&packets_ring_buffer_mutex, NULL)) {
        printf("Can't create packets_ring_buffer_mutex\n");
        exit(EXIT_FAILURE);
    }

    pthread_t dns_ans_check_thread;
    if (pthread_create(&dns_ans_check_thread, NULL, dns_ans_check, NULL)) {
        printf("Can't create dns_ans_check_thread\n");
        exit(EXIT_FAILURE);
    }

    if (pthread_detach(dns_ans_check_thread)) {
        printf("Can't detach dns_ans_check_thread\n");
        exit(EXIT_FAILURE);
    }
}
