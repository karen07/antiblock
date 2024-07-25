#include "dns_ans.h"
#include "DNS.h"
#include "hash.h"
#include "net_data.h"
#include "route.h"
#include "stat.h"
#include "ttl_check.h"
#include "tun.h"
#include "urls_read.h"

pthread_mutex_t packets_ring_buffer_mutex;
pthread_cond_t packets_ring_buffer_step;
int32_t packets_ring_buffer_size;
int32_t packets_ring_buffer_start;
int32_t packets_ring_buffer_end;
packet_t* packets_ring_buffer;

const array_hashmap_t* cname_urls_map_struct;

int32_t cname_url_on_collision(const void* void_elem1, const void* void_elem2)
{
    const cname_urls_map* elem1 = void_elem1;
    const cname_urls_map* elem2 = void_elem2;

    if (elem1->end_time > elem2->end_time) {
        return 1;
    } else {
        return 0;
    }
}

uint32_t cname_url_hash(const void* void_elem)
{
    const cname_urls_map* elem = void_elem;
    return djb33_hash_len(elem->url, -1);
}

int32_t cname_url_cmp(const void* void_elem1, const void* void_elem2)
{
    const cname_urls_map* elem1 = void_elem1;
    const cname_urls_map* elem2 = void_elem2;

    return !strcmp(elem1->url, elem2->url);
}

int32_t get_url_from_packet(char* packet_start, char* hand_point, char* receive_msg_end, char* url, int32_t* first_len)
{
    int32_t url_len = 0;
    url[url_len++] = '.';

    while ((*hand_point != 0) && ((*hand_point & FIRST_TWO_BITS_UINT8) != FIRST_TWO_BITS_UINT8)) {
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

    if (first_len) {
        *first_len = url_len + 1;
    }

    if ((*hand_point & FIRST_TWO_BITS_UINT8) == FIRST_TWO_BITS_UINT8) {
        url_len--;
        int32_t new_len;
        new_len = get_url_from_packet(packet_start, packet_start + *(hand_point + 1), receive_msg_end, &url[url_len], 0);
        if (new_len == -1) {
            return -1;
        }
        url_len += new_len;
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

            cname_urls_map find_elem;
            find_elem.url = dot_pos;

            find_res = array_hashmap_find_elem(cname_urls_map_struct, &find_elem, NULL);
            if (find_res == 1) {
                return 1;
            }
        }
    }

    return 0;
}

struct simple_graph {
    int32_t url_offet;
    uint16_t type;
    uint32_t ttl;
    int32_t cname_offet_or_ip;
};

void change_to_dns_string_format(char* str, int32_t str_len)
{
    int32_t current_pos = str_len;

    for (int i = str_len; i >= 0; i--) {
        if (str[i] == '.') {
            str[i] = current_pos - i - 1;
            current_pos = i;
        }
    }
}

void* dns_ans_check(__attribute__((unused)) void* arg)
{
    int32_t block_que_url_flag = 0;
    uint16_t que_type = 0;

    pthread_barrier_wait(&threads_barrier);

    while (1) {
        pthread_mutex_lock(&packets_ring_buffer_mutex);
        while (packets_ring_buffer_start >= packets_ring_buffer_end) {
            pthread_cond_wait(&packets_ring_buffer_step, &packets_ring_buffer_mutex);
        }
        pthread_mutex_unlock(&packets_ring_buffer_mutex);

        int32_t ring_elem_num = packets_ring_buffer_start % packets_ring_buffer_size;

        char* receive_msg = packets_ring_buffer[ring_elem_num].packet;
        int32_t receive_msg_len = packets_ring_buffer[ring_elem_num].packet_size;

        char* cur_pos_ptr = receive_msg;
        char* receive_msg_end = receive_msg + receive_msg_len;

        block_que_url_flag = 0;
        que_type = 0;

        // DNS HEADER
        if (cur_pos_ptr + sizeof(dns_header_t) > receive_msg_end) {
            stat.request_parsing_error++;
            goto end;
        }

        dns_header_t* header = (dns_header_t*)cur_pos_ptr;

        uint16_t flags = ntohs(header->flags);
        if ((flags & FIRST_BIT_UINT16) == 0) {
            stat.request_parsing_error++;
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

        cur_pos_ptr += sizeof(dns_header_t);
        // DNS HEADER

        // QUE URL
        int32_t que_url_pad_len;
        char que_url[URL_MAX_SIZE];
        char* que_url_start = cur_pos_ptr;
        int32_t que_url_len = get_url_from_packet(receive_msg, que_url_start, receive_msg_end, que_url, &que_url_pad_len);
        if (que_url_len == -1) {
            stat.request_parsing_error++;
            goto end;
        }

        block_que_url_flag = check_url(que_url, que_url_len);
        if (block_que_url_flag != 1) {
            goto end;
        }

        cur_pos_ptr += que_url_pad_len;
        // QUE URL

        // QUE DATA
        if (cur_pos_ptr + sizeof(dns_que_t) > receive_msg_end) {
            stat.request_parsing_error++;
            goto end;
        }

        dns_que_t* que = (dns_que_t*)cur_pos_ptr;

        que_type = ntohs(que->type);
        if (que_type != 1) {
            goto end;
        }

        cur_pos_ptr += sizeof(dns_que_t);
        // QUE DATA

        // GRAPH
        char* ans_start_prt = cur_pos_ptr;

        char big_data[10000];
        int32_t big_data_cur_pos = 0;

        struct simple_graph simple_graph[100];
        int32_t simple_graph_cur_pos = 0;
        // GRAPH

        for (int32_t i = 0; i < ans_count; i++) {
            // ANS URL
            int32_t ans_url_pad_len;
            char ans_url[URL_MAX_SIZE];
            char* ans_url_start = cur_pos_ptr;
            int32_t ans_url_len = get_url_from_packet(receive_msg, ans_url_start, receive_msg_end, ans_url, &ans_url_pad_len);
            if (ans_url_len == -1) {
                stat.request_parsing_error++;
                goto end;
            }

            int32_t block_ans_url_flag __attribute__((unused)) = 0;
            block_ans_url_flag = check_url(ans_url, ans_url_len);

            cur_pos_ptr += ans_url_pad_len;
            // ANS URL

            // ANS DATA
            if (cur_pos_ptr + sizeof(dns_ans_t) - sizeof(uint32_t) > receive_msg_end) {
                stat.request_parsing_error++;
                goto end;
            }

            dns_ans_t* ans = (dns_ans_t*)cur_pos_ptr;

            uint16_t ans_type = ntohs(ans->type);
            uint32_t ans_ttl = ntohl(ans->ttl);
            uint16_t ans_len = ntohs(ans->len);

            // time_t check_time = time(NULL) + ans_ttl;

            if (cur_pos_ptr + sizeof(dns_ans_t) - sizeof(uint32_t) + ans_len > receive_msg_end) {
                stat.request_parsing_error++;
                goto end;
            }

            if (ans_type == 1) {
                strcpy(big_data + big_data_cur_pos, ans_url + 1);
                simple_graph[simple_graph_cur_pos].url_offet = big_data_cur_pos;
                big_data_cur_pos += ans_url_len;
                simple_graph[simple_graph_cur_pos].type = 1;
                simple_graph[simple_graph_cur_pos].ttl = ans_ttl;
                simple_graph[simple_graph_cur_pos].cname_offet_or_ip = ans->ip4;
                simple_graph_cur_pos++;

                /*if (block_ans_url_flag) {
                    uint32_t start_subnet_ip_n = htonl(start_subnet_ip++);

                    ip_ip_map_t add_elem;
                    add_elem.ip_local = start_subnet_ip_n;
                    add_elem.ip_global = ans->ip4;

                    array_hashmap_add_elem(ip_ip_map_struct, &add_elem, NULL, NULL);

                    ans->ip4 = start_subnet_ip_n;
                }

                ttl_map_t add_elem;
                add_elem.ip = ans->ip4;
                add_elem.end_time = check_time;

                ttl_map_t elem;
                if (block_ans_url_flag) {
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
                }*/
            }

            if (ans_type == 5) {
                char cname_url[URL_MAX_SIZE];
                char* cname_url_start = cur_pos_ptr + sizeof(dns_ans_t) - sizeof(uint32_t);
                int32_t cname_url_len = get_url_from_packet(receive_msg, cname_url_start, receive_msg_end, cname_url, 0);

                strcpy(big_data + big_data_cur_pos, ans_url + 1);
                simple_graph[simple_graph_cur_pos].url_offet = big_data_cur_pos;
                big_data_cur_pos += ans_url_len;
                simple_graph[simple_graph_cur_pos].type = 5;
                simple_graph[simple_graph_cur_pos].ttl = ans_ttl;
                strcpy(big_data + big_data_cur_pos, cname_url + 1);
                simple_graph[simple_graph_cur_pos].cname_offet_or_ip = big_data_cur_pos;
                big_data_cur_pos += cname_url_len;
                simple_graph_cur_pos++;

                /*if (block_ans_url_flag) {
                    char data_url[URL_MAX_SIZE];
                    char* cname_url_start = cur_pos_ptr + sizeof(dns_ans_t) - sizeof(uint32_t);
                    int32_t data_url_len = get_url_from_packet(receive_msg, cname_url_start, receive_msg_end, data_url, 0);

                    char* data_url_str = malloc(data_url_len + 1);
                    strcpy(data_url_str, data_url + 1);

                    cname_urls_map add_elem;
                    add_elem.url = data_url_str;
                    add_elem.end_time = check_time;

                    printf("BLOCK CNAME:%s %s\n", data_url_str, ans_url + 1);

                    cname_urls_map elem;
                    int32_t new_elem_flag = array_hashmap_add_elem(cname_urls_map_struct, &add_elem, &elem, cname_url_on_collision);
                    if (new_elem_flag == 1) {
                        add_url_cname(ans_url + 1, add_elem.end_time, add_elem.url);
                    } else if (new_elem_flag == 0) {
                        update_url_cname(ans_url + 1, elem.end_time, elem.url);
                    } else if (new_elem_flag == -1) {
                        stat.cname_url_map_error++;
                        free(data_url_str);
                    }
                }*/
            }

            cur_pos_ptr += sizeof(dns_ans_t) - sizeof(uint32_t) + ans_len;
            // ANS DATA
        }

        if (block_que_url_flag) {
            printf("\nStart %s\n", que_url + 1);

            int32_t que_offet = -1;

            for (int i = 0; i < simple_graph_cur_pos; i++) {
                if (!strcmp(que_url + 1, &big_data[simple_graph[i].url_offet])) {
                    que_offet = simple_graph[i].url_offet;
                    break;
                }
            }

            if (que_offet == -1) {
                printf("No que in ans\n");
                goto end;
            }

            printf("Ans:\n");
            for (int i = 0; i < simple_graph_cur_pos; i++) {
                if (simple_graph[i].type == 1) {
                    char str2[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &simple_graph[i].cname_offet_or_ip, str2, INET_ADDRSTRLEN);
                    printf("A : %s %s %d\n", que_url + 1, str2, simple_graph[i].ttl);
                } else {
                    printf("CNAME : %s %s %d\n", &big_data[simple_graph[i].url_offet], &big_data[simple_graph[i].cname_offet_or_ip], simple_graph[i].ttl);
                }
            }

            char out_que_url[URL_MAX_SIZE];
            strcpy(out_que_url, que_url);
            change_to_dns_string_format(out_que_url, que_url_len);

            uint32_t min_ttl = -1;
            cur_pos_ptr = ans_start_prt;

            int32_t A_find_flag = 0;
            int32_t next_find_flag = 0;

            printf("Walk on graph:\n");
            while (1) {
                A_find_flag = 0;
                next_find_flag = 0;
                for (int i = 0; i < simple_graph_cur_pos; i++) {
                    if (!strcmp(&big_data[que_offet], &big_data[simple_graph[i].url_offet])) {
                        next_find_flag = 1;

                        if (min_ttl > simple_graph[i].ttl) {
                            min_ttl = simple_graph[i].ttl;
                        }

                        if (simple_graph[i].type == 1) {
                            A_find_flag = 1;

                            uint32_t start_subnet_ip_n = htonl(start_subnet_ip++);

                            ip_ip_map_t add_elem;
                            add_elem.ip_local = start_subnet_ip_n;
                            add_elem.ip_global = simple_graph[i].cname_offet_or_ip;

                            array_hashmap_add_elem(ip_ip_map_struct, &add_elem, NULL, ip_ip_on_collision);

                            memcpy(cur_pos_ptr, out_que_url, que_url_len + 1);
                            cur_pos_ptr += que_url_len + 1;

                            uint16_t type = 1;
                            uint16_t class = 1;
                            uint32_t ttl = 10;
                            uint16_t len = 4;

                            dns_ans_t* new_ans = (dns_ans_t*)cur_pos_ptr;

                            new_ans->type = htons(type);
                            new_ans->class = htons(class);
                            new_ans->ttl = htonl(ttl);
                            new_ans->len = htons(len);
                            new_ans->ip4 = start_subnet_ip_n;

                            cur_pos_ptr += sizeof(dns_ans_t);

                            char str1[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &start_subnet_ip_n, str1, INET_ADDRSTRLEN);

                            char str2[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &simple_graph[i].cname_offet_or_ip, str2, INET_ADDRSTRLEN);
                            printf("FINAL : %s %s %s %d\n", que_url + 1, str2, str1, ttl);

                            if (start_subnet_ip == end_subnet_ip) {
                                start_subnet_ip = ntohl(tun_ip) + 1;
                            }

                            break;
                        } else {
                            que_offet = simple_graph[i].cname_offet_or_ip;
                            printf("CNAME : %s %s\n", &big_data[simple_graph[i].url_offet], &big_data[simple_graph[i].cname_offet_or_ip]);
                            break;
                        }
                    }
                }

                if (A_find_flag || !next_find_flag) {
                    break;
                }
            }

            if (A_find_flag) {
                packets_ring_buffer[ring_elem_num].packet_size = cur_pos_ptr - receive_msg;

                uint16_t ans_count_new = 1;
                header->ans = htons(ans_count_new);
            } else {
                printf("A not founded\n");
            }

            printf("End ans\n\n");
        }

    end:
        if (block_que_url_flag) {
            if (que_type == 1) {
                send_packet(ring_elem_num);
            }
        } else {
            send_packet(ring_elem_num);
        }

        packets_ring_buffer[ring_elem_num].packet_size = 0;
        packets_ring_buffer_start++;
    }

    return NULL;
}

void init_dns_ans_check_thread(void)
{
    cname_urls_map_struct = init_array_hashmap(CNAME_URLS_MAP_MAX_SIZE, 1.0, sizeof(cname_urls_map));
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
