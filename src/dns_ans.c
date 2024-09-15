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
packet_t *packets_ring_buffer;

const array_hashmap_t *cname_urls_map_struct;

int32_t cname_url_on_collision(const void *void_elem1, const void *void_elem2)
{
    const cname_urls_map *elem1 = void_elem1;
    const cname_urls_map *elem2 = void_elem2;

    if (elem1->end_time > elem2->end_time) {
        return 1;
    } else {
        return 0;
    }
}

uint32_t cname_url_hash(const void *void_elem)
{
    const cname_urls_map *elem = void_elem;
    return djb33_hash_len(elem->url, -1);
}

int32_t cname_url_cmp(const void *void_elem1, const void *void_elem2)
{
    const cname_urls_map *elem1 = void_elem1;
    const cname_urls_map *elem2 = void_elem2;

    return !strcmp(elem1->url, elem2->url);
}

int32_t get_url_from_packet(char *packet_start, char *hand_point, char *receive_msg_end, char *url,
                            int32_t *first_len)
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
        new_len = get_url_from_packet(packet_start, packet_start + *(hand_point + 1),
                                      receive_msg_end, &url[url_len], 0);
        if (new_len == -1) {
            return -1;
        }
        url_len += new_len;
    }

    url[url_len] = 0;

    return url_len;
}

int32_t check_url(char *url, int32_t url_len)
{
    char *dot_pos = NULL;
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

void *dns_ans_check(__attribute__((unused)) void *arg)
{
    pthread_barrier_wait(&threads_barrier);

    while (1) {
        pthread_mutex_lock(&packets_ring_buffer_mutex);
        while (packets_ring_buffer_start >= packets_ring_buffer_end) {
            pthread_cond_wait(&packets_ring_buffer_step, &packets_ring_buffer_mutex);
        }
        pthread_mutex_unlock(&packets_ring_buffer_mutex);

        int32_t ring_elem_num = packets_ring_buffer_start % packets_ring_buffer_size;

        char *receive_msg = packets_ring_buffer[ring_elem_num].packet;
        int32_t receive_msg_len = packets_ring_buffer[ring_elem_num].packet_size;

        char *cur_pos_ptr = receive_msg;
        char *receive_msg_end = receive_msg + receive_msg_len;

        // DNS HEADER
        if (cur_pos_ptr + sizeof(dns_header_t) > receive_msg_end) {
            stat.request_parsing_error++;
            goto end;
        }

        dns_header_t *header = (dns_header_t *)cur_pos_ptr;

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
        char *que_url_start = cur_pos_ptr;
        int32_t que_url_len = get_url_from_packet(receive_msg, que_url_start, receive_msg_end,
                                                  que_url, &que_url_pad_len);
        if (que_url_len == -1) {
            stat.request_parsing_error++;
            goto end;
        }

        __attribute__((unused)) int32_t block_que_url_flag = check_url(que_url, que_url_len);

        cur_pos_ptr += que_url_pad_len;
        // QUE URL

        // QUE DATA
        if (cur_pos_ptr + sizeof(dns_que_t) > receive_msg_end) {
            stat.request_parsing_error++;
            goto end;
        }

        dns_que_t *que = (dns_que_t *)cur_pos_ptr;

        uint16_t que_type = ntohs(que->type);

        cur_pos_ptr += sizeof(dns_que_t);
        // QUE DATA

        if (log_fd) {
            time_t now = time(NULL);
            struct tm *tm_struct = localtime(&now);
            fprintf(log_fd, "%02d.%02d.%04d %02d:%02d:%02d\n", tm_struct->tm_mday,
                    tm_struct->tm_mon + 1, tm_struct->tm_year + 1900, tm_struct->tm_hour,
                    tm_struct->tm_min, tm_struct->tm_sec);
            fprintf(log_fd, "Que_url %d: %s\n", que_type, que_url + 1);
        }

        for (int32_t i = 0; i < ans_count; i++) {
            // ANS URL
            int32_t ans_url_pad_len;
            char ans_url[URL_MAX_SIZE];
            char *ans_url_start = cur_pos_ptr;
            int32_t ans_url_len = get_url_from_packet(receive_msg, ans_url_start, receive_msg_end,
                                                      ans_url, &ans_url_pad_len);
            if (ans_url_len == -1) {
                stat.request_parsing_error++;
                goto end;
            }

            int32_t block_ans_url_flag = 0;
            block_ans_url_flag = check_url(ans_url, ans_url_len);

            cur_pos_ptr += ans_url_pad_len;
            // ANS URL

            // ANS DATA
            if (cur_pos_ptr + sizeof(dns_ans_t) - sizeof(uint32_t) > receive_msg_end) {
                stat.request_parsing_error++;
                goto end;
            }

            dns_ans_t *ans = (dns_ans_t *)cur_pos_ptr;

            uint16_t ans_type = ntohs(ans->type);
            uint32_t ans_ttl = ntohl(ans->ttl);
            uint16_t ans_len = ntohs(ans->len);

            time_t check_time = time(NULL) + ans_ttl;

            if (cur_pos_ptr + sizeof(dns_ans_t) - sizeof(uint32_t) + ans_len > receive_msg_end) {
                stat.request_parsing_error++;
                goto end;
            }

            if (log_fd) {
                fprintf(log_fd, "    Ans_url %d: %s ", ans_type, ans_url + 1);
            }

            if (ans_type == 1) {
                if (log_fd) {
                    struct in_addr new_ip;
                    new_ip.s_addr = ans->ip4;

                    fprintf(log_fd, "%s\n", inet_ntoa(new_ip));
                }

                if (tun_ip) {
                    if (block_ans_url_flag) {
                        uint32_t start_subnet_ip_n = htonl(start_subnet_ip++);

                        ip_ip_map_t add_elem;
                        add_elem.ip_local = start_subnet_ip_n;
                        add_elem.ip_global = ans->ip4;

                        array_hashmap_add_elem(ip_ip_map_struct, &add_elem, NULL,
                                               ip_ip_on_collision);

                        ans->ip4 = start_subnet_ip_n;

                        if (log_fd) {
                            struct in_addr new_ip;
                            new_ip.s_addr = add_elem.ip_local;

                            struct in_addr old_ip;
                            old_ip.s_addr = add_elem.ip_global;

                            fprintf(log_fd, "    Blocked_IP: %s", ans_url + 1);
                            fprintf(log_fd, " %s", inet_ntoa(old_ip));
                            fprintf(log_fd, " %s\n", inet_ntoa(new_ip));
                        }
                    }
                } else {
                    ttl_map_t add_elem;
                    add_elem.ip = ans->ip4;
                    add_elem.end_time = check_time;

                    ttl_map_t elem;
                    if (block_ans_url_flag) {
                        int32_t new_elem_flag = array_hashmap_add_elem(ttl_map_struct, &add_elem,
                                                                       &elem, ttl_on_collision);
                        if (new_elem_flag == 1) {
                            add_ip_to_route_table(add_elem.ip, add_elem.end_time, ans_url + 1);
                        } else if (new_elem_flag == 0) {
                            update_ip_in_route_table(elem.ip, elem.end_time, ans_url + 1);
                        } else if (new_elem_flag == -1) {
                            stat.ttl_map_error++;
                        }
                    } else {
                        int32_t find_res =
                            array_hashmap_find_elem(ttl_map_struct, &add_elem, &elem);
                        if (find_res == 1) {
                            not_block_ip_in_route_table(elem.ip, elem.end_time, ans_url + 1);
                        }
                    }
                }
            }

            if (ans_type == 5) {
                char cname_url[URL_MAX_SIZE];
                char *cname_url_start = cur_pos_ptr + sizeof(dns_ans_t) - sizeof(uint32_t);
                int32_t cname_url_len = get_url_from_packet(receive_msg, cname_url_start,
                                                            receive_msg_end, cname_url, 0);

                int32_t block_cname_url_flag = 0;
                block_cname_url_flag = check_url(cname_url, cname_url_len);

                if (log_fd) {
                    fprintf(log_fd, "%s\n", cname_url + 1);
                    if (block_ans_url_flag == 1 && block_cname_url_flag == 0) {
                        fprintf(log_fd, "    Blocked_Cname: %s\n", cname_url + 1);
                    }
                }

                if (tun_ip) {
                    if (block_ans_url_flag) {
                    }
                } else {
                    if (block_ans_url_flag) {
                        char *data_url_str = malloc(cname_url_len + 1);
                        strcpy(data_url_str, cname_url + 1);

                        cname_urls_map add_elem;
                        add_elem.url = data_url_str;
                        add_elem.end_time = check_time;

                        cname_urls_map elem;
                        int32_t new_elem_flag = array_hashmap_add_elem(
                            cname_urls_map_struct, &add_elem, &elem, cname_url_on_collision);
                        if (new_elem_flag == 1) {
                            add_url_cname(ans_url + 1, add_elem.end_time, add_elem.url);
                        } else if (new_elem_flag == 0) {
                            update_url_cname(ans_url + 1, elem.end_time, elem.url);
                        } else if (new_elem_flag == -1) {
                            stat.cname_url_map_error++;
                            free(data_url_str);
                        }
                    }
                }
            }

            if (ans_type != 1 && ans_type != 5) {
                if (log_fd) {
                    fprintf(log_fd, "\n");
                }
            }

            cur_pos_ptr += sizeof(dns_ans_t) - sizeof(uint32_t) + ans_len;
            // ANS DATA
        }

        fprintf(log_fd, "\n");
end:
        send_packet(ring_elem_num);

        packets_ring_buffer[ring_elem_num].packet_size = 0;
        packets_ring_buffer_start++;
    }

    return NULL;
}

void init_dns_ans_check_thread(void)
{
    cname_urls_map_struct =
        init_array_hashmap(CNAME_URLS_MAP_MAX_SIZE, 1.0, sizeof(cname_urls_map));
    if (cname_urls_map_struct == NULL) {
        printf("No free memory for cname_urls_map_struct\n");
        exit(EXIT_FAILURE);
    }

    array_hashmap_set_func(cname_urls_map_struct, cname_url_hash, cname_url_cmp, cname_url_hash,
                           cname_url_cmp);

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
