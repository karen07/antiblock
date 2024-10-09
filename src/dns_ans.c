#include "antiblock.h"
#include "config.h"
#include "const.h"
#include "dns_ans.h"
#include "hash.h"
#include "net_data.h"
#include "stat.h"
#include "tun.h"
#include "urls_read.h"

static int32_t get_url_from_packet(char *receive_msg, __attribute__((unused)) char *receive_msg_end,
                                   char *cur_pos_ptr, char **new_cur_pos_ptr, char *url)
{
    uint8_t two_bit_mark = FIRST_TWO_BITS_UINT8;
    int32_t part_len = 0;
    int32_t url_len = 0;

    if (new_cur_pos_ptr) {
        *new_cur_pos_ptr = NULL;
    }

    while (true) {
        if (part_len == 0) {
            uint8_t first_byte_data = (*cur_pos_ptr) & (~two_bit_mark);

            if ((*cur_pos_ptr & two_bit_mark) != two_bit_mark) {
                part_len = first_byte_data;
                cur_pos_ptr++;
                if (part_len == 0) {
                    break;
                } else {
                    url[url_len++] = '.';
                }
            } else {
                if (new_cur_pos_ptr) {
                    if (*new_cur_pos_ptr == NULL) {
                        *new_cur_pos_ptr = cur_pos_ptr + 2;
                    }
                }
                uint8_t second_byte_data = *(cur_pos_ptr + 1);
                int32_t padding = 256 * first_byte_data + second_byte_data;
                cur_pos_ptr = receive_msg + padding;
            }
        } else {
            url[url_len++] = *cur_pos_ptr;
            cur_pos_ptr++;
            part_len--;
        }
    }

    if (new_cur_pos_ptr) {
        if (*new_cur_pos_ptr == NULL) {
            *new_cur_pos_ptr = cur_pos_ptr;
        }
    }

    url[url_len] = 0;

    return url_len;
}

static int32_t check_url(char *url, int32_t url_len)
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
        }
    }

    return 0;
}

void dns_ans_check(memory_t *receive_msg_struct)
{
    char *receive_msg = receive_msg_struct->data;
    int32_t receive_msg_len = receive_msg_struct->size;

    char *cur_pos_ptr = receive_msg;
    char *receive_msg_end = receive_msg + receive_msg_len;

    // DNS HEADER
    if (cur_pos_ptr + sizeof(dns_header_t) > receive_msg_end) {
        stat.request_parsing_error++;
        return;
    }

    dns_header_t *header = (dns_header_t *)cur_pos_ptr;

    uint16_t flags = ntohs(header->flags);
    if ((flags & FIRST_BIT_UINT16) == 0) {
        stat.request_parsing_error++;
        return;
    }

    uint16_t quest_count = ntohs(header->quest);
    if (quest_count != 1) {
        return;
    }

    uint16_t ans_count = ntohs(header->ans);
    if (ans_count == 0) {
        return;
    }

    cur_pos_ptr += sizeof(dns_header_t);
    // DNS HEADER

    // QUE URL
    char *que_new_cur_pos_ptr;
    char *que_url_start = cur_pos_ptr;
    int32_t que_url_len = get_url_from_packet(receive_msg, receive_msg_end, que_url_start,
                                              &que_new_cur_pos_ptr, que_url.data);
    if (que_url_len == -1) {
        stat.request_parsing_error++;
        return;
    }

    __attribute__((unused)) int32_t block_que_url_flag = check_url(que_url.data, que_url_len);

    cur_pos_ptr = que_new_cur_pos_ptr;
    // QUE URL

    // QUE DATA
    if (cur_pos_ptr + sizeof(dns_que_t) > receive_msg_end) {
        stat.request_parsing_error++;
        return;
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
        fprintf(log_fd, "Que_url %d: %s\n", que_type, que_url.data + 1);
    }

    for (int32_t i = 0; i < ans_count; i++) {
        // ANS URL
        char *ans_new_cur_pos_ptr;
        char *ans_url_start = cur_pos_ptr;
        int32_t ans_url_len = get_url_from_packet(receive_msg, receive_msg_end, ans_url_start,
                                                  &ans_new_cur_pos_ptr, ans_url.data);
        if (ans_url_len == -1) {
            stat.request_parsing_error++;
            return;
        }

        int32_t block_ans_url_flag = 0;
        block_ans_url_flag = check_url(ans_url.data, ans_url_len);

        cur_pos_ptr = ans_new_cur_pos_ptr;
        // ANS URL

        // ANS DATA
        if (cur_pos_ptr + sizeof(dns_ans_t) - sizeof(uint32_t) > receive_msg_end) {
            stat.request_parsing_error++;
            return;
        }

        dns_ans_t *ans = (dns_ans_t *)cur_pos_ptr;

        uint16_t ans_type = ntohs(ans->type);
        __attribute__((unused)) uint32_t ans_ttl = ntohl(ans->ttl);
        uint16_t ans_len = ntohs(ans->len);

        if (cur_pos_ptr + sizeof(dns_ans_t) - sizeof(uint32_t) + ans_len > receive_msg_end) {
            stat.request_parsing_error++;
            return;
        }

        if (log_fd) {
            fprintf(log_fd, "    Ans_url %d: %s ", ans_type, ans_url.data + 1);
        }

        if (ans_type == 1) {
            if (log_fd) {
                struct in_addr new_ip;
                new_ip.s_addr = ans->ip4;

                fprintf(log_fd, "%s\n", inet_ntoa(new_ip));
            }

            if (block_ans_url_flag) {
                uint32_t start_subnet_ip_n = htonl(start_subnet_ip++);

                if (start_subnet_ip == end_subnet_ip) {
                    uint32_t netMask = (0xFFFFFFFF << (32 - (tun_prefix + 1)) & 0xFFFFFFFF);
                    start_subnet_ip = (ntohl(tun_ip) & netMask) + 2;
                }

                ip_ip_map_t add_elem;
                add_elem.ip_local = start_subnet_ip_n;
                add_elem.ip_global = ans->ip4;

                array_hashmap_add_elem(ip_ip_map_struct, &add_elem, NULL, ip_ip_on_collision);

                ans->ip4 = start_subnet_ip_n;

                if (log_fd) {
                    struct in_addr new_ip;
                    new_ip.s_addr = add_elem.ip_local;

                    struct in_addr old_ip;
                    old_ip.s_addr = add_elem.ip_global;

                    fprintf(log_fd, "    Blocked_IP: %s", ans_url.data + 1);
                    fprintf(log_fd, " %s", inet_ntoa(old_ip));
                    fprintf(log_fd, " %s\n", inet_ntoa(new_ip));
                }
            }
        }

        if (ans_type == 5) {
            char *cname_url_start = cur_pos_ptr + sizeof(dns_ans_t) - sizeof(uint32_t);
            int32_t cname_url_len = get_url_from_packet(receive_msg, receive_msg_end,
                                                        cname_url_start, NULL, cname_url.data);
            if (cname_url_len == -1) {
                stat.request_parsing_error++;
                return;
            }

            int32_t block_cname_url_flag = 0;
            block_cname_url_flag = check_url(cname_url.data, cname_url_len);

            if (log_fd) {
                fprintf(log_fd, "%s\n", cname_url.data + 1);
            }

            if (block_ans_url_flag == 1 && block_cname_url_flag == 0) {
                strcpy(&(urls.data[urls.size]), cname_url.data + 1);

                int32_t url_offset = urls.size;
                urls.size += cname_url_len;

                array_hashmap_add_elem(urls_map_struct, &url_offset, NULL, NULL);

                if (log_fd) {
                    fprintf(log_fd, "    Blocked_Cname: %s\n", cname_url.data + 1);
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

    if (log_fd) {
        fprintf(log_fd, "\n");
    }
}
