#include "antiblock.h"
#include "config.h"
#include "const.h"
#include "dns_ans.h"
#include "hash.h"
#include "net_data.h"
#include "stat.h"
#include "tun.h"
#include "urls_read.h"

#define DNS_TypeA 1
#define DNS_TypeCNAME 5

int32_t get_url_from_packet(memory_t *receive_msg, char *cur_pos_ptr, char **new_cur_pos_ptr,
                            memory_t *url)
{
    uint8_t two_bit_mark = FIRST_TWO_BITS_UINT8;
    int32_t part_len = 0;
    int32_t url_len = 0;

    int32_t jump_count = 0;

    *new_cur_pos_ptr = NULL;
    char *receive_msg_end = receive_msg->data + receive_msg->size;

    while (true) {
        if (part_len == 0) {
            if (cur_pos_ptr + sizeof(uint8_t) > receive_msg_end) {
                return 1;
            }
            uint8_t first_byte_data = (*cur_pos_ptr) & (~two_bit_mark);

            if ((*cur_pos_ptr & two_bit_mark) == 0) {
                part_len = first_byte_data;
                cur_pos_ptr++;
                if (part_len == 0) {
                    break;
                } else {
                    if (url_len >= (int32_t)url->max_size) {
                        return 2;
                    }
                    url->data[url_len++] = '.';
                }
            } else if ((*cur_pos_ptr & two_bit_mark) == two_bit_mark) {
                if (cur_pos_ptr + sizeof(uint16_t) > receive_msg_end) {
                    return 3;
                }
                if (*new_cur_pos_ptr == NULL) {
                    *new_cur_pos_ptr = cur_pos_ptr + 2;
                }
                uint8_t second_byte_data = *(cur_pos_ptr + 1);
                int32_t padding = 256 * first_byte_data + second_byte_data;
                cur_pos_ptr = receive_msg->data + padding;
                if (jump_count++ > 100) {
                    return 4;
                }
            } else {
                return 5;
            }
        } else {
            if (cur_pos_ptr + sizeof(uint8_t) > receive_msg_end) {
                return 6;
            }
            if (url_len >= (int32_t)url->max_size) {
                return 7;
            }
            url->data[url_len++] = *cur_pos_ptr;
            cur_pos_ptr++;
            part_len--;
        }
    }

    if (*new_cur_pos_ptr == NULL) {
        *new_cur_pos_ptr = cur_pos_ptr;
    }

    if (url_len >= (int32_t)url->max_size) {
        return 8;
    }
    url->data[url_len] = 0;
    url->size = url_len;

    return 0;
}

static int32_t check_url(memory_t *url)
{
    char *dot_pos = NULL;
    int32_t dot_count = 0;
    for (int32_t i = url->size; i >= 0; i--) {
        if (url->data[i] == '.') {
            if (dot_count++ == 0) {
                continue;
            }

            dot_pos = &url->data[i + 1];

            int32_t find_res = array_hashmap_find_elem(urls_map_struct, dot_pos, NULL);
            if (find_res == array_hashmap_elem_finded) {
                return 1;
            }
        }
    }

    return 0;
}

int32_t dns_ans_check(memory_t *receive_msg, memory_t *que_url, memory_t *ans_url,
                      memory_t *cname_url)
{
    char *cur_pos_ptr = receive_msg->data;
    char *receive_msg_end = receive_msg->data + receive_msg->size;

    // DNS HEADER
    if (cur_pos_ptr + sizeof(dns_header_t) > receive_msg_end) {
        stat.request_parsing_error++;
        return 1;
    }

    dns_header_t *header = (dns_header_t *)cur_pos_ptr;

    uint16_t first_bit_mark = FIRST_BIT_UINT16;
    uint16_t flags = ntohs(header->flags);
    if ((flags & first_bit_mark) == 0) {
        stat.request_parsing_error++;
        return 2;
    }

    uint16_t quest_count = ntohs(header->quest);
    if (quest_count != 1) {
        return 3;
    }

    uint16_t ans_count = ntohs(header->ans);
    if (ans_count == 0) {
        return 4;
    }

    cur_pos_ptr += sizeof(dns_header_t);
    // DNS HEADER

    // QUE URL
    char *que_url_start = cur_pos_ptr;
    char *que_url_end = NULL;
    if (get_url_from_packet(receive_msg, que_url_start, &que_url_end, que_url) != 0) {
        stat.request_parsing_error++;
        return 5;
    }
    cur_pos_ptr = que_url_end;

    __attribute__((unused)) int32_t block_que_url_flag = check_url(que_url);
    // QUE URL

    // QUE DATA
    if (cur_pos_ptr + sizeof(dns_que_t) > receive_msg_end) {
        stat.request_parsing_error++;
        return 6;
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
        fprintf(log_fd, "Que_url %d: %s\n", que_type, que_url->data + 1);
    }

    for (int32_t i = 0; i < ans_count; i++) {
        // ANS URL
        char *ans_url_start = cur_pos_ptr;
        char *ans_url_end = NULL;
        if (get_url_from_packet(receive_msg, ans_url_start, &ans_url_end, ans_url) != 0) {
            stat.request_parsing_error++;
            return 7;
        }
        cur_pos_ptr = ans_url_end;

        int32_t block_ans_url_flag = 0;
        block_ans_url_flag = check_url(ans_url);
        // ANS URL

        // ANS DATA
        if (cur_pos_ptr + sizeof(dns_ans_t) - sizeof(uint32_t) > receive_msg_end) {
            stat.request_parsing_error++;
            return 8;
        }

        dns_ans_t *ans = (dns_ans_t *)cur_pos_ptr;

        uint16_t ans_type = ntohs(ans->type);
        __attribute__((unused)) uint32_t ans_ttl = ntohl(ans->ttl);
        uint16_t ans_len = ntohs(ans->len);

        if (cur_pos_ptr + sizeof(dns_ans_t) - sizeof(uint32_t) + ans_len > receive_msg_end) {
            stat.request_parsing_error++;
            return 9;
        }

        if (ans_type == DNS_TypeA) {
            if (block_ans_url_flag) {
#ifdef TUN_MODE
                if (is_tun_name) {
                    uint32_t NAT_subnet_start_n = htonl(NAT_VPN.start_ip++);

                    if (NAT_VPN.start_ip == NAT_VPN.end_ip) {
                        subnet_init(&NAT_VPN);
                    }

                    ip_ip_map_t add_elem;
                    add_elem.ip_local = NAT_subnet_start_n;
                    add_elem.ip_global = ans->ip4;

                    array_hashmap_add_elem(ip_ip_map_struct, &add_elem, NULL,
                                           array_hashmap_save_new_func);

                    ans->ip4 = NAT_subnet_start_n;

                    if (log_fd) {
                        struct in_addr new_ip;
                        new_ip.s_addr = add_elem.ip_local;

                        struct in_addr old_ip;
                        old_ip.s_addr = add_elem.ip_global;

                        fprintf(log_fd, "    Blocked_IP: %s", ans_url->data + 1);
                        fprintf(log_fd, " %s", inet_ntoa(old_ip));
                        fprintf(log_fd, " %s\n", inet_ntoa(new_ip));
                    }
                } else
#endif
                {
                    struct in_addr rec_ip;
                    rec_ip.s_addr = ans->ip4;

                    struct sockaddr_in *route_addr = (struct sockaddr_in *)&route.rt_dst;
                    route_addr->sin_family = AF_INET;
                    route_addr->sin_addr.s_addr = rec_ip.s_addr;

                    if ((ans->ip4 != dns_ip) && (ans->ip4 != 0)) {
                        if (ioctl(route_socket, SIOCADDRT, &route) < 0) {
                            if (strcmp(strerror(errno), "File exists")) {
                                printf("Ioctl can't add %s to route table :%s\n", inet_ntoa(rec_ip),
                                       strerror(errno));
                            }
                        }
                    }

                    if (log_fd) {
                        fprintf(log_fd, "    Blocked_IP: %s", ans_url->data + 1);
                        fprintf(log_fd, " %s\n", inet_ntoa(rec_ip));
                    }
                }
            } else {
                if (log_fd) {
                    struct in_addr new_ip;
                    new_ip.s_addr = ans->ip4;

                    fprintf(log_fd, "    Not_Blocked_IP: %s", ans_url->data + 1);
                    fprintf(log_fd, " %s\n", inet_ntoa(new_ip));
                }
            }
        }

        if (ans_type == DNS_TypeCNAME) {
            char *cname_url_start = cur_pos_ptr + sizeof(dns_ans_t) - sizeof(uint32_t);
            char *cname_url_end = NULL;
            if (get_url_from_packet(receive_msg, cname_url_start, &cname_url_end, cname_url) != 0) {
                stat.request_parsing_error++;
                return 10;
            }

            int32_t block_cname_url_flag = 0;
            block_cname_url_flag = check_url(cname_url);

            if (block_ans_url_flag == 1 && block_cname_url_flag == 0) {
                block_cname_url_flag = 1;
                if (urls_map_struct) {
                    if (urls.size + cname_url->size < urls.max_size) {
                        strcpy(&(urls.data[urls.size]), cname_url->data + 1);

                        int32_t url_offset = urls.size;
                        urls.size += cname_url->size;

                        array_hashmap_add_elem(urls_map_struct, &url_offset, NULL, NULL);
                    }
                }
            }

            if (block_cname_url_flag) {
                if (log_fd) {
                    fprintf(log_fd, "    Blocked_Cname: %s\n", cname_url->data + 1);
                }
            } else {
                if (log_fd) {
                    fprintf(log_fd, "    Not_Blocked_Cname: %s\n", cname_url->data + 1);
                }
            }
        }

        if (ans_type != DNS_TypeA && ans_type != DNS_TypeCNAME) {
            if (log_fd) {
                fprintf(log_fd, "    Ans_url %d: %s\n", ans_type, ans_url->data + 1);
            }
        }

        cur_pos_ptr += sizeof(dns_ans_t) - sizeof(uint32_t) + ans_len;
        // ANS DATA
    }

    if (log_fd) {
        fprintf(log_fd, "\n");
    }

    if ((header->auth == 0) && (header->add == 0)) {
        if (cur_pos_ptr != receive_msg_end) {
            stat.request_parsing_error++;
            return 11;
        }
    }

    return 0;
}

void dns_ans_check_test(void)
{
    memory_t receive_msg;
    receive_msg.size = 0;
    receive_msg.max_size = PACKET_MAX_SIZE;
    receive_msg.data = (char *)malloc(receive_msg.max_size * sizeof(char));
    if (receive_msg.data == 0) {
        printf("No free memory for receive_msg from DNS\n");
        exit(EXIT_FAILURE);
    }

    memory_t que_url;
    que_url.size = 0;
    que_url.max_size = URL_MAX_SIZE;
    que_url.data = (char *)malloc(que_url.max_size * sizeof(char));
    if (que_url.data == 0) {
        printf("No free memory for que_url\n");
        exit(EXIT_FAILURE);
    }

    memory_t ans_url;
    ans_url.size = 0;
    ans_url.max_size = URL_MAX_SIZE;
    ans_url.data = (char *)malloc(ans_url.max_size * sizeof(char));
    if (ans_url.data == 0) {
        printf("No free memory for ans_url\n");
        exit(EXIT_FAILURE);
    }

    memory_t cname_url;
    cname_url.size = 0;
    cname_url.max_size = URL_MAX_SIZE;
    cname_url.data = (char *)malloc(cname_url.max_size * sizeof(char));
    if (cname_url.data == 0) {
        printf("No free memory for cname_url\n");
        exit(EXIT_FAILURE);
    }

    FILE *log_fd_tmp = log_fd;
    log_fd = NULL;

    uint8_t correct_test[] = { 0x0f, 0x32, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00,
                               0x00, 0x03, 0x79, 0x74, 0x33, 0x05, 0x67, 0x67, 0x70, 0x68, 0x74,
                               0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c,
                               0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0x09, 0x00, 0x18, 0x0c,
                               0x77, 0x69, 0x64, 0x65, 0x2d, 0x79, 0x6f, 0x75, 0x74, 0x75, 0x62,
                               0x65, 0x01, 0x6c, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0xc0,
                               0x16, 0xc0, 0x2b, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x09,
                               0x00, 0x04, 0x40, 0xe9, 0xa1, 0xc6 };

    receive_msg.size = sizeof(correct_test);
    memcpy(receive_msg.data, correct_test, receive_msg.size);
    if (dns_ans_check(&receive_msg, &que_url, &ans_url, &cname_url) != 0) {
        printf("Test DNS correct fail\n");
        exit(EXIT_FAILURE);
    }

    receive_msg.size = 11;
    if (dns_ans_check(&receive_msg, &que_url, &ans_url, &cname_url) != 1) {
        printf("Test DNS header size fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.size = sizeof(correct_test);

    receive_msg.data[2] = 1;
    if (dns_ans_check(&receive_msg, &que_url, &ans_url, &cname_url) != 2) {
        printf("Test DNS flag fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.data[2] = correct_test[2];

    receive_msg.data[5] = 2;
    if (dns_ans_check(&receive_msg, &que_url, &ans_url, &cname_url) != 3) {
        printf("Test DNS quest count fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.data[5] = correct_test[5];

    receive_msg.data[7] = 0;
    if (dns_ans_check(&receive_msg, &que_url, &ans_url, &cname_url) != 4) {
        printf("Test DNS ans count fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.data[7] = correct_test[7];

    receive_msg.size = 26;
    if (dns_ans_check(&receive_msg, &que_url, &ans_url, &cname_url) != 5) {
        printf("Test DNS que url fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.size = sizeof(correct_test);

    receive_msg.size = 30;
    if (dns_ans_check(&receive_msg, &que_url, &ans_url, &cname_url) != 6) {
        printf("Test DNS header que size fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.size = sizeof(correct_test);

    receive_msg.size = 32;
    if (dns_ans_check(&receive_msg, &que_url, &ans_url, &cname_url) != 7) {
        printf("Test DNS ans url fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.size = sizeof(correct_test);

    receive_msg.size = 42;
    if (dns_ans_check(&receive_msg, &que_url, &ans_url, &cname_url) != 8) {
        printf("Test DNS header ans size fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.size = sizeof(correct_test);

    receive_msg.size = 66;
    if (dns_ans_check(&receive_msg, &que_url, &ans_url, &cname_url) != 9) {
        printf("Test DNS header ans data size fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.size = sizeof(correct_test);

    receive_msg.data[58] = 0x3F;
    if (dns_ans_check(&receive_msg, &que_url, &ans_url, &cname_url) != 10) {
        printf("Test DNS cname url fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.data[58] = correct_test[58];

    receive_msg.size = sizeof(correct_test) + 1;
    if (dns_ans_check(&receive_msg, &que_url, &ans_url, &cname_url) != 11) {
        printf("Test DNS end fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.size = sizeof(correct_test);

    char *tmp_ptr;

    if (get_url_from_packet(&receive_msg, receive_msg.data + 12, &tmp_ptr, &que_url) != 0) {
        printf("Test get url correct fail\n");
        exit(EXIT_FAILURE);
    }

    receive_msg.size = 12;
    if (get_url_from_packet(&receive_msg, receive_msg.data + 12, &tmp_ptr, &que_url) != 1) {
        printf("Test get url first byte fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.size = sizeof(correct_test);

    que_url.max_size = 0;
    if (get_url_from_packet(&receive_msg, receive_msg.data + 12, &tmp_ptr, &que_url) != 2) {
        printf("Test get url first byte url len fail\n");
        exit(EXIT_FAILURE);
    }
    que_url.max_size = URL_MAX_SIZE;

    receive_msg.size = 32;
    if (get_url_from_packet(&receive_msg, receive_msg.data + 31, &tmp_ptr, &que_url) != 3) {
        printf("Test get url second byte fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.size = sizeof(correct_test);

    receive_msg.data[32] = 0x43;
    receive_msg.data[68] = 0x1F;
    if (get_url_from_packet(&receive_msg, receive_msg.data + 31, &tmp_ptr, &que_url) != 4) {
        printf("Test get url endless jumping fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.data[32] = correct_test[32];
    receive_msg.data[68] = correct_test[68];

    receive_msg.data[31] = 0x7F;
    if (get_url_from_packet(&receive_msg, receive_msg.data + 31, &tmp_ptr, &que_url) != 5) {
        printf("Test get url byte 01 10 fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.data[31] = correct_test[31];

    receive_msg.size = 13;
    if (get_url_from_packet(&receive_msg, receive_msg.data + 12, &tmp_ptr, &que_url) != 6) {
        printf("Test get url data byte fail\n");
        exit(EXIT_FAILURE);
    }
    receive_msg.size = sizeof(correct_test);

    que_url.max_size = 1;
    if (get_url_from_packet(&receive_msg, receive_msg.data + 12, &tmp_ptr, &que_url) != 7) {
        printf("Test get url data url len fail\n");
        exit(EXIT_FAILURE);
    }
    que_url.max_size = URL_MAX_SIZE;

    que_url.max_size = 14;
    if (get_url_from_packet(&receive_msg, receive_msg.data + 12, &tmp_ptr, &que_url) != 8) {
        printf("Test get url data url last byte fail\n");
        exit(EXIT_FAILURE);
    }
    que_url.max_size = URL_MAX_SIZE;

    log_fd = log_fd_tmp;

    free(receive_msg.data);
    free(que_url.data);
    free(ans_url.data);
    free(cname_url.data);
}
