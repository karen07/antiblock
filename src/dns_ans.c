#include "antiblock.h"
#include "config.h"
#include "const.h"
#include "dns_ans.h"
#include "hash.h"
#include "net_data.h"
#include "stat.h"
#include "tun.h"
#include "domains_read.h"

#define DNS_TypeA 1
#define DNS_TypeCNAME 5

#define GET_DOMAIN_OK 0
#define GET_DOMAIN_FIRST_BYTE_ERROR 1
#define GET_DOMAIN_SECOND_BYTE_ERROR 3
#define GET_DOMAIN_LAST_CH_DOMAIN_ERROR 2
#define GET_DOMAIN_JUMP_COUNT_ERROR 4
#define GET_DOMAIN_TWO_BITS_ERROR 5
#define GET_DOMAIN_CH_BYTE_ERROR 6
#define GET_DOMAIN_ADD_CH_DOMAIN_ERROR 7
#define GET_DOMAIN_NULL_CH_DOMAIN_ERROR 8

#define CHECK_DOMAIN_NOT_BLOCKED -1

int32_t get_domain_from_packet(memory_t *receive_msg, char *cur_pos_ptr, char **new_cur_pos_ptr,
                               memory_t *domain)
{
    uint8_t two_bit_mark = FIRST_TWO_BITS_UINT8;
    int32_t part_len = 0;
    int32_t domain_len = 0;

    int32_t jump_count = 0;

    *new_cur_pos_ptr = NULL;
    char *receive_msg_end = receive_msg->data + receive_msg->size;

    while (true) {
        if (part_len == 0) {
            if (cur_pos_ptr + sizeof(uint8_t) > receive_msg_end) {
                return GET_DOMAIN_FIRST_BYTE_ERROR;
            }
            uint8_t first_byte_data = (*cur_pos_ptr) & (~two_bit_mark);

            if ((*cur_pos_ptr & two_bit_mark) == 0) {
                part_len = first_byte_data;
                cur_pos_ptr++;
                if (part_len == 0) {
                    break;
                } else {
                    if (domain_len >= (int32_t)domain->max_size) {
                        return GET_DOMAIN_LAST_CH_DOMAIN_ERROR;
                    }
                    domain->data[domain_len++] = '.';
                }
            } else if ((*cur_pos_ptr & two_bit_mark) == two_bit_mark) {
                if (cur_pos_ptr + sizeof(uint16_t) > receive_msg_end) {
                    return GET_DOMAIN_SECOND_BYTE_ERROR;
                }
                if (*new_cur_pos_ptr == NULL) {
                    *new_cur_pos_ptr = cur_pos_ptr + 2;
                }
                uint8_t second_byte_data = *(cur_pos_ptr + 1);
                int32_t padding = 256 * first_byte_data + second_byte_data;
                cur_pos_ptr = receive_msg->data + padding;
                if (jump_count++ > 100) {
                    return GET_DOMAIN_JUMP_COUNT_ERROR;
                }
            } else {
                return GET_DOMAIN_TWO_BITS_ERROR;
            }
        } else {
            if (cur_pos_ptr + sizeof(uint8_t) > receive_msg_end) {
                return GET_DOMAIN_CH_BYTE_ERROR;
            }
            if (domain_len >= (int32_t)domain->max_size) {
                return GET_DOMAIN_ADD_CH_DOMAIN_ERROR;
            }
            domain->data[domain_len++] = *cur_pos_ptr;
            cur_pos_ptr++;
            part_len--;
        }
    }

    if (*new_cur_pos_ptr == NULL) {
        *new_cur_pos_ptr = cur_pos_ptr;
    }

    if (domain_len >= (int32_t)domain->max_size) {
        return GET_DOMAIN_NULL_CH_DOMAIN_ERROR;
    }
    domain->data[domain_len] = 0;
    domain->size = domain_len;

    return GET_DOMAIN_OK;
}

static int32_t check_domain(memory_t *domain)
{
    char *dot_pos = NULL;
    int32_t dot_count = 0;
    for (int32_t i = domain->size; i >= 0; i--) {
        if (domain->data[i] == '.') {
            if (dot_count++ == 0) {
                continue;
            }

            dot_pos = &domain->data[i + 1];

            domains_gateway_t res_elem;

            int32_t find_res = array_hashmap_find_elem(domains_map_struct, dot_pos, &res_elem);
            if (find_res == array_hashmap_elem_finded) {
                return res_elem.gateway;
            }
        }
    }

    return CHECK_DOMAIN_NOT_BLOCKED;
}

#define DNS_ANS_CHECK_HEADER_SIZE_ERROR -2
#define DNS_ANS_CHECK_RES_TYPE_ERROR -3
#define DNS_ANS_CHECK_QUE_COUNT_ERROR -4
#define DNS_ANS_CHECK_ANS_COUNT_ERROR -5
#define DNS_ANS_CHECK_QUE_URL_GET_ERROR -6
#define DNS_ANS_CHECK_QUE_DATA_GET_ERROR -7
#define DNS_ANS_CHECK_ANS_URL_GET_ERROR -8
#define DNS_ANS_CHECK_ANS_DATA_GET_ERROR -9
#define DNS_ANS_CHECK_ANS_LEN_ERROR -10
#define DNS_ANS_CHECK_CNAME_URL_GET_ERROR -11
#define DNS_ANS_CHECK_NOT_END_ERROR -12

int32_t dns_ans_check(memory_t *receive_msg, memory_t *que_domain, memory_t *ans_domain,
                      memory_t *cname_domain)
{
    char *cur_pos_ptr = receive_msg->data;
    char *receive_msg_end = receive_msg->data + receive_msg->size;

    // DNS HEADER
    if (cur_pos_ptr + sizeof(dns_header_t) > receive_msg_end) {
        stat.request_parsing_error++;
        return DNS_ANS_CHECK_HEADER_SIZE_ERROR;
    }

    dns_header_t *header = (dns_header_t *)cur_pos_ptr;

    //uint16_t first_bit_mark = FIRST_BIT_UINT16;
    //uint16_t flags = ntohs(header->flags);
    //if ((flags & first_bit_mark) == 0) {
    //    stat.request_parsing_error++;
    //    return DNS_ANS_CHECK_RES_TYPE_ERROR;
    //}

    uint16_t quest_count = ntohs(header->quest);
    if (quest_count != 1) {
        return DNS_ANS_CHECK_QUE_COUNT_ERROR;
    }

    uint16_t ans_count = ntohs(header->ans);
    //if (ans_count == 0) {
    //    return DNS_ANS_CHECK_ANS_COUNT_ERROR;
    //}

    cur_pos_ptr += sizeof(dns_header_t);
    // DNS HEADER

    // QUE DOMAIN
    char *que_domain_start = cur_pos_ptr;
    char *que_domain_end = NULL;
    if (get_domain_from_packet(receive_msg, que_domain_start, &que_domain_end, que_domain) != 0) {
        stat.request_parsing_error++;
        return DNS_ANS_CHECK_QUE_URL_GET_ERROR;
    }
    cur_pos_ptr = que_domain_end;

    int32_t block_que_domain_flag = check_domain(que_domain);
    // QUE DOMAIN

    // QUE DATA
    if (cur_pos_ptr + sizeof(dns_que_t) > receive_msg_end) {
        stat.request_parsing_error++;
        return DNS_ANS_CHECK_QUE_DATA_GET_ERROR;
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
        fprintf(log_fd, "Que_domain %d: %s\n", que_type, que_domain->data + 1);
    }

    for (int32_t i = 0; i < ans_count; i++) {
        // ANS DOMAIN
        char *ans_domain_start = cur_pos_ptr;
        char *ans_domain_end = NULL;
        if (get_domain_from_packet(receive_msg, ans_domain_start, &ans_domain_end, ans_domain) !=
            0) {
            stat.request_parsing_error++;
            return DNS_ANS_CHECK_ANS_URL_GET_ERROR;
        }
        cur_pos_ptr = ans_domain_end;

        int32_t block_ans_domain_flag = CHECK_DOMAIN_NOT_BLOCKED;
        block_ans_domain_flag = check_domain(ans_domain);
        // ANS DOMAIN

        // ANS DATA
        if (cur_pos_ptr + sizeof(dns_ans_t) - sizeof(uint32_t) > receive_msg_end) {
            stat.request_parsing_error++;
            return DNS_ANS_CHECK_ANS_DATA_GET_ERROR;
        }

        dns_ans_t *ans = (dns_ans_t *)cur_pos_ptr;

        uint16_t ans_type = ntohs(ans->type);
        __attribute__((unused)) uint32_t ans_ttl = ntohl(ans->ttl);
        uint16_t ans_len = ntohs(ans->len);

        if (cur_pos_ptr + sizeof(dns_ans_t) - sizeof(uint32_t) + ans_len > receive_msg_end) {
            stat.request_parsing_error++;
            return DNS_ANS_CHECK_ANS_LEN_ERROR;
        }

        if (ans_type == DNS_TypeA) {
            if (block_ans_domain_flag != CHECK_DOMAIN_NOT_BLOCKED) {
#ifdef TUN_MODE
                uint32_t NAT_subnet_start_n = htonl(NAT.start_ip++);

                if (NAT.start_ip == NAT.end_ip) {
                    subnet_init(&NAT);
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

                    fprintf(log_fd, "    Blocked_IP: %s", ans_domain->data + 1);
                    fprintf(log_fd, " %s", inet_ntoa(old_ip));
                    fprintf(log_fd, " %s\n", inet_ntoa(new_ip));
                }
#else

                int32_t correct_ip4_flag = 1;
                for (int j = 0; j < gateways_count + 1; j++) {
                    if ((ans->ip4 == dns_addr[j].sin_addr.s_addr) || (ans->ip4 == 0)) {
                        correct_ip4_flag = 0;
                    }
                }
                if (correct_ip4_flag) {
                    add_route(block_ans_domain_flag, ans->ip4);
                }

                if (log_fd) {
                    struct in_addr rec_ip;
                    rec_ip.s_addr = ans->ip4;
                    fprintf(log_fd, "    Blocked_IP: %s", ans_domain->data + 1);
                    fprintf(log_fd, " %s\n", inet_ntoa(rec_ip));
                }
#endif
            } else {
                if (log_fd) {
                    struct in_addr new_ip;
                    new_ip.s_addr = ans->ip4;

                    fprintf(log_fd, "    Not_Blocked_IP: %s", ans_domain->data + 1);
                    fprintf(log_fd, " %s\n", inet_ntoa(new_ip));
                }
            }
        }

        if (ans_type == DNS_TypeCNAME) {
            char *cname_domain_start = cur_pos_ptr + sizeof(dns_ans_t) - sizeof(uint32_t);
            char *cname_domain_end = NULL;
            if (get_domain_from_packet(receive_msg, cname_domain_start, &cname_domain_end,
                                       cname_domain) != 0) {
                stat.request_parsing_error++;
                return DNS_ANS_CHECK_CNAME_URL_GET_ERROR;
            }

            int32_t block_cname_domain_flag = CHECK_DOMAIN_NOT_BLOCKED;
            block_cname_domain_flag = check_domain(cname_domain);

            if (block_ans_domain_flag != CHECK_DOMAIN_NOT_BLOCKED &&
                block_cname_domain_flag == CHECK_DOMAIN_NOT_BLOCKED) {
                block_cname_domain_flag = block_ans_domain_flag;
                if (domains_map_struct) {
                    if (domains.size + cname_domain->size < domains.max_size) {
                        strcpy(&(domains.data[domains.size]), cname_domain->data + 1);

                        domains_gateway_t add_elem;
                        add_elem.offset = domains.size;
                        add_elem.gateway = block_cname_domain_flag;

                        domains.size += cname_domain->size;

                        array_hashmap_add_elem(domains_map_struct, &add_elem, NULL, NULL);
                    }
                }
            }

            if (block_cname_domain_flag != CHECK_DOMAIN_NOT_BLOCKED) {
                if (log_fd) {
                    fprintf(log_fd, "    Blocked_Cname: %s\n", cname_domain->data + 1);
                }
            } else {
                if (log_fd) {
                    fprintf(log_fd, "    Not_Blocked_Cname: %s\n", cname_domain->data + 1);
                }
            }
        }

        if (ans_type != DNS_TypeA && ans_type != DNS_TypeCNAME) {
            if (log_fd) {
                fprintf(log_fd, "    Ans_domain %d: %s\n", ans_type, ans_domain->data + 1);
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
            return DNS_ANS_CHECK_NOT_END_ERROR;
        }
    }

    return block_que_domain_flag;
}

void dns_ans_check_test(void)
{
    memory_t receive_msg;
    receive_msg.size = 0;
    receive_msg.max_size = PACKET_MAX_SIZE;
    receive_msg.data = (char *)malloc(receive_msg.max_size * sizeof(char));
    if (receive_msg.data == 0) {
        errmsg("No free memory for receive_msg from DNS\n");
    }

    memory_t que_domain;
    que_domain.size = 0;
    que_domain.max_size = DOMAIN_MAX_SIZE;
    que_domain.data = (char *)malloc(que_domain.max_size * sizeof(char));
    if (que_domain.data == 0) {
        errmsg("No free memory for que_domain\n");
    }

    memory_t ans_domain;
    ans_domain.size = 0;
    ans_domain.max_size = DOMAIN_MAX_SIZE;
    ans_domain.data = (char *)malloc(ans_domain.max_size * sizeof(char));
    if (ans_domain.data == 0) {
        errmsg("No free memory for ans_domain\n");
    }

    memory_t cname_domain;
    cname_domain.size = 0;
    cname_domain.max_size = DOMAIN_MAX_SIZE;
    cname_domain.data = (char *)malloc(cname_domain.max_size * sizeof(char));
    if (cname_domain.data == 0) {
        errmsg("No free memory for cname_domain\n");
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
    if (dns_ans_check(&receive_msg, &que_domain, &ans_domain, &cname_domain) !=
        CHECK_DOMAIN_NOT_BLOCKED) {
        errmsg("Test DNS correct fail\n");
    }

    receive_msg.size = 11;
    if (dns_ans_check(&receive_msg, &que_domain, &ans_domain, &cname_domain) !=
        DNS_ANS_CHECK_HEADER_SIZE_ERROR) {
        errmsg("Test DNS header size fail\n");
    }
    receive_msg.size = sizeof(correct_test);

    //receive_msg.data[2] = 1;
    //if (dns_ans_check(&receive_msg, &que_domain, &ans_domain, &cname_domain) != DNS_ANS_CHECK_RES_TYPE_ERROR) {
    //    errmsg("Test DNS flag fail\n");
    //}
    //receive_msg.data[2] = correct_test[2];

    receive_msg.data[5] = 2;
    if (dns_ans_check(&receive_msg, &que_domain, &ans_domain, &cname_domain) !=
        DNS_ANS_CHECK_QUE_COUNT_ERROR) {
        errmsg("Test DNS quest count fail\n");
    }
    receive_msg.data[5] = correct_test[5];

    //receive_msg.data[7] = 0;
    //if (dns_ans_check(&receive_msg, &que_domain, &ans_domain, &cname_domain) != DNS_ANS_CHECK_ANS_COUNT_ERROR) {
    //    errmsg("Test DNS ans count fail\n");
    //}
    //receive_msg.data[7] = correct_test[7];

    receive_msg.size = 26;
    if (dns_ans_check(&receive_msg, &que_domain, &ans_domain, &cname_domain) !=
        DNS_ANS_CHECK_QUE_URL_GET_ERROR) {
        errmsg("Test DNS que domain fail\n");
    }
    receive_msg.size = sizeof(correct_test);

    receive_msg.size = 30;
    if (dns_ans_check(&receive_msg, &que_domain, &ans_domain, &cname_domain) !=
        DNS_ANS_CHECK_QUE_DATA_GET_ERROR) {
        errmsg("Test DNS header que size fail\n");
    }
    receive_msg.size = sizeof(correct_test);

    receive_msg.size = 32;
    if (dns_ans_check(&receive_msg, &que_domain, &ans_domain, &cname_domain) !=
        DNS_ANS_CHECK_ANS_URL_GET_ERROR) {
        errmsg("Test DNS ans domain fail\n");
    }
    receive_msg.size = sizeof(correct_test);

    receive_msg.size = 42;
    if (dns_ans_check(&receive_msg, &que_domain, &ans_domain, &cname_domain) !=
        DNS_ANS_CHECK_ANS_DATA_GET_ERROR) {
        errmsg("Test DNS header ans size fail\n");
    }
    receive_msg.size = sizeof(correct_test);

    receive_msg.size = 66;
    if (dns_ans_check(&receive_msg, &que_domain, &ans_domain, &cname_domain) !=
        DNS_ANS_CHECK_ANS_LEN_ERROR) {
        errmsg("Test DNS header ans data size fail\n");
    }
    receive_msg.size = sizeof(correct_test);

    receive_msg.data[58] = 0x3F;
    if (dns_ans_check(&receive_msg, &que_domain, &ans_domain, &cname_domain) !=
        DNS_ANS_CHECK_CNAME_URL_GET_ERROR) {
        errmsg("Test DNS cname domain fail\n");
    }
    receive_msg.data[58] = correct_test[58];

    receive_msg.size = sizeof(correct_test) + 1;
    if (dns_ans_check(&receive_msg, &que_domain, &ans_domain, &cname_domain) !=
        DNS_ANS_CHECK_NOT_END_ERROR) {
        errmsg("Test DNS end fail\n");
    }
    receive_msg.size = sizeof(correct_test);

    char *tmp_ptr;
    if (get_domain_from_packet(&receive_msg, receive_msg.data + 12, &tmp_ptr, &que_domain) !=
        GET_DOMAIN_OK) {
        errmsg("Test get domain correct fail\n");
    }

    receive_msg.size = 12;
    if (get_domain_from_packet(&receive_msg, receive_msg.data + 12, &tmp_ptr, &que_domain) !=
        GET_DOMAIN_FIRST_BYTE_ERROR) {
        errmsg("Test get domain first byte fail\n");
    }
    receive_msg.size = sizeof(correct_test);

    que_domain.max_size = 0;
    if (get_domain_from_packet(&receive_msg, receive_msg.data + 12, &tmp_ptr, &que_domain) !=
        GET_DOMAIN_LAST_CH_DOMAIN_ERROR) {
        errmsg("Test get domain first byte domain len fail\n");
    }
    que_domain.max_size = DOMAIN_MAX_SIZE;

    receive_msg.size = 32;
    if (get_domain_from_packet(&receive_msg, receive_msg.data + 31, &tmp_ptr, &que_domain) !=
        GET_DOMAIN_SECOND_BYTE_ERROR) {
        errmsg("Test get domain second byte fail\n");
    }
    receive_msg.size = sizeof(correct_test);

    receive_msg.data[32] = 0x43;
    receive_msg.data[68] = 0x1F;
    if (get_domain_from_packet(&receive_msg, receive_msg.data + 31, &tmp_ptr, &que_domain) !=
        GET_DOMAIN_JUMP_COUNT_ERROR) {
        errmsg("Test get domain endless jumping fail\n");
    }
    receive_msg.data[32] = correct_test[32];
    receive_msg.data[68] = correct_test[68];

    receive_msg.data[31] = 0x7F;
    if (get_domain_from_packet(&receive_msg, receive_msg.data + 31, &tmp_ptr, &que_domain) !=
        GET_DOMAIN_TWO_BITS_ERROR) {
        errmsg("Test get domain byte 01 10 fail\n");
    }
    receive_msg.data[31] = correct_test[31];

    receive_msg.size = 13;
    if (get_domain_from_packet(&receive_msg, receive_msg.data + 12, &tmp_ptr, &que_domain) !=
        GET_DOMAIN_CH_BYTE_ERROR) {
        errmsg("Test get domain data byte fail\n");
    }
    receive_msg.size = sizeof(correct_test);

    que_domain.max_size = 1;
    if (get_domain_from_packet(&receive_msg, receive_msg.data + 12, &tmp_ptr, &que_domain) !=
        GET_DOMAIN_ADD_CH_DOMAIN_ERROR) {
        errmsg("Test get domain data domain len fail\n");
    }
    que_domain.max_size = DOMAIN_MAX_SIZE;

    que_domain.max_size = 14;
    if (get_domain_from_packet(&receive_msg, receive_msg.data + 12, &tmp_ptr, &que_domain) !=
        GET_DOMAIN_NULL_CH_DOMAIN_ERROR) {
        errmsg("Test get domain data domain last byte fail\n");
    }
    que_domain.max_size = DOMAIN_MAX_SIZE;

    log_fd = log_fd_tmp;

    free(receive_msg.data);
    free(que_domain.data);
    free(ans_domain.data);
    free(cname_domain.data);
}
