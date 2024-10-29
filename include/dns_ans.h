#include "antiblock.h"

typedef struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t quest;
    uint16_t ans;
    uint16_t auth;
    uint16_t add;
} __attribute__((packed)) dns_header_t;

typedef struct dns_que {
    uint16_t type;
    uint16_t class;
} __attribute__((packed)) dns_que_t;

typedef struct dns_ans {
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t len;
    uint32_t ip4;
} __attribute__((packed)) dns_ans_t;

#ifndef _STRUCT_MEMORY_ANTIBLOCK
#define _STRUCT_MEMORY_ANTIBLOCK
typedef struct memory {
    char *data;
    size_t size;
    size_t max_size;
} memory_t;
#endif

int32_t dns_ans_check(memory_t *receive_msg_struct);
int32_t get_url_from_packet(memory_t *receive_msg, char *cur_pos_ptr, char **new_cur_pos_ptr,
                            memory_t *url);
