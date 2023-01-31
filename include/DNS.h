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
