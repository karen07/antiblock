#include "antiblock.h"
#include "array_hashmap.h"

typedef struct packet {
    int32_t packet_size;
    char packet[PACKET_MAX_SIZE];
} packet_t;

typedef struct cname_urls_map {
    time_t end_time;
    char *url;
} cname_urls_map;

extern pthread_mutex_t packets_ring_buffer_mutex;
extern pthread_cond_t packets_ring_buffer_step;
extern int32_t packets_ring_buffer_size;
extern int32_t packets_ring_buffer_start;
extern int32_t packets_ring_buffer_end;
extern packet_t *packets_ring_buffer;

extern const array_hashmap_t *cname_urls_map_struct;

int32_t get_url_from_packet(char *packet_start, char *hand_point, char *receive_msg_end, char *url,
                            int32_t *first_len);
void *dns_ans_check(void *arg);
void init_dns_ans_check_thread(void);
