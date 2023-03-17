#include "antiblock.h"

typedef struct packet {
    int32_t packet_size;
    char packet[PACKET_MAX_SIZE];
} packet_t;

extern pthread_mutex_t packets_ring_buffer_mutex;
extern pthread_cond_t packets_ring_buffer_step;
extern int32_t packets_ring_buffer_size;
extern int32_t packets_ring_buffer_start;
extern int32_t packets_ring_buffer_end;
extern packet_t* packets_ring_buffer;

int32_t get_url_from_packet(char* packet_start, char* hand_point, char* receive_msg_end, char* url);
void* dns_ans_check(void* arg);
void init_dns_ans_check_thread(void);
