#include "antiblock.h"

extern int32_t route_socket;
extern struct rtentry route;

void add_ip_to_route_table(uint32_t ip, time_t check_time, char* url);
void add_url_cname(char* ans_url, time_t check_time, char* data_url);
void update_ip_in_route_table(uint32_t ip, time_t check_time, char* url);
void not_block_ip_in_route_table(uint32_t ip, time_t check_time, char* url);
void del_ip_from_route_table(uint32_t ip, time_t now);
void init_route_socket(void);
