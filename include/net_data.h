#include "antiblock.h"

int32_t add_route_to_hashmap(int32_t gateway_index, uint32_t dst, uint32_t ans_ttl);
void del_expired_routes_from_hashmap(void);
void PCAP_mode_init(void);
int32_t PCAP_get_msg(memory_t *receive_msg);
