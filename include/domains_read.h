#include "antiblock.h"

#define GET_GATEWAY_NOT_IN_ROUTES -1

int32_t get_gateway(memory_t *domain);
void add_domain(memory_t *cname_domain, int32_t cname_domain_gateway);
int32_t domains_read(void);
