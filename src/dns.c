#include "dns.h"

#include <stdio.h>
#include <string.h>

#define DNS_HEADER_LEN 12u
#define DNS_QR_RESPONSE 0x8000u
#define DNS_CLASS_IN 1u
#define DNS_TYPE_A 1u
#define DNS_TYPE_CNAME 5u
#define DNS_TYPE_HTTPS 65u
#define DNS_MAX_POINTER_JUMPS 128u

enum dns_error {
    DNS_E_HEADER = -1,
    DNS_E_NOT_RESPONSE = -2,
    DNS_E_QUESTION_COUNT = -3,
    DNS_E_NAME = -4,
    DNS_E_QUESTION = -5,
    DNS_E_RR = -6,
    DNS_E_A_LENGTH = -7,
    DNS_E_CNAME = -8,
    DNS_E_HTTPS = -9
};

typedef struct dns_rr {
    char owner[AB_DOMAIN_MAX];
    uint16_t type;
    uint16_t class_;
    uint32_t ttl;
    uint16_t rdlength;
    size_t rdata_offset;
    size_t next_offset;
} dns_rr_t;

static char lower_ascii(char ch)
{
    if (ch >= 'A' && ch <= 'Z') {
        return (char)(ch + ('a' - 'A'));
    }
    return ch;
}

static int dns_decode_name(const uint8_t *packet, size_t packet_len, size_t offset,
                           size_t *next_offset, char *out, size_t out_size)
{
    size_t pos = offset;
    size_t out_len = 0;
    size_t resume = 0;
    unsigned int jumps = 0;
    int jumped = 0;

    if (out_size == 0 || offset >= packet_len) {
        return -1;
    }

    for (;;) {
        uint8_t ch;
        uint8_t label_len;
        size_t i;

        if (pos >= packet_len) {
            return -1;
        }
        ch = packet[pos];

        if (ch == 0) {
            if (!jumped) {
                resume = pos + 1u;
            }
            if (out_len >= out_size) {
                return -1;
            }
            out[out_len] = '\0';
            *next_offset = resume;
            return 0;
        }

        if ((ch & 0xc0u) == 0xc0u) {
            uint16_t pointer;
            if (pos + 1u >= packet_len) {
                return -1;
            }
            pointer = (uint16_t)(((uint16_t)(ch & 0x3fu) << 8) | packet[pos + 1u]);
            if ((size_t)pointer >= packet_len || ++jumps > DNS_MAX_POINTER_JUMPS) {
                return -1;
            }
            if (!jumped) {
                resume = pos + 2u;
                jumped = 1;
            }
            pos = pointer;
            continue;
        }
        if ((ch & 0xc0u) != 0) {
            return -1;
        }

        label_len = ch;
        if (label_len > 63u || pos + 1u + label_len > packet_len) {
            return -1;
        }
        if (out_len != 0) {
            if (out_len + 1u >= out_size) {
                return -1;
            }
            out[out_len++] = '.';
        }
        if (out_len + label_len >= out_size) {
            return -1;
        }
        for (i = 0; i < label_len; ++i) {
            out[out_len++] = lower_ascii((char)packet[pos + 1u + i]);
        }
        pos += 1u + label_len;
    }
}

static int dns_parse_rr(const ab_bytes_t *packet, size_t offset, dns_rr_t *rr)
{
    size_t fixed;

    if (dns_decode_name(packet->data, packet->len, offset, &fixed, rr->owner, sizeof(rr->owner)) !=
        0) {
        return -1;
    }
    if (fixed + 10u > packet->len) {
        return -1;
    }

    rr->type = ab_read_be16(packet->data + fixed);
    rr->class_ = ab_read_be16(packet->data + fixed + 2u);
    rr->ttl = ab_read_be32(packet->data + fixed + 4u);
    rr->rdlength = ab_read_be16(packet->data + fixed + 8u);
    rr->rdata_offset = fixed + 10u;
    rr->next_offset = rr->rdata_offset + rr->rdlength;
    if (rr->next_offset > packet->len) {
        return -1;
    }
    return 0;
}

static int dns_decode_cname(const ab_bytes_t *packet, const dns_rr_t *rr, char *target,
                            size_t target_size)
{
    size_t consumed;
    size_t rdata_end = rr->rdata_offset + rr->rdlength;

    if (dns_decode_name(packet->data, packet->len, rr->rdata_offset, &consumed, target,
                        target_size) != 0) {
        return -1;
    }
    if (consumed != rdata_end) {
        return -1;
    }
    return 0;
}

static int dns_decode_uncompressed_name(const uint8_t *packet, size_t offset, size_t end,
                                        size_t *next_offset, char *out, size_t out_size)
{
    size_t pos = offset;
    size_t out_len = 0;

    if (out_size == 0 || offset >= end) {
        return -1;
    }

    for (;;) {
        uint8_t label_len;
        size_t i;

        if (pos >= end) {
            return -1;
        }
        label_len = packet[pos++];
        if (label_len == 0) {
            if (out_len >= out_size) {
                return -1;
            }
            out[out_len] = '\0';
            *next_offset = pos;
            return 0;
        }
        if ((label_len & 0xc0u) != 0 || label_len > 63u || pos + label_len > end) {
            return -1;
        }
        if (out_len != 0) {
            if (out_len + 1u >= out_size) {
                return -1;
            }
            out[out_len++] = '.';
        }
        if (out_len + label_len >= out_size) {
            return -1;
        }
        for (i = 0; i < label_len; ++i) {
            out[out_len++] = lower_ascii((char)packet[pos + i]);
        }
        pos += label_len;
    }
}

/* Return 1 for HTTPS AliasMode, 0 for ignored ServiceMode, -1 for malformed AliasMode. */
static int dns_decode_https_alias(const ab_bytes_t *packet, const dns_rr_t *rr, char *target,
                                  size_t target_size)
{
    size_t rdata_end = rr->rdata_offset + rr->rdlength;
    size_t target_end;
    uint16_t priority;

    if (rr->rdlength < 2u) {
        return -1;
    }
    priority = ab_read_be16(packet->data + rr->rdata_offset);
    if (priority != 0u) {
        return 0;
    }
    if (rr->rdlength < 3u) {
        return -1;
    }

    /* RFC 9460 requires TargetName in SVCB/HTTPS RDATA to be uncompressed. */
    if (dns_decode_uncompressed_name(packet->data, rr->rdata_offset + 2u, rdata_end, &target_end,
                                     target, target_size) != 0) {
        return -1;
    }
    (void)target_end;
    return 1;
}

static int propagate_aliases(const ab_bytes_t *packet, size_t answers_offset, uint16_t answer_count,
                             domain_table_t *domains)
{
    uint32_t pass_limit = answer_count;
    uint32_t pass;

    if (pass_limit > AB_ALIAS_MAX_PASSES) {
        pass_limit = AB_ALIAS_MAX_PASSES;
    }

    for (pass = 0; pass < pass_limit; ++pass) {
        size_t offset = answers_offset;
        uint16_t i;
        int changed = 0;

        for (i = 0; i < answer_count; ++i) {
            dns_rr_t rr;
            char target[AB_DOMAIN_MAX];
            int is_alias = 0;

            if (dns_parse_rr(packet, offset, &rr) != 0) {
                return DNS_E_RR;
            }
            if (rr.class_ == DNS_CLASS_IN && rr.type == DNS_TYPE_CNAME) {
                if (dns_decode_cname(packet, &rr, target, sizeof(target)) != 0) {
                    return DNS_E_CNAME;
                }
                is_alias = 1;
            } else if (rr.class_ == DNS_CLASS_IN && rr.type == DNS_TYPE_HTTPS) {
                int https_rc = dns_decode_https_alias(packet, &rr, target, sizeof(target));
                if (https_rc < 0) {
                    return DNS_E_HTTPS;
                }
                is_alias = https_rc;
            }

            if (is_alias && target[0] != '\0') {
                int owner_gateway = domains_lookup(domains, rr.owner);
                int target_gateway = domains_lookup(domains, target);

                if (owner_gateway >= 0 && target_gateway < 0) {
                    int learn_rc = domains_learn(domains, target, (uint8_t)owner_gateway, 1);
                    if (learn_rc > 0) {
                        changed = 1;
                    }
                }
            }
            offset = rr.next_offset;
        }

        if (!changed) {
            break;
        }
    }
    return 0;
}

int dns_process_response(const ab_bytes_t *packet, const ab_config_t *cfg, domain_table_t *domains,
                         route_state_t *routes, telemetry_t *telemetry, uint32_t now)
{
    uint16_t flags;
    uint16_t question_count;
    uint16_t answer_count;
    size_t offset;
    size_t next;
    char question[AB_DOMAIN_MAX];
    uint16_t question_type;
    int rc;
    uint16_t i;

    if (packet->len < DNS_HEADER_LEN) {
        rc = DNS_E_HEADER;
        goto parse_error;
    }

    flags = ab_read_be16(packet->data + 2u);
    question_count = ab_read_be16(packet->data + 4u);
    answer_count = ab_read_be16(packet->data + 6u);

    if ((flags & DNS_QR_RESPONSE) == 0) {
        rc = DNS_E_NOT_RESPONSE;
        goto parse_error;
    }
    if (question_count != 1u) {
        rc = DNS_E_QUESTION_COUNT;
        goto parse_error;
    }

    offset = DNS_HEADER_LEN;
    if (dns_decode_name(packet->data, packet->len, offset, &next, question, sizeof(question)) !=
        0) {
        rc = DNS_E_NAME;
        goto parse_error;
    }
    offset = next;
    if (offset + 4u > packet->len) {
        rc = DNS_E_QUESTION;
        goto parse_error;
    }
    question_type = ab_read_be16(packet->data + offset);
    offset += 4u;
    telemetry_log_query(telemetry, question_type, question);

    rc = propagate_aliases(packet, offset, answer_count, domains);
    if (rc != 0) {
        goto parse_error;
    }

    for (i = 0; i < answer_count; ++i) {
        dns_rr_t rr;
        if (dns_parse_rr(packet, offset, &rr) != 0) {
            rc = DNS_E_RR;
            goto parse_error;
        }

        if (rr.class_ == DNS_CLASS_IN && rr.type == DNS_TYPE_A) {
            uint32_t ip_be;
            int gateway;
            int blocked;

            if (rr.rdlength != 4u) {
                rc = DNS_E_A_LENGTH;
                goto parse_error;
            }
            memcpy(&ip_be, packet->data + rr.rdata_offset, sizeof(ip_be));
            gateway = domains_lookup(domains, rr.owner);
            blocked = config_ip_blocked(cfg, ip_be);
            if (gateway >= 0 && !blocked && ip_be != 0) {
                (void)routes_observe(routes, (uint8_t)gateway, ip_be, rr.ttl, now);
            }
            telemetry_log_a(telemetry, gateway, blocked || ip_be == 0, rr.owner, ip_be);
        } else if (rr.class_ == DNS_CLASS_IN && rr.type == DNS_TYPE_CNAME) {
            char target[AB_DOMAIN_MAX];
            int gateway;

            if (dns_decode_cname(packet, &rr, target, sizeof(target)) != 0) {
                rc = DNS_E_CNAME;
                goto parse_error;
            }
            gateway = domains_lookup(domains, target);
            telemetry_log_cname(telemetry, gateway, rr.owner, target);
        } else if (rr.class_ == DNS_CLASS_IN && rr.type == DNS_TYPE_HTTPS) {
            char target[AB_DOMAIN_MAX];
            int https_rc = dns_decode_https_alias(packet, &rr, target, sizeof(target));

            if (https_rc < 0) {
                rc = DNS_E_HTTPS;
                goto parse_error;
            }
            if (https_rc > 0 && target[0] != '\0') {
                int gateway = domains_lookup(domains, target);
                telemetry_log_https_alias(telemetry, gateway, rr.owner, target);
            } else {
                telemetry_log_other(telemetry, rr.type, rr.owner);
            }
        } else {
            telemetry_log_other(telemetry, rr.type, rr.owner);
        }

        offset = rr.next_offset;
    }

    telemetry_dns_processed(telemetry);
    return 0;

parse_error:
    telemetry_dns_error(telemetry, rc, packet->data, packet->len);
    return rc;
}
