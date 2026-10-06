#include "domains.h"

#include <curl/curl.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct domain_entry {
    unsigned int gateway : 5;
    unsigned int match_subdomains : 1;
    unsigned int offset : 26;
} domain_entry_t;

typedef char domain_entry_must_be_4_bytes[(sizeof(domain_entry_t) == 4u) ? 1 : -1];

/* array_hashmap callbacks have no context argument. AntiBlock has exactly one
 * live domain table, so keep the arena used by callbacks here. */
static const domain_table_t *domain_map_context;

static uint32_t fnv1a32(const char *s)
{
    uint32_t h = 2166136261u;
    while (*s != '\0') {
        h ^= (uint8_t)*s++;
        h *= 16777619u;
    }
    return h;
}

static array_hashmap_hash domain_add_hash(const void *data)
{
    const domain_entry_t *entry = data;
    return fnv1a32(domain_map_context->arena + entry->offset);
}

static array_hashmap_bool domain_add_cmp(const void *add_data, const void *map_data)
{
    const domain_entry_t *add = add_data;
    const domain_entry_t *stored = map_data;
    return strcmp(domain_map_context->arena + add->offset,
                  domain_map_context->arena + stored->offset) == 0;
}

static array_hashmap_hash domain_find_hash(const void *data)
{
    return fnv1a32((const char *)data);
}

static array_hashmap_bool domain_find_cmp(const void *find_data, const void *map_data)
{
    const domain_entry_t *stored = map_data;
    return strcmp((const char *)find_data, domain_map_context->arena + stored->offset) == 0;
}

static int arena_reserve(domain_table_t *table, uint32_t needed)
{
    char *p;

    if (needed <= table->arena_capacity) {
        return 0;
    }
    if (needed >= AB_DOMAIN_OFFSET_LIMIT) {
        fprintf(stderr, "Domain arena exceeds %u MiB offset limit\n",
                AB_DOMAIN_OFFSET_LIMIT / 1024u / 1024u);
        return -1;
    }
    p = realloc(table->arena, needed);
    if (p == NULL) {
        fprintf(stderr, "Out of memory while growing domain arena to %u bytes\n", needed);
        return -1;
    }
    table->arena = p;
    table->arena_capacity = needed;
    return 0;
}

static int arena_append(domain_table_t *table, const void *data, size_t len)
{
    uint64_t needed64;
    uint32_t needed;

    /* libcurl may deliver a zero-length chunk before arena allocation. */
    if (len == 0) {
        return 0;
    }
    needed64 = (uint64_t)table->arena_size + len;

    if (needed64 >= AB_DOMAIN_OFFSET_LIMIT || needed64 > UINT32_MAX) {
        fprintf(stderr, "Domain arena is too large\n");
        return -1;
    }
    needed = (uint32_t)needed64;
    if (arena_reserve(table, needed) != 0) {
        return -1;
    }
    memcpy(table->arena + table->arena_size, data, len);
    table->arena_size = needed;
    return 0;
}

static int arena_append_byte(domain_table_t *table, char ch)
{
    return arena_append(table, &ch, 1u);
}

typedef struct curl_sink {
    domain_table_t *table;
    int failed;
} curl_sink_t;

static size_t curl_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    curl_sink_t *sink = userdata;
    size_t n;

    if (size != 0 && nmemb > SIZE_MAX / size) {
        sink->failed = 1;
        return 0;
    }
    n = size * nmemb;
    if (arena_append(sink->table, ptr, n) != 0) {
        sink->failed = 1;
        return 0;
    }
    return n;
}

static int source_is_http(const char *source)
{
    return strncmp(source, "http://", 7) == 0 || strncmp(source, "https://", 8) == 0;
}

static int load_http(domain_table_t *table, const char *url)
{
    CURL *curl;
    CURLcode rc;
    long status = 0;
    curl_sink_t sink;
    uint32_t rollback = table->arena_size;

    curl = curl_easy_init();
    if (curl == NULL) {
        fprintf(stderr, "curl_easy_init failed for %s\n", url);
        return -1;
    }

    sink.table = table;
    sink.failed = 0;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long)AB_HTTP_CONNECT_TIMEOUT_SEC);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)AB_HTTP_TIMEOUT_SEC);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "AntiBlock/" AB_VERSION);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sink);

    rc = curl_easy_perform(curl);
    (void)curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK || sink.failed || status < 200 || status >= 300) {
        table->arena_size = rollback;
        fprintf(stderr, "Can't load %s: %s (HTTP %ld)\n", url, curl_easy_strerror(rc), status);
        return -1;
    }
    return 0;
}

static int load_file(domain_table_t *table, const char *path)
{
    FILE *fp;
    long end;
    uint32_t old_size = table->arena_size;
    size_t got;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Can't open domain file %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0 || (end = ftell(fp)) < 0 || fseek(fp, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Can't size domain file %s\n", path);
        fclose(fp);
        return -1;
    }
    if ((uint64_t)old_size + (uint64_t)end >= AB_DOMAIN_OFFSET_LIMIT) {
        fprintf(stderr, "Domain files exceed offset limit\n");
        fclose(fp);
        return -1;
    }
    /* An empty first source leaves arena NULL; never form arena + 0 in that case. */
    if (end == 0) {
        fclose(fp);
        return 0;
    }
    if (arena_reserve(table, old_size + (uint32_t)end) != 0) {
        fclose(fp);
        return -1;
    }
    got = fread(table->arena + old_size, 1u, (size_t)end, fp);
    fclose(fp);
    if (got != (size_t)end) {
        fprintf(stderr, "Can't read domain file %s\n", path);
        table->arena_size = old_size;
        return -1;
    }
    table->arena_size = old_size + (uint32_t)end;
    return 0;
}

static uint32_t count_lines(const char *data, uint32_t start, uint32_t end)
{
    uint32_t i;
    uint32_t count = 0;

    for (i = start; i < end; ++i) {
        if (data[i] == '\n') {
            ++count;
        }
    }
    return count;
}

static int table_allocate_map(domain_table_t *table, uint32_t expected)
{
    if (expected == 0) {
        expected = 1;
    }
    if (expected > INT32_MAX) {
        fprintf(stderr, "Too many domains for array_hashmap\n");
        return -1;
    }

    table->map = array_hashmap_init((int32_t)expected, 1.0, (int32_t)sizeof(domain_entry_t));
    if (table->map == NULL) {
        fprintf(stderr, "Can't allocate domain hashmap for %u entries\n", expected);
        return -1;
    }
    table->map_capacity = expected;
    domain_map_context = table;
    array_hashmap_set_func(table->map, domain_add_hash, domain_add_cmp, domain_find_hash,
                           domain_find_cmp, domain_find_hash, domain_find_cmp);
    return 0;
}

static char ascii_lower(char ch)
{
    if (ch >= 'A' && ch <= 'Z') {
        return (char)(ch + ('a' - 'A'));
    }
    return ch;
}

static int insert_domain_offset(domain_table_t *table, uint32_t offset, uint8_t gateway,
                                int match_subdomains)
{
    domain_entry_t entry;
    array_hashmap_ret_t rc;

    if (gateway >= AB_MAX_RULES || offset >= AB_DOMAIN_OFFSET_LIMIT) {
        return -1;
    }

    memset(&entry, 0, sizeof(entry));
    entry.gateway = gateway;
    entry.match_subdomains = match_subdomains != 0;
    entry.offset = offset;

    rc = array_hashmap_add_elem(table->map, &entry, NULL, NULL);
    if (rc == array_hashmap_elem_added) {
        return 1;
    }
    if (rc == array_hashmap_elem_already_in) {
        return 0;
    }
    return -1;
}

static int index_source_range(domain_table_t *table, uint32_t start, uint32_t end, uint8_t gateway,
                              uint32_t *added)
{
    uint32_t pos = start;

    while (pos < end) {
        uint32_t line_start = pos;
        uint32_t line_end;
        uint32_t domain_start;
        uint32_t i;
        int match_subdomains = 1;
        int rc;

        while (pos < end && table->arena[pos] != '\n') {
            ++pos;
        }
        line_end = pos;
        if (pos < end) {
            table->arena[pos++] = '\0';
        }

        while (line_start < line_end &&
               (table->arena[line_start] == ' ' || table->arena[line_start] == '\t' ||
                table->arena[line_start] == '\r')) {
            ++line_start;
        }
        while (line_end > line_start &&
               (table->arena[line_end - 1u] == ' ' || table->arena[line_end - 1u] == '\t' ||
                table->arena[line_end - 1u] == '\r')) {
            --line_end;
        }
        if (line_start == line_end || table->arena[line_start] == '#') {
            continue;
        }

        if (table->arena[line_start] == '!') {
            match_subdomains = 0;
            ++line_start;
        }
        /* Normalize the www. prefix independently of the source's letter case. */
        if (line_end >= line_start + 4u && ascii_lower(table->arena[line_start]) == 'w' &&
            ascii_lower(table->arena[line_start + 1u]) == 'w' &&
            ascii_lower(table->arena[line_start + 2u]) == 'w' &&
            table->arena[line_start + 3u] == '.') {
            line_start += 4u;
        }
        while (line_end > line_start && table->arena[line_end - 1u] == '.') {
            --line_end;
        }
        if (line_start == line_end) {
            continue;
        }

        domain_start = line_start;
        for (i = line_start; i < line_end; ++i) {
            unsigned char ch = (unsigned char)table->arena[i];
            if (isspace(ch)) {
                domain_start = UINT32_MAX;
                break;
            }
            table->arena[i] = ascii_lower(table->arena[i]);
        }
        if (domain_start == UINT32_MAX) {
            continue;
        }
        table->arena[line_end] = '\0';

        rc = insert_domain_offset(table, domain_start, gateway, match_subdomains);
        if (rc < 0) {
            fprintf(stderr, "Domain hashmap is full\n");
            return -1;
        }
        if (rc > 0) {
            ++*added;
            table->static_count++;
        }
    }
    return 0;
}

void domains_destroy(domain_table_t *table)
{
    if (domain_map_context == table) {
        domain_map_context = NULL;
    }
    array_hashmap_del(&table->map);
    free(table->arena);
    memset(table, 0, sizeof(*table));
}

int domains_reload(domain_table_t *table, const ab_config_t *cfg)
{
    uint32_t source_start[AB_MAX_RULES];
    uint32_t source_end[AB_MAX_RULES];
    uint32_t estimated = AB_LEARNED_DOMAIN_RESERVE_COUNT;
    uint32_t i;
    int any_error = 0;

    domains_destroy(table);

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        fprintf(stderr, "curl_global_init failed\n");
        return -1;
    }

    for (i = 0; i < cfg->rule_count; ++i) {
        uint32_t lines;

        source_start[i] = table->arena_size;
        if (source_is_http(cfg->rules[i].source)) {
            if (load_http(table, cfg->rules[i].source) != 0) {
                any_error = 1;
            }
        } else if (load_file(table, cfg->rules[i].source) != 0) {
            curl_global_cleanup();
            domains_destroy(table);
            return -1;
        }

        if (table->arena_size == source_start[i] || table->arena[table->arena_size - 1u] != '\n') {
            if (arena_append_byte(table, '\n') != 0) {
                curl_global_cleanup();
                domains_destroy(table);
                return -1;
            }
        }
        source_end[i] = table->arena_size;
        lines = count_lines(table->arena, source_start[i], source_end[i]);
        if (UINT32_MAX - estimated < lines) {
            curl_global_cleanup();
            domains_destroy(table);
            return -1;
        }
        estimated += lines;
    }
    curl_global_cleanup();

    if (arena_reserve(table, table->arena_size + AB_LEARNED_DOMAIN_RESERVE_BYTES) != 0) {
        domains_destroy(table);
        return -1;
    }
    if (table_allocate_map(table, estimated) != 0) {
        domains_destroy(table);
        return -1;
    }

    for (i = 0; i < cfg->rule_count; ++i) {
        uint32_t count = 0;
        if (index_source_range(table, source_start[i], source_end[i], (uint8_t)i, &count) != 0) {
            domains_destroy(table);
            return -1;
        }
        printf("From %s read %u domains\n", cfg->rules[i].source, count);
    }

    return any_error ? 1 : 0;
}

int domains_lookup(const domain_table_t *table, const char *domain)
{
    const char *base = domain;
    const char *candidate;

    if (table->map == NULL || domain_map_context != table) {
        return -1;
    }
    if (strncmp(base, "www.", 4u) == 0) {
        base += 4;
    }

    candidate = base;
    for (;;) {
        domain_entry_t entry;
        array_hashmap_ret_t rc = array_hashmap_find_elem(table->map, candidate, &entry);

        if (rc == array_hashmap_elem_finded) {
            if (candidate == base || entry.match_subdomains) {
                return (int)entry.gateway;
            }
        }
        candidate = strchr(candidate, '.');
        if (candidate == NULL) {
            break;
        }
        ++candidate;
        if (*candidate == '\0') {
            break;
        }
    }
    return -1;
}

static void warn_learn_capacity(domain_table_t *table)
{
    if (!table->learn_capacity_warned) {
        fprintf(stderr, "Learned domain capacity reached; further aliases may be skipped "
                        "until domain reload\n");
        table->learn_capacity_warned = 1;
    }
}

int domains_learn(domain_table_t *table, const char *domain, uint8_t gateway, int match_subdomains)
{
    domain_entry_t existing;
    uint32_t len;
    uint32_t offset;
    int rc;

    if (table->map == NULL || domain_map_context != table) {
        return -1;
    }
    if (array_hashmap_find_elem(table->map, domain, &existing) == array_hashmap_elem_finded) {
        return 0;
    }

    len = (uint32_t)strlen(domain) + 1u;
    if (len > AB_DOMAIN_MAX) {
        return -1;
    }
    if (table->arena_size + len > table->arena_capacity) {
        warn_learn_capacity(table);
        return -1;
    }

    offset = table->arena_size;
    memcpy(table->arena + offset, domain, len);
    table->arena_size += len;

    rc = insert_domain_offset(table, offset, gateway, match_subdomains);
    if (rc <= 0) {
        table->arena_size = offset;
        if (rc < 0) {
            warn_learn_capacity(table);
        }
        return rc;
    }
    table->learned_count++;
    return 1;
}
