/* Deterministic collision/churn regression against an independent reference map. */
#include "array_hashmap.h"

#include <stdint.h>
#include <stdio.h>

#define MAP_CAPACITY 191
#define KEY_COUNT 350
#define OPERATIONS 250000

typedef struct map_value {
    uint32_t key;
    uint32_t value;
} map_value_t;

static uint32_t random_state = 0x98765432u;
static uint8_t delete_mask[KEY_COUNT];

static uint32_t next_random(void)
{
    random_state ^= random_state << 13;
    random_state ^= random_state >> 17;
    random_state ^= random_state << 5;
    return random_state;
}

/* Force many collisions, including collisions between displaced entries. */
static uint32_t add_hash(const void *entry)
{
    return ((const map_value_t *)entry)->key % 17u;
}

static uint32_t find_hash(const void *key)
{
    return *(const uint32_t *)key % 17u;
}

static int32_t add_cmp(const void *a, const void *b)
{
    return ((const map_value_t *)a)->key == ((const map_value_t *)b)->key;
}

static int32_t find_cmp(const void *key, const void *entry)
{
    return *(const uint32_t *)key == ((const map_value_t *)entry)->key;
}

static int32_t replace_entry(const void *a, const void *b)
{
    (void)a;
    (void)b;
    return array_hashmap_save_new;
}

static int32_t should_delete(const void *entry)
{
    return delete_mask[((const map_value_t *)entry)->key];
}

static int check_all(array_hashmap_t map, const map_value_t *reference, const uint8_t *present,
                     int count)
{
    uint32_t key;
    map_value_t got;
    array_hashmap_ret_t rc;

    if (array_hashmap_now_in_map(map) != count) {
        return -1;
    }
    for (key = 0; key < KEY_COUNT; ++key) {
        rc = array_hashmap_find_elem(map, &key, &got);
        if (present[key]) {
            if (rc != array_hashmap_elem_finded || got.value != reference[key].value) {
                return -1;
            }
        } else if (rc != array_hashmap_elem_not_finded) {
            return -1;
        }
    }
    return 0;
}

int main(void)
{
    array_hashmap_t map = array_hashmap_init(MAP_CAPACITY, 1.0, sizeof(map_value_t));
    map_value_t reference[KEY_COUNT] = { { 0 } };
    uint8_t present[KEY_COUNT] = { 0 };
    int count = 0;
    int step;
    int status = 1;

    if (map == NULL) {
        return status;
    }
    array_hashmap_set_func(map, add_hash, add_cmp, find_hash, find_cmp, find_hash, find_cmp);

    for (step = 0; step < OPERATIONS; ++step) {
        uint32_t key = next_random() % KEY_COUNT;
        int operation = (int)(next_random() % 8u);
        map_value_t value = { key, next_random() };
        map_value_t got = { 0 };
        array_hashmap_ret_t rc;

        if (operation < 3) {
            rc = array_hashmap_add_elem(map, &value, NULL, replace_entry);
            if (present[key]) {
                if (rc != array_hashmap_elem_already_in) {
                    goto done;
                }
                reference[key] = value;
            } else if (count < MAP_CAPACITY) {
                if (rc != array_hashmap_elem_added) {
                    goto done;
                }
                reference[key] = value;
                present[key] = 1;
                ++count;
            } else if (rc != array_hashmap_full) {
                goto done;
            }
        } else if (operation < 5) {
            rc = array_hashmap_del_elem(map, &key, &got);
            if (present[key]) {
                if (rc != array_hashmap_elem_deled || got.value != reference[key].value) {
                    goto done;
                }
                present[key] = 0;
                --count;
            } else if (rc != array_hashmap_elem_not_deled) {
                goto done;
            }
        } else if (operation == 5) {
            int deleted = 0;
            uint32_t i;
            int got_count;

            for (i = 0; i < KEY_COUNT; ++i) {
                delete_mask[i] = (uint8_t)(i % 4u == key % 4u);
            }
            got_count = array_hashmap_del_elem_by_func(map, should_delete);
            for (i = 0; i < KEY_COUNT; ++i) {
                if (present[i] && delete_mask[i]) {
                    present[i] = 0;
                    --count;
                    ++deleted;
                }
            }
            if (got_count != deleted) {
                goto done;
            }
        } else {
            rc = array_hashmap_find_elem(map, &key, &got);
            if (present[key]) {
                if (rc != array_hashmap_elem_finded || got.value != reference[key].value) {
                    goto done;
                }
            } else if (rc != array_hashmap_elem_not_finded) {
                goto done;
            }
        }

        if (array_hashmap_now_in_map(map) != count) {
            goto done;
        }
        if (step % 101 == 0 && check_all(map, reference, present, count) != 0) {
            goto done;
        }
    }
    if (check_all(map, reference, present, count) == 0) {
        puts("PASS: 250000 hashmap operations with heavy collisions");
        status = 0;
    }

done:
    if (status != 0) {
        fprintf(stderr, "FAIL: hashmap regression at operation %d\n", step);
    }
    array_hashmap_del(&map);
    return status;
}
